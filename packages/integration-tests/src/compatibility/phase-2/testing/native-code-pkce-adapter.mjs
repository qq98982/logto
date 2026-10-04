import { createHash, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { createLocalJWKSet, jwtVerify } from 'jose';

const fail = (category) => { throw new TypeError(`callback rejected (${category})`); };
const bounded = (value, category, limit = 8192) =>
  typeof value === 'string' && value.length > 0 && value.length <= limit && !/[\0\r\n]/u.test(value)
    ? value : fail(category);

const hidden = (label, publicFields, secrets) => Object.freeze({
  ...publicFields,
  ...Object.fromEntries(Object.entries(secrets).map(([name, value]) => [
    `get${name[0].toUpperCase()}${name.slice(1)}`, () => value,
  ])),
  toJSON: () => fail('credential-serialization'),
  [inspect.custom]: () => `${label}(<redacted>)`,
});

const verifyJwt = async ({ token, jwks, algorithm, issuer, audience, now, nonce, resource }) => {
  let verified;
  try {
    verified = await jwtVerify(bounded(token, 'jwt'), createLocalJWKSet(jwks), {
      algorithms: [algorithm], issuer, audience, currentDate: new Date(now * 1000),
      clockTolerance: 15, requiredClaims: ['sub', 'iat', 'exp'],
    });
  } catch { return fail('jwt-verification'); }
  const { payload, protectedHeader } = verified;
  const subject = bounded(payload.sub, 'subject', 256);
  if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp)) fail('jwt-time');
  if (nonce !== undefined && payload.nonce !== nonce) fail('nonce');
  if (resource !== undefined && (
    protectedHeader.typ !== 'at+jwt' || payload.client_id !== resource.clientId ||
    payload.scope !== resource.scope || payload.iat > now + 15 ||
    payload.exp <= payload.iat || payload.exp - payload.iat > 300
  )) fail('resource-claims');
  return { subject };
};

const validatedRedirect = (value) => {
  const redirect = new URL(value);
  if (redirect.search || redirect.hash || redirect.username || redirect.password) fail('redirect-config');
  return redirect;
};
const sameRedirectEndpoint = (actual, expected) =>
  actual.protocol === expected.protocol && actual.username === expected.username &&
  actual.password === expected.password && actual.hostname === expected.hostname &&
  actual.port === expected.port && actual.pathname === expected.pathname;
const issuerEndpoint = (issuer, path) => {
  const base = new URL(issuer);
  if (base.search || base.hash || base.username || base.password) fail('issuer-config');
  base.pathname = base.pathname.endsWith('/') ? base.pathname : `${base.pathname}/`;
  return new URL(path, base);
};
const selectedScope = (value) =>
  bounded(value, 'scope', 256) === 'session:exchange' ? value : fail('scope');
const selectedIdTokenAlgorithm = (value) =>
  value === 'ES384' ? value : fail('id-token-algorithm');

export const startNativeAuthorization = (config, entropy = randomBytes) => {
  selectedIdTokenAlgorithm(config.idTokenAlgorithm);
  const redirect = validatedRedirect(config.redirectUri);
  const verifier = entropy(32).toString('base64url');
  const state = entropy(32).toString('base64url');
  const nonce = entropy(32).toString('base64url');
  const authorization = issuerEndpoint(config.issuer, 'auth');
  authorization.search = new URLSearchParams({
    client_id: bounded(config.clientId, 'client-id', 256), redirect_uri: redirect.href,
    response_type: 'code',
    scope: `openid offline_access profile ${selectedScope(config.resourceScope)}`,
    resource: new URL(config.resource).href,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256', state, nonce,
  }).toString();
  return hidden('NativeAuthorizationAttempt', { authorizationUrl: authorization.href }, { verifier, state, nonce });
};

const tokenRequest = async (fetcher, issuer, fields) => {
  const response = await fetcher(issuerEndpoint(issuer, 'token'), {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields), redirect: 'manual',
  });
  if (response.status !== 200) fail('token-http');
  const body = await response.json();
  if (body.token_type !== 'Bearer') fail('token-type');
  return body;
};

export const completeNativeCallback = async ({ callbackUrl, attempt, config, jwks, fetcher, now }) => {
  selectedScope(config.resourceScope);
  const idTokenAlgorithm = selectedIdTokenAlgorithm(config.idTokenAlgorithm);
  const callback = new URL(callbackUrl);
  const expected = validatedRedirect(config.redirectUri);
  const callbackKeys = [...callback.searchParams.keys()];
  if (!sameRedirectEndpoint(callback, expected) || callback.hash ||
    callbackKeys.some((key) => key !== 'code' && key !== 'state' && key !== 'iss') ||
    callback.searchParams.getAll('state').length !== 1 ||
    callback.searchParams.get('state') !== attempt.getState() ||
    callback.searchParams.getAll('iss').length !== 1 ||
    callback.searchParams.get('iss') !== config.issuer ||
    callback.searchParams.getAll('code').length !== 1 || callback.searchParams.has('error')) {
    fail('callback-binding');
  }
  const code = bounded(callback.searchParams.get('code'), 'code', 4096);
  const resourceResult = await tokenRequest(fetcher, config.issuer, {
    grant_type: 'authorization_code', code, code_verifier: attempt.getVerifier(),
    redirect_uri: expected.href, client_id: config.clientId, resource: config.resource,
  });
  const resourceAccessToken = bounded(resourceResult.access_token, 'resource-token');
  const refreshToken = bounded(resourceResult.refresh_token, 'refresh-token');
  const id = await verifyJwt({ token: resourceResult.id_token, jwks, algorithm: idTokenAlgorithm,
    issuer: config.issuer, audience: config.clientId, now, nonce: attempt.getNonce() });
  const resource = await verifyJwt({ token: resourceAccessToken, jwks, algorithm: 'ES384',
    issuer: config.issuer, audience: config.resource, now,
    resource: { clientId: config.clientId, scope: config.resourceScope } });
  if (resource.subject !== id.subject) fail('subject-binding');
  const profileResult = await tokenRequest(fetcher, config.issuer, {
    grant_type: 'refresh_token', refresh_token: refreshToken, client_id: config.clientId,
  });
  const profileAccessToken = bounded(profileResult.access_token, 'profile-token');
  if (profileAccessToken.split('.').length === 3) fail('profile-token-shape');
  const userinfoResponse = await fetcher(issuerEndpoint(config.issuer, 'me'), {
    headers: { authorization: `Bearer ${profileAccessToken}`, accept: 'application/json' }, redirect: 'manual',
  });
  if (userinfoResponse.status !== 200) fail('userinfo-http');
  const profile = await userinfoResponse.json();
  if (bounded(profile?.sub, 'profile-subject', 256) !== resource.subject) fail('subject-binding');
  return hidden('NativeCallbackCredentials', { subject: resource.subject, profile },
    { resourceAccessToken, profileAccessToken });
};

export const completeMiniProviderCode = async ({ code, verifyCodeOnly }) =>
  verifyCodeOnly(Object.freeze({ code: bounded(code, 'mini-code', 4096) }));
