#!/usr/bin/env node

import { Buffer } from 'node:buffer';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';

const origin = 'http://localhost:3312';
const directory = '/var/tmp/henry-build/aster-phase2-token-status-oracle';
const marker = randomBytes(6).toString('hex');
const secrets = [];
const created = [];
const results = [];

const call = async (path, method = 'GET', body, headers = {}) => {
  const response = await fetch(new URL(path, origin), {
    method,
    headers: { ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  return response;
};

const admin = async (path, method = 'GET', body) => {
  const response = await call(`/api/${path}`, method, body, {
    'development-user-id': 'integration-test-admin-user',
  });
  if (!response.ok) throw new Error(`management ${method} ${path}: ${response.status}`);
  return response.status === 204 ? null : response.json();
};

const postForm = async (path, fields, headers = {}) => {
  const response = await fetch(new URL(path, origin), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(fields),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  return response;
};

const observe = async (kind, name, token, hint, proof = {}) => {
  const response = await postForm(`/oidc/token/${kind}`, {
    token,
    ...(hint === undefined ? {} : { token_type_hint: hint }),
    ...(proof.form ?? {}),
  }, proof.headers);
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  const entry = {
    kind,
    name,
    status: response.status,
    headers: Object.fromEntries(
      ['content-type', 'cache-control', 'www-authenticate', 'access-control-allow-origin']
        .filter((key) => response.headers.has(key))
        .map((key) => [key, response.headers.get(key)]),
    ),
    body,
  };
  results.push(entry);
  return entry;
};

const cookie = (response, prior = '') => {
  const map = new Map(prior.split('; ').filter(Boolean).map((part) => part.split('=', 2)));
  for (const value of response.headers.getSetCookie()) {
    const part = value.split(';', 1)[0];
    const index = part.indexOf('=');
    if (index > 0) map.set(part.slice(0, index), part.slice(index + 1));
  }
  return [...map].map(([key, value]) => `${key}=${value}`).join('; ');
};

const requireStatus = (response, expected, label) => {
  if (response.status !== expected) throw new Error(`${label}: ${response.status}`);
  return response;
};

await mkdir(directory, { recursive: true, mode: 0o700 });
let failure;
try {
  const redirectUri = `${origin}/callback`;
  const app = await admin('applications', 'POST', {
    name: `status-owner-${marker}`,
    type: 'Traditional',
    oidcClientMetadata: { redirectUris: [redirectUri], postLogoutRedirectUris: [] },
    customClientMetadata: { alwaysIssueRefreshToken: true },
  });
  created.push(`applications/${encodeURIComponent(app.id)}`);
  const [secret] = await admin(`applications/${encodeURIComponent(app.id)}/secrets`);
  secrets.push(secret.value);
  const basic = `Basic ${Buffer.from(`${app.id}:${secret.value}`).toString('base64')}`;
  secrets.push(basic);
  const outsider = await admin('applications', 'POST', {
    name: `status-outsider-${marker}`,
    type: 'SPA',
    oidcClientMetadata: { redirectUris: [redirectUri], postLogoutRedirectUris: [] },
  });
  created.push(`applications/${encodeURIComponent(outsider.id)}`);
  const resource = await admin('resources', 'POST', {
    name: `status-resource-${marker}`,
    indicator: `https://status-${marker}.example.invalid/api`,
  });
  created.push(`resources/${encodeURIComponent(resource.id)}`);
  const username = `status${marker}`;
  const password = `${randomBytes(20).toString('base64url')}A1!`;
  secrets.push(password);
  const user = await admin('users', 'POST', { username, password, name: 'Status Probe' });
  created.push(`users/${encodeURIComponent(user.id)}`);
  await admin('sign-in-exp', 'PATCH', {
    signInMode: 'SignInAndRegister',
    signUp: { identifiers: [], password: false, verify: false },
    signIn: { methods: [{ identifier: 'username', password: true, verificationCode: false, isPasswordPrimary: false }] },
    mfa: { factors: [], policy: 'PromptAtSignInAndSignUp' },
  });

  const verifier = randomBytes(32).toString('base64url');
  secrets.push(verifier);
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const authorization = new URL('/oidc/auth', origin);
  authorization.search = new URLSearchParams({
    client_id: app.id,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid offline_access profile',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    resource: resource.indicator,
  }).toString();
  const begin = requireStatus(await call(authorization.pathname + authorization.search), 303, 'authorize');
  let cookies = cookie(begin);
  const bootstrap = requireStatus(await call('/api/experience', 'PUT', { interactionEvent: 'SignIn' }, { cookie: cookies }), 204, 'bootstrap');
  cookies = cookie(bootstrap, cookies);
  const verified = requireStatus(await call('/api/experience/verification/password', 'POST', {
    identifier: { type: 'username', value: username }, password,
  }, { cookie: cookies }), 200, 'password');
  const { verificationId } = await verified.json();
  secrets.push(verificationId);
  requireStatus(await call('/api/experience/identification', 'POST', { verificationId }, { cookie: cookies }), 204, 'identify');
  const submit = requireStatus(await call('/api/experience/submit', 'POST', undefined, { cookie: cookies }), 200, 'submit');
  cookies = cookie(submit, cookies);
  const submitted = await submit.json();
  const bridge = requireStatus(await call(new URL(submitted.redirectTo).pathname, 'GET', undefined, { cookie: cookies }), 303, 'bridge');
  cookies = cookie(bridge, cookies);
  requireStatus(await call('/api/interaction/consent', 'GET', undefined, { cookie: cookies }), 200, 'consent-get');
  const consent = requireStatus(await call('/api/interaction/consent', 'POST', {}, { cookie: cookies }), 200, 'consent-post');
  const consentBody = await consent.json();
  const resume = requireStatus(await call(new URL(consentBody.redirectTo).pathname, 'GET', undefined, { cookie: cookies }), 303, 'resume');
  const code = new URL(resume.headers.get('location')).searchParams.get('code');
  if (!code) throw new Error('authorization code missing');
  secrets.push(code);
  const issued = requireStatus(await postForm('/oidc/token', {
    grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri,
  }, { authorization: basic }), 200, 'token');
  const tokens = await issued.json();
  if (typeof tokens.access_token !== 'string' || typeof tokens.refresh_token !== 'string') {
    throw new Error('opaque credentials missing');
  }
  secrets.push(tokens.access_token, tokens.refresh_token);
  const proof = { headers: { authorization: basic } };
  const postProof = { form: { client_id: app.id, client_secret: secret.value } };
  const wrongProof = { headers: { authorization: `Basic ${Buffer.from(`${app.id}:wrong-secret`).toString('base64')}` } };
  const resourceTokenResponse = requireStatus(await postForm('/oidc/token', {
    grant_type: 'refresh_token', refresh_token: tokens.refresh_token, resource: resource.indicator,
  }, { authorization: basic }), 200, 'resource-token');
  const resourceTokens = await resourceTokenResponse.json();
  if (typeof resourceTokens.access_token !== 'string' || resourceTokens.access_token.split('.').length !== 3) {
    throw new Error('structured resource token missing');
  }
  secrets.push(resourceTokens.access_token);
  await observe('introspection', 'owner-access', tokens.access_token, 'access_token', proof);
  await observe('introspection', 'owner-refresh', tokens.refresh_token, 'refresh_token', proof);
  await observe('introspection', 'owner-access-wrong-hint', tokens.access_token, 'refresh_token', proof);
  await observe('introspection', 'owner-refresh-no-hint', tokens.refresh_token, undefined, proof);
  await observe('introspection', 'owner-access-post-proof', tokens.access_token, 'access_token', postProof);
  await observe('introspection', 'owner-access-wrong-secret', tokens.access_token, 'access_token', wrongProof);
  await observe('introspection', 'owner-access-no-proof', tokens.access_token, 'access_token');
  await observe('introspection', 'structured-jwt', resourceTokens.access_token, 'access_token', proof);
  await observe('revocation', 'structured-jwt', resourceTokens.access_token, 'access_token', proof);
  await observe('introspection', 'public-other', tokens.access_token, 'access_token', { form: { client_id: outsider.id } });
  await observe('revocation', 'public-other', tokens.access_token, 'access_token', { form: { client_id: outsider.id } });
  await observe('introspection', 'owner-after-cross-client', tokens.access_token, 'access_token', proof);
  await observe('revocation', 'owner-access', tokens.access_token, 'access_token', proof);
  await observe('introspection', 'owner-after-revoke', tokens.access_token, 'access_token', proof);
  await observe('introspection', 'owner-refresh-after-revoke', tokens.refresh_token, 'refresh_token', proof);
  const refresh = await postForm('/oidc/token', {
    grant_type: 'refresh_token', refresh_token: tokens.refresh_token,
  }, { authorization: basic });
  const refreshBody = await refresh.json();
  results.push({ kind: 'token', name: 'refresh-after-access-revoke', status: refresh.status,
    body: { error: refreshBody.error, error_description: refreshBody.error_description } });

  const nextAuthorization = new URL('/oidc/auth', origin);
  const nextVerifier = randomBytes(32).toString('base64url');
  secrets.push(nextVerifier);
  nextAuthorization.search = new URLSearchParams({
    client_id: app.id, redirect_uri: redirectUri, response_type: 'code',
    scope: 'openid offline_access profile',
    code_challenge: createHash('sha256').update(nextVerifier).digest('base64url'),
    code_challenge_method: 'S256', resource: resource.indicator,
  }).toString();
  const nextBegin = requireStatus(await call(nextAuthorization.pathname + nextAuthorization.search), 303, 'next-authorize');
  let nextCookies = cookie(nextBegin);
  const nextBootstrap = requireStatus(await call('/api/experience', 'PUT', { interactionEvent: 'SignIn' }, { cookie: nextCookies }), 204, 'next-bootstrap');
  nextCookies = cookie(nextBootstrap, nextCookies);
  const nextVerified = requireStatus(await call('/api/experience/verification/password', 'POST', {
    identifier: { type: 'username', value: username }, password,
  }, { cookie: nextCookies }), 200, 'next-password');
  const { verificationId: nextVerificationId } = await nextVerified.json();
  secrets.push(nextVerificationId);
  requireStatus(await call('/api/experience/identification', 'POST', { verificationId: nextVerificationId }, { cookie: nextCookies }), 204, 'next-identify');
  const nextSubmit = requireStatus(await call('/api/experience/submit', 'POST', undefined, { cookie: nextCookies }), 200, 'next-submit');
  nextCookies = cookie(nextSubmit, nextCookies);
  const nextSubmitted = await nextSubmit.json();
  const nextBridge = requireStatus(await call(new URL(nextSubmitted.redirectTo).pathname, 'GET', undefined, { cookie: nextCookies }), 303, 'next-bridge');
  nextCookies = cookie(nextBridge, nextCookies);
  requireStatus(await call('/api/interaction/consent', 'GET', undefined, { cookie: nextCookies }), 200, 'next-consent-get');
  const nextConsent = requireStatus(await call('/api/interaction/consent', 'POST', {}, { cookie: nextCookies }), 200, 'next-consent-post');
  const nextConsentBody = await nextConsent.json();
  const nextResume = requireStatus(await call(new URL(nextConsentBody.redirectTo).pathname, 'GET', undefined, { cookie: nextCookies }), 303, 'next-resume');
  const nextCode = new URL(nextResume.headers.get('location')).searchParams.get('code');
  if (!nextCode) throw new Error('next authorization code missing');
  secrets.push(nextCode);
  const nextIssued = requireStatus(await postForm('/oidc/token', {
    grant_type: 'authorization_code', code: nextCode, code_verifier: nextVerifier, redirect_uri: redirectUri,
  }, { authorization: basic }), 200, 'next-token');
  const nextTokens = await nextIssued.json();
  if (typeof nextTokens.refresh_token !== 'string') throw new Error('next refresh credential missing');
  secrets.push(nextTokens.access_token, nextTokens.refresh_token);
  const rotatedResponse = requireStatus(await postForm('/oidc/token', {
    grant_type: 'refresh_token', refresh_token: nextTokens.refresh_token,
  }, { authorization: basic }), 200, 'rotate-refresh');
  const rotated = await rotatedResponse.json();
  if (typeof rotated.refresh_token !== 'string') throw new Error('rotated refresh credential missing');
  secrets.push(rotated.access_token, rotated.refresh_token);
  await observe('introspection', 'consumed-refresh', nextTokens.refresh_token, 'refresh_token', proof);
  await observe('revocation', 'consumed-refresh', nextTokens.refresh_token, 'refresh_token', proof);
  await observe('introspection', 'rotated-refresh-after-consumed-revoke', rotated.refresh_token, 'refresh_token', proof);
} catch (error) {
  failure = error;
} finally {
  for (const path of created.toReversed()) {
    try {
      await admin(path, 'DELETE');
    } catch (error) {
      failure ??= error;
    }
  }
}
if (failure) throw failure;
const serialized = JSON.stringify(results, null, 2);
if (secrets.some((value) => value && serialized.includes(value)) || /(?:"token"\s*:|Bearer\s+[A-Za-z0-9._~-]+)/u.test(serialized)) {
  throw new Error('token-status lifecycle packet contains credentials');
}
const path = `${directory}/lifecycle-${marker}.json`;
await writeFile(path, `${serialized}\n`, { flag: 'wx', mode: 0o600 });
console.log(path);
