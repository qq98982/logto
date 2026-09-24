/* eslint-disable complexity, no-restricted-syntax, no-await-in-loop, no-control-regex, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This bounded transport keeps cookies, password, verifier and issued credentials inside one private flow. */
import { createHash, randomBytes } from 'node:crypto';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export type IssuedPublicUserTokens = Readonly<{
  access: string;
  refresh: string;
  toJSON(): never;
}>;

const diagnostic = 'Invalid Phase 2 public user token issuance';
const fail = (): never => {
  throw new TypeError(diagnostic);
};

const bounded = (value: unknown, maximum = 8192): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();

const jsonBody = async (response: Response): Promise<Record<string, unknown>> => {
  const maximum = 16 * 1024;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    return fail();
  }
  const reader = response.body?.getReader();
  if (!reader) {
    return fail();
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    // eslint-disable-next-line no-constant-condition -- The response reader terminates on done.
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      size += value.byteLength;
      if (size > maximum) {
        await reader.cancel();
        return fail();
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const parsed: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    Array.isArray(parsed) ||
    Object.getPrototypeOf(parsed) !== Object.prototype
  ) {
    return fail();
  }
  return parsed as Record<string, unknown>;
};

const requireStatus = async (response: Response, expected: number): Promise<Response> => {
  if (response.status !== expected || response.redirected) {
    await response.body?.cancel();
    return fail();
  }
  return response;
};

const discard = async (response: Response): Promise<void> => {
  await response.body?.cancel();
};

const mergeCookies = (jar: Map<string, string>, response: Response): void => {
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (
      separator <= 0 ||
      !/^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u.test(name) ||
      Buffer.byteLength(value) > 4096 ||
      /[\u0000-\u001F\u007F;]/u.test(value)
    ) {
      fail();
    }
    jar.set(name, value);
    if (jar.size > 16) {
      fail();
    }
  }
};

const localRedirect = (value: unknown, origin: URL): URL => {
  const destination = new URL(bounded(value), origin);
  if (destination.origin !== origin.origin || destination.username || destination.password) {
    return fail();
  }
  return destination;
};

export const issuePublicUserTokens = async (
  targetInput: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status' | 'withSecretLease'>,
  requestFetch: typeof fetch = fetch
): Promise<IssuedPublicUserTokens> => {
  try {
    const target = validateTargetConfig(targetInput);
    const status = fixture.status ?? fail();
    const origin = new URL(target.coreUrl);
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const cookies = new Map<string, string>();
    const endpoint = (path: string): URL => new URL(path, origin);
    const send = async (
      url: URL,
      method: 'GET' | 'POST' | 'PUT',
      body?: Readonly<Record<string, unknown>> | URLSearchParams
    ): Promise<Response> => {
      const headers = new Headers();
      if (cookies.size > 0) {
        headers.set('cookie', [...cookies].map(([name, value]) => name + '=' + value).join('; '));
      }
      if (body !== undefined) {
        headers.set(
          'content-type',
          body instanceof URLSearchParams ? 'application/x-www-form-urlencoded' : 'application/json'
        );
      }
      const response = await requestFetch(url, {
        method,
        headers,
        ...(body === undefined
          ? {}
          : { body: body instanceof URLSearchParams ? body : JSON.stringify(body) }),
        redirect: 'manual',
        signal: AbortSignal.timeout(10_000),
      });
      mergeCookies(cookies, response);
      return response;
    };
    const authorization = endpoint('/oidc/auth');
    authorization.search = new URLSearchParams({
      client_id: status.client.id,
      redirect_uri: status.client.redirectUri,
      response_type: 'code',
      scope: 'openid offline_access profile',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString();
    await discard(await requireStatus(await send(authorization, 'GET'), 303));
    await fixture.withSecretLease(async (lease) => {
      const password = bounded(lease.getSubjectPassword?.() ?? fail(), 256);
      await discard(
        await requireStatus(
          await send(endpoint('/api/experience'), 'PUT', { interactionEvent: 'SignIn' }),
          204
        )
      );
      const verification = await jsonBody(
        await requireStatus(
          await send(endpoint('/api/experience/verification/password'), 'POST', {
            identifier: { type: 'username', value: status.user.username },
            password,
          }),
          200
        )
      );
      const verificationId = bounded(verification.verificationId, 4096);
      await discard(
        await requireStatus(
          await send(endpoint('/api/experience/identification'), 'POST', { verificationId }),
          204
        )
      );
    });
    const submitted = await jsonBody(
      await requireStatus(await send(endpoint('/api/experience/submit'), 'POST'), 200)
    );
    const bridge = await requireStatus(
      await send(localRedirect(submitted.redirectTo, origin), 'GET'),
      303
    );
    await bridge.body?.cancel();
    await discard(
      await requireStatus(await send(endpoint('/api/interaction/consent'), 'GET'), 200)
    );
    const consent = await jsonBody(
      await requireStatus(await send(endpoint('/api/interaction/consent'), 'POST', {}), 200)
    );
    const resumed = await requireStatus(
      await send(localRedirect(consent.redirectTo, origin), 'GET'),
      303
    );
    const location = new URL(bounded(resumed.headers.get('location')));
    await resumed.body?.cancel();
    if (location.origin + location.pathname !== status.client.redirectUri) {
      return fail();
    }
    const code = bounded(location.searchParams.get('code'), 4096);
    const issued = await jsonBody(
      await requireStatus(
        await send(
          endpoint('/oidc/token'),
          'POST',
          new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            code_verifier: verifier,
            redirect_uri: status.client.redirectUri,
            client_id: status.client.id,
          })
        ),
        200
      )
    );
    if (issued.token_type !== 'Bearer') {
      return fail();
    }
    const access = bounded(issued.access_token);
    const refresh = bounded(issued.refresh_token);
    if (access === refresh) {
      return fail();
    }
    return Object.freeze({ access, refresh, toJSON: (): never => fail() });
  } catch {
    return fail();
  }
};
/* eslint-enable complexity, no-restricted-syntax, no-await-in-loop, no-control-regex, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
