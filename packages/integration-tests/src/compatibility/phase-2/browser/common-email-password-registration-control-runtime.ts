/* eslint-disable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment -- Parsed and reflected transport values are validated before use. */
import { createHash, randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import { observeVerificationCodePrivate } from '../clients/verification-code.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import type {
  EmailPasswordRegistrationControlKind,
  EmailPasswordRegistrationControlRuntime,
} from './common-email-password-registration-controls.js';

const fail = (): never => {
  throw new TypeError('Invalid email password registration control runtime');
};
const mergeCookies = (cookies: Map<string, string>, response: Response): void => {
  for (const raw of response.headers.getSetCookie()) {
    const pair = raw.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    const name = pair.slice(0, separator);
    const value = pair.slice(separator + 1);
    if (
      separator <= 0 ||
      !/^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u.test(name) ||
      Buffer.byteLength(value) > 4096 ||
      /[\u0000-\u001F\u007F;]/u.test(value) ||
      cookies.size >= 16
    ) {
      return fail();
    }
    cookies.set(name, value);
  }
};
const cookieHeader = (cookies: Map<string, string>): string =>
  [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
const readAction = async (
  response: Response
): Promise<Readonly<{ status: number; error: string }>> => {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > 65_536)) {
    return fail();
  }
  const text = await response.text();
  if (Buffer.byteLength(text) > 65_536) {
    return fail();
  }
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    return fail();
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return fail();
  }
  const error = Reflect.get(parsed, 'code');
  return Object.freeze({ status: response.status, error: typeof error === 'string' ? error : '' });
};

export const createEmailPasswordRegistrationControlRuntime = (
  input: Readonly<{
    target: TargetConfig;
    request: Phase2AdminRequestFunction;
    clientId: string;
    redirectUri: string;
    fetch?: typeof fetch;
    takePasscode(recipient: string): Promise<string>;
  }>
): EmailPasswordRegistrationControlRuntime => ({
  authenticatedLookupExactEmail: async (email) => {
    const users = await input.request({
      method: 'GET',
      path: 'users',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (!Array.isArray(users) || users.length >= 100) {
      return fail();
    }
    const ids: string[] = [];
    for (const user of users) {
      if (
        typeof user === 'object' &&
        user !== null &&
        Reflect.get(user, 'primaryEmail') === email
      ) {
        const id = Reflect.get(user, 'id');
        if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(id)) {
          return fail();
        }
        ids.push(id);
      }
    }
    return Object.freeze(ids);
  },
  runVerifiedRegistration: async (kind: EmailPasswordRegistrationControlKind, email: string) => {
    const requestFetch = input.fetch ?? fetch;
    const cookies = new Map<string, string>();
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    if (verifier.length !== 43 || challenge.length !== 43) {
      return fail();
    }
    const auth = new URL('/oidc/auth', input.target.coreUrl);
    auth.search = new URLSearchParams({
      client_id: input.clientId,
      redirect_uri: input.redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    }).toString();
    const admitted = await requestFetch(auth, {
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    mergeCookies(cookies, admitted);
    await admitted.body?.cancel();
    if (
      admitted.status !== 303 ||
      !cookies.has('_interaction') ||
      !cookies.has('_interaction.sig')
    ) {
      return fail();
    }
    const headers = {
      'content-type': 'application/json',
      cookie: cookieHeader(cookies),
      'aster-app-id': input.clientId,
    };
    const initialized = await requestFetch(new URL('/api/experience', input.target.coreUrl), {
      method: 'PUT',
      headers,
      body: JSON.stringify({ interactionEvent: 'Register' }),
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    mergeCookies(cookies, initialized);
    await initialized.body?.cancel();
    if (initialized.status !== 204) {
      return fail();
    }
    const observedFetch: typeof fetch = async (resource, options) => {
      const response = await requestFetch(resource, options);
      mergeCookies(cookies, response);
      return response;
    };
    const requested = await observeVerificationCodePrivate(
      {
        target: input.target,
        surface: 'experience',
        operation: 'request',
        identifier: email,
        event: 'Register',
        cookie: cookieHeader(cookies),
        clientId: input.clientId,
      },
      observedFetch
    );
    if (
      requested.projection.status !== 200 ||
      requested.projection.outcome !== 'created' ||
      !requested.handle
    ) {
      return fail();
    }
    const code = await input.takePasscode(email);
    if (!/^\d{6}$/u.test(code)) {
      return fail();
    }
    const verified = await observeVerificationCodePrivate(
      {
        target: input.target,
        surface: 'experience',
        operation: 'verify',
        identifier: email,
        handle: requested.handle,
        code,
        cookie: cookieHeader(cookies),
        clientId: input.clientId,
      },
      observedFetch
    );
    if (
      verified.projection.status !== 200 ||
      verified.projection.outcome !== 'verified' ||
      !verified.handle
    ) {
      return fail();
    }
    const action =
      kind === 'policy'
        ? await requestFetch(new URL('/api/experience/profile', input.target.coreUrl), {
            method: 'POST',
            headers: { ...headers, cookie: cookieHeader(cookies) },
            body: JSON.stringify({
              type: 'password',
              value: randomBytes(1).toString('hex').slice(0, 1),
            }),
            redirect: 'manual',
            signal: AbortSignal.timeout(10_000),
          })
        : await requestFetch(new URL('/api/experience/identification', input.target.coreUrl), {
            method: 'POST',
            headers: { ...headers, cookie: cookieHeader(cookies) },
            body: JSON.stringify({ verificationId: verified.handle }),
            redirect: 'manual',
            signal: AbortSignal.timeout(10_000),
          });
    const actionProjection = await readAction(action);
    return Object.freeze({
      requestStatus: requested.projection.status,
      requestOutcome: requested.projection.outcome,
      requestError: requested.projection.error ?? '',
      verifyStatus: verified.projection.status,
      verifyOutcome: verified.projection.outcome,
      verifyError: verified.projection.error ?? '',
      actionStatus: actionProjection.status,
      actionError: actionProjection.error,
    });
  },
});
/* eslint-enable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment */
