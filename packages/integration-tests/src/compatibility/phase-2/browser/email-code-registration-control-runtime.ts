/* eslint-disable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/member-ordering, @typescript-eslint/no-unsafe-assignment -- Fresh cookie-bound interaction and private verification material stay in one adapter boundary. */
import { createHash, randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import { observeVerificationCodePrivate } from '../clients/verification-code.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import type { RegistrationInteractionRuntime } from './common-email-code-registration-controls.js';

const fail = (): never => {
  throw new TypeError('Invalid email code registration control runtime');
};
const runtimeFail = (stage: string, status: number, error = 'other'): never => {
  const safeStatus =
    Number.isInteger(status) && status >= 100 && status <= 599 ? `s${status}` : 'unavailable';
  const safeError = [
    'guard.invalid_input',
    'session.interaction_not_found',
    'request.message_rate_limited',
    'connector.not_found',
    'connector.invalid_config',
    'connector.general',
  ].includes(error)
    ? error.replaceAll(/[._]/gu, '-')
    : error === ''
      ? 'none'
      : 'other';
  throw new TypeError(
    `Email code registration control runtime failed: ${stage}-${safeStatus}-${safeError}`
  );
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
const readIdentification = async (response: Response) => {
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > 65_536)) {
    return fail();
  }
  const text = await response.text();
  if (Buffer.byteLength(text) > 65_536) {
    return fail();
  }
  let value: unknown;
  try {
    value = text ? JSON.parse(text) : {};
  } catch {
    return fail();
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  const error = Reflect.get(value, 'code');
  return { status: response.status, error: typeof error === 'string' ? error : '' };
};

export const createEmailCodeRegistrationControlRuntime = (
  input: Readonly<{
    target: TargetConfig;
    request: Phase2AdminRequestFunction;
    clientId: string;
    redirectUri: string;
    takePasscode(recipient: string): Promise<string>;
    fetch?: typeof fetch;
  }>
): RegistrationInteractionRuntime => ({
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
  runFreshVerifiedIdentification: async (event, email) => {
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
      return runtimeFail('auth', admitted.status);
    }
    const headers = {
      'content-type': 'application/json',
      cookie: cookieHeader(cookies),
      'aster-app-id': input.clientId,
    };
    const initialized = await requestFetch(new URL('/api/experience', input.target.coreUrl), {
      method: 'PUT',
      headers,
      body: JSON.stringify({ interactionEvent: event }),
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    mergeCookies(cookies, initialized);
    await initialized.body?.cancel();
    if (initialized.status !== 204) {
      return runtimeFail('init', initialized.status);
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
        event,
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
      return runtimeFail(
        'request',
        requested.projection.status,
        requested.projection.error ?? 'other'
      );
    }
    const { handle } = requested;
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
        handle,
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
      return runtimeFail(
        'verify',
        verified.projection.status,
        verified.projection.error ?? 'other'
      );
    }
    const identification = await readIdentification(
      await requestFetch(new URL('/api/experience/identification', input.target.coreUrl), {
        method: 'POST',
        headers: { ...headers, cookie: cookieHeader(cookies) },
        body: JSON.stringify({ verificationId: verified.handle }),
        redirect: 'manual',
        signal: AbortSignal.timeout(10_000),
      })
    );
    return Object.freeze({
      requestStatus: requested.projection.status,
      requestOutcome: requested.projection.outcome,
      requestError: requested.projection.error ?? '',
      verifyStatus: verified.projection.status,
      verifyOutcome: verified.projection.outcome,
      verifyError: verified.projection.error ?? '',
      identificationStatus: identification.status,
      identificationError: identification.error,
    });
  },
});
/* eslint-enable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/member-ordering, @typescript-eslint/no-unsafe-assignment */
