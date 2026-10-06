/* eslint-disable complexity, no-control-regex, @silverhand/fp/no-mutation -- One fresh Register interaction owns its private cookies, handle, and code across two ordered verification attempts. */
import { createHash, randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import {
  observeVerificationCodePrivate,
  type VerificationCodeProjection,
} from '../clients/verification-code.js';

export type RegistrationReplayError =
  | 'none'
  | 'verification_code.not_found'
  | 'guard.invalid_input'
  | 'session.interaction_not_found'
  | 'request.message_rate_limited'
  | 'other';

export type RegistrationReplayStatus = 's200' | 's400' | 's404' | 's409' | 's429' | 'other';

export type RegistrationReplayAttempt = Readonly<{
  status: RegistrationReplayStatus;
  outcome: 'verified' | 'error';
  error: RegistrationReplayError;
}>;

export type RegistrationReplayObservation = Readonly<{
  first: RegistrationReplayAttempt;
  second: RegistrationReplayAttempt;
}>;

const fail = (): never => {
  throw new TypeError('Invalid email code registration replay probe');
};

const vettedTargetLabels: readonly string[] = Object.freeze(['oracle', 'candidate']);
const requireVettedTarget = (target: TargetConfig): void => {
  if (!vettedTargetLabels.includes(target.label)) {
    fail();
  }
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

const closedError = (value: unknown): RegistrationReplayError => {
  switch (value) {
    case 'verification_code.not_found':
    case 'guard.invalid_input':
    case 'session.interaction_not_found':
    case 'request.message_rate_limited': {
      return value;
    }
    default: {
      return 'other';
    }
  }
};

const closedStatus = (value: number): RegistrationReplayStatus => {
  switch (value) {
    case 200:
    case 400:
    case 404:
    case 409:
    case 429: {
      return `s${value}`;
    }
    default: {
      return 'other';
    }
  }
};

const attempt = (projection: VerificationCodeProjection): RegistrationReplayAttempt => {
  if (!Number.isInteger(projection.status) || projection.status < 100 || projection.status > 599) {
    return fail();
  }
  if (projection.outcome === 'verified' && projection.status === 200) {
    return Object.freeze({ status: 's200', outcome: 'verified', error: 'none' });
  }
  if (projection.outcome === 'error') {
    return Object.freeze({
      status: closedStatus(projection.status),
      outcome: 'error',
      error: closedError(projection.error),
    });
  }
  return fail();
};

export const observeRegisterVerificationReplay = async (
  input: Readonly<{
    target: TargetConfig;
    clientId: string;
    redirectUri: string;
    email: string;
    fetch?: typeof fetch;
    takePasscode(recipient: string): Promise<string>;
  }>
): Promise<RegistrationReplayObservation> => {
  requireVettedTarget(input.target);
  const requestFetch = input.fetch ?? fetch;
  const cookies = new Map<string, string>();
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  if (verifier.length !== 43 || challenge.length !== 43) {
    return fail();
  }

  const authorization = new URL('/oidc/auth', input.target.coreUrl);
  authorization.search = new URLSearchParams({
    client_id: input.clientId,
    redirect_uri: input.redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  const admitted = await requestFetch(authorization, {
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  mergeCookies(cookies, admitted);
  await admitted.body?.cancel();
  if (admitted.status !== 303 || !cookies.has('_interaction') || !cookies.has('_interaction.sig')) {
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
      identifier: input.email,
      event: 'Register',
      cookie: cookieHeader(cookies),
      clientId: input.clientId,
    },
    observedFetch
  );
  const handle = requested.handle ?? fail();
  const code = await input.takePasscode(input.email);
  if (!/^\d{6}$/u.test(code)) {
    return fail();
  }
  const verify = async () =>
    observeVerificationCodePrivate(
      {
        target: input.target,
        surface: 'experience',
        operation: 'verify',
        identifier: input.email,
        handle,
        code,
        cookie: cookieHeader(cookies),
        clientId: input.clientId,
      },
      observedFetch
    );
  const firstObserved = await verify();
  const first = attempt(firstObserved.projection);
  if (first.status !== 's200' || first.outcome !== 'verified' || first.error !== 'none') {
    return fail();
  }
  const secondObserved = await verify();
  const second = attempt(secondObserved.projection);
  if (
    second.status !== 's400' ||
    second.outcome !== 'error' ||
    second.error !== 'verification_code.not_found'
  ) {
    return fail();
  }
  return Object.freeze({ first, second });
};

/* eslint-enable complexity, no-control-regex, @silverhand/fp/no-mutation */
