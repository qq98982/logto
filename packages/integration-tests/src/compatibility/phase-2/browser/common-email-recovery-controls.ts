/* eslint-disable no-control-regex, @silverhand/fp/no-mutation -- Fresh cookie-bound interactions keep verification secrets inside one HTTP control boundary. */
import { createHash, randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import {
  observeVerificationCodePrivate,
  type VerificationCodeProjection,
} from '../clients/verification-code.js';

export type EmailRecoveryControlAttempt = Readonly<{
  status: 's200' | 's400' | 's404' | 's409' | 's429' | 'other';
  outcome: 'verified' | 'error';
  error:
    | 'none'
    | 'verification_code.not_found'
    | 'session.verification_session_not_found'
    | 'session.interaction_not_found'
    | 'guard.invalid_input'
    | 'other';
}>;

export type EmailRecoveryControlsProjection = Readonly<{
  verificationReplay: Readonly<{
    first: EmailRecoveryControlAttempt;
    second: EmailRecoveryControlAttempt;
  }>;
  wrongPurpose: Readonly<{
    recovery: EmailRecoveryControlAttempt;
    ownerAfterRecovery: EmailRecoveryControlAttempt;
  }>;
}>;

export type EmailRecoveryControlRuntime = Readonly<{
  replay(): Promise<
    Readonly<{ first: EmailRecoveryControlAttempt; second: EmailRecoveryControlAttempt }>
  >;
  wrongPurpose(): Promise<
    Readonly<{
      recovery: EmailRecoveryControlAttempt;
      ownerAfterRecovery: EmailRecoveryControlAttempt;
    }>
  >;
}>;

type ControlStage = 'replay' | 'wrong-purpose';
const fail = (stage?: ControlStage): never => {
  throw new TypeError(
    stage
      ? `Common email recovery controls failed: ${stage}`
      : 'Invalid Common email recovery controls'
  );
};
const atStage = async <Result>(
  stage: ControlStage,
  run: () => Promise<Result>
): Promise<Result> => {
  try {
    return await run();
  } catch {
    return fail(stage);
  }
};

const expectedVerified = Object.freeze({
  status: 's200',
  outcome: 'verified',
  error: 'none',
}) satisfies EmailRecoveryControlAttempt;
const expectedReplay = Object.freeze({
  status: 's400',
  outcome: 'error',
  error: 'verification_code.not_found',
}) satisfies EmailRecoveryControlAttempt;
const expectedWrongPurpose = Object.freeze({
  status: 's404',
  outcome: 'error',
  error: 'session.verification_session_not_found',
}) satisfies EmailRecoveryControlAttempt;

export const commonEmailRecoveryExpectedControls = Object.freeze({
  verificationReplay: Object.freeze({
    first: Object.freeze({ ...expectedVerified }),
    second: Object.freeze({ ...expectedReplay }),
  }),
  wrongPurpose: Object.freeze({
    recovery: Object.freeze({ ...expectedWrongPurpose }),
    ownerAfterRecovery: Object.freeze({ ...expectedVerified }),
  }),
}) satisfies EmailRecoveryControlsProjection;

const sameAttempt = (left: EmailRecoveryControlAttempt, right: EmailRecoveryControlAttempt) =>
  left.status === right.status && left.outcome === right.outcome && left.error === right.error;

export const runCommonEmailRecoveryControls = async (
  runtime: EmailRecoveryControlRuntime
): Promise<EmailRecoveryControlsProjection> => {
  const replay = await atStage('replay', runtime.replay);
  if (!sameAttempt(replay.first, expectedVerified) || !sameAttempt(replay.second, expectedReplay)) {
    return fail('replay');
  }
  const wrongPurpose = await atStage('wrong-purpose', runtime.wrongPurpose);
  if (
    !sameAttempt(wrongPurpose.recovery, expectedWrongPurpose) ||
    !sameAttempt(wrongPurpose.ownerAfterRecovery, expectedVerified)
  ) {
    return fail('wrong-purpose');
  }
  return commonEmailRecoveryExpectedControls;
};

const closedStatus = (status: number): EmailRecoveryControlAttempt['status'] => {
  switch (status) {
    case 200:
    case 400:
    case 404:
    case 409:
    case 429: {
      return `s${status}`;
    }
    default: {
      return 'other';
    }
  }
};

const closedError = (error: unknown): EmailRecoveryControlAttempt['error'] => {
  switch (error) {
    case 'verification_code.not_found':
    case 'session.verification_session_not_found':
    case 'session.interaction_not_found':
    case 'guard.invalid_input': {
      return error;
    }
    default: {
      return 'other';
    }
  }
};

const attempt = (projection: VerificationCodeProjection): EmailRecoveryControlAttempt => {
  if (projection.status === 200 && projection.outcome === 'verified') {
    return expectedVerified;
  }
  if (projection.outcome !== 'error') {
    return fail();
  }
  return Object.freeze({
    status: closedStatus(projection.status),
    outcome: 'error',
    error: closedError(projection.error),
  });
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
      (!cookies.has(name) && cookies.size >= 16)
    ) {
      return fail();
    }
    cookies.set(name, value);
  }
};

const cookieHeader = (cookies: Map<string, string>): string =>
  [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');

const openInteraction = async (
  input: Readonly<{
    target: TargetConfig;
    clientId: string;
    redirectUri: string;
    event: 'SignIn' | 'ForgotPassword';
    fetch: typeof fetch;
  }>
) => {
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
  const admitted = await input.fetch(authorization, {
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  mergeCookies(cookies, admitted);
  await admitted.body?.cancel();
  if (admitted.status !== 303 || !cookies.has('_interaction') || !cookies.has('_interaction.sig')) {
    return fail();
  }
  const initialized = await input.fetch(new URL('/api/experience', input.target.coreUrl), {
    method: 'PUT',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(cookies),
      'aster-app-id': input.clientId,
    },
    body: JSON.stringify({ interactionEvent: input.event }),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  mergeCookies(cookies, initialized);
  await initialized.body?.cancel();
  if (initialized.status !== 204) {
    return fail();
  }
  const observedFetch: typeof fetch = async (resource, options) => {
    const response = await input.fetch(resource, options);
    mergeCookies(cookies, response);
    return response;
  };
  return Object.freeze({
    request: async (recipient: string, event: 'SignIn' | 'ForgotPassword') => {
      const requested = await observeVerificationCodePrivate(
        {
          target: input.target,
          surface: 'experience',
          operation: 'request',
          identifier: recipient,
          event,
          cookie: cookieHeader(cookies),
          clientId: input.clientId,
        },
        observedFetch
      );
      if (requested.projection.status !== 200 || requested.projection.outcome !== 'created') {
        return fail();
      }
      return requested.handle ?? fail();
    },
    verify: async (recipient: string, handle: string, code: string) => {
      const observed = await observeVerificationCodePrivate(
        {
          target: input.target,
          surface: 'experience',
          operation: 'verify',
          identifier: recipient,
          handle,
          code,
          cookie: cookieHeader(cookies),
          clientId: input.clientId,
        },
        observedFetch
      );
      return attempt(observed.projection);
    },
  });
};

export const createEmailRecoveryControlRuntime = (
  input: Readonly<{
    target: TargetConfig;
    clientId: string;
    redirectUri: string;
    recipient: string;
    fetch?: typeof fetch;
    takeVerificationCode(recipient: string): Promise<string>;
  }>
): EmailRecoveryControlRuntime => {
  if (!['oracle', 'candidate'].includes(input.target.label)) {
    return fail();
  }
  const requestFetch = input.fetch ?? fetch;
  const code = async () => {
    const value = await input.takeVerificationCode(input.recipient);
    return /^\d{6}$/u.test(value) ? value : fail();
  };
  return Object.freeze({
    replay: async () => {
      const owner = await openInteraction({
        ...input,
        event: 'ForgotPassword',
        fetch: requestFetch,
      });
      const handle = await owner.request(input.recipient, 'ForgotPassword');
      const secret = await code();
      return Object.freeze({
        first: await owner.verify(input.recipient, handle, secret),
        second: await owner.verify(input.recipient, handle, secret),
      });
    },
    wrongPurpose: async () => {
      const owner = await openInteraction({ ...input, event: 'SignIn', fetch: requestFetch });
      const handle = await owner.request(input.recipient, 'SignIn');
      const secret = await code();
      const recovery = await openInteraction({
        ...input,
        event: 'ForgotPassword',
        fetch: requestFetch,
      });
      return Object.freeze({
        recovery: await recovery.verify(input.recipient, handle, secret),
        ownerAfterRecovery: await owner.verify(input.recipient, handle, secret),
      });
    },
  });
};
/* eslint-enable no-control-regex, @silverhand/fp/no-mutation */
