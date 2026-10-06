/* eslint-disable complexity, max-lines, max-params, no-control-regex -- Ordered challenge lifecycles and signed-cookie parsing remain one auditable HTTP control. */
import type { TargetConfig } from '../../model.js';
import { issuePublicUserTokens } from '../clients/user-token-issuance.js';
import {
  observeVerificationCodePrivate,
  type VerificationCodeProjection,
} from '../clients/verification-code.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import {
  createVerificationCodeScenarioRuntime,
  type VerificationCodeScenarioRuntime,
} from '../scenarios/verification-code.js';

import type { CommonEmailCodeControlResult } from './common-email-code-sign-in.js';

export const emailCodeExpiryWaitMilliseconds = 62_000;

export type EmailCodeControlProjection = Readonly<{
  recipientMismatchRejected: true;
  ownerAfterRecipientMismatch: 'verified';
  consumedReplayRejected: true;
  expiredChallengeRejected: true;
}>;

export type EmailCodeReferenceControlCapture = Readonly<{
  recipient: Readonly<{ status: number; error?: string; ownerAfterStatus: number }>;
  consumedReplay: Readonly<{ status: number; error?: string }>;
  expiry: Readonly<{ status: number; error?: string }>;
}>;

type RuntimeFactory = () => Promise<VerificationCodeScenarioRuntime>;
type ChallengeSecret = Readonly<{ identifier: string; handle: string; code: string }>;

const fail = (): never => {
  throw new TypeError('Invalid Common email code control');
};

type ControlGroupStage = 'basic' | 'foreign-account' | 'secondary-client';

const atControlGroup = async <Result>(
  stage: ControlGroupStage,
  run: () => Promise<Result>
): Promise<Result> => {
  try {
    return await run();
  } catch {
    throw new TypeError(`Common email code control stage failed: ${stage}`);
  }
};

export const runCommonEmailCodeControlGroups = async <Basic, Purpose, Client>(
  input: Readonly<{
    basic(): Promise<Basic>;
    purpose(): Promise<Purpose>;
    client(): Promise<Client>;
  }>
): Promise<Readonly<{ basic: Basic; purpose: Purpose; client: Client }>> => {
  const basic = await atControlGroup('basic', input.basic);
  const purpose = await atControlGroup('foreign-account', input.purpose);
  const client = await atControlGroup('secondary-client', input.client);
  return Object.freeze({ basic, purpose, client });
};

const challenge = async (runtime: VerificationCodeScenarioRuntime, identifier: string) => {
  const requested = await runtime.request({ identifier, surface: 'experience' });
  if (requested.projection.status !== 200 || requested.projection.outcome !== 'created') {
    return fail();
  }
  const secret = await runtime.takeDelivery(requested.delivery);
  return Object.freeze({ runtime, identifier, ...secret });
};

export const runEmailCodeControls = async (
  input: Readonly<{
    createRuntime: RuntimeFactory;
    recipient: string;
    waitForExpiry?: () => Promise<void>;
  }>
): Promise<EmailCodeControlProjection> => {
  const recipientControl = await challenge(await input.createRuntime(), input.recipient);
  const recipientDenied = await recipientControl.runtime.verify({
    identifier: `wrong-${input.recipient}`,
    surface: 'experience',
    handle: recipientControl.handle,
    code: recipientControl.code,
  });
  if (
    recipientDenied.status !== 400 ||
    recipientDenied.outcome !== 'error' ||
    recipientDenied.error !== 'verification_code.email_mismatch'
  ) {
    return fail();
  }
  const recipientOwner = await recipientControl.runtime.verify({
    identifier: recipientControl.identifier,
    surface: 'experience',
    handle: recipientControl.handle,
    code: recipientControl.code,
  });
  if (recipientOwner.status !== 200 || recipientOwner.outcome !== 'verified') {
    return fail();
  }

  const replayControl = await challenge(await input.createRuntime(), input.recipient);
  const consumed = await replayControl.runtime.verify({
    identifier: replayControl.identifier,
    surface: 'experience',
    handle: replayControl.handle,
    code: replayControl.code,
  });
  const replay = await replayControl.runtime.verify({
    identifier: replayControl.identifier,
    surface: 'experience',
    handle: replayControl.handle,
    code: replayControl.code,
  });
  if (
    consumed.status !== 200 ||
    consumed.outcome !== 'verified' ||
    replay.status !== 400 ||
    replay.outcome !== 'error' ||
    replay.error !== 'verification_code.not_found'
  ) {
    return fail();
  }

  const expiryControl = await challenge(await input.createRuntime(), input.recipient);
  const waitForExpiry =
    input.waitForExpiry ??
    (async () => {
      await new Promise<void>((resolve) => {
        setTimeout(resolve, emailCodeExpiryWaitMilliseconds);
      });
    });
  await waitForExpiry();
  const expired = await expiryControl.runtime.verify({
    identifier: expiryControl.identifier,
    surface: 'experience',
    handle: expiryControl.handle,
    code: expiryControl.code,
  });
  if (
    expired.status !== 400 ||
    expired.outcome !== 'error' ||
    expired.error !== 'verification_code.expired'
  ) {
    return fail();
  }

  return Object.freeze({
    recipientMismatchRejected: true,
    ownerAfterRecipientMismatch: 'verified',
    consumedReplayRejected: true,
    expiredChallengeRejected: true,
  });
};

const publicOutcome = (projection: VerificationCodeProjection) =>
  Object.freeze({
    status: projection.status,
    ...(typeof projection.error === 'string' ? { error: projection.error } : {}),
  });

export const captureEmailCodeReferenceControls = async (
  input: Readonly<{
    createRuntime: RuntimeFactory;
    recipient: string;
    waitForExpiry?: () => Promise<void>;
  }>
): Promise<EmailCodeReferenceControlCapture> => {
  const recipientControl = await challenge(await input.createRuntime(), input.recipient);
  const recipient = await recipientControl.runtime.verify({
    identifier: `wrong-${input.recipient}`,
    surface: 'experience',
    handle: recipientControl.handle,
    code: recipientControl.code,
  });
  const recipientOwner = await recipientControl.runtime.verify({
    identifier: recipientControl.identifier,
    surface: 'experience',
    handle: recipientControl.handle,
    code: recipientControl.code,
  });

  const replayControl = await challenge(await input.createRuntime(), input.recipient);
  await replayControl.runtime.verify({
    identifier: replayControl.identifier,
    surface: 'experience',
    handle: replayControl.handle,
    code: replayControl.code,
  });
  const replay = await replayControl.runtime.verify({
    identifier: replayControl.identifier,
    surface: 'experience',
    handle: replayControl.handle,
    code: replayControl.code,
  });

  const expiryControl = await challenge(await input.createRuntime(), input.recipient);
  const waitForExpiry =
    input.waitForExpiry ??
    (async () => {
      await new Promise<void>((resolve) => {
        setTimeout(resolve, emailCodeExpiryWaitMilliseconds);
      });
    });
  await waitForExpiry();
  const expiry = await expiryControl.runtime.verify({
    identifier: expiryControl.identifier,
    surface: 'experience',
    handle: expiryControl.handle,
    code: expiryControl.code,
  });
  return Object.freeze({
    recipient: Object.freeze({
      ...publicOutcome(recipient),
      ownerAfterStatus: recipientOwner.status,
    }),
    consumedReplay: publicOutcome(replay),
    expiry: publicOutcome(expiry),
  });
};

export const createEmailCodeControlRuntimeFactory =
  (
    target: TargetConfig,
    fixture: ProvisionedPhase2Fixture,
    requestFetch: typeof fetch = fetch
  ): RuntimeFactory =>
  async () =>
    createVerificationCodeScenarioRuntime(target, fixture, requestFetch);

export type EmailCodePurposeCapture = Readonly<{
  account: Readonly<{ status: number; error?: string }>;
  ownerAfterAccount: Readonly<{
    status: number;
    outcome: VerificationCodeProjection['outcome'];
    error?: string;
  }>;
}>;

export const captureEmailCodePurposeControl = async (
  input: Readonly<{
    createRuntime: RuntimeFactory;
    recipient: string;
    verifyAccount(secret: ChallengeSecret): Promise<VerificationCodeProjection>;
  }>
): Promise<EmailCodePurposeCapture> => {
  const created = await challenge(await input.createRuntime(), input.recipient);
  const secret = Object.freeze({
    identifier: created.identifier,
    handle: created.handle,
    code: created.code,
  });
  const account = await input.verifyAccount(secret);
  const owner = await created.runtime.verify({
    ...secret,
    surface: 'experience',
  });
  return Object.freeze({
    account: Object.freeze({
      status: account.status,
      ...(typeof account.error === 'string' ? { error: account.error } : {}),
    }),
    ownerAfterAccount: Object.freeze({
      status: owner.status,
      outcome: owner.outcome,
      ...(typeof owner.error === 'string' ? { error: owner.error } : {}),
    }),
  });
};

export const captureEmailCodePurposeReference = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  recipient: string,
  requestFetch: typeof fetch = fetch
): Promise<EmailCodePurposeCapture> => {
  const tokens = await issuePublicUserTokens(target, fixture, requestFetch);
  return captureEmailCodePurposeControl({
    createRuntime: createEmailCodeControlRuntimeFactory(target, fixture, requestFetch),
    recipient,
    verifyAccount: async ({ identifier, handle, code }) => {
      const observed = await observeVerificationCodePrivate(
        {
          target,
          surface: 'account',
          operation: 'verify',
          identifier,
          handle,
          code,
          bearer: tokens.access,
        },
        requestFetch
      );
      return observed.projection;
    },
  });
};

const alternateExperience = async (
  target: TargetConfig,
  clientId: string,
  redirectUri: string,
  requestFetch: typeof fetch
) => {
  const cookies = new Map<string, string>();
  const admitted = await requestFetch(
    new URL(
      `/oidc/auth?${new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid profile email',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      }).toString()}`,
      target.coreUrl
    ),
    { redirect: 'manual' }
  );
  for (const value of admitted.headers.getSetCookie()) {
    const pair = value.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    const name = pair.slice(0, separator);
    const cookieValue = pair.slice(separator + 1);
    if (
      separator <= 0 ||
      !/^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u.test(name) ||
      Buffer.byteLength(cookieValue) > 4096 ||
      /[\u0000-\u001F\u007F;]/u.test(cookieValue) ||
      cookies.size >= 16
    ) {
      return fail();
    }
    cookies.set(name, cookieValue);
  }
  await admitted.body?.cancel();
  if (admitted.status !== 303 || !cookies.has('_interaction') || !cookies.has('_interaction.sig')) {
    return fail();
  }
  const cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  const initialized = await requestFetch(new URL('/api/experience', target.coreUrl), {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie, 'aster-app-id': clientId },
    body: JSON.stringify({ interactionEvent: 'SignIn' }),
    redirect: 'manual',
  });
  await initialized.body?.cancel();
  if (initialized.status !== 204) {
    return fail();
  }
  return Object.freeze({ cookie, clientId });
};

const clientOutcome = (projection: VerificationCodeProjection) => {
  const allowed = new Set([
    'verification_code.not_found',
    'session.interaction_not_found',
    'session.verification_session_not_found',
  ]);
  if (projection.error && !allowed.has(projection.error)) {
    return fail();
  }
  return projection;
};

const captureClient = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  recipient: string,
  requestFetch: typeof fetch
) => {
  const runtime = await createVerificationCodeScenarioRuntime(target, fixture, requestFetch);
  const requested = await runtime.request({ identifier: recipient, surface: 'experience' });
  const secret = await runtime.takeDelivery(requested.delivery);
  const status = fixture.status ?? fail();
  const alternate = await alternateExperience(
    target,
    status.confidentialClient.id,
    status.confidentialClient.redirectUri,
    requestFetch
  );
  const secondary = await observeVerificationCodePrivate(
    {
      target,
      surface: 'experience',
      operation: 'verify',
      identifier: recipient,
      ...secret,
      ...alternate,
    },
    requestFetch
  );
  const owner = await runtime.verify({ identifier: recipient, surface: 'experience', ...secret });
  return Object.freeze({
    secondary: clientOutcome(secondary.projection),
    owner: clientOutcome(owner),
  });
};

export const validateCommonEmailCodeControlGroups = async (
  input: Readonly<{
    basic: EmailCodeReferenceControlCapture;
    purpose: EmailCodePurposeCapture;
    client: Awaited<ReturnType<typeof captureClient>>;
  }>
): Promise<CommonEmailCodeControlResult> => {
  await atControlGroup('basic', async () => {
    if (
      input.basic.recipient.status !== 400 ||
      input.basic.recipient.error !== 'verification_code.email_mismatch' ||
      input.basic.recipient.ownerAfterStatus !== 200 ||
      input.basic.consumedReplay.status !== 400 ||
      input.basic.consumedReplay.error !== 'verification_code.not_found' ||
      input.basic.expiry.status !== 400 ||
      input.basic.expiry.error !== 'verification_code.expired'
    ) {
      return fail();
    }
  });
  await atControlGroup('foreign-account', async () => {
    if (
      input.purpose.account.status !== 400 ||
      input.purpose.account.error !== 'verification_record.not_found' ||
      input.purpose.ownerAfterAccount.status !== 200 ||
      input.purpose.ownerAfterAccount.outcome !== 'verified'
    ) {
      return fail();
    }
  });
  await atControlGroup('secondary-client', async () => {
    if (
      input.client.secondary.status !== 404 ||
      input.client.secondary.outcome !== 'error' ||
      input.client.secondary.error !== 'session.verification_session_not_found' ||
      input.client.owner.status !== 200 ||
      input.client.owner.outcome !== 'verified'
    ) {
      return fail();
    }
  });
  return Object.freeze({
    recipientMismatch: Object.freeze({ status: 400, error: 'verification_code.email_mismatch' }),
    ownerAfterRecipientMismatch: Object.freeze({ status: 200, outcome: 'verified' }),
    consumedReplay: Object.freeze({ status: 400, error: 'verification_code.not_found' }),
    expiry: Object.freeze({ status: 400, error: 'verification_code.expired' }),
    foreignAccountSurface: Object.freeze({ status: 400, error: 'verification_record.not_found' }),
    ownerAfterForeignAccountSurface: Object.freeze({ status: 200, outcome: 'verified' }),
    secondaryInteraction: Object.freeze({
      admissionStatus: 303,
      interactionBound: true,
      initializationStatus: 204,
    }),
    secondaryVerify: Object.freeze({
      status: 404,
      outcome: 'error',
      error: 'session.verification_session_not_found',
    }),
    ownerAfterSecondaryVerify: Object.freeze({ status: 200, outcome: 'verified' }),
  });
};

export const runCommonEmailCodeHttpControls = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  recipient: string,
  requestFetch: typeof fetch = fetch,
  waitForExpiry?: () => Promise<void>
): Promise<CommonEmailCodeControlResult> => {
  const factory = createEmailCodeControlRuntimeFactory(target, fixture, requestFetch);
  const { basic, purpose, client } = await runCommonEmailCodeControlGroups({
    basic: async () =>
      captureEmailCodeReferenceControls({
        createRuntime: factory,
        recipient,
        ...(waitForExpiry && { waitForExpiry }),
      }),
    purpose: async () => captureEmailCodePurposeReference(target, fixture, recipient, requestFetch),
    client: async () => captureClient(target, fixture, recipient, requestFetch),
  });
  return validateCommonEmailCodeControlGroups({ basic, purpose, client });
};
/* eslint-enable complexity, max-lines, max-params, no-control-regex */
