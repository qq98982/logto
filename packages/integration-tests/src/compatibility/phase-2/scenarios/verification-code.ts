/* eslint-disable max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-await-expression-member, unicorn/consistent-function-scoping -- The selected lifecycle must remain ordered; delivery secrets stay inside this bounded runtime and never enter projections. */
import { randomBytes } from 'node:crypto';

import type { TargetConfig } from '../../model.js';
import { issuePublicUserTokens } from '../clients/user-token-issuance.js';
import {
  observeVerificationCodePrivate,
  type VerificationCodeProjection,
} from '../clients/verification-code.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2ProfileRegistries } from '../profile.js';

export const verificationCodeScenarioIds = Object.freeze([
  'verification-code.experience-request-verify',
  'verification-code.experience-recipient-mismatch',
  'verification-code.experience-replaced-current',
  'verification-code.experience-retry-cap',
  'verification-code.recipient-send-cap',
  'verification-code.failed-delivery-preserves-current',
  'verification-code.experience-consumed-replay',
  'verification-code.account-request-verify-replay',
] as const);

type SecretDelivery = Readonly<{ handle: string; code: string }>;
type DeliveryReference = string;

export type VerificationCodeScenarioRuntime = Readonly<{
  request(
    input: Readonly<{ identifier: string; surface: 'experience' }>
  ): Promise<Readonly<{ projection: VerificationCodeProjection; delivery: DeliveryReference }>>;
  takeDelivery(delivery: DeliveryReference): Promise<SecretDelivery>;
  verify(
    input: Readonly<{
      identifier: string;
      surface: 'experience';
      handle: string;
      code: string;
    }>
  ): Promise<VerificationCodeProjection>;
  runRetryCap(identifier: string): Promise<readonly VerificationCodeProjection[]>;
  runSendCap(
    identifier: string
  ): Promise<Readonly<{ accepted: number; capped: VerificationCodeProjection }>>;
  runFailedDelivery(
    identifier: string
  ): Promise<
    Readonly<{ failed: VerificationCodeProjection; previous: VerificationCodeProjection }>
  >;
  runAccountLifecycle(identifier: string): Promise<
    Readonly<{
      requested: VerificationCodeProjection;
      verified: VerificationCodeProjection;
      replay: VerificationCodeProjection;
    }>
  >;
}>;

const initializeExperience = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  requestFetch: typeof fetch
): Promise<Readonly<{ cookie: string; clientId: string }>> => {
  const status = fixture.status ?? fail();
  const cookies = new Map<string, string>();
  const merge = (response: Response): void => {
    for (const value of response.headers.getSetCookie()) {
      const pair = value.split(';', 1)[0] ?? '';
      const separator = pair.indexOf('=');
      if (separator <= 0 || pair.length > 8192) {
        fail();
      }
      cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    }
  };
  const authorization = new URL('/oidc/auth', target.coreUrl);
  authorization.search = new URLSearchParams({
    client_id: status.client.id,
    redirect_uri: status.client.redirectUri,
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: randomBytes(32).toString('base64url'),
    code_challenge_method: 'S256',
  }).toString();
  const admitted = await requestFetch(authorization, {
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  merge(admitted);
  await admitted.body?.cancel();
  if (admitted.status !== 303 || cookies.size === 0) {
    return fail();
  }
  const cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  const initialized = await requestFetch(new URL('/api/experience', target.coreUrl), {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie, 'aster-app-id': status.client.id },
    body: JSON.stringify({ interactionEvent: 'SignIn' }),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  await initialized.body?.cancel();
  if (initialized.status !== 204) {
    return fail();
  }
  return Object.freeze({ cookie, clientId: status.client.id });
};

export const createVerificationCodeScenarioRuntime = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture,
  requestFetch: typeof fetch = fetch
): Promise<VerificationCodeScenarioRuntime> => {
  const experience = await initializeExperience(target, fixture, requestFetch);
  const requestExperience = async (identifier: string) => {
    const result = await observeVerificationCodePrivate(
      {
        target,
        surface: 'experience',
        operation: 'request',
        identifier,
        event: 'SignIn',
        ...experience,
      },
      requestFetch
    );
    if (!result.handle) {
      return fail();
    }
    return Object.freeze({
      projection: result.projection,
      delivery: identifier,
      handle: result.handle,
    });
  };
  const take = async (recipient: string): Promise<string> =>
    fixture.withSecretLease(async (lease) => lease.takeVerificationCode?.(recipient) ?? fail());
  const verifyExperience = async (identifier: string, handle: string, code: string) =>
    (
      await observeVerificationCodePrivate(
        {
          target,
          surface: 'experience',
          operation: 'verify',
          identifier,
          handle,
          code,
          ...experience,
        },
        requestFetch
      )
    ).projection;
  const wrongCode = (code: string): string => `${code.startsWith('0') ? '1' : '0'}${code.slice(1)}`;
  return Object.freeze({
    request: async ({ identifier }) => {
      const result = await requestExperience(identifier);
      return Object.freeze({
        projection: result.projection,
        delivery: `${identifier}\n${result.handle}`,
      });
    },
    takeDelivery: async (delivery) => {
      const separator = delivery.indexOf('\n');
      if (separator <= 0) {
        return fail();
      }
      const recipient = delivery.slice(0, separator);
      return Object.freeze({ handle: delivery.slice(separator + 1), code: await take(recipient) });
    },
    verify: async ({ identifier, handle, code }) => verifyExperience(identifier, handle, code),
    runRetryCap: async (identifier) => {
      const requested = await requestExperience(identifier);
      const code = await take(identifier);
      const wrong = wrongCode(code);
      const results: VerificationCodeProjection[] = [];
      for (let index = 0; index < 11; index += 1) {
        results.push(await verifyExperience(identifier, requested.handle, wrong));
      }
      results.push(await verifyExperience(identifier, requested.handle, code));
      return Object.freeze(results);
    },
    runSendCap: async (identifier) => {
      let accepted = 0;
      for (let index = 0; index < 10; index += 1) {
        const result = await requestExperience(identifier);
        await take(identifier);
        if (result.projection.status === 200) {
          accepted += 1;
        }
      }
      const capped = (
        await observeVerificationCodePrivate(
          {
            target,
            surface: 'experience',
            operation: 'request',
            identifier,
            event: 'SignIn',
            ...experience,
          },
          requestFetch
        )
      ).projection;
      return Object.freeze({ accepted, capped });
    },
    runFailedDelivery: async (identifier) => {
      const first = await requestExperience(identifier);
      const code = await take(identifier);
      const failed = (
        await observeVerificationCodePrivate(
          {
            target,
            surface: 'experience',
            operation: 'request',
            identifier,
            event: 'SignIn',
            ...experience,
          },
          requestFetch
        )
      ).projection;
      return Object.freeze({
        failed,
        previous: await verifyExperience(identifier, first.handle, code),
      });
    },
    runAccountLifecycle: async (identifier) => {
      const tokens = await issuePublicUserTokens(target, fixture, requestFetch);
      const requestedPrivate = await observeVerificationCodePrivate(
        { target, surface: 'account', operation: 'request', identifier, bearer: tokens.access },
        requestFetch
      );
      const handle = requestedPrivate.handle ?? fail();
      const code = await take(identifier);
      const verifyInput = {
        target,
        surface: 'account' as const,
        operation: 'verify' as const,
        identifier,
        bearer: tokens.access,
        handle,
        code,
      };
      const verified = (await observeVerificationCodePrivate(verifyInput, requestFetch)).projection;
      const replay = (await observeVerificationCodePrivate(verifyInput, requestFetch)).projection;
      return Object.freeze({ requested: requestedPrivate.projection, verified, replay });
    },
  });
};

export type VerificationCodeScenarioResult = Readonly<{
  id: (typeof verificationCodeScenarioIds)[number];
  projection:
    | VerificationCodeProjection
    | readonly VerificationCodeProjection[]
    | Readonly<Record<string, unknown>>;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 verification-code registry');
};

const assertProjection = (
  projection: VerificationCodeProjection,
  status: number,
  outcome: VerificationCodeProjection['outcome'],
  error?: string
): VerificationCodeProjection => {
  if (
    projection.status !== status ||
    projection.outcome !== outcome ||
    (error !== undefined && projection.error !== error)
  ) {
    return fail();
  }
  return projection;
};

export const runVerificationCodeScenarios = async (
  profile: Phase2ProfileRegistries,
  runtime: VerificationCodeScenarioRuntime
): Promise<readonly VerificationCodeScenarioResult[]> => {
  const start = profile.differentialScenarios.indexOf(verificationCodeScenarioIds[0] as never);
  const segment = profile.differentialScenarios.slice(
    start,
    start + verificationCodeScenarioIds.length
  );
  if (
    start < 0 ||
    segment.length !== verificationCodeScenarioIds.length ||
    segment.some((id, index) => id !== verificationCodeScenarioIds[index])
  ) {
    return fail();
  }
  const recipient = (caseName: string) => `${caseName}@phase2.example.invalid`;
  const request = async (identifier: string) => {
    const created = await runtime.request({ identifier, surface: 'experience' });
    assertProjection(created.projection, 200, 'created');
    return Object.freeze({
      projection: created.projection,
      secret: await runtime.takeDelivery(created.delivery),
    });
  };

  const success = await request(recipient('success'));
  const successVerified = await runtime.verify({
    identifier: recipient('success'),
    surface: 'experience',
    ...success.secret,
  });
  assertProjection(successVerified, 200, 'verified');

  const mismatch = await request(recipient('recipient'));
  const recipientMismatch = await runtime.verify({
    identifier: recipient('wrong-recipient'),
    surface: 'experience',
    ...mismatch.secret,
  });
  assertProjection(recipientMismatch, 400, 'error', 'verification_code.email_mismatch');

  const old = await request(recipient('replacement'));
  const current = await request(recipient('replacement'));
  const replaced = await runtime.verify({
    identifier: recipient('replacement'),
    surface: 'experience',
    ...old.secret,
  });
  assertProjection(replaced, 404, 'error', 'session.verification_session_not_found');
  const currentVerified = await runtime.verify({
    identifier: recipient('replacement'),
    surface: 'experience',
    ...current.secret,
  });
  assertProjection(currentVerified, 200, 'verified');

  const retries = await runtime.runRetryCap(recipient('retry'));
  if (retries.length !== 12) {
    return fail();
  }
  for (const entry of retries.slice(0, 10)) {
    assertProjection(entry, 400, 'error', 'verification_code.code_mismatch');
  }
  for (const entry of retries.slice(10)) {
    assertProjection(entry, 400, 'error', 'verification_code.exceed_max_try');
  }

  const sendCap = await runtime.runSendCap(recipient('send-cap'));
  if (sendCap.accepted !== 10) {
    return fail();
  }
  assertProjection(sendCap.capped, 429, 'error', 'request.message_rate_limited');

  const failedDelivery = await runtime.runFailedDelivery(recipient('delivery-failure'));
  assertProjection(failedDelivery.failed, 400, 'error');
  assertProjection(failedDelivery.previous, 200, 'verified');

  const consumedReplay = await runtime.verify({
    identifier: recipient('success'),
    surface: 'experience',
    ...success.secret,
  });
  assertProjection(consumedReplay, 400, 'error', 'verification_code.not_found');

  const account = await runtime.runAccountLifecycle(recipient('account'));
  assertProjection(account.requested, 201, 'created');
  assertProjection(account.verified, 200, 'verified');
  assertProjection(account.replay, 400, 'error', 'verification_code.not_found');

  return Object.freeze([
    Object.freeze({
      id: verificationCodeScenarioIds[0],
      projection: Object.freeze({ request: success.projection, verify: successVerified }),
    }),
    Object.freeze({ id: verificationCodeScenarioIds[1], projection: recipientMismatch }),
    Object.freeze({
      id: verificationCodeScenarioIds[2],
      projection: Object.freeze({ replaced, current: currentVerified }),
    }),
    Object.freeze({ id: verificationCodeScenarioIds[3], projection: Object.freeze([...retries]) }),
    Object.freeze({ id: verificationCodeScenarioIds[4], projection: sendCap }),
    Object.freeze({ id: verificationCodeScenarioIds[5], projection: failedDelivery }),
    Object.freeze({ id: verificationCodeScenarioIds[6], projection: consumedReplay }),
    Object.freeze({ id: verificationCodeScenarioIds[7], projection: account }),
  ]);
};
/* eslint-enable max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-await-expression-member, unicorn/consistent-function-scoping */
