/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Stored policy and fresh owned interactions are compensated in one selected contract boundary. */
import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  createCommonExperienceSession,
  type CommonExperienceSession,
} from '../clients/common-experience.js';
import {
  observeExperiencePasswordProfile,
  observeExperienceRecoveryPassword,
  type PasswordPolicyObservation,
} from '../clients/password-policy.js';
import { observePublicAccountPasswordSignIn } from '../clients/user-token-issuance.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedEmailRecoveryFixture } from './selected-email-recovery-fixture.js';

export type PasswordCompromiseFixture = Readonly<{
  withAttempt<Result>(
    input: Readonly<{ password: string; outcome: 'clear' | 'compromised' | 'unavailable' }>,
    use: () => Promise<Result>
  ): Promise<Result>;
}>;
export type CommonPasswordPolicyProjection = Readonly<{
  localMinimum: PasswordPolicyObservation;
  localWord: PasswordPolicyObservation;
  registrationValid: PasswordPolicyObservation;
  compromised: PasswordPolicyObservation;
  compromiseClear: PasswordPolicyObservation;
  lookupUnavailable: PasswordPolicyObservation;
  recoverySamePassword: PasswordPolicyObservation;
  recoveryUserInfo: PasswordPolicyObservation;
  failuresPreservedOwner: true;
  noRegistrationOwnerCreated: true;
  oldPasswordAccepted: true;
  policyRestored: true;
}>;
export const commonPasswordPolicyFailurePhases = [
  'initialization',
  'local-policy',
  'compromise-compromised',
  'compromise-clear',
  'compromise-unavailable',
  'recovery',
  'cleanup-policy',
] as const;
export type CommonPasswordPolicyFailurePhase = (typeof commonPasswordPolicyFailurePhases)[number];
const passwordPolicyFailures = new WeakMap<WeakKey, CommonPasswordPolicyFailurePhase>();
const errorKey = (error: unknown): WeakKey | undefined =>
  (typeof error === 'object' && error !== null) || typeof error === 'function' ? error : undefined;
export const getCommonPasswordPolicyFailurePhase = (
  error: unknown
): CommonPasswordPolicyFailurePhase | undefined => {
  const key = errorKey(error);
  return key ? passwordPolicyFailures.get(key) : undefined;
};
export const createCommonPasswordPolicyExecutionFailure = (
  phase: CommonPasswordPolicyFailurePhase,
  stage: 'execution' | 'cleanup-policy'
): TypeError => {
  const error = new TypeError(`Invalid Common password policy flow (${stage})`);
  passwordPolicyFailures.set(error, phase);
  return error;
};

const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common password policy flow (${stage})`);
};
const object = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value))
    : fail('record');
const handle = (value: unknown): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 4096
    ? value
    : fail('proof');
const localPolicy = Object.freeze({
  length: { min: 12, max: 128 },
  characterTypes: { min: 3 },
  rejects: { pwned: false, repetitionAndSequence: false, userInfo: true, words: ['blockedword'] },
});
const compromisePolicy = Object.freeze({
  length: { min: 8, max: 128 },
  characterTypes: { min: 1 },
  rejects: { pwned: true, repetitionAndSequence: false, userInfo: false, words: [] },
});
export const recoveryUserInfoPassword = (email: string): string => {
  const local = email.split('@')[0] ?? fail('email');

  return `A9${local}`;
};
const selectedOwner = (value: unknown) => {
  const record = object(value);
  return Object.fromEntries(
    [
      'id',
      'username',
      'primaryEmail',
      'primaryPhone',
      'identities',
      'hasPassword',
      'isSuspended',
    ].map((key) => [key, record[key]])
  );
};

const withInteraction = async <Result>(
  input: Readonly<{
    target: TargetConfig;
    clientId: string;
    redirectUri: string;
    event: 'Register' | 'ForgotPassword';
    signal: AbortSignal;
    fetch?: typeof fetch;
  }>,
  use: (session: CommonExperienceSession) => Promise<Result>
): Promise<Result> => {
  const session = createCommonExperienceSession(input);
  try {
    const verifier = randomBytes(32).toString('base64url');
    const authorize = new URL('/oidc/auth', input.target.coreUrl);
    authorize.search = new URLSearchParams({
      client_id: input.clientId,
      redirect_uri: input.redirectUri,
      response_type: 'code',
      scope: 'openid profile email',
      prompt: 'login',
      code_challenge_method: 'S256',
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    }).toString();
    const opened = await session.request(authorize.href, 'GET');
    if (opened.getStatus() !== 303) {
      return fail('authorization');
    }
    const initialized = await session.request('/api/experience', 'PUT', {
      interactionEvent: input.event,
    });
    if (initialized.getStatus() !== 204) {
      return fail('initialization');
    }
    return await use(session);
  } finally {
    session.close();
  }
};

export const runCommonPasswordPolicyForTarget = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    request: Phase2AdminRequestFunction;
    signal: AbortSignal;
    fetch?: typeof fetch;
    compromiseFixture: PasswordCompromiseFixture;
    getPassword(): string;
    takeRecoveryCode(email: string): Promise<string>;
  }>
): Promise<CommonPasswordPolicyProjection> => {
  let failurePhase: CommonPasswordPolicyFailurePhase = 'initialization';
  const status = input.fixture.status ?? fail('fixture');
  const previousExperience = object(
    await input.request({
      method: 'GET',
      path: 'sign-in-exp',
      expectedStatuses: [200],
      responseKind: 'object',
    })
  );
  const previous = previousExperience.passwordPolicy;
  const previousSignUp = previousExperience.signUp;
  if (previous === undefined || previousSignUp === undefined) {
    return fail('policy-authority');
  }
  const setPolicy = async (policy: unknown) => {
    await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { passwordPolicy: policy },
      expectedStatuses: [200],
      responseKind: 'object',
    });
    const read = object(
      await input.request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    if (!isDeepStrictEqual(read.passwordPolicy, policy)) {
      return fail('policy-readback');
    }
  };
  const setRegistration = async (signUp: unknown) => {
    const updated = object(
      await input.request({
        method: 'PATCH',
        path: 'sign-in-exp',
        body: { signUp },
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    const persisted = object(
      await input.request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    if (
      !isDeepStrictEqual(updated.signUp, signUp) ||
      !isDeepStrictEqual(persisted.signUp, signUp)
    ) {
      return fail('registration-readback');
    }
  };
  const userSnapshot = async () => {
    const users = await input.request({
      method: 'GET',
      path: 'users',
      query: { page: '1', page_size: '100' },
      expectedStatuses: [200],
      responseKind: 'array',
    });
    if (!Array.isArray(users) || users.length >= 100) {
      return fail('owner-count');
    }
    return users
      .map((user: unknown) => selectedOwner(user))
      .slice()
      .sort((left, right) => handle(left.id).localeCompare(handle(right.id)));
  };
  const before = await userSnapshot();
  let projection: CommonPasswordPolicyProjection | undefined;
  let bodyFailure: unknown;
  let bodyFailurePhase: CommonPasswordPolicyFailurePhase | undefined;
  try {
    await setRegistration({ identifiers: ['email'], password: true, verify: true });
    failurePhase = 'local-policy';
    await setPolicy(localPolicy);
    const registration = async (password: string) =>
      withInteraction(
        {
          target: input.target,
          clientId: status.client.id,
          redirectUri: status.client.redirectUri,
          event: 'Register',
          signal: input.signal,
          ...(input.fetch ? { fetch: input.fetch } : {}),
        },
        async (session) => observeExperiencePasswordProfile(session, password)
      );
    const localMinimum = await registration('Aa1!');
    const localWord = await registration('blockedwordA1');
    const registrationValid = await registration(`Aa9!${randomBytes(16).toString('hex')}`);
    if (
      localMinimum.status !== 422 ||
      !localMinimum.issues.some(
        ({ code, minimum }) => code === 'password_rejected.too_short' && minimum === 12
      ) ||
      localWord.status !== 422 ||
      !localWord.issues.some(({ code }) => code === 'password_rejected.restricted.words') ||
      registrationValid.status !== 204 ||
      registrationValid.error !== 'none'
    ) {
      return fail('local-contract');
    }
    await setPolicy(compromisePolicy);
    const compromise = async (outcome: 'clear' | 'compromised' | 'unavailable') => {
      const password = `Aa9!${randomBytes(16).toString('hex')}`;
      return input.compromiseFixture.withAttempt({ password, outcome }, async () =>
        registration(password)
      );
    };
    failurePhase = 'compromise-compromised';
    const compromised = await compromise('compromised');
    failurePhase = 'compromise-clear';
    const compromiseClear = await compromise('clear');
    failurePhase = 'compromise-unavailable';
    const lookupUnavailable = await compromise('unavailable');
    if (
      compromised.status !== 422 ||
      !isDeepStrictEqual(compromised.issues, [{ code: 'password_rejected.pwned' }]) ||
      compromiseClear.status !== 204 ||
      !isDeepStrictEqual(lookupUnavailable, { status: 500, error: 'none', issues: [] })
    ) {
      return fail('compromise-contract');
    }
    if (!isDeepStrictEqual(await userSnapshot(), before)) {
      return fail('registration-state');
    }
    failurePhase = 'recovery';
    await setPolicy(localPolicy);
    const recovery = await withSelectedEmailRecoveryFixture({
      fixture: input.fixture,
      request: input.request,
      browser: { clientId: status.client.id, redirectUri: status.client.redirectUri },
      getOldPassword: input.getPassword,
      use: async (identity) => {
        const path = `users/${encodeURIComponent(identity.id)}`;
        const readOwner = async () =>
          selectedOwner(
            await input.request({
              method: 'GET',
              path,
              expectedStatuses: [200],
              responseKind: 'object',
            })
          );
        const ownerBefore = await readOwner();
        return withInteraction(
          {
            target: input.target,
            clientId: status.client.id,
            redirectUri: status.client.redirectUri,
            event: 'ForgotPassword',
            signal: input.signal,
            ...(input.fetch ? { fetch: input.fetch } : {}),
          },
          async (session) => {
            const identifier = { type: 'email', value: identity.primaryEmail };
            const requested = await session.request(
              '/api/experience/verification/verification-code',
              'POST',
              { identifier, interactionEvent: 'ForgotPassword' }
            );
            if (requested.getStatus() !== 200) {
              return fail('recovery-request');
            }
            const verificationId = handle(requested.getRecord().verificationId);
            const code = await input.takeRecoveryCode(identity.primaryEmail);
            if (!/^\d{6}$/u.test(code)) {
              return fail('recovery-delivery');
            }
            const verified = await session.request(
              '/api/experience/verification/verification-code/verify',
              'POST',
              { identifier, verificationId, code }
            );
            if (verified.getStatus() !== 200) {
              return fail('recovery-verification');
            }
            const identified = await session.request('/api/experience/identification', 'POST', {
              verificationId,
            });
            if (identified.getStatus() !== 204) {
              return fail('recovery-identification');
            }
            const recoverySamePassword = await observeExperienceRecoveryPassword(
              session,
              input.getPassword()
            );
            const recoveryUserInfo = await observeExperienceRecoveryPassword(
              session,
              recoveryUserInfoPassword(identity.primaryEmail)
            );
            if (
              recoverySamePassword.status !== 422 ||
              recoverySamePassword.error !== 'user.same_password' ||
              recoveryUserInfo.status !== 422 ||
              !recoveryUserInfo.issues.some(
                ({ code: issue }) => issue === 'password_rejected.restricted.user_info'
              ) ||
              !isDeepStrictEqual(ownerBefore, await readOwner())
            ) {
              return fail('recovery-state');
            }
            const login = await observePublicAccountPasswordSignIn(
              input.target,
              input.fixture,
              { email: identity.primaryEmail, password: input.getPassword() },
              input.fetch
            );
            if (!login.accepted) {
              return fail('old-credential');
            }
            return { recoverySamePassword, recoveryUserInfo };
          }
        );
      },
    });
    projection = Object.freeze({
      localMinimum,
      localWord,
      registrationValid,
      compromised,
      compromiseClear,
      lookupUnavailable,
      ...recovery,
      failuresPreservedOwner: true,
      noRegistrationOwnerCreated: true,
      oldPasswordAccepted: true,
      policyRestored: true,
    });
  } catch (error: unknown) {
    bodyFailure = error;
    bodyFailurePhase = failurePhase;
    const key = errorKey(error);
    if (key) {
      passwordPolicyFailures.set(key, failurePhase);
    }
  }
  failurePhase = 'cleanup-policy';
  try {
    await input.request({
      method: 'PATCH',
      path: 'sign-in-exp',
      body: { passwordPolicy: previous, signUp: previousSignUp },
      expectedStatuses: [200],
      responseKind: 'object',
    });
    const restored = object(
      await input.request({
        method: 'GET',
        path: 'sign-in-exp',
        expectedStatuses: [200],
        responseKind: 'object',
      })
    );
    if (
      !isDeepStrictEqual(restored.passwordPolicy, previous) ||
      !isDeepStrictEqual(restored.signUp, previousSignUp)
    ) {
      return fail('policy-readback');
    }
  } catch {
    throw createCommonPasswordPolicyExecutionFailure('cleanup-policy', 'cleanup-policy');
  }
  if (bodyFailure) {
    if (
      bodyFailure instanceof Error &&
      /^Invalid Common password policy flow \([a-z-]+\)$/u.test(bodyFailure.message)
    ) {
      throw bodyFailure;
    }
    throw createCommonPasswordPolicyExecutionFailure(
      bodyFailurePhase ?? 'initialization',
      'execution'
    );
  }
  return projection ?? fail('result');
};
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
