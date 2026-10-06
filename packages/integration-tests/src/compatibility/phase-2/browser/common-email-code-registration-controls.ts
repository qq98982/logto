/* eslint-disable complexity, no-restricted-syntax, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The two controls validate hostile runtime data and compare private ownership snapshots without publishing identifiers. */
import { types as nodeTypes } from 'node:util';

export type RegistrationInteractionEvent = 'SignIn' | 'Register';

type VerificationOutcome = Readonly<{
  requestStatus: number;
  requestOutcome: string;
  requestError: string;
  verifyStatus: number;
  verifyOutcome: string;
  verifyError: string;
  identificationStatus: number;
  identificationError: string;
}>;

export type RegistrationInteractionRuntime = Readonly<{
  authenticatedLookupExactEmail(email: string): Promise<readonly string[]>;
  runFreshVerifiedIdentification(
    event: RegistrationInteractionEvent,
    email: string
  ): Promise<unknown>;
}>;

export type EmailCodeRegistrationControls = Readonly<{
  noImplicitRegistration: Readonly<{
    requestStatus: 200;
    verifyStatus: 200;
    identificationStatus: 404;
    error: 'user.user_not_exist';
    beforeCount: 0;
    afterCount: 0;
  }>;
  occupiedRegistration: Readonly<{
    requestStatus: 200;
    verifyStatus: 200;
    identificationStatus: 422;
    error: 'user.email_already_in_use';
    beforeCount: 1;
    afterCount: 1;
    ownerUnchanged: true;
  }>;
}>;

type ControlStage =
  | 'admission'
  | 'signin-before'
  | 'signin-proof'
  | 'signin-identification'
  | 'signin-after'
  | 'register-before'
  | 'register-proof'
  | 'register-identification'
  | 'register-after';

const fail = (stage: ControlStage): never => {
  throw new TypeError(`Common email code registration controls failed: ${stage}`);
};

const atStage = async <Result>(
  stage: ControlStage,
  run: () => Promise<Result>
): Promise<Result> => {
  try {
    return await run();
  } catch (error: unknown) {
    const message =
      !nodeTypes.isProxy(error) && error instanceof Error
        ? Object.getOwnPropertyDescriptor(error, 'message')?.value
        : undefined;
    const runtime =
      typeof message === 'string'
        ? /^Email code registration control runtime failed: ((?:auth|init|request|verify|identify)-(?:s[1-5][0-9]{2}|unavailable)-(?:none|guard-invalid-input|session-interaction-not-found|request-message-rate-limited|connector-not-found|connector-invalid-config|connector-general|user-user-not-exist|user-email-already-in-use|other))$/u.exec(
            message
          )?.[1]
        : undefined;
    if (runtime) {
      throw new TypeError(`Common email code registration controls failed: ${stage}-${runtime}`);
    }
    return fail(stage);
  }
};

const exactRecord = (value: unknown, keys: readonly string[]): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    return fail('admission');
  }
  const prototype = Object.getPrototypeOf(value);
  const ownKeys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
  ) {
    return fail('admission');
  }
  const entries: Array<readonly [string, unknown]> = [];
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail('admission');
    }
    entries.push([key, descriptor.value]);
  }
  return Object.fromEntries(entries);
};

const privateOwners = (value: readonly string[]): readonly string[] => {
  if (nodeTypes.isProxy(value) || !Array.isArray(value) || value.length > 2) {
    return fail('admission');
  }
  const keys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    keys.length !== value.length + 1 ||
    keys.some((key) => key !== 'length' && (typeof key !== 'string' || !/^\d+$/u.test(key)))
  ) {
    return fail('admission');
  }
  const owners: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (
      !descriptor ||
      !Object.hasOwn(descriptor, 'value') ||
      !descriptor.enumerable ||
      typeof descriptor.value !== 'string' ||
      !/^[A-Za-z0-9_-]{1,128}$/u.test(descriptor.value)
    ) {
      return fail('admission');
    }
    owners.push(descriptor.value);
  }
  if (new Set(owners).size !== owners.length) {
    return fail('admission');
  }
  return Object.freeze(owners);
};

const outcome = (value: unknown): VerificationOutcome => {
  const record = exactRecord(value, [
    'requestStatus',
    'requestOutcome',
    'requestError',
    'verifyStatus',
    'verifyOutcome',
    'verifyError',
    'identificationStatus',
    'identificationError',
  ]);
  return Object.freeze({
    requestStatus: record.requestStatus as number,
    requestOutcome: record.requestOutcome as string,
    requestError: record.requestError as string,
    verifyStatus: record.verifyStatus as number,
    verifyOutcome: record.verifyOutcome as string,
    verifyError: record.verifyError as string,
    identificationStatus: record.identificationStatus as number,
    identificationError: record.identificationError as string,
  });
};

const validEmail = (value: string): boolean =>
  value.length > 0 && value.length <= 320 && value === value.toLowerCase() && value.includes('@');
const publicError = (value: string): string =>
  [
    'guard.invalid_input',
    'session.interaction_not_found',
    'request.message_rate_limited',
    'connector.not_found',
    'connector.invalid_config',
    'connector.general',
    'user.user_not_exist',
    'user.email_already_in_use',
  ].includes(value)
    ? value.replaceAll(/[._]/gu, '-')
    : value === ''
      ? 'none'
      : 'other';
const status = (value: number): string =>
  Number.isInteger(value) && value >= 100 && value <= 599 ? `s${value}` : 'unavailable';
const detailedFail = (stage: ControlStage, detail: string): never => {
  throw new TypeError(`Common email code registration controls failed: ${stage}-${detail}`);
};

export const runEmailCodeRegistrationControls = async (
  runtime: RegistrationInteractionRuntime,
  input: Readonly<{ missingEmail: string; occupiedEmail: string }>
): Promise<EmailCodeRegistrationControls> => {
  if (!validEmail(input.missingEmail) || !validEmail(input.occupiedEmail)) {
    return fail('admission');
  }

  const signInBefore = await atStage('signin-before', async () =>
    privateOwners(await runtime.authenticatedLookupExactEmail(input.missingEmail))
  );
  if (signInBefore.length > 0) {
    return fail('signin-before');
  }
  const signIn = await atStage('signin-proof', async () =>
    outcome(await runtime.runFreshVerifiedIdentification('SignIn', input.missingEmail))
  );
  if (signIn.requestStatus !== 200 || signIn.requestOutcome !== 'created') {
    return detailedFail(
      'signin-proof',
      `request-${status(signIn.requestStatus)}-${publicError(signIn.requestError)}`
    );
  }
  if (signIn.verifyStatus !== 200 || signIn.verifyOutcome !== 'verified') {
    return detailedFail(
      'signin-proof',
      `verify-${status(signIn.verifyStatus)}-${publicError(signIn.verifyError)}`
    );
  }
  if (signIn.identificationStatus !== 404 || signIn.identificationError !== 'user.user_not_exist') {
    return detailedFail(
      'signin-identification',
      `identify-${status(signIn.identificationStatus)}-${publicError(signIn.identificationError)}`
    );
  }
  const signInAfter = await atStage('signin-after', async () =>
    privateOwners(await runtime.authenticatedLookupExactEmail(input.missingEmail))
  );
  if (signInAfter.length > 0) {
    return fail('signin-after');
  }

  const registerBefore = await atStage('register-before', async () =>
    privateOwners(await runtime.authenticatedLookupExactEmail(input.occupiedEmail))
  );
  if (registerBefore.length !== 1) {
    return fail('register-before');
  }
  const register = await atStage('register-proof', async () =>
    outcome(await runtime.runFreshVerifiedIdentification('Register', input.occupiedEmail))
  );
  if (register.requestStatus !== 200 || register.requestOutcome !== 'created') {
    return detailedFail(
      'register-proof',
      `request-${status(register.requestStatus)}-${publicError(register.requestError)}`
    );
  }
  if (register.verifyStatus !== 200 || register.verifyOutcome !== 'verified') {
    return detailedFail(
      'register-proof',
      `verify-${status(register.verifyStatus)}-${publicError(register.verifyError)}`
    );
  }
  if (
    register.identificationStatus !== 422 ||
    register.identificationError !== 'user.email_already_in_use'
  ) {
    return detailedFail(
      'register-identification',
      `identify-${status(register.identificationStatus)}-${publicError(register.identificationError)}`
    );
  }
  const registerAfter = await atStage('register-after', async () =>
    privateOwners(await runtime.authenticatedLookupExactEmail(input.occupiedEmail))
  );
  if (registerAfter.length !== 1 || registerAfter[0] !== registerBefore[0]) {
    return fail('register-after');
  }

  return Object.freeze({
    noImplicitRegistration: Object.freeze({
      requestStatus: 200 as const,
      verifyStatus: 200 as const,
      identificationStatus: 404 as const,
      error: 'user.user_not_exist' as const,
      beforeCount: 0 as const,
      afterCount: 0 as const,
    }),
    occupiedRegistration: Object.freeze({
      requestStatus: 200 as const,
      verifyStatus: 200 as const,
      identificationStatus: 422 as const,
      error: 'user.email_already_in_use' as const,
      beforeCount: 1 as const,
      afterCount: 1 as const,
      ownerUnchanged: true as const,
    }),
  });
};
/* eslint-enable complexity, no-restricted-syntax, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
