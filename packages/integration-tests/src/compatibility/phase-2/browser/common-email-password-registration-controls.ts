/* eslint-disable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment -- Ordered hostile-value validation keeps the retained projection exact and bounded. */
import { types as nodeTypes } from 'node:util';

export type EmailPasswordRegistrationControlKind = 'incomplete' | 'duplicate' | 'policy';
type RegistrationControlOutcome = Readonly<{
  requestStatus: number;
  requestOutcome: string;
  requestError: string;
  verifyStatus: number;
  verifyOutcome: string;
  verifyError: string;
  actionStatus: number;
  actionError: string;
}>;
export type EmailPasswordRegistrationControlRuntime = Readonly<{
  authenticatedLookupExactEmail(email: string): Promise<readonly string[]>;
  runVerifiedRegistration(
    kind: EmailPasswordRegistrationControlKind,
    email: string
  ): Promise<unknown>;
}>;
export type CommonEmailPasswordRegistrationControls = Readonly<{
  missingProfile: Readonly<{
    requestStatus: 200;
    verifyStatus: 200;
    identificationStatus: 422;
    error: 'user.missing_profile';
    beforeCount: 0;
    afterCount: 0;
  }>;
  duplicateEmail: Readonly<{
    requestStatus: 200;
    verifyStatus: 200;
    identificationStatus: 422;
    error: 'user.email_already_in_use';
    beforeCount: 1;
    afterCount: 1;
    ownerUnchanged: true;
  }>;
  rejectedPolicy: Readonly<{
    requestStatus: 200;
    verifyStatus: 200;
    profileStatus: 422;
    error: 'password.rejected';
    beforeCount: 0;
    afterCount: 0;
  }>;
}>;

export const commonEmailPasswordRegistrationExpectedControls = Object.freeze({
  missingProfile: Object.freeze({
    requestStatus: 200,
    verifyStatus: 200,
    identificationStatus: 422,
    error: 'user.missing_profile',
    beforeCount: 0,
    afterCount: 0,
  }),
  duplicateEmail: Object.freeze({
    requestStatus: 200,
    verifyStatus: 200,
    identificationStatus: 422,
    error: 'user.email_already_in_use',
    beforeCount: 1,
    afterCount: 1,
    ownerUnchanged: true,
  }),
  rejectedPolicy: Object.freeze({
    requestStatus: 200,
    verifyStatus: 200,
    profileStatus: 422,
    error: 'password.rejected',
    beforeCount: 0,
    afterCount: 0,
  }),
}) satisfies CommonEmailPasswordRegistrationControls;

type ControlStage =
  | 'admission'
  | 'incomplete-before'
  | 'incomplete-proof'
  | 'incomplete-identification'
  | 'incomplete-after'
  | 'duplicate-before'
  | 'duplicate-proof'
  | 'duplicate-identification'
  | 'duplicate-after'
  | 'policy-before'
  | 'policy-proof'
  | 'policy-profile'
  | 'policy-after';
const fail = (stage: ControlStage): never => {
  throw new TypeError(`Common email password registration controls failed: ${stage}`);
};
const validEmail = (value: string): boolean =>
  value.length > 0 && value.length <= 320 && value === value.toLowerCase() && value.includes('@');
const owners = (value: readonly string[]): readonly string[] => {
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
  const result: string[] = [];
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
    result.push(descriptor.value);
  }
  if (new Set(result).size !== result.length) {
    return fail('admission');
  }
  return Object.freeze(result);
};
const outcome = (value: unknown): RegistrationControlOutcome => {
  if (
    nodeTypes.isProxy(value) ||
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).length !== 8
  ) {
    return fail('admission');
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    return fail('admission');
  }
  const keys = [
    'requestStatus',
    'requestOutcome',
    'requestError',
    'verifyStatus',
    'verifyOutcome',
    'verifyError',
    'actionStatus',
    'actionError',
  ] as const;
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    keys.some((key) => {
      const descriptor = descriptors[key];
      return !descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable;
    })
  ) {
    return fail('admission');
  }
  const requestStatus = descriptors.requestStatus?.value;
  const requestOutcome = descriptors.requestOutcome?.value;
  const requestError = descriptors.requestError?.value;
  const verifyStatus = descriptors.verifyStatus?.value;
  const verifyOutcome = descriptors.verifyOutcome?.value;
  const verifyError = descriptors.verifyError?.value;
  const actionStatus = descriptors.actionStatus?.value;
  const actionError = descriptors.actionError?.value;
  if (
    typeof requestStatus !== 'number' ||
    typeof requestOutcome !== 'string' ||
    typeof requestError !== 'string' ||
    typeof verifyStatus !== 'number' ||
    typeof verifyOutcome !== 'string' ||
    typeof verifyError !== 'string' ||
    typeof actionStatus !== 'number' ||
    typeof actionError !== 'string'
  ) {
    return fail('admission');
  }
  return Object.freeze({
    requestStatus,
    requestOutcome,
    requestError,
    verifyStatus,
    verifyOutcome,
    verifyError,
    actionStatus,
    actionError,
  });
};
const atStage = async <Result>(
  stage: ControlStage,
  use: () => Promise<Result>
): Promise<Result> => {
  try {
    return await use();
  } catch {
    return fail(stage);
  }
};
const assertProof = (value: RegistrationControlOutcome, stage: ControlStage): void => {
  if (
    value.requestStatus !== 200 ||
    value.requestOutcome !== 'created' ||
    value.requestError !== '' ||
    value.verifyStatus !== 200 ||
    value.verifyOutcome !== 'verified' ||
    value.verifyError !== ''
  ) {
    return fail(stage);
  }
};

export const runCommonEmailPasswordRegistrationControls = async (
  runtime: EmailPasswordRegistrationControlRuntime,
  input: Readonly<{
    incompleteEmail: string;
    duplicateEmail: string;
    rejectedPolicyEmail: string;
  }>
): Promise<CommonEmailPasswordRegistrationControls> => {
  if (
    !validEmail(input.incompleteEmail) ||
    !validEmail(input.duplicateEmail) ||
    !validEmail(input.rejectedPolicyEmail) ||
    new Set(Object.values(input)).size !== 3
  ) {
    return fail('admission');
  }

  const incompleteBefore = owners(
    await atStage('incomplete-before', async () =>
      runtime.authenticatedLookupExactEmail(input.incompleteEmail)
    )
  );
  if (incompleteBefore.length > 0) {
    return fail('incomplete-before');
  }
  const incomplete = outcome(
    await atStage('incomplete-proof', async () =>
      runtime.runVerifiedRegistration('incomplete', input.incompleteEmail)
    )
  );
  assertProof(incomplete, 'incomplete-proof');
  if (incomplete.actionStatus !== 422 || incomplete.actionError !== 'user.missing_profile') {
    return fail('incomplete-identification');
  }
  const incompleteAfter = owners(
    await atStage('incomplete-after', async () =>
      runtime.authenticatedLookupExactEmail(input.incompleteEmail)
    )
  );
  if (incompleteAfter.length > 0) {
    return fail('incomplete-after');
  }

  const duplicateBefore = owners(
    await atStage('duplicate-before', async () =>
      runtime.authenticatedLookupExactEmail(input.duplicateEmail)
    )
  );
  if (duplicateBefore.length !== 1) {
    return fail('duplicate-before');
  }
  const duplicate = outcome(
    await atStage('duplicate-proof', async () =>
      runtime.runVerifiedRegistration('duplicate', input.duplicateEmail)
    )
  );
  assertProof(duplicate, 'duplicate-proof');
  if (duplicate.actionStatus !== 422 || duplicate.actionError !== 'user.email_already_in_use') {
    return fail('duplicate-identification');
  }
  const duplicateAfter = owners(
    await atStage('duplicate-after', async () =>
      runtime.authenticatedLookupExactEmail(input.duplicateEmail)
    )
  );
  if (duplicateAfter.length !== 1 || duplicateAfter[0] !== duplicateBefore[0]) {
    return fail('duplicate-after');
  }

  const policyBefore = owners(
    await atStage('policy-before', async () =>
      runtime.authenticatedLookupExactEmail(input.rejectedPolicyEmail)
    )
  );
  if (policyBefore.length > 0) {
    return fail('policy-before');
  }
  const policy = outcome(
    await atStage('policy-proof', async () =>
      runtime.runVerifiedRegistration('policy', input.rejectedPolicyEmail)
    )
  );
  assertProof(policy, 'policy-proof');
  if (policy.actionStatus !== 422 || policy.actionError !== 'password.rejected') {
    return fail('policy-profile');
  }
  const policyAfter = owners(
    await atStage('policy-after', async () =>
      runtime.authenticatedLookupExactEmail(input.rejectedPolicyEmail)
    )
  );
  if (policyAfter.length > 0) {
    return fail('policy-after');
  }
  return commonEmailPasswordRegistrationExpectedControls;
};
/* eslint-enable complexity, max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment */
