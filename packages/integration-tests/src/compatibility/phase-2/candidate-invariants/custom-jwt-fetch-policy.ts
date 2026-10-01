/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition -- Closed hostile-value validation needs narrowed assertions and retains runtime checks for typed callers. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

export const customJwtFetchPolicyCandidateInvariantIds = Object.freeze([
  'custom-jwt.fetch-policy-boundary',
] as const);

export type CustomJwtFetchPolicyCandidateInvariantId =
  (typeof customJwtFetchPolicyCandidateInvariantIds)[number];

export type CustomJwtFetchPolicyProjection = Readonly<{
  invariant: 'fetch-policy-boundary';
  allowed: Readonly<{
    claim: 'bounded-response';
    request: 'single-get-text';
    headers: 'matched';
    body: 'matched';
  }>;
  denied: Readonly<{
    claim: 'caught-rejection';
    category: 'TypeError';
    requests: 'none';
  }>;
}>;

export type CustomJwtFetchPolicyControlEvidence = Readonly<{
  id: CustomJwtFetchPolicyCandidateInvariantId;
  candidate: CustomJwtFetchPolicyProjection;
  positiveControl: Readonly<{ detected: true }>;
  negativeControl: Readonly<{ detected: true; pointer: '/denied/requests' }>;
}>;

export type CustomJwtFetchPolicyPort = Readonly<{
  installCustomizer(kind: 'allowed-fetch' | 'denied-origin'): Promise<void>;
  assertDeniedOriginReachable(): Promise<void>;
  issueM2MAndVerifyClaim(): Promise<unknown>;
  readAndResetSanitizedReceipts(): Promise<unknown>;
  restoreConfiguration(): Promise<void>;
}>;

const diagnostic = 'Invalid Phase 2 custom JWT fetch policy candidate invariant';
const fail = (): never => {
  throw new TypeError(diagnostic);
};

const expectedProjection: CustomJwtFetchPolicyProjection = Object.freeze({
  invariant: 'fetch-policy-boundary',
  allowed: Object.freeze({
    claim: 'bounded-response',
    request: 'single-get-text',
    headers: 'matched',
    body: 'matched',
  }),
  denied: Object.freeze({
    claim: 'caught-rejection',
    category: 'TypeError',
    requests: 'none',
  }),
});

const exactRecord = (value: unknown, keys: readonly string[]): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !isDeepStrictEqual(Reflect.ownKeys(value), keys)
  ) {
    return fail();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      return fail();
    }
  }
  return value as Record<string, unknown>;
};

const exactReceipts = (value: unknown, count: 0 | 1): readonly unknown[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    !isDeepStrictEqual(Reflect.ownKeys(value), [
      ...Array.from({ length: count }, (_, index) => String(index)),
      'length',
    ])
  ) {
    return fail();
  }
  return value.length === count ? value : fail();
};

const assertEmptyReceipts = (value: unknown): void => {
  exactReceipts(value, 0);
};

const assertAllowedReceipt = (value: unknown): void => {
  const [receipt] = exactReceipts(value, 1);
  const record = exactRecord(receipt, ['method', 'path', 'headerMatches', 'bodyMatches']);
  if (
    record.method !== 'GET' ||
    record.path !== '/text' ||
    record.headerMatches !== true ||
    record.bodyMatches !== true
  ) {
    fail();
  }
};

const assertBoundedCleanupReceipts = (value: unknown): void => {
  try {
    assertEmptyReceipts(value);
  } catch {
    assertAllowedReceipt(value);
  }
};

const assertProjection = (value: unknown): CustomJwtFetchPolicyProjection => {
  const projection = exactRecord(value, ['invariant', 'allowed', 'denied']);
  const allowed = exactRecord(projection.allowed, ['claim', 'request', 'headers', 'body']);
  const denied = exactRecord(projection.denied, ['claim', 'category', 'requests']);
  return projection.invariant === 'fetch-policy-boundary' &&
    allowed.claim === 'bounded-response' &&
    allowed.request === 'single-get-text' &&
    allowed.headers === 'matched' &&
    allowed.body === 'matched' &&
    denied.claim === 'caught-rejection' &&
    denied.category === 'TypeError' &&
    denied.requests === 'none'
    ? (value as CustomJwtFetchPolicyProjection)
    : fail();
};

export const customJwtFetchPolicyExpectedProjection = (
  id: CustomJwtFetchPolicyCandidateInvariantId
): CustomJwtFetchPolicyProjection =>
  id === customJwtFetchPolicyCandidateInvariantIds[0] ? expectedProjection : fail();

export const runCustomJwtFetchPolicyControls = (
  id: CustomJwtFetchPolicyCandidateInvariantId,
  candidate: unknown
): CustomJwtFetchPolicyControlEvidence => {
  if (id !== customJwtFetchPolicyCandidateInvariantIds[0]) {
    fail();
  }
  const validated = assertProjection(candidate);
  if (!isDeepStrictEqual(validated, expectedProjection)) {
    fail();
  }
  const mutation = {
    invariant: validated.invariant,
    allowed: { ...validated.allowed },
    denied: { ...validated.denied, requests: 'present' },
  };
  let detected = false;
  try {
    assertProjection(mutation);
  } catch {
    detected = true;
  }
  if (!detected) {
    fail();
  }
  return Object.freeze({
    id,
    candidate: validated,
    positiveControl: Object.freeze({ detected: true as const }),
    negativeControl: Object.freeze({
      detected: true as const,
      pointer: '/denied/requests' as const,
    }),
  });
};

export const runCustomJwtFetchPolicyCandidateInvariant = async (
  port: CustomJwtFetchPolicyPort
): Promise<CustomJwtFetchPolicyControlEvidence> => {
  let failed = false;
  try {
    assertEmptyReceipts(await port.readAndResetSanitizedReceipts());
    await port.installCustomizer('allowed-fetch');
    if ((await port.issueM2MAndVerifyClaim()) !== 'bounded-response') {
      fail();
    }
    assertAllowedReceipt(await port.readAndResetSanitizedReceipts());

    assertEmptyReceipts(await port.readAndResetSanitizedReceipts());
    await port.assertDeniedOriginReachable();
    await port.installCustomizer('denied-origin');
    if ((await port.issueM2MAndVerifyClaim()) !== 'caught-TypeError') {
      fail();
    }
    assertEmptyReceipts(await port.readAndResetSanitizedReceipts());
  } catch {
    failed = true;
  } finally {
    try {
      assertBoundedCleanupReceipts(await port.readAndResetSanitizedReceipts());
    } catch {
      failed = true;
    }
    try {
      await port.restoreConfiguration();
    } catch {
      failed = true;
    }
  }
  if (failed) {
    fail();
  }
  return runCustomJwtFetchPolicyControls(
    customJwtFetchPolicyCandidateInvariantIds[0],
    expectedProjection
  );
};

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition */
