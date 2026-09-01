/* eslint-disable max-lines, complexity, @silverhand/fp/no-mutating-methods, no-restricted-syntax, @typescript-eslint/consistent-type-definitions, no-control-regex, unicorn/escape-case, @typescript-eslint/ban-types, unicorn/no-useless-undefined, @silverhand/fp/no-let, @silverhand/fp/no-mutation, max-params -- Secret lease revocation, timeout state, and cleanup aggregation are intentionally centralized in this lifecycle boundary while preserving the plan's exact interfaces. */
import { inspect, types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../config.js';
import { assertEvidenceIsSanitized } from '../evidence.js';
import type { TargetConfig } from '../model.js';

import {
  createPhase1FixtureMap,
  type Phase1FixtureMap,
  type Phase1FixtureStateProjection,
} from './fixture-map.js';
import type { Phase1FixtureRecipe } from './model.js';

export type SemanticStateProjection = Phase1FixtureStateProjection;

export interface Phase1FixtureSecretLease {
  getPassword(logicalUserId: string): string;
  getClientSecret(logicalApplicationId: string): string | undefined;
  toJSON(): never;
}

export interface ProvisionedPhase1Fixture {
  readonly public: Phase1FixtureMap;
  readonly foreignTarget?: TargetConfig;
  withSecretLease<Result>(
    use: (lease: Phase1FixtureSecretLease) => Promise<Result>
  ): Promise<Result>;
}

export interface Phase1FixtureProvisioner {
  provision(recipe: Phase1FixtureRecipe): Promise<ProvisionedPhase1Fixture>;
  projectState(fixture: ProvisionedPhase1Fixture): Promise<SemanticStateProjection>;
  cleanup(fixture: ProvisionedPhase1Fixture): Promise<void>;
}

export type Phase1FixtureSecretSeed = Readonly<{
  logicalId: string;
  value: string;
}>;

export type ProvisionedPhase1FixtureInput = Readonly<{
  public: Phase1FixtureMap;
  foreignTarget?: TargetConfig;
  passwords: readonly Phase1FixtureSecretSeed[];
  clientSecrets: readonly Phase1FixtureSecretSeed[];
}>;

export type RunWithPhase1FixtureOptions = Readonly<{
  timeoutMs?: number;
}>;

const invalidSecretSeedsMessage = 'Invalid Phase 1 fixture secret seeds';
const cloneBarrierKey = '__phase1SecretLeaseCloneBarrier';
const maximumSecretLength = 512;
const maximumSeedCount = 16;
const maximumRuntimeGraphDepth = 24;
const maximumRuntimeArrayLength = 4096;
const safeTextPattern = /^[^\u0000-\u001f\u007f]+$/u;
const runtimeCredentialFailure = 'Phase 1 runtime output contains forbidden credential material';
const reviewedRuntimeCredentialMetadataKeys = new Set([
  'cookiekeyid',
  'signingkeyid',
  'tokenfamily',
]);
const standaloneCookiePairPattern =
  /^(?:__Host-|__Secure-)?[!#$%&'*+.^_`|~0-9A-Za-z-]+=[^;\r\n]*(?:;\s*[!#$%&'*+.^_`|~0-9A-Za-z-]+(?:=[^;\r\n]*)?)*$/u;
const nativeErrorToString = Error.prototype.toString;
const errorPrototypeKeys = Object.freeze(['constructor', 'message', 'name', 'toString']);
const nativeErrorStackDescriptor = Object.getOwnPropertyDescriptor(
  new Error('stack descriptor probe'),
  'stack'
);

const failSecretSeeds = (): never => {
  throw new TypeError(invalidSecretSeedsMessage);
};

const ownData = (value: object, key: string): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);

  if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
    return failSecretSeeds();
  }

  return descriptor.value;
};

const assertPlainObjectKeys = (
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = []
): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return failSecretSeeds();
  }
  const keys = Reflect.ownKeys(value);
  const allowed = new Set([...required, ...optional]);

  if (
    keys.some((key) => typeof key !== 'string' || !allowed.has(key)) ||
    required.some((key) => !keys.includes(key))
  ) {
    return failSecretSeeds();
  }
  for (const key of keys as string[]) {
    ownData(value, key);
  }

  return value as Record<string, unknown>;
};

const assertDenseArray = (value: unknown): readonly unknown[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximumSeedCount ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    return failSecretSeeds();
  }
  const result = Array.from({ length: value.length }, (_, index) => ownData(value, String(index)));

  return Object.freeze(result);
};

const assertSeedText = (value: unknown, minimumLength = 1): string => {
  if (
    typeof value !== 'string' ||
    value.length < minimumLength ||
    value.length > maximumSecretLength ||
    !safeTextPattern.test(value)
  ) {
    return failSecretSeeds();
  }

  return value;
};

const snapshotTarget = (value: unknown): TargetConfig => {
  const target = assertPlainObjectKeys(value, ['label', 'coreUrl', 'adminUrl']);

  try {
    return validateTargetConfig({
      label: assertSeedText(ownData(target, 'label')),
      coreUrl: assertSeedText(ownData(target, 'coreUrl')),
      adminUrl: assertSeedText(ownData(target, 'adminUrl')),
    });
  } catch {
    throw new TypeError('Invalid Phase 1 foreign target');
  }
};

const snapshotSeeds = (
  rawSeeds: unknown,
  allowedLogicalIds: ReadonlySet<string>
): ReadonlyMap<string, string> => {
  const entries = assertDenseArray(rawSeeds).map((rawSeed) => {
    const seed = assertPlainObjectKeys(rawSeed, ['logicalId', 'value']);
    const logicalId = assertSeedText(ownData(seed, 'logicalId'));
    const value = assertSeedText(ownData(seed, 'value'), 12);

    if (!allowedLogicalIds.has(logicalId)) {
      return failSecretSeeds();
    }

    return [logicalId, value] as const;
  });

  if (new Set(entries.map(([logicalId]) => logicalId)).size !== entries.length) {
    return failSecretSeeds();
  }

  return new Map(entries);
};

const stringContainsSeededSecret = (value: string, secretValues: readonly string[]) =>
  secretValues.some((secret) => value.includes(secret));

const assertRuntimeCredentialString = (value: string, secretValues: readonly string[]): void => {
  if (
    stringContainsSeededSecret(value, secretValues) ||
    standaloneCookiePairPattern.test(value.trim())
  ) {
    throw new Error(runtimeCredentialFailure);
  }
  try {
    // Use the Phase 0 reviewed JOSE/Bearer/Cookie/private-key authority without its metadata-key policy.
    assertEvidenceIsSanitized({ value });
  } catch {
    throw new Error(runtimeCredentialFailure);
  }
};

const assertRuntimeCredentialKey = (value: string, secretValues: readonly string[]): void => {
  assertRuntimeCredentialString(value, secretValues);
  const normalizedKey = value.replaceAll(/[_\s-]/gu, '').toLowerCase();

  if (reviewedRuntimeCredentialMetadataKeys.has(normalizedKey)) {
    return;
  }
  try {
    // Reuse Phase 0's reviewed forbidden-wrapper key authority on an isolated plain record.
    assertEvidenceIsSanitized({ [value]: 'ordinary-value' });
  } catch {
    throw new Error(runtimeCredentialFailure);
  }
};

const inspectRuntimeCredentialGraph = (
  value: unknown,
  secretValues: readonly string[],
  ancestors: WeakSet<object>,
  depth: number
): void => {
  if (typeof value === 'string') {
    assertRuntimeCredentialString(value, secretValues);
    return;
  }
  if (
    value === null ||
    value === undefined ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return;
  }
  if (
    typeof value !== 'object' ||
    nodeTypes.isProxy(value) ||
    ancestors.has(value) ||
    depth > maximumRuntimeGraphDepth
  ) {
    throw new Error(runtimeCredentialFailure);
  }
  const prototype: unknown = Object.getPrototypeOf(value);

  if (prototype === Error.prototype) {
    const prototypeKeys = Reflect.ownKeys(Error.prototype);

    if (
      prototypeKeys.length !== errorPrototypeKeys.length ||
      prototypeKeys.some((key) => typeof key !== 'string' || !errorPrototypeKeys.includes(key))
    ) {
      throw new Error(runtimeCredentialFailure);
    }
    for (const key of errorPrototypeKeys) {
      const descriptor = Object.getOwnPropertyDescriptor(Error.prototype, key);

      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        throw new Error(runtimeCredentialFailure);
      }
      if (
        (key === 'constructor' && descriptor.value !== Error) ||
        (key === 'toString' && descriptor.value !== nativeErrorToString)
      ) {
        throw new Error(runtimeCredentialFailure);
      }
      if ((key === 'message' || key === 'name') && typeof descriptor.value !== 'string') {
        throw new Error(runtimeCredentialFailure);
      }
    }
    const keys = Reflect.ownKeys(value);

    if (keys.length > 64 || keys.some((key) => typeof key !== 'string')) {
      throw new Error(runtimeCredentialFailure);
    }
    ancestors.add(value);
    for (const key of keys) {
      if (typeof key !== 'string') {
        ancestors.delete(value);
        throw new Error(runtimeCredentialFailure);
      }
      assertRuntimeCredentialKey(key, secretValues);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);

      if (
        !descriptor ||
        (!Object.hasOwn(descriptor, 'value') &&
          !(
            key === 'stack' &&
            descriptor.get === nativeErrorStackDescriptor?.get &&
            descriptor.set === nativeErrorStackDescriptor?.set &&
            descriptor.enumerable === false
          ))
      ) {
        ancestors.delete(value);
        throw new Error(runtimeCredentialFailure);
      }
      if (Object.hasOwn(descriptor, 'value')) {
        inspectRuntimeCredentialGraph(descriptor.value, secretValues, ancestors, depth + 1);
      }
    }
    ancestors.delete(value);
    return;
  }

  if (
    (Array.isArray(value) && prototype !== Array.prototype) ||
    (!Array.isArray(value) && prototype !== Object.prototype)
  ) {
    throw new Error(runtimeCredentialFailure);
  }
  const keys = Reflect.ownKeys(value);

  if (Array.isArray(value)) {
    if (
      value.length > maximumRuntimeArrayLength ||
      keys.length !== value.length + 1 ||
      keys.some(
        (key) =>
          typeof key !== 'string' ||
          (key !== 'length' &&
            (!/^(?:0|[1-9]\d*)$/u.test(key) || Number.parseInt(key, 10) >= value.length))
      )
    ) {
      throw new Error(runtimeCredentialFailure);
    }
  } else if (keys.some((key) => typeof key !== 'string')) {
    throw new Error(runtimeCredentialFailure);
  }
  ancestors.add(value);

  for (const key of keys) {
    if (typeof key !== 'string') {
      ancestors.delete(value);
      throw new Error(runtimeCredentialFailure);
    }
    if (key !== 'length') {
      assertRuntimeCredentialKey(key, secretValues);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (
      !descriptor ||
      !Object.hasOwn(descriptor, 'value') ||
      (key !== 'length' && !descriptor.enumerable)
    ) {
      ancestors.delete(value);
      throw new Error(runtimeCredentialFailure);
    }
    inspectRuntimeCredentialGraph(descriptor.value, secretValues, ancestors, depth + 1);
  }
  ancestors.delete(value);
};

export const assertPhase1RuntimeCredentialGraphIsSanitized = (
  value: unknown,
  secretValues: readonly string[] = []
): void => {
  try {
    inspectRuntimeCredentialGraph(value, secretValues, new WeakSet(), 0);
  } catch {
    throw new Error(runtimeCredentialFailure);
  }
};

const freezeRuntimeCredentialGraph = <Value>(
  value: Value,
  visited = new WeakSet<object>()
): Value => {
  if (typeof value !== 'object' || value === null || visited.has(value)) {
    return value;
  }
  visited.add(value);

  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      freezeRuntimeCredentialGraph(descriptor.value, visited);
    }
  }

  return Object.freeze(value);
};

export const phase1TargetOriginsArePairwiseDisjoint = (
  primary: TargetConfig,
  foreign?: TargetConfig
): boolean => {
  try {
    if (foreign && primary.label !== foreign.label) {
      return false;
    }
    const origins = [
      primary.coreUrl,
      primary.adminUrl,
      ...(foreign ? [foreign.coreUrl, foreign.adminUrl] : []),
    ].map((value) => new URL(value).origin);

    return new Set(origins).size === origins.length;
  } catch {
    return false;
  }
};

const containsSeededSecret = (
  value: unknown,
  secretValues: readonly string[],
  ancestors = new WeakSet<object>(),
  depth = 0,
  allowError = false
): boolean => {
  if (typeof value === 'string') {
    return stringContainsSeededSecret(value, secretValues);
  }
  if (
    value === null ||
    value === undefined ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return false;
  }
  if (typeof value === 'bigint' || typeof value === 'symbol') {
    return true;
  }
  if (typeof value === 'function' || depth > 24) {
    return true;
  }
  if (nodeTypes.isProxy(value) || ancestors.has(value)) {
    return true;
  }
  const prototype: unknown = Object.getPrototypeOf(value);

  if (
    prototype !== Object.prototype &&
    prototype !== Array.prototype &&
    !(allowError && value instanceof Error)
  ) {
    return true;
  }
  if (Array.isArray(value)) {
    const keys = Reflect.ownKeys(value);

    if (
      keys.length !== value.length + 1 ||
      keys.some(
        (key) =>
          typeof key !== 'string' ||
          (key !== 'length' &&
            (!/^(?:0|[1-9]\d*)$/u.test(key) || Number.parseInt(key, 10) >= value.length))
      )
    ) {
      return true;
    }
  }
  ancestors.add(value);
  const contains = Reflect.ownKeys(value).some((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    return (
      typeof key !== 'string' ||
      stringContainsSeededSecret(key, secretValues) ||
      !descriptor ||
      !Object.hasOwn(descriptor, 'value') ||
      containsSeededSecret(descriptor.value, secretValues, ancestors, depth + 1, allowError)
    );
  });
  ancestors.delete(value);

  return contains;
};

class SecretLease implements Phase1FixtureSecretLease {
  readonly #passwords: ReadonlyMap<string, string>;
  readonly #clientSecrets: ReadonlyMap<string, string>;
  #revoked = false;

  constructor(passwords: ReadonlyMap<string, string>, clientSecrets: ReadonlyMap<string, string>) {
    this.#passwords = new Map(passwords);
    this.#clientSecrets = new Map(clientSecrets);
    Object.defineProperty(this, cloneBarrierKey, {
      configurable: false,
      enumerable: true,
      value: () => undefined,
      writable: false,
    });
    Object.freeze(this);
  }

  getPassword(logicalUserId: string): string {
    this.#assertActive();
    const password = this.#passwords.get(logicalUserId);

    if (password === undefined) {
      throw new Error('Secret seed is unavailable');
    }

    return password;
  }

  getClientSecret(logicalApplicationId: string): string | undefined {
    this.#assertActive();
    return this.#clientSecrets.get(logicalApplicationId);
  }

  revoke(): void {
    this.#revoked = true;
    (this.#passwords as Map<string, string>).clear();
    (this.#clientSecrets as Map<string, string>).clear();
  }

  toJSON(): never {
    throw new TypeError('Secret lease serialization is forbidden');
  }

  [inspect.custom](): string {
    return 'Phase1FixtureSecretLease { [REDACTED] }';
  }

  #assertActive(): void {
    if (this.#revoked) {
      throw new Error('Secret lease is revoked');
    }
  }
}

Object.freeze(SecretLease.prototype);

class ProvisionedFixture implements ProvisionedPhase1Fixture {
  readonly #public: Phase1FixtureMap;
  readonly #foreignTarget: TargetConfig | undefined;
  readonly #passwords: Map<string, string>;
  readonly #clientSecrets: Map<string, string>;
  readonly #activeLeases = new Set<SecretLease>();
  #revoked = false;

  constructor(
    publicMap: Phase1FixtureMap,
    foreignTarget: TargetConfig | undefined,
    passwords: ReadonlyMap<string, string>,
    clientSecrets: ReadonlyMap<string, string>
  ) {
    this.#public = publicMap;
    this.#foreignTarget = foreignTarget;
    this.#passwords = new Map(passwords);
    this.#clientSecrets = new Map(clientSecrets);
    Object.freeze(this);
  }

  get public(): Phase1FixtureMap {
    return this.#public;
  }

  get foreignTarget(): TargetConfig | undefined {
    return this.#foreignTarget;
  }

  async withSecretLease<Result>(
    use: (lease: Phase1FixtureSecretLease) => Promise<Result>
  ): Promise<Result> {
    if (this.#revoked) {
      throw new Error('Fixture secrets are revoked');
    }
    if (typeof use !== 'function') {
      throw new TypeError('Secret lease callback must be a function');
    }
    const lease = new SecretLease(this.#passwords, this.#clientSecrets);
    const secretValues = [...this.#passwords.values(), ...this.#clientSecrets.values()];
    this.#activeLeases.add(lease);

    try {
      let pending: Promise<Result>;

      try {
        const result = use(lease);

        if (!(result instanceof Promise)) {
          throw new TypeError('Secret lease callback must return a Promise');
        }
        pending = result;
      } catch (error: unknown) {
        try {
          assertPhase1RuntimeCredentialGraphIsSanitized(error, secretValues);
          freezeRuntimeCredentialGraph(error);
        } catch {
          throw new Error('Secret lease callback failed');
        }
        throw error;
      }
      const result = await pending.catch((error: unknown) => {
        try {
          assertPhase1RuntimeCredentialGraphIsSanitized(error, secretValues);
          freezeRuntimeCredentialGraph(error);
        } catch {
          throw new Error('Secret lease callback failed');
        }
        throw error;
      });

      try {
        assertPhase1RuntimeCredentialGraphIsSanitized(result, secretValues);
        freezeRuntimeCredentialGraph(result);
      } catch {
        throw new Error('Secret lease result is not redacted');
      }

      return result;
    } finally {
      lease.revoke();
      this.#activeLeases.delete(lease);
    }
  }

  revoke(): void {
    this.#revoked = true;
    this.#passwords.clear();
    this.#clientSecrets.clear();
    for (const lease of this.#activeLeases) {
      lease.revoke();
    }
    this.#activeLeases.clear();
  }

  [inspect.custom](): string {
    return `ProvisionedPhase1Fixture { recipe: ${this.#public.recipe} }`;
  }
}

Object.freeze(ProvisionedFixture.prototype);

export const createProvisionedPhase1Fixture = (
  input: ProvisionedPhase1FixtureInput
): ProvisionedPhase1Fixture => {
  try {
    const source = assertPlainObjectKeys(
      input,
      ['public', 'passwords', 'clientSecrets'],
      ['foreignTarget']
    );
    const publicMap = createPhase1FixtureMap(ownData(source, 'public'));
    const foreignTargetValue = Object.hasOwn(source, 'foreignTarget')
      ? ownData(source, 'foreignTarget')
      : undefined;
    const hasForeignAllocation = publicMap.allocations.some(({ role }) => role === 'foreign');

    if (hasForeignAllocation !== (foreignTargetValue !== undefined)) {
      throw new TypeError('Invalid Phase 1 foreign target');
    }
    const foreignTarget =
      foreignTargetValue === undefined ? undefined : snapshotTarget(foreignTargetValue);
    const userIds = new Set(
      publicMap.allocations.flatMap(({ entities }) =>
        entities.filter(({ kind }) => kind === 'user').map(({ logicalId }) => logicalId)
      )
    );
    const applicationIds = new Set(
      publicMap.allocations.flatMap(({ entities }) =>
        entities.filter(({ kind }) => kind === 'application').map(({ logicalId }) => logicalId)
      )
    );
    const passwords = snapshotSeeds(ownData(source, 'passwords'), userIds);
    const clientSecrets = snapshotSeeds(ownData(source, 'clientSecrets'), applicationIds);
    const secretValues = [...passwords.values(), ...clientSecrets.values()];

    if (containsSeededSecret(publicMap, secretValues)) {
      return failSecretSeeds();
    }
    assertPhase1RuntimeCredentialGraphIsSanitized(publicMap, secretValues);
    if (foreignTarget) {
      assertPhase1RuntimeCredentialGraphIsSanitized(foreignTarget, secretValues);
    }
    return new ProvisionedFixture(publicMap, foreignTarget, passwords, clientSecrets);
  } catch (error: unknown) {
    if (error instanceof TypeError && error.message === 'Invalid Phase 1 foreign target') {
      throw error;
    }
    return failSecretSeeds();
  }
};

const requireProvisionedFixture = (fixture: ProvisionedPhase1Fixture): ProvisionedFixture => {
  if (!(fixture instanceof ProvisionedFixture)) {
    throw new TypeError('Invalid provisioned Phase 1 fixture');
  }

  return fixture;
};

export const revokeProvisionedPhase1Fixture = (fixture: ProvisionedPhase1Fixture): void => {
  requireProvisionedFixture(fixture).revoke();
};

export const assertPhase1FixtureAllocationsAreDistinct = (
  left: ProvisionedPhase1Fixture,
  right: ProvisionedPhase1Fixture
): void => {
  const leftMap = requireProvisionedFixture(left).public;
  const rightMap = requireProvisionedFixture(right).public;
  const leftAllocationIds = new Set(leftMap.allocations.map(({ allocationId }) => allocationId));
  const overlaps = rightMap.allocations.some(({ allocationId }) =>
    leftAllocationIds.has(allocationId)
  );

  if (overlaps) {
    throw new Error('Phase 1 fixture allocations must be distinct');
  }
};

const runWithTimeout = async <Result>(
  run: (signal: AbortSignal) => Promise<Result>,
  timeoutMs: number | undefined,
  beforeAbort: () => void
): Promise<Result> => {
  const controller = new AbortController();

  if (timeoutMs === undefined) {
    return run(controller.signal);
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 300_000) {
    throw new TypeError('Invalid Phase 1 fixture timeout');
  }
  const observeScenario = async () => {
    try {
      return { status: 'fulfilled' as const, value: await run(controller.signal) };
    } catch (error: unknown) {
      return { status: 'rejected' as const, error };
    }
  };
  const scenario = observeScenario();
  let timer: NodeJS.Timeout | undefined;
  const timed = await Promise.race([
    scenario,
    new Promise<Readonly<{ status: 'timed-out' }>>((resolve) => {
      timer = setTimeout(() => {
        resolve({ status: 'timed-out' });
      }, timeoutMs);
    }),
  ]);
  if (timer) {
    clearTimeout(timer);
  }

  if (timed.status === 'timed-out') {
    beforeAbort();
    controller.abort();
    await scenario;
    throw new Error('Phase 1 fixture scenario timed out');
  }
  if (timed.status === 'rejected') {
    throw timed.error;
  }

  return timed.value;
};

export const runWithPhase1Fixture = async <Result>(
  provisioner: Phase1FixtureProvisioner,
  recipe: Phase1FixtureRecipe,
  use: (fixture: ProvisionedPhase1Fixture, signal: AbortSignal) => Promise<Result>,
  options: RunWithPhase1FixtureOptions = {}
): Promise<Result> => {
  const fixture = await provisioner.provision(recipe);
  let result: Result | undefined;
  let primaryFailed = false;
  let primaryError: unknown;

  try {
    requireProvisionedFixture(fixture);
    result = await runWithTimeout(
      async (signal) => use(fixture, signal),
      options.timeoutMs,
      () => {
        revokeProvisionedPhase1Fixture(fixture);
      }
    );
  } catch (error: unknown) {
    primaryFailed = true;
    primaryError = error;
  }

  let cleanupFailed = false;
  let cleanupError: unknown;
  revokeProvisionedPhase1Fixture(fixture);
  try {
    await provisioner.cleanup(fixture);
  } catch (error: unknown) {
    cleanupFailed = true;
    cleanupError = error;
  } finally {
    revokeProvisionedPhase1Fixture(fixture);
  }

  if (primaryFailed && cleanupFailed) {
    throw new AggregateError(
      [primaryError, cleanupError],
      'Phase 1 fixture scenario and cleanup failed',
      { cause: primaryError }
    );
  }
  if (primaryFailed) {
    throw primaryError;
  }
  if (cleanupFailed) {
    throw new AggregateError([cleanupError], 'Phase 1 fixture cleanup failed');
  }

  return result as Result;
};

/* eslint-enable max-lines, complexity, @silverhand/fp/no-mutating-methods, no-restricted-syntax, @typescript-eslint/consistent-type-definitions, no-control-regex, unicorn/escape-case, @typescript-eslint/ban-types, unicorn/no-useless-undefined, @silverhand/fp/no-let, @silverhand/fp/no-mutation, max-params */
