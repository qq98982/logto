/* eslint-disable complexity, max-lines, no-restricted-syntax, @typescript-eslint/ban-types -- The Phase 1 runner is a closed execution boundary for descriptor-safe step validation, fixture lifetime, and sanitized semantic-state projection. */
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../config.js';
import { jsonValueGuard, type TargetConfig } from '../model.js';
import type { JsonValue } from '../normalize.js';
import { SymbolTable } from '../symbol-table.js';

import type { AccountClient } from './clients/account.js';
import type { ConsentClient } from './clients/consent.js';
import type { ExperienceClient } from './clients/experience.js';
import type { ManagementClient } from './clients/management.js';
import { MemoryProtocolSecretStore, type OidcClient } from './clients/oidc.js';
import type { StateClient } from './clients/state.js';
import { assertPhase1EvidenceIsSanitized } from './evidence.js';
import {
  getPhase1FixtureRuntimePublicValues,
  type Phase1FixtureAllocationRole,
} from './fixture-map.js';
import {
  assertPhase1RuntimeCredentialGraphIsSanitized,
  runWithPhase1Fixture,
  type Phase1FixtureProvisioner,
  type ProvisionedPhase1Fixture,
} from './fixtures.js';
import {
  snapshotClosedDataGraph,
  type Phase1DifferentialScenario,
  type Phase1DifferentialScenarioId,
  type Phase1ObservationKind,
  type Phase1ScenarioStepResult,
} from './model.js';
import type { Phase1Profile } from './profile-types.js';
import { phase1HttpProjectionGuard } from './projections/http.js';

export type Phase1ScenarioStateProjectionInput = Readonly<{
  body: JsonValue;
  semanticState: JsonValue;
  sideEffects: JsonValue;
  persistedState?: JsonValue | undefined;
  generatedIds?: JsonValue | undefined;
  outcomes?: readonly JsonValue[] | undefined;
}>;

export type Phase1AllocationProtocolClients = Readonly<{
  oidc: Pick<OidcClient, 'request' | 'store'>;
  experience: Pick<ExperienceClient, 'requestExperience' | 'store'>;
  consent: Pick<ConsentClient, 'requestConsent' | 'store'>;
  management: Pick<ManagementClient, 'requestManagement' | 'store'>;
  account: Pick<AccountClient, 'requestAccount' | 'store'>;
  state: Pick<StateClient, 'requestState' | 'store'>;
}>;

export type Phase1ProtocolSession = Readonly<{
  publicOidc: Pick<OidcClient, 'request' | 'allocationRole'>;
  publicSymbols: SymbolTable;
  forAllocation(role: Phase1FixtureAllocationRole): Phase1AllocationProtocolClients;
  symbolsFor(allocationId: string): SymbolTable | undefined;
}>;

export type Phase1ProtocolSessionFactoryInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase1Fixture;
  signal: AbortSignal;
}>;

type ScenarioStateRequest = Readonly<{
  scenarioId: Phase1DifferentialScenarioId;
  stepId: string;
  fixture: ProvisionedPhase1Fixture;
}>;

export type Phase1TargetRuntime = Readonly<{
  profile: Readonly<Phase1Profile>;
  target: TargetConfig;
  provisioner: Phase1FixtureProvisioner;
  timeoutMs?: number;
  createProtocolSession(input: Phase1ProtocolSessionFactoryInput): Phase1ProtocolSession;
  projectScenarioState(
    input: ScenarioStateRequest & Readonly<{ target: TargetConfig; signal: AbortSignal }>
  ): Promise<unknown>;
}>;

export type Phase1TargetStepEvidence = Readonly<{
  target: TargetConfig['label'];
  steps: readonly Phase1ScenarioStepResult[];
}>;

const invalidStepResults = 'Invalid phase 1 scenario step results';
const invalidRuntime = 'Invalid phase 1 scenario runtime';
const invalidStateRequest = 'Invalid phase 1 scenario state request';
const invalidStateProjection = 'Invalid phase 1 scenario state projection';
const scenarioExecutionFailure = 'Phase 1 scenario execution failed';
const maximumStepCount = 256;
const denseArrayIndexPattern = /^(?:0|[1-9]\d*)$/u;
const stateProjectionKeys = Object.freeze([
  'body',
  'semanticState',
  'sideEffects',
  'persistedState',
  'generatedIds',
  'outcomes',
] as const);
const requiredStateProjectionKeys = Object.freeze([
  'body',
  'semanticState',
  'sideEffects',
] as const);
const httpProjectionKeys = Object.freeze([
  'status',
  'mediaType',
  'error',
  'headers',
  'body',
  'redirect',
  'cookies',
  'urls',
  'tokens',
  'generatedIds',
  'persistedState',
  'semanticState',
  'sideEffects',
  'outcomes',
] as const);
const forbiddenStateKeyNames = new Set([
  'authorization',
  'cookie',
  'setcookie',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'password',
  'passworddigest',
  'clientsecret',
  'privatekey',
  'code',
  'state',
  'nonce',
  'codeverifier',
  'codechallenge',
  'verificationid',
  'verificationcredential',
  'verificationtoken',
]);
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const logicalSymbolPattern = /^<[A-Za-z0-9][A-Za-z0-9._-]*>$/u;
const fixedSemanticStateLiterals = Object.freeze([
  'accepted',
  'active',
  'candidate',
  'consumed',
  'error',
  'foreign',
  'inactive',
  'loser',
  'missing',
  'none',
  'opaque',
  'oracle',
  'present',
  'primary',
  'rejected',
  'replaced',
  'rotated',
  'success',
  'suspended',
  'unchanged',
  'winner',
]);

const fail = (message: string): never => {
  throw new TypeError(message);
};

const isPlainRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  !nodeTypes.isProxy(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const ownDataValue = (value: object, key: string, message: string): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);

  if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
    return fail(message);
  }

  return descriptor.value;
};

const hasExactOwnDataKeys = (
  value: unknown,
  keys: readonly string[],
  required: readonly string[],
  message: string
): value is Record<string, unknown> => {
  if (!isPlainRecord(value)) {
    return false;
  }
  const ownKeys = Reflect.ownKeys(value);

  if (
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key)) ||
    required.some((key) => !ownKeys.includes(key))
  ) {
    return false;
  }
  for (const key of ownKeys as string[]) {
    ownDataValue(value, key, message);
  }

  return true;
};

type StateKeyInspectionContext =
  | 'ordinary'
  | 'http-projection'
  | 'normalized-headers'
  | 'outcomes'
  | 'outcome';

const inspectStateKeys = (
  value: unknown,
  context: StateKeyInspectionContext = 'ordinary'
): void => {
  if (context === 'http-projection' && !phase1HttpProjectionGuard.safeParse(value).success) {
    return fail(invalidStateProjection);
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      inspectStateKeys(
        item,
        context === 'outcomes' || context === 'outcome' ? 'outcome' : 'ordinary'
      );
    }
    return;
  }
  if (!isPlainRecord(value)) {
    return;
  }
  const normalizedKeys = Object.keys(value).map((key) =>
    key.replaceAll(/[_\s-]/gu, '').toLowerCase()
  );

  if (typeof value.kty === 'string' && normalizedKeys.some((key) => privateJwkMembers.has(key))) {
    return fail(invalidStateProjection);
  }
  for (const [key, nested] of Object.entries(value)) {
    const normalized = key.replaceAll(/[_\s-]/gu, '').toLowerCase();
    const reviewedSetCookieHeader = context === 'normalized-headers' && key === 'set-cookie';

    if (
      forbiddenStateKeyNames.has(normalized) &&
      !reviewedSetCookieHeader &&
      !(normalized === 'verificationcode' && typeof nested === 'boolean')
    ) {
      return fail(invalidStateProjection);
    }
    const childContext: StateKeyInspectionContext =
      context === 'http-projection' && key === 'headers'
        ? 'normalized-headers'
        : context === 'http-projection' && key === 'outcomes'
          ? 'outcomes'
          : context === 'outcome' && key === 'response'
            ? 'http-projection'
            : context === 'outcome'
              ? 'outcome'
              : 'ordinary';

    inspectStateKeys(nested, childContext);
  }
};

const sanitizerView = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map((item) => sanitizerView(item));
  }
  if (!isPlainRecord(value)) {
    return value;
  }

  return Object.entries(value).map(([key, nested]) => ({
    metadata: key,
    value: sanitizerView(nested),
  }));
};

const containsOnlyLogicalGeneratedIds = (value: unknown): boolean => {
  if (typeof value === 'string') {
    return logicalSymbolPattern.test(value);
  }
  if (Array.isArray(value)) {
    return value.every((item) => containsOnlyLogicalGeneratedIds(item));
  }
  if (isPlainRecord(value)) {
    return Object.values(value).every((nested) => containsOnlyLogicalGeneratedIds(nested));
  }

  return false;
};

const collectStringLiterals = (
  value: unknown,
  result: Set<string>,
  visited: WeakSet<object>
): void => {
  if (typeof value === 'string') {
    result.add(value);
    return;
  }
  if (typeof value !== 'object' || value === null || visited.has(value)) {
    return;
  }
  visited.add(value);
  for (const nested of Object.values(value)) {
    collectStringLiterals(nested, result, visited);
  }
};

const createStateStringAuthority = (
  profile: Readonly<Phase1Profile>,
  fixture: ProvisionedPhase1Fixture,
  target: TargetConfig,
  scenario: Phase1DifferentialScenario
): ReadonlySet<string> => {
  const values = new Set(fixedSemanticStateLiterals);

  for (const source of [profile, fixture.public, target, scenario.id, ...scenario.orderedSteps]) {
    collectStringLiterals(source, values, new WeakSet());
  }
  if (isPlainRecord(profile) && isPlainRecord(profile.fixtures)) {
    for (const value of getPhase1FixtureRuntimePublicValues(profile, fixture.public)) {
      values.add(value);
    }
  }

  return values;
};

const containsOnlyAuthorizedStateStrings = (
  value: unknown,
  allowed: ReadonlySet<string>
): boolean => {
  if (typeof value === 'string') {
    return allowed.has(value) || logicalSymbolPattern.test(value);
  }
  if (Array.isArray(value)) {
    return value.every((item) => containsOnlyAuthorizedStateStrings(item, allowed));
  }
  if (isPlainRecord(value)) {
    return Object.values(value).every((nested) =>
      containsOnlyAuthorizedStateStrings(nested, allowed)
    );
  }

  return value === null || typeof value === 'number' || typeof value === 'boolean';
};

const assertSanitizedProjection = (value: unknown, tokens?: unknown): void => {
  try {
    inspectStateKeys(value, 'http-projection');
    assertPhase1EvidenceIsSanitized({
      metadata: sanitizerView(value),
      ...(tokens === undefined ? {} : { tokens }),
    });
  } catch {
    fail(invalidStepResults);
  }
};

const parseStateProjection = (
  value: unknown,
  allowedStrings: ReadonlySet<string>
): Phase1ScenarioStateProjectionInput => {
  try {
    const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(value);

    if (
      !snapshot ||
      Array.isArray(snapshot) ||
      !hasExactOwnDataKeys(
        snapshot,
        stateProjectionKeys,
        requiredStateProjectionKeys,
        invalidStateProjection
      )
    ) {
      return fail(invalidStateProjection);
    }
    for (const key of requiredStateProjectionKeys) {
      if (!jsonValueGuard.safeParse(ownDataValue(snapshot, key, invalidStateProjection)).success) {
        return fail(invalidStateProjection);
      }
    }
    for (const key of ['persistedState', 'generatedIds'] as const) {
      if (
        Object.hasOwn(snapshot, key) &&
        !jsonValueGuard.safeParse(ownDataValue(snapshot, key, invalidStateProjection)).success
      ) {
        return fail(invalidStateProjection);
      }
    }
    if (
      Object.hasOwn(snapshot, 'generatedIds') &&
      !containsOnlyLogicalGeneratedIds(
        ownDataValue(snapshot, 'generatedIds', invalidStateProjection)
      )
    ) {
      return fail(invalidStateProjection);
    }
    if (
      Object.hasOwn(snapshot, 'outcomes') &&
      !Array.isArray(ownDataValue(snapshot, 'outcomes', invalidStateProjection))
    ) {
      return fail(invalidStateProjection);
    }
    inspectStateKeys(snapshot);
    if (!containsOnlyAuthorizedStateStrings(snapshot, allowedStrings)) {
      return fail(invalidStateProjection);
    }
    assertPhase1RuntimeCredentialGraphIsSanitized(snapshot, []);
    assertPhase1EvidenceIsSanitized({ metadata: sanitizerView(snapshot) });

    return snapshot as Phase1ScenarioStateProjectionInput;
  } catch {
    return fail(invalidStateProjection);
  }
};

const requireProjectionRecord = (value: unknown): Record<string, unknown> => {
  if (
    !isPlainRecord(value) ||
    Reflect.ownKeys(value).length !== httpProjectionKeys.length ||
    httpProjectionKeys.some((key) => !Reflect.ownKeys(value).includes(key))
  ) {
    return fail(invalidStepResults);
  }
  for (const key of httpProjectionKeys) {
    ownDataValue(value, key, invalidStepResults);
  }

  return value;
};

const hasTokenSurface = (tokens: unknown, property: 'header' | 'claims'): boolean =>
  Array.isArray(tokens) &&
  tokens.some(
    (token) =>
      isPlainRecord(token) &&
      Object.hasOwn(token, property) &&
      isPlainRecord(ownDataValue(token, property, invalidStepResults))
  );

const validateProjectionKinds = (value: unknown, kinds: readonly Phase1ObservationKind[]): void => {
  const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(value);

  if (!snapshot || !phase1HttpProjectionGuard.safeParse(snapshot).success) {
    return fail(invalidStepResults);
  }
  const originalProjection = requireProjectionRecord(value);
  const projection = requireProjectionRecord(snapshot);
  const redirect = ownDataValue(projection, 'redirect', invalidStepResults);
  const tokens = ownDataValue(projection, 'tokens', invalidStepResults);
  const originalTokens = ownDataValue(originalProjection, 'tokens', invalidStepResults);
  const semanticState = ownDataValue(projection, 'semanticState', invalidStepResults);

  if (kinds.includes('redirect') && !isPlainRecord(redirect)) {
    return fail(invalidStepResults);
  }
  if (kinds.includes('jwt-header') && !hasTokenSurface(tokens, 'header')) {
    return fail(invalidStepResults);
  }
  if (kinds.includes('jwt-claims') && !hasTokenSurface(tokens, 'claims')) {
    return fail(invalidStepResults);
  }
  if (kinds.includes('semantic-state') && !isPlainRecord(semanticState)) {
    return fail(invalidStepResults);
  }
  assertSanitizedProjection(snapshot, originalTokens);
};

const deepFreezeProjection = <Value>(value: Value): Value => {
  if (typeof value !== 'object' || value === null) {
    return value;
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreezeProjection(descriptor.value);
    }
  }

  return Object.freeze(value);
};

const readDenseStepResults = (value: unknown): readonly unknown[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximumStepCount
  ) {
    return fail(invalidStepResults);
  }
  const ownKeys = Reflect.ownKeys(value);

  if (
    ownKeys.length !== value.length + 1 ||
    ownKeys.some(
      (key) =>
        typeof key !== 'string' ||
        (key !== 'length' && (!denseArrayIndexPattern.test(key) || Number(key) >= value.length))
    )
  ) {
    return fail(invalidStepResults);
  }

  return Array.from({ length: value.length }, (_, index) =>
    ownDataValue(value, String(index), invalidStepResults)
  );
};

export const validateExactPhase1ScenarioSteps = (
  scenario: Phase1DifferentialScenario,
  steps: unknown
): readonly Phase1ScenarioStepResult[] => {
  try {
    const entries = readDenseStepResults(steps);

    if (entries.length !== scenario.orderedSteps.length) {
      return fail(invalidStepResults);
    }
    const validated = entries.map((entry, index) => {
      if (
        !hasExactOwnDataKeys(entry, ['stepId', 'value'], ['stepId', 'value'], invalidStepResults)
      ) {
        return fail(invalidStepResults);
      }
      const expected = scenario.orderedSteps[index];
      const stepId = ownDataValue(entry, 'stepId', invalidStepResults);
      const value = ownDataValue(entry, 'value', invalidStepResults);

      if (!expected || stepId !== expected.id) {
        return fail(invalidStepResults);
      }
      validateProjectionKinds(value, expected.kinds);
      deepFreezeProjection(value);

      return Object.freeze({ stepId, value }) as Phase1ScenarioStepResult;
    });

    return Object.freeze(validated);
  } catch {
    return fail(invalidStepResults);
  }
};

const validateProtocolSession = (
  value: unknown,
  fixture: ProvisionedPhase1Fixture
): Readonly<{
  protocol: Phase1ProtocolSession;
  credentialStores: readonly MemoryProtocolSecretStore[];
}> => {
  try {
    if (
      !isPlainRecord(value) ||
      !(ownDataValue(value, 'publicSymbols', invalidRuntime) instanceof SymbolTable) ||
      typeof ownDataValue(value, 'forAllocation', invalidRuntime) !== 'function' ||
      typeof ownDataValue(value, 'symbolsFor', invalidRuntime) !== 'function'
    ) {
      return fail(invalidRuntime);
    }
    const publicOidc = ownDataValue(value, 'publicOidc', invalidRuntime);

    if (
      (typeof publicOidc !== 'object' && typeof publicOidc !== 'function') ||
      publicOidc === null ||
      typeof Reflect.get(publicOidc, 'request') !== 'function' ||
      Reflect.get(publicOidc, 'allocationRole') !== undefined
    ) {
      return fail(invalidRuntime);
    }
    const source = value as Phase1ProtocolSession;
    const clientsByRole = new Map<Phase1FixtureAllocationRole, Phase1AllocationProtocolClients>();
    const symbolsByAllocation = new Map<string, SymbolTable>();
    const stores = fixture.public.allocations.map(({ allocationId, role }) => {
      const clients = source.forAllocation(role);
      const { store } = clients.oidc;

      if (
        !(store instanceof MemoryProtocolSecretStore) ||
        typeof clients.oidc.request !== 'function' ||
        typeof clients.experience.requestExperience !== 'function' ||
        typeof clients.consent.requestConsent !== 'function' ||
        typeof clients.management.requestManagement !== 'function' ||
        typeof clients.account.requestAccount !== 'function' ||
        typeof clients.state.requestState !== 'function' ||
        clients.experience.store !== store ||
        clients.consent.store !== store ||
        clients.management.store !== store ||
        clients.account.store !== store ||
        clients.state.store !== store
      ) {
        return fail(invalidRuntime);
      }
      const symbols = source.symbolsFor(allocationId);

      if (!(symbols instanceof SymbolTable) || clientsByRole.has(role)) {
        return fail(invalidRuntime);
      }
      clientsByRole.set(role, Object.freeze({ ...clients }));
      symbolsByAllocation.set(allocationId, symbols);

      return store;
    });
    const protocol = Object.freeze({
      publicOidc: source.publicOidc,
      publicSymbols: source.publicSymbols,
      forAllocation: (role: Phase1FixtureAllocationRole) =>
        clientsByRole.get(role) ?? fail(invalidRuntime),
      symbolsFor: (allocationId: string) => symbolsByAllocation.get(allocationId),
    });
    const credentialStores = Object.freeze(
      stores.filter((store, index) => stores.indexOf(store) === index)
    );

    return Object.freeze({ protocol, credentialStores });
  } catch {
    return fail(invalidRuntime);
  }
};

const assertCredentialFree = (
  stores: readonly MemoryProtocolSecretStore[],
  value: unknown,
  diagnostic: string
): void => {
  try {
    for (const store of stores) {
      store.assertNoCredentialMaterial(value);
    }
  } catch {
    fail(diagnostic);
  }
};

const parseScenarioStateRequest = (
  value: unknown,
  scenario: Phase1DifferentialScenario,
  fixture: ProvisionedPhase1Fixture
): Readonly<{ scenarioId: Phase1DifferentialScenarioId; stepId: string }> => {
  if (
    !hasExactOwnDataKeys(
      value,
      ['scenarioId', 'stepId', 'fixture'],
      ['scenarioId', 'stepId', 'fixture'],
      invalidStateRequest
    )
  ) {
    return fail(invalidStateRequest);
  }
  const scenarioId = ownDataValue(value, 'scenarioId', invalidStateRequest);
  const stepId = ownDataValue(value, 'stepId', invalidStateRequest);
  const requestedFixture = ownDataValue(value, 'fixture', invalidStateRequest);
  const step = scenario.orderedSteps.find(({ id }) => id === stepId);

  if (
    scenarioId !== scenario.id ||
    requestedFixture !== fixture ||
    typeof stepId !== 'string' ||
    !step
  ) {
    return fail(invalidStateRequest);
  }

  return Object.freeze({ scenarioId: scenario.id, stepId });
};

export const runPhase1ScenarioForTarget = async (
  scenario: Phase1DifferentialScenario,
  runtime: Phase1TargetRuntime
): Promise<Phase1TargetStepEvidence> => {
  const target = validateTargetConfig(runtime.target);
  const steps = await runWithPhase1Fixture(
    runtime.provisioner,
    scenario.fixture,
    async (fixture, signal) => {
      const validatedProtocol = (() => {
        try {
          return validateProtocolSession(
            runtime.createProtocolSession({ target, fixture, signal }),
            fixture
          );
        } catch {
          return fail(invalidRuntime);
        }
      })();
      const { protocol, credentialStores } = validatedProtocol;
      const stateStringAuthority = createStateStringAuthority(
        runtime.profile,
        fixture,
        target,
        scenario
      );
      const context = Object.freeze({
        profile: runtime.profile,
        target,
        fixture,
        signal,
        protocol,
        projectFixtureState: async () => runtime.provisioner.projectState(fixture),
        projectScenarioState: async (input: ScenarioStateRequest) => {
          const request = parseScenarioStateRequest(input, scenario, fixture);
          try {
            const projected = await runtime.projectScenarioState({
              ...request,
              fixture,
              target,
              signal,
            });
            assertCredentialFree(credentialStores, projected, invalidStateProjection);

            return parseStateProjection(projected, stateStringAuthority);
          } catch {
            return fail(invalidStateProjection);
          }
        },
      });
      const result = await (async () => {
        try {
          return await scenario.run(context);
        } catch (error: unknown) {
          if (
            error instanceof TypeError &&
            [invalidStateRequest, invalidStateProjection].includes(error.message)
          ) {
            throw error;
          }

          return fail(scenarioExecutionFailure);
        }
      })();
      assertCredentialFree(credentialStores, result, invalidStepResults);

      return validateExactPhase1ScenarioSteps(scenario, result);
    },
    runtime.timeoutMs === undefined ? {} : { timeoutMs: runtime.timeoutMs }
  );

  return Object.freeze({ target: target.label, steps });
};

/* eslint-enable complexity, max-lines, no-restricted-syntax, @typescript-eslint/ban-types */
