/* eslint-disable @typescript-eslint/ban-types, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutating-methods, complexity, max-lines, no-control-regex, no-restricted-syntax, unicorn/escape-case, unicorn/no-new-array, unicorn/prevent-abbreviations -- This closed runtime boundary requires recursive JSON null/object types, descriptor-preserving cloning, and a bounded path-control regex. */
import { types as nodeTypes } from 'node:util';

import { z } from 'zod';

import { jsonValueGuard, type TargetConfig } from '../model.js';
import type { JsonObject, JsonValue } from '../normalize.js';

import type { ProvisionedPhase1Fixture, SemanticStateProjection } from './fixtures.js';
import type { Phase1SourceEvidenceRef as ProfilePhase1SourceEvidenceRef } from './profile-semantics/provenance.js';
import type { Phase1Profile } from './profile-types.js';
import type { Phase1HttpProjection } from './projections/http.js';
import type {
  Phase1ProtocolSession,
  Phase1ScenarioStateProjectionInput,
} from './scenario-runtime.js';

export const oracleCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
export const phase0HarnessCommit = '40135e37201f36ac05ece1eff82e37bb6d9649f1';

export const differentialScenarioIds = Object.freeze([
  'discovery.config',
  'authorization.password-pkce-consent',
  'token.authorization-code',
  'token.refresh-rotation',
  'userinfo.openid',
  'management.application-read',
  'management.user-read',
  'console.admin-auth-resource-refresh',
  'console.admin-organization-token-refresh',
  'account.admin-operator-read',
  'cors.management-list',
  'cookie.localhost-port-interleaving',
  'authorization.redirect-uri-rejected',
  'authorization.pkce-method-rejected',
  'token.pkce-verifier-rejected',
  'token.code-reuse-rejected',
  'interaction.password-rejected',
  'interaction.consent-session-boundary',
  'token.refresh-reuse-rejected',
  'token.issuer-audience-scope-rejected',
  'token.concurrent-code-single-winner',
  'token.concurrent-refresh-single-winner',
] as const);

export const candidateInvariantScenarioIds = Object.freeze([
  'tenant.cross-tenant-read-rejected',
  'tenant.suspended-epoch-rejected',
  'tenant.admin-operation-binding',
  'tenant.admin-operation-status-matrix',
  'database.owner-role-membership-boundary',
  'reaper.activity-visibility-redaction',
  'reaper.object-audit-disabled',
  'keystore.unwrap-failure-rolls-back-code',
  'keystore.wrapping-fence-late-commit',
  'keystore.sign-seal-during-rewrap',
  'keystore.metadata-dml-boundary',
  'keystore.forced-rls-owner-boundary',
  'keystore.reference-count-ledger',
  'keystore.reference-ledger-verifier-boundary',
  'keystore.live-ledger-limit-and-tombstone',
  'keystore.stale-keyring-rejoin-rejected',
  'keystore.required-readable-key-set',
  'hosts.unavailable-pkce-independent',
] as const);

export const candidateInvariantNegativeControlPointers = Object.freeze([
  '/outcome/crossTenantRows/0',
  '/activation/accepted',
  '/mutations/1/tenantId',
  '/matrix/deleted/provision',
  '/roles/aster_request/memberOf/0',
  '/observations/0/queryText',
  '/artifacts/0/matches/0',
  '/semanticState/code/consumed',
  '/semanticState/material/oldKeyReferences',
  '/availability/tokenSigning',
  '/semanticState/keyMetadata/activeGeneration',
  '/semanticState/crossTenantRows/0',
  '/ledger/mismatches/0/count',
  '/verifier/disclosedTenantIds/0',
  '/liveLedger/reusedTombstoneId',
  '/replica/readiness',
  '/replica/missingRequired/0',
  '/protocol/pkce/available',
] as const);

export type Phase1DifferentialScenarioId = (typeof differentialScenarioIds)[number];
export type CandidateInvariantScenarioId = (typeof candidateInvariantScenarioIds)[number];

export const differentialScenarioIdGuard = z.enum(differentialScenarioIds);
export const candidateInvariantScenarioIdGuard = z.enum(candidateInvariantScenarioIds);

export const phase1ObservationKinds = Object.freeze([
  'http',
  'redirect',
  'cookie-metadata',
  'jwt-header',
  'jwt-claims',
  'semantic-state',
] as const);
export type Phase1ObservationKind = (typeof phase1ObservationKinds)[number];

export const phase1FixtureRecipes = Object.freeze([
  'none',
  'dataProtocol',
  'adminConsole',
  'fullPhase1',
  'corsBoundary',
  'consentBoundary',
] as const);
export type Phase1FixtureRecipe = (typeof phase1FixtureRecipes)[number];

export type Phase1SourceEvidenceRef = ProfilePhase1SourceEvidenceRef;

export type Phase1ScenarioStep = Readonly<{
  id: string;
  kinds: readonly Phase1ObservationKind[];
}>;

export type Phase1ObservationContract = Readonly<{
  status: readonly string[];
  mediaType: readonly string[];
  headers: readonly string[];
  cookies: readonly string[];
  redirects: readonly string[];
}>;

export type Phase1ScenarioStepResult = Readonly<{
  stepId: string;
  value: Phase1HttpProjection;
}>;

export type Phase1ScenarioRunContext = Readonly<{
  profile: Readonly<Phase1Profile>;
  target: TargetConfig;
  fixture: ProvisionedPhase1Fixture;
  signal: AbortSignal;
  protocol: Phase1ProtocolSession;
  projectFixtureState(): Promise<SemanticStateProjection>;
  projectScenarioState(
    input: Readonly<{
      scenarioId: Phase1DifferentialScenarioId;
      stepId: string;
      fixture: ProvisionedPhase1Fixture;
    }>
  ): Promise<Phase1ScenarioStateProjectionInput>;
}>;

export type Phase1ScenarioRun = (
  context: Phase1ScenarioRunContext
) => Promise<readonly Phase1ScenarioStepResult[]>;

export type Phase1DifferentialScenario = Readonly<{
  id: Phase1DifferentialScenarioId;
  evidenceKind: 'differential';
  fixture: Phase1FixtureRecipe;
  sourceEvidence: readonly Phase1SourceEvidenceRef[];
  orderedSteps: readonly Phase1ScenarioStep[];
  observationContract: Phase1ObservationContract;
  normalizablePointers: readonly string[];
  semanticProjectionVersion: 1;
  cleanup: 'fresh-fixture-reverse-cleanup';
  run: Phase1ScenarioRun;
}>;

export type CandidateInvariantPrecondition = Readonly<JsonObject>;
export type CandidateInvariantPerturbation = Readonly<JsonObject>;
export type CandidateInvariantCleanup = Readonly<JsonObject>;
export type CandidateInvariantProjection = Readonly<JsonObject>;

export type CandidateInvariantControl = Readonly<{
  kind: 'positive' | 'negative';
  name: string;
  input: JsonValue;
  expectedProjection: JsonValue;
  expectedDifferencePointer: string | null;
}>;

export type CandidateInvariantContract = Readonly<{
  id: CandidateInvariantScenarioId;
  evidenceKind: 'candidate-invariant';
  executor: 'aster';
  livePrecondition: CandidateInvariantPrecondition;
  perturbation: CandidateInvariantPerturbation;
  expectedPublicOutcome: JsonValue;
  expectedPersistedOutcome: JsonValue;
  forbiddenOutcome: JsonValue;
  cleanup: CandidateInvariantCleanup;
  sanitizedProjection: CandidateInvariantProjection;
  projectionVersion: 1;
  positiveControl: CandidateInvariantControl;
  negativeControl: CandidateInvariantControl;
  oracle?: never;
  candidate?: never;
  differences?: never;
  compare?: never;
  oracleComparison?: never;
}>;

/** Compatibility alias retained for callers that imported the pre-Task-14 registry type. */
export type CandidateInvariantAuthority = CandidateInvariantContract;

const maximumDenseArrayLength = 4096;
const denseArrayIndexPattern = /^(?:0|[1-9]\d*)$/u;
const invalidClosedDataSnapshot = Symbol('invalid-closed-data-snapshot');

export type ClosedDataGraphSnapshotOptions = Readonly<{
  allowFunction?: (path: string, value: unknown) => boolean;
}>;

const snapshotClosedDataGraphValue = (
  value: unknown,
  path: string,
  ancestors: WeakSet<object>,
  options: ClosedDataGraphSnapshotOptions
): unknown | typeof invalidClosedDataSnapshot => {
  if (typeof value === 'function') {
    return options.allowFunction?.(path, value) === true ? value : invalidClosedDataSnapshot;
  }
  if (typeof value !== 'object' || value === null) {
    return typeof value === 'symbol' ? invalidClosedDataSnapshot : value;
  }
  if (nodeTypes.isProxy(value) || ancestors.has(value)) {
    return invalidClosedDataSnapshot;
  }
  const prototype = Object.getPrototypeOf(value);

  if (Array.isArray(value)) {
    if (prototype !== Array.prototype) {
      return invalidClosedDataSnapshot;
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');

    if (
      !lengthDescriptor ||
      !Object.hasOwn(lengthDescriptor, 'value') ||
      typeof lengthDescriptor.value !== 'number' ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0 ||
      lengthDescriptor.value > maximumDenseArrayLength ||
      lengthDescriptor.enumerable === true ||
      lengthDescriptor.configurable === true
    ) {
      return invalidClosedDataSnapshot;
    }
    const length = lengthDescriptor.value;
    const keys = Reflect.ownKeys(value);

    if (keys.length !== length + 1) {
      return invalidClosedDataSnapshot;
    }
    for (const key of keys) {
      if (
        typeof key !== 'string' ||
        (key !== 'length' &&
          (!denseArrayIndexPattern.test(key) || Number.parseInt(key, 10) >= length))
      ) {
        return invalidClosedDataSnapshot;
      }
    }
    ancestors.add(value);
    const snapshot: unknown[] = [];

    for (const index of Array.from({ length }, (_, index) => index)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));

      if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
        ancestors.delete(value);
        return invalidClosedDataSnapshot;
      }
      const item = snapshotClosedDataGraphValue(
        descriptor.value,
        `${path}/${index}`,
        ancestors,
        options
      );

      if (item === invalidClosedDataSnapshot) {
        ancestors.delete(value);
        return invalidClosedDataSnapshot;
      }
      snapshot.push(item);
    }
    ancestors.delete(value);

    return Object.freeze(snapshot);
  }
  if (prototype !== Object.prototype) {
    return invalidClosedDataSnapshot;
  }
  const keys = Reflect.ownKeys(value);
  const snapshot: Record<string, unknown> = {};
  ancestors.add(value);

  for (const key of keys) {
    if (typeof key !== 'string') {
      ancestors.delete(value);
      return invalidClosedDataSnapshot;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || descriptor.enumerable !== true) {
      ancestors.delete(value);
      return invalidClosedDataSnapshot;
    }
    const item = snapshotClosedDataGraphValue(
      descriptor.value,
      `${path}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`,
      ancestors,
      options
    );

    if (item === invalidClosedDataSnapshot) {
      ancestors.delete(value);
      return invalidClosedDataSnapshot;
    }
    Object.defineProperty(snapshot, key, {
      configurable: false,
      enumerable: true,
      value: item,
      writable: false,
    });
  }
  ancestors.delete(value);

  return Object.freeze(snapshot);
};

export const snapshotClosedDataGraph = <Value>(
  value: unknown,
  options: ClosedDataGraphSnapshotOptions = {}
): Readonly<Value> | undefined => {
  try {
    const snapshot = snapshotClosedDataGraphValue(value, '', new WeakSet(), options);

    return snapshot === invalidClosedDataSnapshot ? undefined : (snapshot as Readonly<Value>);
  } catch {
    return undefined;
  }
};

export const snapshotDensePlainArray = <Value>(
  value: unknown,
  options: ClosedDataGraphSnapshotOptions = {}
): readonly Value[] | undefined => {
  const snapshot = snapshotClosedDataGraph<unknown>(value, options);

  return Array.isArray(snapshot) ? (snapshot as readonly Value[]) : undefined;
};

const repositoryPathPattern = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*[\u0000-\u001f\u007f]).+$/u;
const pointerPattern = /^(?:\/(?:[^~]|~[01])*)+$/u;
const sourceEvidenceRefGuard = z
  .object({
    commit: z.union([z.literal(oracleCommit), z.literal(phase0HarnessCommit)]),
    path: z
      .string()
      .min(1)
      .regex(repositoryPathPattern)
      .refine((path) => path.split('/').every((segment) => segment.length > 0 && segment !== '.')),
  })
  .strict();
const scenarioStepGuard = z
  .object({
    id: z.string().min(1),
    kinds: z.array(z.enum(phase1ObservationKinds)).min(1),
  })
  .strict()
  .superRefine(({ kinds }, context) => {
    if (new Set(kinds).size !== kinds.length) {
      context.addIssue({ code: z.ZodIssueCode.custom });
    }
  });
const observationContractGuard = z
  .object({
    status: z.array(z.string().min(1)),
    mediaType: z.array(z.string().min(1)),
    headers: z.array(z.string().min(1)),
    cookies: z.array(z.string().min(1)),
    redirects: z.array(z.string().min(1)),
  })
  .strict();
const runGuard = z.custom<Phase1ScenarioRun>((value) => typeof value === 'function');

const deriveObservationSteps = (
  orderedSteps: readonly Phase1ScenarioStep[],
  kind: Phase1ObservationKind
) => orderedSteps.filter(({ kinds }) => kinds.includes(kind)).map(({ id }) => id);

const equalStrings = (left: readonly string[], right: readonly string[]) =>
  left.length === right.length && left.every((value, index) => value === right[index]);

export const phase1DifferentialScenarioGuard = z
  .object({
    id: differentialScenarioIdGuard,
    evidenceKind: z.literal('differential'),
    fixture: z.enum(phase1FixtureRecipes),
    sourceEvidence: z.array(sourceEvidenceRefGuard).min(1),
    orderedSteps: z.array(scenarioStepGuard).min(1),
    observationContract: observationContractGuard,
    normalizablePointers: z.array(z.string().regex(pointerPattern)),
    semanticProjectionVersion: z.literal(1),
    cleanup: z.literal('fresh-fixture-reverse-cleanup'),
    run: runGuard,
  })
  .strict()
  .superRefine(
    ({ sourceEvidence, orderedSteps, observationContract, normalizablePointers }, context) => {
      const sourceKeys = sourceEvidence.map(({ commit, path }) => `${commit}\u0000${path}`);
      const stepIds = orderedSteps.map(({ id }) => id);
      const expectedStatus = deriveObservationSteps(orderedSteps, 'http');
      const expectedCookies = deriveObservationSteps(orderedSteps, 'cookie-metadata');
      const expectedRedirects = deriveObservationSteps(orderedSteps, 'redirect');

      if (
        new Set(sourceKeys).size !== sourceKeys.length ||
        new Set(stepIds).size !== stepIds.length ||
        new Set(normalizablePointers).size !== normalizablePointers.length ||
        !equalStrings(observationContract.status, expectedStatus) ||
        !equalStrings(observationContract.mediaType, expectedStatus) ||
        !equalStrings(observationContract.headers, expectedStatus) ||
        !equalStrings(observationContract.cookies, expectedCookies) ||
        !equalStrings(observationContract.redirects, expectedRedirects)
      ) {
        context.addIssue({ code: z.ZodIssueCode.custom });
      }
    }
  );

const jsonObjectGuard = z
  .custom<JsonObject>((value) => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return false;
    }
    const prototype = Object.getPrototypeOf(value);

    return prototype === Object.prototype || prototype === null;
  })
  .pipe(z.record(jsonValueGuard));
const candidateControlGuard = z
  .object({
    kind: z.enum(['positive', 'negative']),
    name: z.string().min(1),
    input: jsonValueGuard,
    expectedProjection: jsonValueGuard,
    expectedDifferencePointer: z.string().regex(pointerPattern).nullable(),
  })
  .strict();

export const candidateInvariantContractGuard = z
  .object({
    id: candidateInvariantScenarioIdGuard,
    evidenceKind: z.literal('candidate-invariant'),
    executor: z.literal('aster'),
    livePrecondition: jsonObjectGuard,
    perturbation: jsonObjectGuard,
    expectedPublicOutcome: jsonValueGuard,
    expectedPersistedOutcome: jsonValueGuard,
    forbiddenOutcome: jsonValueGuard,
    cleanup: jsonObjectGuard,
    sanitizedProjection: jsonObjectGuard,
    projectionVersion: z.literal(1),
    positiveControl: candidateControlGuard,
    negativeControl: candidateControlGuard,
  })
  .strict()
  .superRefine(({ positiveControl, negativeControl }, context) => {
    if (
      positiveControl.kind !== 'positive' ||
      positiveControl.expectedDifferencePointer !== null ||
      negativeControl.kind !== 'negative' ||
      negativeControl.expectedDifferencePointer === null
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom });
    }
  });

/** Compatibility alias retained for callers that imported the pre-Task-14 registry guard. */
export const candidateInvariantAuthorityGuard = candidateInvariantContractGuard;

const differentialKeys = new Set<string>([
  'id',
  'evidenceKind',
  'fixture',
  'sourceEvidence',
  'orderedSteps',
  'observationContract',
  'normalizablePointers',
  'semanticProjectionVersion',
  'cleanup',
  'run',
]);
const candidateKeys = new Set<string>([
  'id',
  'evidenceKind',
  'executor',
  'livePrecondition',
  'perturbation',
  'expectedPublicOutcome',
  'expectedPersistedOutcome',
  'forbiddenOutcome',
  'cleanup',
  'sanitizedProjection',
  'projectionVersion',
  'positiveControl',
  'negativeControl',
]);
const forbiddenCandidateKeys = new Set<string>([
  'oracle',
  'candidate',
  'differences',
  'compare',
  'oraclecomparison',
]);

const hasExactOwnKeys = (value: unknown, allowed: ReadonlySet<string>): value is object => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  return Reflect.ownKeys(value).every((key) => typeof key === 'string' && allowed.has(key));
};

const normalizeCandidateKey = (key: string) => key.replaceAll(/[_\s-]/gu, '').toLowerCase();

const hasForbiddenCandidateKey = (
  value: unknown,
  ancestors: WeakSet<object> = new WeakSet()
): boolean => {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  if (nodeTypes.isProxy(value) || ancestors.has(value)) {
    return true;
  }
  ancestors.add(value);

  const forbidden = Reflect.ownKeys(value).some((key) => {
    if (typeof key !== 'string') {
      return true;
    }
    if (key !== 'length' && forbiddenCandidateKeys.has(normalizeCandidateKey(key))) {
      return true;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    return (
      !descriptor ||
      !Object.hasOwn(descriptor, 'value') ||
      hasForbiddenCandidateKey(descriptor.value, ancestors)
    );
  });
  ancestors.delete(value);

  return forbidden;
};

const arrayIndexPattern = /^(?:0|[1-9]\d*)$/u;

const hasClosedDataGraph = (
  value: unknown,
  allowFunctions: boolean,
  visited: WeakSet<object> = new WeakSet()
): boolean => {
  if (
    ((typeof value === 'object' && value !== null) || typeof value === 'function') &&
    nodeTypes.isProxy(value)
  ) {
    return false;
  }
  if (typeof value === 'function') {
    return allowFunctions;
  }
  if (typeof value !== 'object' || value === null) {
    return true;
  }
  if (visited.has(value)) {
    return true;
  }
  const isArray = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);

  if (
    (!isArray && prototype !== Object.prototype && prototype !== null) ||
    (isArray && prototype !== Array.prototype)
  ) {
    return false;
  }
  visited.add(value);
  const ownKeys = Reflect.ownKeys(value);

  if (isArray && ownKeys.filter((key) => key !== 'length').length !== value.length) {
    return false;
  }

  return ownKeys.every((key) => {
    if (typeof key !== 'string') {
      return false;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      return false;
    }
    if (isArray) {
      if (key === 'length') {
        return descriptor.enumerable === false && typeof descriptor.value === 'number';
      }
      if (!arrayIndexPattern.test(key) || descriptor.enumerable !== true) {
        return false;
      }
    } else if (descriptor.enumerable !== true) {
      return false;
    }

    return hasClosedDataGraph(descriptor.value, allowFunctions, visited);
  });
};

const cloneValue = <Value>(value: Value, clones: WeakMap<object, object>): Value => {
  if ((typeof value !== 'object' || value === null) && typeof value !== 'function') {
    return value;
  }
  const objectValue = value as object;
  const existing = clones.get(objectValue);

  if (existing) {
    return existing as Value;
  }

  if (typeof value === 'function') {
    clones.set(objectValue, objectValue);
    return value;
  }

  const clone: object = Array.isArray(value)
    ? new Array(value.length)
    : Object.create(Object.getPrototypeOf(value));
  clones.set(objectValue, clone);

  for (const key of Reflect.ownKeys(value)) {
    if (Array.isArray(value) && key === 'length') {
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor) {
      continue;
    }
    const clonedDescriptor = Object.hasOwn(descriptor, 'value')
      ? { ...descriptor, value: cloneValue(descriptor.value, clones) }
      : descriptor;
    Object.defineProperty(clone, key, clonedDescriptor);
  }

  if (Array.isArray(value)) {
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');

    if (lengthDescriptor) {
      Object.defineProperty(clone, 'length', lengthDescriptor);
    }
  }

  return clone as Value;
};

const deepFreeze = <Value>(value: Value, visited: WeakSet<object>): Value => {
  if ((typeof value !== 'object' || value === null) && typeof value !== 'function') {
    return value;
  }
  const objectValue = value as object;

  if (visited.has(objectValue)) {
    return value;
  }
  visited.add(objectValue);

  for (const key of Reflect.ownKeys(objectValue)) {
    const descriptor = Object.getOwnPropertyDescriptor(objectValue, key);

    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreeze(descriptor.value, visited);
    }
  }

  return Object.freeze(value);
};

export const cloneAndDeepFreeze = <Value>(value: Value): Readonly<Value> =>
  deepFreeze(cloneValue(value, new WeakMap()), new WeakSet());

const differentialDiagnostic = 'Invalid phase 1 differential scenario contract';
const candidateDiagnostic = 'Invalid phase 1 candidate invariant contract';

export const defineDifferentialScenario = (
  scenario: Phase1DifferentialScenario
): Phase1DifferentialScenario => {
  try {
    if (!hasExactOwnKeys(scenario, differentialKeys) || !hasClosedDataGraph(scenario, true)) {
      throw new TypeError(differentialDiagnostic);
    }
    const cleanClone = cloneValue(scenario, new WeakMap());
    const result = phase1DifferentialScenarioGuard.safeParse(cleanClone);

    if (!result.success) {
      throw new TypeError(differentialDiagnostic);
    }

    return deepFreeze(cleanClone, new WeakSet());
  } catch {
    throw new TypeError(differentialDiagnostic);
  }
};

export const defineCandidateInvariant = (
  contract: CandidateInvariantContract
): CandidateInvariantContract => {
  try {
    if (
      hasForbiddenCandidateKey(contract) ||
      !hasExactOwnKeys(contract, candidateKeys) ||
      !hasClosedDataGraph(contract, false)
    ) {
      throw new TypeError(candidateDiagnostic);
    }
    const cleanClone = cloneValue(contract, new WeakMap());
    const result = candidateInvariantContractGuard.safeParse(cleanClone);

    if (!result.success) {
      throw new TypeError(candidateDiagnostic);
    }

    return deepFreeze(cleanClone, new WeakSet()) as CandidateInvariantContract;
  } catch {
    throw new TypeError(candidateDiagnostic);
  }
};

/* eslint-enable @typescript-eslint/ban-types, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutating-methods, complexity, max-lines, no-control-regex, no-restricted-syntax, unicorn/escape-case, unicorn/no-new-array, unicorn/prevent-abbreviations */
