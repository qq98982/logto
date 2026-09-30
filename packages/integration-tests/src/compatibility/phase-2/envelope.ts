/* eslint-disable complexity, max-lines, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/prefer-nullish-coalescing, no-restricted-syntax -- Closed nested provenance and exact candidate evidence validation intentionally check every optional mode branch. */
import { types as nodeTypes } from 'node:util';

import { jsonValueGuard } from '../model.js';
import type { JsonValue } from '../normalize.js';
import { snapshotClosedDataGraph } from '../phase-1/model.js';

import {
  clientCredentialsCandidateInvariantExpectedProjection,
  clientCredentialsCandidateInvariantIds,
  runClientCredentialsCandidateInvariantControls,
} from './candidate-invariants/client-credentials.js';
import {
  deviceCandidateInvariantExpectedProjection,
  deviceCandidateInvariantIds,
  runDeviceCandidateInvariantControls,
} from './candidate-invariants/device-authorization.js';
import type { Phase2ProfileRegistries } from './profile.js';
import { phase2ExpectedBaseAcceptance } from './profile.js';
import { assertClientCredentialsEvidenceIsSanitized } from './projections/client-credentials.js';
import {
  assertDeviceAuthorizationEvidenceIsSanitized,
  snapshotDenseArray,
} from './projections/device-authorization.js';
import {
  phase2OracleImageDigest,
  phase2OracleSourceCommit,
  type Phase2PublicHarnessProvenance,
  type Phase2SourceIdentity,
} from './provenance.js';
import {
  deviceAuthorizationScenarioIds,
  publishDeviceScenarioProjection,
  restoreDeviceScenarioProjectionFromJson,
  type DeviceAuthorizationScenarioId,
  type DeviceScenarioProjection,
} from './scenarios/device-authorization.js';

export type Phase2EvidenceMode = 'oracle' | 'differential' | 'candidate-invariants';

export type Phase2TargetProvenance = Readonly<{
  sourceCommit: string;
  imageDigest: string;
  topology: Readonly<{ primaryRole: string; foreignRole: string }>;
  drivers: Readonly<{
    state: Readonly<{ role: 'state-driver'; sha256: string }>;
    fixture?: Readonly<{ role: 'fixture-executable'; sha256: string }>;
    invariant?: Readonly<{ role: 'invariant-driver'; sha256: string }>;
  }>;
}>;

export type Phase2EvidenceEnvelope = Readonly<{
  schemaVersion: 1;
  mode: Phase2EvidenceMode;
  provenance: Readonly<{
    profileSha256: string;
    schemaSha256: string;
    baseAcceptance: Phase2ProfileRegistries['baseAcceptance'];
    harness: Phase2PublicHarnessProvenance;
    oracle?: Phase2TargetProvenance;
    candidate?: Phase2TargetProvenance;
  }>;
  sanitizerSuccess: true;
  payload: JsonValue;
}>;

const commitPattern = /^[0-9a-f]{40}$/u;
const imagePattern = /^sha256:[0-9a-f]{64}$/u;
const diagnostic = 'Invalid Phase 2 evidence envelope';

const fail = (): never => {
  throw new TypeError(diagnostic);
};
const exactKeys = (value: unknown, keys: readonly string[]): boolean =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  Object.keys(value).every((key) => keys.includes(key));

const snapshotExactDataRecord = (
  value: unknown,
  keys: readonly string[]
): Readonly<Record<string, unknown>> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  const ownKeys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
  ) {
    return fail();
  }
  const snapshot = Object.fromEntries(
    keys.map((key) => {
      const descriptor = descriptors[key];
      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
        return fail();
      }
      return [key, descriptor.value as unknown] as const;
    })
  );
  return Object.freeze(snapshot);
};

const canonicalJsonValue = (value: unknown): JsonValue => {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }
  if (Array.isArray(value)) {
    if (value.includes(undefined)) {
      return fail();
    }
    return value.map((entry) => canonicalJsonValue(entry));
  }
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, entry]) => entry !== undefined)
        .map(([key, entry]) => [key, canonicalJsonValue(entry)])
    );
  }
  return fail();
};

const snapshotJsonWire = (value: unknown): JsonValue => {
  const snapshot = snapshotClosedDataGraph<unknown>(value);
  if (snapshot === undefined) {
    return fail();
  }
  const wire = canonicalJsonValue(snapshot);
  return jsonValueGuard.safeParse(wire).success ? wire : fail();
};

const restoreOracleWirePayload = (value: unknown): JsonValue => {
  const payload = snapshotExactDataRecord(value, ['schemaVersion', 'mode', 'target']);
  const target = snapshotExactDataRecord(payload.target, [
    'target',
    'scenarios',
    'discovery',
    'controls',
  ]);
  const scenarios = snapshotDenseArray(target.scenarios, 161).map((entry) => {
    const scenario = snapshotExactDataRecord(entry, ['id', 'projection']);
    const { id, projection } = scenario;
    if (typeof id !== 'string') {
      return fail();
    }
    return Object.freeze({
      id,
      projection: (deviceAuthorizationScenarioIds as readonly string[]).includes(id)
        ? restoreDeviceScenarioProjectionFromJson(projection, id as DeviceAuthorizationScenarioId)
        : projection,
    });
  });
  return Object.freeze({
    schemaVersion: payload.schemaVersion,
    mode: payload.mode,
    target: Object.freeze({
      target: target.target,
      scenarios: Object.freeze(scenarios),
      discovery: target.discovery,
      controls: target.controls,
    }),
  }) as unknown as JsonValue;
};

const validateTarget = (value: Phase2TargetProvenance): void => {
  const hash = /^[0-9a-f]{64}$/u;
  const serialized = JSON.stringify(value);
  if (
    !exactKeys(value, ['sourceCommit', 'imageDigest', 'topology', 'drivers']) ||
    !exactKeys(value.topology, ['primaryRole', 'foreignRole']) ||
    !exactKeys(
      value.drivers,
      Object.keys(
        value.drivers.fixture
          ? value.drivers.invariant
            ? { state: 1, fixture: 1, invariant: 1 }
            : { state: 1, fixture: 1 }
          : value.drivers.invariant
            ? { state: 1, invariant: 1 }
            : { state: 1 }
      )
    ) ||
    !exactKeys(value.drivers.state, ['role', 'sha256']) ||
    !commitPattern.test(value.sourceCommit) ||
    !imagePattern.test(value.imageDigest) ||
    !hash.test(value.drivers.state.sha256) ||
    value.drivers.state.role !== 'state-driver' ||
    !/^(?:oracle|candidate)-(?:primary|foreign)-core$/u.test(value.topology.primaryRole) ||
    !/^(?:oracle|candidate)-(?:primary|foreign)-core$/u.test(value.topology.foreignRole) ||
    (value.drivers.fixture &&
      (!hash.test(value.drivers.fixture.sha256) ||
        value.drivers.fixture.role !== 'fixture-executable')) ||
    (value.drivers.invariant &&
      (!hash.test(value.drivers.invariant.sha256) ||
        value.drivers.invariant.role !== 'invariant-driver')) ||
    serialized.includes('/') ||
    /(?:container|project|socket|\bdev\b|\bino\b|\buid\b|\bmode\b|\bnlink\b|repositoryRoot)/u.test(
      serialized
    )
  ) {
    fail();
  }
};

const validateCandidateInvariantPayload = (
  value: unknown,
  profile: Phase2ProfileRegistries
): void => {
  if (!exactKeys(value, ['schemaVersion', 'mode', 'invariants'])) {
    fail();
  }
  const payload = value as Record<string, unknown>;
  const { invariants } = payload;
  if (
    payload.schemaVersion !== 1 ||
    payload.mode !== 'candidate-invariants' ||
    !Array.isArray(invariants) ||
    invariants.length !== profile.candidateInvariantScenarios.length
  ) {
    fail();
  }
  const invariantEntries = invariants as unknown[];
  const allIds = [...clientCredentialsCandidateInvariantIds, ...deviceCandidateInvariantIds];
  if (
    allIds.length !== profile.candidateInvariantScenarios.length ||
    allIds.some((id, index) => id !== profile.candidateInvariantScenarios[index])
  ) {
    fail();
  }
  for (const [index, entry] of invariantEntries.entries()) {
    if (!exactKeys(entry, ['id', 'candidate', 'positiveControl', 'negativeControl'])) {
      fail();
    }
    const evidence = entry as Record<string, unknown>;
    const id = allIds[index] ?? fail();
    if (evidence.id !== id) {
      fail();
    }
    const expectedEvidence = (clientCredentialsCandidateInvariantIds as readonly string[]).includes(
      id
    )
      ? runClientCredentialsCandidateInvariantControls(
          id as (typeof clientCredentialsCandidateInvariantIds)[number],
          clientCredentialsCandidateInvariantExpectedProjection(
            id as (typeof clientCredentialsCandidateInvariantIds)[number]
          )
        )
      : runDeviceCandidateInvariantControls(
          id as (typeof deviceCandidateInvariantIds)[number],
          deviceCandidateInvariantExpectedProjection(
            id as (typeof deviceCandidateInvariantIds)[number]
          )
        );
    if (JSON.stringify(evidence) !== JSON.stringify(expectedEvidence)) {
      fail();
    }
  }
};

const assertWithBothSanitizers = (value: unknown): void => {
  assertClientCredentialsEvidenceIsSanitized(value);
  assertDeviceAuthorizationEvidenceIsSanitized(value);
};

export class Phase2SanitizerFailure extends TypeError {
  constructor(readonly stage: string) {
    super('Invalid Phase 2 evidence sanitizer');
  }
}

const assertSanitizedAt = (stage: string, check: () => void): void => {
  try {
    check();
  } catch {
    throw new Phase2SanitizerFailure(stage);
  }
};

export const assertPhase2TargetEvidenceIsSanitized = (value: unknown): void => {
  if (!exactKeys(value, ['target', 'scenarios', 'discovery', 'controls'])) {
    assertWithBothSanitizers(value);
    return;
  }
  const evidence = snapshotExactDataRecord(value, ['target', 'scenarios', 'discovery', 'controls']);
  const shared = [
    ['target', evidence.target],
    ['discovery', evidence.discovery],
    ['controls', evidence.controls],
  ] as const;
  for (const [stage, part] of shared) {
    assertSanitizedAt(stage, () => {
      assertWithBothSanitizers(part);
    });
  }
  const scenarios = (() => {
    try {
      const snapshot = snapshotDenseArray(evidence.scenarios, 161).map((entry) =>
        snapshotExactDataRecord(entry, ['id', 'projection'])
      );
      if (snapshot.some((entry) => typeof entry.id !== 'string')) {
        return fail();
      }
      return snapshot as Array<{ id: string; projection: unknown }>;
    } catch {
      throw new Phase2SanitizerFailure('ids');
    }
  })();
  assertSanitizedAt('ids', () => {
    assertDeviceAuthorizationEvidenceIsSanitized({
      scenarios: scenarios.map(({ id }) => id),
    });
  });
  for (const [index, scenario] of scenarios.entries()) {
    if ((deviceAuthorizationScenarioIds as readonly string[]).includes(scenario.id)) {
      assertSanitizedAt(`device-${index}`, () => {
        publishDeviceScenarioProjection(
          scenario.projection as DeviceScenarioProjection,
          scenario.id as DeviceAuthorizationScenarioId
        );
      });
    } else {
      assertSanitizedAt(`client-${index}`, () => {
        assertWithBothSanitizers(scenario.projection);
      });
    }
  }
};

const assertCandidateInvariantEvidenceIsSanitized = (value: unknown): void => {
  const payload = value as Record<string, unknown>;
  const invariants = payload.invariants as unknown[];
  assertWithBothSanitizers({ schemaVersion: payload.schemaVersion, mode: payload.mode });
  for (const invariant of invariants) {
    const id = (invariant as Record<string, unknown>).id as string;
    if ((clientCredentialsCandidateInvariantIds as readonly string[]).includes(id)) {
      assertClientCredentialsEvidenceIsSanitized(invariant);
    } else {
      assertDeviceAuthorizationEvidenceIsSanitized(invariant);
    }
  }
};

const snapshotCandidateInvariantPayload = (value: unknown): JsonValue => {
  try {
    const payload = snapshotExactDataRecord(value, ['schemaVersion', 'mode', 'invariants']);
    const invariants = snapshotDenseArray(
      payload.invariants,
      clientCredentialsCandidateInvariantIds.length + deviceCandidateInvariantIds.length
    ).map((entry) =>
      snapshotExactDataRecord(entry, ['id', 'candidate', 'positiveControl', 'negativeControl'])
    );
    return Object.freeze({
      schemaVersion: payload.schemaVersion,
      mode: payload.mode,
      invariants: Object.freeze(invariants),
    }) as unknown as JsonValue;
  } catch {
    return fail();
  }
};

const assertPhase2PayloadIsSanitized = (mode: Phase2EvidenceMode, value: unknown): void => {
  if (mode === 'candidate-invariants') {
    assertCandidateInvariantEvidenceIsSanitized(value);
    return;
  }
  if (exactKeys(value, ['schemaVersion', 'mode', 'target'])) {
    const payload = snapshotExactDataRecord(value, ['schemaVersion', 'mode', 'target']);
    assertWithBothSanitizers({ schemaVersion: payload.schemaVersion, mode: payload.mode });
    assertPhase2TargetEvidenceIsSanitized(payload.target);
    return;
  }
  if (exactKeys(value, ['schemaVersion', 'mode', 'oracle', 'candidate', 'comparisons'])) {
    const payload = snapshotExactDataRecord(value, [
      'schemaVersion',
      'mode',
      'oracle',
      'candidate',
      'comparisons',
    ]);
    assertWithBothSanitizers({
      schemaVersion: payload.schemaVersion,
      mode: payload.mode,
      comparisons: payload.comparisons,
    });
    assertPhase2TargetEvidenceIsSanitized(payload.oracle);
    assertPhase2TargetEvidenceIsSanitized(payload.candidate);
    return;
  }
  assertWithBothSanitizers(value);
};

export const createPhase2EvidenceEnvelope = (
  input: Readonly<{
    mode: Phase2EvidenceMode;
    profile: Phase2ProfileRegistries;
    harness: Phase2SourceIdentity;
    oracle?: Phase2TargetProvenance;
    candidate?: Phase2TargetProvenance;
    payload: JsonValue;
  }>
): Phase2EvidenceEnvelope => {
  const payload =
    input.mode === 'candidate-invariants'
      ? snapshotCandidateInvariantPayload(input.payload)
      : input.payload;
  if (input.mode === 'candidate-invariants') {
    validateCandidateInvariantPayload(payload, input.profile);
  }
  assertPhase2PayloadIsSanitized(input.mode, payload);
  const hash = /^[0-9a-f]{64}$/u;
  if (
    !input.profile.profileSha256 ||
    !hash.test(input.profile.profileSha256) ||
    !input.profile.schemaSha256 ||
    !hash.test(input.profile.schemaSha256) ||
    JSON.stringify(input.profile.baseAcceptance) !== JSON.stringify(phase2ExpectedBaseAcceptance) ||
    !exactKeys(input.harness.public, [
      'repositoryUrl',
      'headCommit',
      'headTree',
      'runtimeBundleSha256',
    ]) ||
    input.harness.public.repositoryUrl !== 'https://github.com/qq98982/logto.git' ||
    !commitPattern.test(input.harness.public.headCommit) ||
    !commitPattern.test(input.harness.public.headTree) ||
    !hash.test(input.harness.public.runtimeBundleSha256)
  ) {
    return fail();
  }
  if (input.oracle) {
    validateTarget(input.oracle);
  }
  if (input.candidate) {
    validateTarget(input.candidate);
  }
  const oracleValid =
    input.oracle?.sourceCommit === phase2OracleSourceCommit &&
    input.oracle.imageDigest === phase2OracleImageDigest;
  if (
    (input.mode === 'oracle' && (!oracleValid || input.candidate !== undefined)) ||
    (input.mode === 'differential' &&
      (!oracleValid ||
        input.candidate === undefined ||
        input.candidate.sourceCommit === input.oracle.sourceCommit ||
        input.candidate.imageDigest === input.oracle.imageDigest)) ||
    (input.mode === 'candidate-invariants' &&
      (input.oracle !== undefined || input.candidate === undefined))
  ) {
    return fail();
  }
  return Object.freeze({
    schemaVersion: 1,
    mode: input.mode,
    provenance: Object.freeze({
      profileSha256: input.profile.profileSha256,
      schemaSha256: input.profile.schemaSha256,
      baseAcceptance: input.profile.baseAcceptance,
      harness: input.harness.public,
      ...(input.oracle && { oracle: input.oracle }),
      ...(input.candidate && { candidate: input.candidate }),
    }),
    sanitizerSuccess: true,
    payload: snapshotJsonWire(payload),
  });
};

const validatePhase2OracleArtifactUnchecked = (
  value: unknown,
  profile: Phase2ProfileRegistries,
  harness: Phase2SourceIdentity
): Phase2EvidenceEnvelope => {
  const wire = snapshotClosedDataGraph<Phase2EvidenceEnvelope>(value);
  if (
    wire === undefined ||
    !jsonValueGuard.safeParse(wire).success ||
    !exactKeys(wire, ['schemaVersion', 'mode', 'provenance', 'sanitizerSuccess', 'payload'])
  ) {
    return fail();
  }
  const envelope = wire;
  if (
    envelope.schemaVersion !== 1 ||
    envelope.mode !== 'oracle' ||
    !envelope.sanitizerSuccess ||
    !exactKeys(envelope.provenance, [
      'profileSha256',
      'schemaSha256',
      'baseAcceptance',
      'harness',
      'oracle',
    ]) ||
    envelope.provenance.oracle === undefined
  ) {
    return fail();
  }
  const semanticPayload = restoreOracleWirePayload(envelope.payload);
  const canonical = createPhase2EvidenceEnvelope({
    mode: 'oracle',
    profile,
    harness,
    oracle: envelope.provenance.oracle,
    payload: semanticPayload,
  });
  if (JSON.stringify(canonical) !== JSON.stringify(envelope)) {
    return fail();
  }
  const payload = semanticPayload;
  if (!exactKeys(payload, ['schemaVersion', 'mode', 'target'])) {
    return fail();
  }
  const oraclePayload = payload as Record<string, unknown>;
  if (oraclePayload.schemaVersion !== 1 || oraclePayload.mode !== 'oracle') {
    return fail();
  }
  const { target } = oraclePayload;
  if (!exactKeys(target, ['target', 'scenarios', 'discovery', 'controls'])) {
    return fail();
  }
  const targetRecord = target as Record<string, unknown>;
  if (targetRecord.target !== 'oracle' || !Array.isArray(targetRecord.scenarios)) {
    return fail();
  }
  const scenarioIds = targetRecord.scenarios.map((entry) => {
    if (!exactKeys(entry, ['id', 'projection'])) {
      return fail();
    }
    const { id, projection } = entry as Record<string, unknown>;
    if (
      typeof id === 'string' &&
      (deviceAuthorizationScenarioIds as readonly string[]).includes(id)
    ) {
      publishDeviceScenarioProjection(
        projection as DeviceScenarioProjection,
        id as DeviceAuthorizationScenarioId
      );
    }
    return typeof id === 'string' ? id : fail();
  });
  if (
    scenarioIds.length !== profile.differentialScenarios.length ||
    new Set(scenarioIds).size !== scenarioIds.length ||
    scenarioIds.some((id, index) => id !== profile.differentialScenarios[index])
  ) {
    return fail();
  }
  assertPhase2PayloadIsSanitized(envelope.mode, payload);
  return snapshotClosedDataGraph<Phase2EvidenceEnvelope>({ ...envelope, payload }) ?? fail();
};

export const validatePhase2OracleArtifact = (
  value: unknown,
  profile: Phase2ProfileRegistries,
  harness: Phase2SourceIdentity
): Phase2EvidenceEnvelope => {
  try {
    return validatePhase2OracleArtifactUnchecked(value, profile, harness);
  } catch {
    return fail();
  }
};

/* eslint-enable complexity, max-lines, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/prefer-nullish-coalescing, no-restricted-syntax */
