/* eslint-disable complexity, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/prefer-nullish-coalescing -- Closed nested provenance validation intentionally checks every optional mode branch. */
import type { JsonValue } from '../normalize.js';

import type { Phase2ProfileRegistries } from './profile.js';
import { phase2ExpectedBaseAcceptance } from './profile.js';
import { assertClientCredentialsEvidenceIsSanitized } from './projections/client-credentials.js';
import {
  phase2OracleImageDigest,
  phase2OracleSourceCommit,
  type Phase2PublicHarnessProvenance,
  type Phase2SourceIdentity,
} from './provenance.js';

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
  assertClientCredentialsEvidenceIsSanitized(input.payload);
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
    payload: input.payload,
  });
};

/* eslint-enable complexity, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/prefer-nullish-coalescing */
