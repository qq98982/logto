/* eslint-disable complexity, max-lines, no-control-regex, no-restricted-syntax, unicorn/escape-case, @typescript-eslint/no-unsafe-assignment -- This composition boundary closes authorization, paths, target topology, and non-secret isolation attestations before any live adapter runs; the guarded runtime narrowing requires explicit casts and control-character rejection. */
import path from 'node:path';
import { types as nodeTypes } from 'node:util';

import { validateTargetConfig } from '../../config.js';
import type { TargetConfig } from '../../model.js';
import type { Phase1FixtureIsolation } from '../fixture-map.js';
import { assertPhase1RuntimeCredentialGraphIsSanitized } from '../fixtures.js';
import {
  authorizePhase1ProtectedExecution,
  type Phase1ProtectedExecutionMode,
  type Phase1ProvenanceResult,
} from '../profile-semantics.js';
import { assertAuthorizedPhase1Run, type Phase1RunAuthorization } from '../run-authorization.js';

type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;
type ImplementationLabel = TargetConfig['label'];

export type Phase1RuntimeTargetGraph = Readonly<
  Record<
    ImplementationLabel,
    Readonly<{
      primary: TargetConfig;
      foreign: TargetConfig;
    }>
  >
>;

export type Phase1RuntimeImplementationIsolation = Readonly<{
  data: Phase1FixtureIsolation;
  admin: Phase1FixtureIsolation;
  foreign: Phase1FixtureIsolation;
}>;

export type Phase1RuntimeIsolationAttestations = Readonly<
  Record<ImplementationLabel, Phase1RuntimeImplementationIsolation>
>;

export type Phase1EvidenceRuntimeContext = Readonly<{
  authorization: Phase1RunAuthorization;
  oracleImageDigest: string;
  candidateImageDigest: string;
  evidenceDirectory: string;
  oracleSnapshotPath: string;
  repositoryRoot: string;
  conformanceRoot: string;
  targets: Phase1RuntimeTargetGraph;
  isolationAttestations: Phase1RuntimeIsolationAttestations;
}>;

export type CreatePhase1EvidenceRuntimeContextInput = Readonly<{
  authorization: Phase1RunAuthorization;
  oracleImageDigest: string;
  candidateImageDigest: string;
  evidenceDirectory: string;
  oracleSnapshotPath: string;
  repositoryRoot: string;
  conformanceRoot: string;
  isolationAttestations: Phase1RuntimeIsolationAttestations;
}>;

export type Phase1RuntimeContextDependencies = Readonly<{
  authorizeProtectedExecution: (
    mode: Phase1ProtectedExecutionMode,
    provenance: Phase1ProvenanceResult
  ) => Readonly<{
    mode: Phase1ProtectedExecutionMode;
    provenance: Phase1ProvenanceResult;
  }>;
  assertRunAuthorization(value: unknown): asserts value is Phase1RunAuthorization;
}>;

const diagnostic = 'Invalid Phase 1 evidence runtime context';
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const commitPattern = /^[0-9a-f]{40}$/u;
const safeTextPattern = /^[^\u0000-\u001f\u007f]+$/u;

const targetVariables = Object.freeze({
  oracle: Object.freeze({
    primary: Object.freeze({
      core: 'ASTER_PHASE1_ORACLE_URL',
      admin: 'ASTER_PHASE1_ORACLE_ADMIN_URL',
    }),
    foreign: Object.freeze({
      core: 'ASTER_PHASE1_ORACLE_FOREIGN_URL',
      admin: 'ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL',
    }),
  }),
  candidate: Object.freeze({
    primary: Object.freeze({
      core: 'ASTER_PHASE1_CANDIDATE_URL',
      admin: 'ASTER_PHASE1_CANDIDATE_ADMIN_URL',
    }),
    foreign: Object.freeze({
      core: 'ASTER_PHASE1_CANDIDATE_FOREIGN_URL',
      admin: 'ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL',
    }),
  }),
} as const);
const defaultDependencies: Phase1RuntimeContextDependencies = Object.freeze({
  assertRunAuthorization: assertAuthorizedPhase1Run,
  authorizeProtectedExecution: authorizePhase1ProtectedExecution,
});
const validatedRuntimeContexts = new WeakSet<Record<string, unknown>>();

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const exactRecord = (
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

  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
  ) {
    return fail();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail();
    }
  }

  return value as Readonly<Record<string, unknown>>;
};

const ownValue = (value: Readonly<Record<string, unknown>>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const safeText = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 1024 ||
    !safeTextPattern.test(value)
  ) {
    return fail();
  }

  return value;
};

const requireAbsolutePath = (value: unknown): string => {
  const resolved = safeText(value);

  if (!path.isAbsolute(resolved) || path.resolve(resolved) !== resolved) {
    return fail();
  }

  return resolved;
};

const environmentValue = (environment: RuntimeEnvironment, key: string): string => {
  const value = environment[key];

  return value === undefined ? fail() : safeText(value);
};

const targetFrom = (
  label: ImplementationLabel,
  variables: Readonly<{ core: string; admin: string }>,
  environment: RuntimeEnvironment
): TargetConfig => {
  try {
    return validateTargetConfig({
      label,
      coreUrl: environmentValue(environment, variables.core),
      adminUrl: environmentValue(environment, variables.admin),
    });
  } catch {
    return fail();
  }
};

export const loadPhase1RuntimeTargetGraph = (
  environment: RuntimeEnvironment = process.env
): Phase1RuntimeTargetGraph => {
  try {
    const targets = Object.freeze({
      oracle: Object.freeze({
        primary: targetFrom('oracle', targetVariables.oracle.primary, environment),
        foreign: targetFrom('oracle', targetVariables.oracle.foreign, environment),
      }),
      candidate: Object.freeze({
        primary: targetFrom('candidate', targetVariables.candidate.primary, environment),
        foreign: targetFrom('candidate', targetVariables.candidate.foreign, environment),
      }),
    });
    const origins = [
      targets.oracle.primary.coreUrl,
      targets.oracle.primary.adminUrl,
      targets.oracle.foreign.coreUrl,
      targets.oracle.foreign.adminUrl,
      targets.candidate.primary.coreUrl,
      targets.candidate.primary.adminUrl,
      targets.candidate.foreign.coreUrl,
      targets.candidate.foreign.adminUrl,
    ].map((value) => new URL(value).origin);

    if (new Set(origins).size !== origins.length) {
      return fail();
    }
    assertPhase1RuntimeCredentialGraphIsSanitized(targets);

    return targets;
  } catch {
    return fail();
  }
};

const isolationValue = (value: unknown): Phase1FixtureIsolation => {
  const record = exactRecord(value, ['persistenceId', 'cookieKeyId', 'signingKeyId']);
  const result = Object.freeze({
    persistenceId: safeText(ownValue(record, 'persistenceId')),
    cookieKeyId: safeText(ownValue(record, 'cookieKeyId')),
    signingKeyId: safeText(ownValue(record, 'signingKeyId')),
  });

  if (new Set(Object.values(result)).size !== 3) {
    return fail();
  }

  return result;
};

const implementationIsolation = (value: unknown): Phase1RuntimeImplementationIsolation => {
  const record = exactRecord(value, ['data', 'admin', 'foreign']);

  return Object.freeze({
    data: isolationValue(ownValue(record, 'data')),
    admin: isolationValue(ownValue(record, 'admin')),
    foreign: isolationValue(ownValue(record, 'foreign')),
  });
};

const isolationAttestations = (value: unknown): Phase1RuntimeIsolationAttestations => {
  const record = exactRecord(value, ['oracle', 'candidate']);
  const attestations = Object.freeze({
    oracle: implementationIsolation(ownValue(record, 'oracle')),
    candidate: implementationIsolation(ownValue(record, 'candidate')),
  });

  for (const implementation of [attestations.oracle, attestations.candidate]) {
    if (
      implementation.data.persistenceId !== implementation.admin.persistenceId ||
      implementation.foreign.persistenceId === implementation.data.persistenceId
    ) {
      return fail();
    }
  }
  const allIdentifiers = [attestations.oracle, attestations.candidate].flatMap(
    ({ data, admin, foreign }) => [
      data.persistenceId,
      data.cookieKeyId,
      data.signingKeyId,
      admin.persistenceId,
      admin.cookieKeyId,
      admin.signingKeyId,
      foreign.persistenceId,
      foreign.cookieKeyId,
      foreign.signingKeyId,
    ]
  );

  // Each implementation deliberately repeats only its primary persistence identity for data/admin.
  if (new Set(allIdentifiers).size !== allIdentifiers.length - 2) {
    return fail();
  }
  assertPhase1RuntimeCredentialGraphIsSanitized(attestations);

  return attestations;
};

const assertAcceptedAuthorization = (
  value: Phase1RunAuthorization,
  dependencies: Phase1RuntimeContextDependencies
): void => {
  dependencies.assertRunAuthorization(value);
  const runtimeGateKeys = (
    ['differentialGate', 'candidateInvariantGate', 'browserGate', 'conformanceGate'] as const
  ).filter((key) => Object.hasOwn(value, key));
  const runtimeGateKey = runtimeGateKeys[0];
  const runtimeGate = runtimeGateKey !== undefined;
  if (runtimeGateKeys.length > 1) {
    return fail();
  }
  const authorization = exactRecord(
    value,
    runtimeGate
      ? [
          'mode',
          'profile',
          'profileSha256',
          'schemaSha256',
          'provenance',
          'protectedExecution',
          'controls',
          runtimeGateKey,
        ]
      : [
          'mode',
          'profile',
          'profileSha256',
          'schemaSha256',
          'provenance',
          'protectedExecution',
          'controls',
        ]
  );
  const mode = ownValue(authorization, 'mode');
  const profile = ownValue(authorization, 'profile');
  const provenance = ownValue(authorization, 'provenance');
  const protectedExecution = ownValue(authorization, 'protectedExecution');

  if (
    (mode !== 'review-candidate' && mode !== 'mirror-control' && mode !== 'runtime-candidate') ||
    typeof profile !== 'object' ||
    profile === null ||
    typeof provenance !== 'object' ||
    provenance === null ||
    typeof ownValue(authorization, 'profileSha256') !== 'string' ||
    !sha256Pattern.test(ownValue(authorization, 'profileSha256') as string) ||
    typeof ownValue(authorization, 'schemaSha256') !== 'string' ||
    !sha256Pattern.test(ownValue(authorization, 'schemaSha256') as string)
  ) {
    return fail();
  }
  const harness = Reflect.get(profile, 'phase1Harness') as unknown;
  const harnessCommit =
    typeof harness === 'object' && harness !== null ? Reflect.get(harness, 'commit') : undefined;
  const provenanceCommit = Reflect.get(provenance, 'harnessCommit') as unknown;

  if (
    typeof harnessCommit !== 'string' ||
    !commitPattern.test(harnessCommit) ||
    provenanceCommit !== harnessCommit
  ) {
    return fail();
  }
  if (runtimeGate) {
    if (
      ownValue(authorization, runtimeGateKey) !== true ||
      mode !== 'runtime-candidate' ||
      protectedExecution !== undefined ||
      Reflect.get(provenance, 'kind') !== 'review-candidate' ||
      Reflect.get(provenance, 'publishable') !== false
    ) {
      return fail();
    }
    return;
  }
  if (mode === 'review-candidate') {
    if (
      protectedExecution !== undefined ||
      Reflect.get(provenance, 'kind') !== 'review-candidate' ||
      Reflect.get(provenance, 'publishable') !== false
    ) {
      return fail();
    }
    return;
  }
  const accepted = dependencies.authorizeProtectedExecution(
    mode,
    provenance as Phase1ProvenanceResult
  );

  if (
    typeof protectedExecution !== 'object' ||
    protectedExecution === null ||
    Reflect.get(protectedExecution, 'mode') !== mode ||
    Reflect.get(protectedExecution, 'provenance') !== provenance ||
    accepted.mode !== mode ||
    accepted.provenance !== provenance ||
    Reflect.get(provenance, 'kind') !== 'accepted-harness' ||
    Reflect.get(provenance, 'publishable') !== true
  ) {
    return fail();
  }
};

const createRuntimeContext = (
  input: CreatePhase1EvidenceRuntimeContextInput,
  environment: RuntimeEnvironment,
  dependencies: Phase1RuntimeContextDependencies
): Phase1EvidenceRuntimeContext => {
  try {
    const source = exactRecord(input, [
      'authorization',
      'oracleImageDigest',
      'candidateImageDigest',
      'evidenceDirectory',
      'oracleSnapshotPath',
      'repositoryRoot',
      'conformanceRoot',
      'isolationAttestations',
    ]);
    const authorization = ownValue(source, 'authorization') as Phase1RunAuthorization;
    const oracleImageDigest = safeText(ownValue(source, 'oracleImageDigest'));
    const candidateImageDigest = safeText(ownValue(source, 'candidateImageDigest'));

    assertAcceptedAuthorization(authorization, dependencies);
    if (
      !imageDigestPattern.test(oracleImageDigest) ||
      !imageDigestPattern.test(candidateImageDigest) ||
      (authorization.mode === 'mirror-control' && oracleImageDigest !== candidateImageDigest)
    ) {
      return fail();
    }

    const context = Object.freeze({
      authorization,
      oracleImageDigest,
      candidateImageDigest,
      evidenceDirectory: requireAbsolutePath(ownValue(source, 'evidenceDirectory')),
      oracleSnapshotPath: requireAbsolutePath(ownValue(source, 'oracleSnapshotPath')),
      repositoryRoot: requireAbsolutePath(ownValue(source, 'repositoryRoot')),
      conformanceRoot: requireAbsolutePath(ownValue(source, 'conformanceRoot')),
      targets: loadPhase1RuntimeTargetGraph(environment),
      isolationAttestations: isolationAttestations(ownValue(source, 'isolationAttestations')),
    });
    validatedRuntimeContexts.add(context);

    return context;
  } catch {
    return fail();
  }
};

export function assertValidatedPhase1EvidenceRuntimeContext(
  value: unknown
): asserts value is Phase1EvidenceRuntimeContext {
  if (
    typeof value !== 'object' ||
    value === null ||
    !validatedRuntimeContexts.has(value as Record<string, unknown>)
  ) {
    return fail();
  }
}

export const createPhase1EvidenceRuntimeContext = (
  input: CreatePhase1EvidenceRuntimeContextInput,
  environment: RuntimeEnvironment = process.env
): Phase1EvidenceRuntimeContext => createRuntimeContext(input, environment, defaultDependencies);

/** Test-only authority boundary. Production always re-enters the accepted-provenance WeakSet. */
export const createPhase1EvidenceRuntimeContextForTesting = (
  input: CreatePhase1EvidenceRuntimeContextInput,
  environment: RuntimeEnvironment,
  dependencies: Phase1RuntimeContextDependencies
): Phase1EvidenceRuntimeContext => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return createRuntimeContext(input, environment, dependencies);
};

/* eslint-enable complexity, max-lines, no-control-regex, no-restricted-syntax, unicorn/escape-case, @typescript-eslint/no-unsafe-assignment */
