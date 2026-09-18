/* eslint-disable complexity, max-lines, no-control-regex, no-restricted-syntax, unicorn/escape-case -- This authority boundary keeps descriptor validation, recursive snapshotting, and capability minting together for auditability. */
import path from 'node:path';
import { types as nodeTypes } from 'node:util';

import type { Phase1Profile } from '../profile-types.js';
import {
  assertAuthorizedPhase1Run,
  mintPhase1RunAuthorization,
  type Phase1RunAuthorization,
  type Phase1RunControls,
} from '../run-authorization.js';
import {
  assertValidatedPhase1EvidenceRuntimeContext,
  type Phase1EvidenceRuntimeContext,
} from '../snapshots/runtime-context.js';

export type Phase1ConformanceRuntimeContext = Readonly<{
  authorization: Phase1RunAuthorization;
  candidateImageDigest: string;
  oracleImageDigest?: string;
  evidenceDirectory: string;
  repositoryRoot: string;
  conformanceRoot: string;
}>;

export type CreatePhase1ConformanceGateRuntimeContextInput = Readonly<{
  authorization: Phase1RunAuthorization;
  candidateImageDigest: string;
  evidenceDirectory: string;
  repositoryRoot: string;
  conformanceRoot: string;
}>;

type CreatePhase1ConformanceRuntimeContextForTestingInput =
  CreatePhase1ConformanceGateRuntimeContextInput & Readonly<{ oracleImageDigest?: string }>;

const diagnostic = 'Invalid Phase 1 conformance runtime context';
const imageDigestPattern = /^sha256:[0-9a-f]{64}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const commitPattern = /^[0-9a-f]{40}$/u;
const safeTextPattern = /^[^\u0000-\u001f\u007f]+$/u;
const validatedContexts = new WeakSet<Record<string, unknown>>();
const authorizationKeys = Object.freeze([
  'mode',
  'profile',
  'profileSha256',
  'schemaSha256',
  'provenance',
  'protectedExecution',
  'controls',
] as const);
const gateAuthorizationKeys = Object.freeze([...authorizationKeys, 'conformanceGate'] as const);
const gateKeys = Object.freeze([
  'differentialGate',
  'candidateInvariantGate',
  'browserGate',
  'conformanceGate',
] as const);
const controlKeys = Object.freeze([
  'recordOracle',
  'observationControls',
  'discoveryExtraControl',
  'candidateInvariantControls',
] as const);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const dataRecord = (value: unknown): Readonly<Record<string, unknown>> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      return fail();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail();
    }
  }

  return value as Readonly<Record<string, unknown>>;
};

const exactRecord = (
  value: unknown,
  keys: readonly string[]
): Readonly<Record<string, unknown>> => {
  const record = dataRecord(value);
  const ownKeys = Reflect.ownKeys(record);

  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
  ) {
    return fail();
  }

  return record;
};

const ownValue = (value: Readonly<Record<string, unknown>>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const exactFrozenRecord = (
  value: unknown,
  keys: readonly string[]
): Readonly<Record<string, unknown>> => {
  const record = exactRecord(value, keys);

  return Object.isFrozen(record) ? record : fail();
};

const snapshotDataGraph = (
  value: unknown,
  visited: WeakSet<Record<PropertyKey, unknown>> = new WeakSet()
): unknown => {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  if (typeof value !== 'object' || nodeTypes.isProxy(value)) {
    return fail();
  }
  const source = value as Record<PropertyKey, unknown>;

  if (visited.has(source)) {
    return fail();
  }
  visited.add(source);
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      return fail();
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    const candidateLength: unknown = lengthDescriptor?.value;

    if (
      typeof candidateLength !== 'number' ||
      !Number.isSafeInteger(candidateLength) ||
      candidateLength < 0
    ) {
      return fail();
    }
    const length = candidateLength;
    const expectedKeys = [...Array.from({ length }, (_unused, index) => String(index)), 'length'];
    const ownKeys = Reflect.ownKeys(value);

    if (
      ownKeys.length !== expectedKeys.length ||
      ownKeys.some((key) => typeof key !== 'string' || !expectedKeys.includes(key))
    ) {
      return fail();
    }
    const snapshot = Array.from({ length }, (_unused, index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));

      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
        return fail();
      }

      const item: unknown = descriptor.value;

      return snapshotDataGraph(item, visited);
    });

    return Object.freeze(snapshot);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    return fail();
  }
  const entries = Reflect.ownKeys(value).map((key) => {
    if (typeof key !== 'string') {
      return fail();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail();
    }

    const item: unknown = descriptor.value;

    return [key, snapshotDataGraph(item, visited)] as const;
  });

  return Object.freeze(Object.fromEntries(entries));
};

const snapshotProfile = (value: unknown): Readonly<Phase1Profile> => {
  const snapshot = snapshotDataGraph(value);
  const profile = dataRecord(snapshot);
  const phase1Harness = ownValue(profile, 'phase1Harness');

  if (typeof phase1Harness !== 'object' || phase1Harness === null) {
    return fail();
  }
  const harnessRecord = phase1Harness as Readonly<Record<string, unknown>>;
  const harnessCommit = ownValue(harnessRecord, 'commit');

  if (typeof harnessCommit !== 'string' || !commitPattern.test(harnessCommit)) {
    return fail();
  }

  return snapshot as Readonly<Phase1Profile>;
};

const snapshotControls = (value: unknown): Phase1RunControls => {
  const source = exactFrozenRecord(value, controlKeys);
  const controls = Object.freeze({
    recordOracle: ownValue(source, 'recordOracle'),
    observationControls: ownValue(source, 'observationControls'),
    discoveryExtraControl: ownValue(source, 'discoveryExtraControl'),
    candidateInvariantControls: ownValue(source, 'candidateInvariantControls'),
  });

  if (
    typeof controls.recordOracle !== 'boolean' ||
    typeof controls.observationControls !== 'boolean' ||
    typeof controls.discoveryExtraControl !== 'boolean' ||
    typeof controls.candidateInvariantControls !== 'boolean'
  ) {
    return fail();
  }

  return controls as Phase1RunControls;
};

const snapshotProvenance = (value: unknown) => {
  const source = dataRecord(value);
  const candidate = exactRecord(
    source,
    Object.hasOwn(source, 'protectedBranch')
      ? ['kind', 'harnessCommit', 'protectedBranch', 'pullRequestNumber', 'publishable']
      : ['kind', 'harnessCommit', 'publishable']
  );

  if (!Object.isFrozen(candidate)) {
    return fail();
  }
  const kind = ownValue(candidate, 'kind');
  const harnessCommit = ownValue(candidate, 'harnessCommit');
  const publishable = ownValue(candidate, 'publishable');

  if (typeof harnessCommit !== 'string' || !commitPattern.test(harnessCommit)) {
    return fail();
  }
  if (kind === 'review-candidate' && publishable === false) {
    return Object.freeze({ kind, harnessCommit, publishable });
  }
  const protectedBranch = ownValue(candidate, 'protectedBranch');
  const pullRequestNumber = ownValue(candidate, 'pullRequestNumber');

  if (
    kind !== 'accepted-harness' ||
    publishable !== true ||
    typeof protectedBranch !== 'string' ||
    protectedBranch.length === 0 ||
    !Number.isSafeInteger(pullRequestNumber) ||
    (pullRequestNumber as number) <= 0
  ) {
    return fail();
  }

  return Object.freeze({
    kind,
    harnessCommit,
    protectedBranch,
    pullRequestNumber: pullRequestNumber as number,
    publishable,
  });
};

const snapshotAuthorization = (value: unknown): Phase1RunAuthorization => {
  assertAuthorizedPhase1Run(value);
  const source = dataRecord(value);
  const shape = exactRecord(
    source,
    Object.hasOwn(source, 'conformanceGate') ? gateAuthorizationKeys : authorizationKeys
  );

  if (!Object.isFrozen(shape)) {
    return fail();
  }
  const hasConformanceGate = Object.hasOwn(shape, 'conformanceGate');

  if (
    gateKeys.some((key) => key !== 'conformanceGate' && key in (value as Record<string, unknown>))
  ) {
    return fail();
  }
  const mode = ownValue(shape, 'mode');
  const profile = snapshotProfile(ownValue(shape, 'profile'));
  const profileSha256 = ownValue(shape, 'profileSha256');
  const schemaSha256 = ownValue(shape, 'schemaSha256');
  const sourceProvenance = ownValue(shape, 'provenance');
  const provenance = snapshotProvenance(sourceProvenance);
  const controls = snapshotControls(ownValue(shape, 'controls'));
  const protectedExecutionSource = ownValue(shape, 'protectedExecution');

  if (
    typeof profileSha256 !== 'string' ||
    !sha256Pattern.test(profileSha256) ||
    typeof schemaSha256 !== 'string' ||
    !sha256Pattern.test(schemaSha256) ||
    provenance.harnessCommit !== profile.phase1Harness.commit
  ) {
    return fail();
  }
  if (hasConformanceGate) {
    if (
      mode !== 'runtime-candidate' ||
      ownValue(shape, 'conformanceGate') !== true ||
      protectedExecutionSource !== undefined ||
      provenance.kind !== 'review-candidate' ||
      controls.recordOracle ||
      !controls.observationControls ||
      !controls.discoveryExtraControl ||
      !controls.candidateInvariantControls
    ) {
      return fail();
    }
    return mintPhase1RunAuthorization(
      Object.freeze({
        mode,
        profile,
        profileSha256,
        schemaSha256,
        provenance,
        protectedExecution: undefined,
        controls,
        conformanceGate: true as const,
      })
    );
  }
  if (mode === 'review-candidate') {
    if (protectedExecutionSource !== undefined || provenance.kind !== 'review-candidate') {
      return fail();
    }
    return mintPhase1RunAuthorization(
      Object.freeze({
        mode,
        profile,
        profileSha256,
        schemaSha256,
        provenance,
        protectedExecution: undefined,
        controls,
      })
    );
  }
  if (mode !== 'mirror-control' || provenance.kind !== 'accepted-harness') {
    return fail();
  }
  const protectedExecution = exactFrozenRecord(protectedExecutionSource, ['mode', 'provenance']);

  if (
    ownValue(protectedExecution, 'mode') !== mode ||
    ownValue(protectedExecution, 'provenance') !== sourceProvenance
  ) {
    return fail();
  }

  return mintPhase1RunAuthorization(
    Object.freeze({
      mode,
      profile,
      profileSha256,
      schemaSha256,
      provenance,
      protectedExecution: Object.freeze({ mode, provenance }),
      controls,
    })
  );
};

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

const absolutePath = (value: unknown): string => {
  const resolved = safeText(value);

  return path.isAbsolute(resolved) && path.resolve(resolved) === resolved ? resolved : fail();
};

const contextFrom = ({
  authorization,
  candidateImageDigest,
  evidenceDirectory,
  repositoryRoot,
  conformanceRoot,
  oracleImageDigest,
}: Readonly<{
  authorization: Phase1RunAuthorization;
  candidateImageDigest: unknown;
  evidenceDirectory: unknown;
  repositoryRoot: unknown;
  conformanceRoot: unknown;
  oracleImageDigest?: unknown;
}>): Phase1ConformanceRuntimeContext => {
  const candidateDigest = safeText(candidateImageDigest);

  if (!imageDigestPattern.test(candidateDigest)) {
    return fail();
  }
  const oracleDigest = oracleImageDigest === undefined ? undefined : safeText(oracleImageDigest);

  if (oracleDigest !== undefined && !imageDigestPattern.test(oracleDigest)) {
    return fail();
  }
  const context = Object.freeze({
    authorization,
    candidateImageDigest: candidateDigest,
    ...(oracleDigest === undefined ? {} : { oracleImageDigest: oracleDigest }),
    evidenceDirectory: absolutePath(evidenceDirectory),
    repositoryRoot: absolutePath(repositoryRoot),
    conformanceRoot: absolutePath(conformanceRoot),
  });

  validatedContexts.add(context);
  return context;
};

export const createPhase1ConformanceGateRuntimeContext = (
  input: CreatePhase1ConformanceGateRuntimeContextInput
): Phase1ConformanceRuntimeContext => {
  try {
    const source = exactRecord(input, [
      'authorization',
      'candidateImageDigest',
      'evidenceDirectory',
      'repositoryRoot',
      'conformanceRoot',
    ]);
    const authorization = snapshotAuthorization(ownValue(source, 'authorization'));

    if (authorization.conformanceGate !== true) {
      return fail();
    }
    return contextFrom({
      authorization,
      candidateImageDigest: ownValue(source, 'candidateImageDigest'),
      evidenceDirectory: ownValue(source, 'evidenceDirectory'),
      repositoryRoot: ownValue(source, 'repositoryRoot'),
      conformanceRoot: ownValue(source, 'conformanceRoot'),
    });
  } catch {
    return fail();
  }
};

export const createPhase1ConformanceRuntimeContextFromEvidence = (
  source: Phase1EvidenceRuntimeContext
): Phase1ConformanceRuntimeContext => {
  try {
    assertValidatedPhase1EvidenceRuntimeContext(source);
    const authorization = snapshotAuthorization(source.authorization);

    if (authorization.mode !== 'review-candidate' && authorization.mode !== 'mirror-control') {
      return fail();
    }

    return contextFrom({
      authorization,
      candidateImageDigest: source.candidateImageDigest,
      evidenceDirectory: source.evidenceDirectory,
      repositoryRoot: source.repositoryRoot,
      conformanceRoot: source.conformanceRoot,
      oracleImageDigest: source.oracleImageDigest,
    });
  } catch {
    return fail();
  }
};

export const createPhase1ConformanceRuntimeContextForTesting = (
  input: CreatePhase1ConformanceRuntimeContextForTestingInput
): Phase1ConformanceRuntimeContext => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }
  try {
    const hasOracleDigest = Object.hasOwn(input, 'oracleImageDigest');
    const source = exactRecord(
      input,
      hasOracleDigest
        ? [
            'authorization',
            'candidateImageDigest',
            'oracleImageDigest',
            'evidenceDirectory',
            'repositoryRoot',
            'conformanceRoot',
          ]
        : [
            'authorization',
            'candidateImageDigest',
            'evidenceDirectory',
            'repositoryRoot',
            'conformanceRoot',
          ]
    );
    const authorization = snapshotAuthorization(ownValue(source, 'authorization'));

    if (
      (authorization.mode === 'runtime-candidate' && hasOracleDigest) ||
      (authorization.mode !== 'runtime-candidate' && !hasOracleDigest)
    ) {
      return fail();
    }

    return contextFrom({
      authorization,
      candidateImageDigest: ownValue(source, 'candidateImageDigest'),
      evidenceDirectory: ownValue(source, 'evidenceDirectory'),
      repositoryRoot: ownValue(source, 'repositoryRoot'),
      conformanceRoot: ownValue(source, 'conformanceRoot'),
      oracleImageDigest: ownValue(source, 'oracleImageDigest'),
    });
  } catch {
    return fail();
  }
};

export function assertValidatedPhase1ConformanceRuntimeContext(
  value: unknown
): asserts value is Phase1ConformanceRuntimeContext {
  if (
    typeof value !== 'object' ||
    value === null ||
    !validatedContexts.has(value as Record<string, unknown>)
  ) {
    return fail();
  }
}

/* eslint-enable complexity, max-lines, no-control-regex, no-restricted-syntax, unicorn/escape-case */
