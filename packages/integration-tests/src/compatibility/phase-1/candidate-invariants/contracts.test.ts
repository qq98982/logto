/* eslint-disable @silverhand/fp/no-mutation, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-assertions -- Contract controls intentionally inject forbidden vocabulary and recursively inspect mixed object/array graphs. */
import { assertEvidenceIsSanitized } from '../../evidence.js';
import {
  candidateInvariantContractGuard,
  candidateInvariantNegativeControlPointers,
  candidateInvariantScenarioIds,
  defineCandidateInvariant,
  type CandidateInvariantContract,
} from '../model.js';

import { databaseOwnerRoleMembershipBoundary } from './database-owner-role-membership-boundary.js';
import { hostsUnavailablePkceIndependent } from './hosts-unavailable-pkce-independent.js';
import { candidateInvariantContracts } from './index.js';
import { keystoreForcedRlsOwnerBoundary } from './keystore-forced-rls-owner-boundary.js';
import { keystoreLiveLedgerLimitAndTombstone } from './keystore-live-ledger-limit-and-tombstone.js';
import { keystoreMetadataDmlBoundary } from './keystore-metadata-dml-boundary.js';
import { keystoreReferenceCountLedger } from './keystore-reference-count-ledger.js';
import { keystoreReferenceLedgerVerifierBoundary } from './keystore-reference-ledger-verifier-boundary.js';
import { keystoreRequiredReadableKeySet } from './keystore-required-readable-key-set.js';
import { keystoreSignSealDuringRewrap } from './keystore-sign-seal-during-rewrap.js';
import { keystoreStaleKeyringRejoinRejected } from './keystore-stale-keyring-rejoin-rejected.js';
import { keystoreUnwrapFailureRollsBackCode } from './keystore-unwrap-failure-rolls-back-code.js';
import { keystoreWrappingFenceLateCommit } from './keystore-wrapping-fence-late-commit.js';
import { reaperActivityVisibilityRedaction } from './reaper-activity-visibility-redaction.js';
import { reaperObjectAuditDisabled } from './reaper-object-audit-disabled.js';
import { tenantAdminOperationBinding } from './tenant-admin-operation-binding.js';
import { tenantAdminOperationStatusMatrix } from './tenant-admin-operation-status-matrix.js';
import { tenantCrossTenantReadRejected } from './tenant-cross-tenant-read-rejected.js';
import { tenantSuspendedEpochRejected } from './tenant-suspended-epoch-rejected.js';

const expectedModules = [
  ['tenant-cross-tenant-read-rejected.ts', tenantCrossTenantReadRejected],
  ['tenant-suspended-epoch-rejected.ts', tenantSuspendedEpochRejected],
  ['tenant-admin-operation-binding.ts', tenantAdminOperationBinding],
  ['tenant-admin-operation-status-matrix.ts', tenantAdminOperationStatusMatrix],
  ['database-owner-role-membership-boundary.ts', databaseOwnerRoleMembershipBoundary],
  ['reaper-activity-visibility-redaction.ts', reaperActivityVisibilityRedaction],
  ['reaper-object-audit-disabled.ts', reaperObjectAuditDisabled],
  ['keystore-unwrap-failure-rolls-back-code.ts', keystoreUnwrapFailureRollsBackCode],
  ['keystore-wrapping-fence-late-commit.ts', keystoreWrappingFenceLateCommit],
  ['keystore-sign-seal-during-rewrap.ts', keystoreSignSealDuringRewrap],
  ['keystore-metadata-dml-boundary.ts', keystoreMetadataDmlBoundary],
  ['keystore-forced-rls-owner-boundary.ts', keystoreForcedRlsOwnerBoundary],
  ['keystore-reference-count-ledger.ts', keystoreReferenceCountLedger],
  ['keystore-reference-ledger-verifier-boundary.ts', keystoreReferenceLedgerVerifierBoundary],
  ['keystore-live-ledger-limit-and-tombstone.ts', keystoreLiveLedgerLimitAndTombstone],
  ['keystore-stale-keyring-rejoin-rejected.ts', keystoreStaleKeyringRejoinRejected],
  ['keystore-required-readable-key-set.ts', keystoreRequiredReadableKeySet],
  ['hosts-unavailable-pkce-independent.ts', hostsUnavailablePkceIndependent],
] as const;

const record = (value: unknown): Readonly<Record<string, unknown>> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('Expected candidate invariant object projection');
  }

  return value as Readonly<Record<string, unknown>>;
};

const list = (value: unknown): readonly unknown[] => {
  if (!Array.isArray(value)) {
    throw new TypeError('Expected candidate invariant array projection');
  }

  return value;
};

const projectionFor = (id: (typeof candidateInvariantScenarioIds)[number]) => {
  const contract = candidateInvariantContracts.find((candidate) => candidate.id === id);

  if (!contract) {
    throw new TypeError('Candidate invariant contract is missing');
  }

  return record(contract.positiveControl.expectedProjection);
};

const recursivelyFrozen = (value: unknown, visited: WeakSet<object> = new WeakSet()): boolean => {
  if (typeof value !== 'object' || value === null) {
    return true;
  }
  if (visited.has(value)) {
    return true;
  }
  visited.add(value);

  return (
    Object.isFrozen(value) &&
    Reflect.ownKeys(value).every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);

      return Boolean(
        descriptor &&
          Object.hasOwn(descriptor, 'value') &&
          recursivelyFrozen(descriptor.value, visited)
      );
    })
  );
};

describe('phase 1 candidate invariant contracts', () => {
  it('locks the exact filename export ID and negative-pointer mappings', () => {
    expect(expectedModules.map(([, contract]) => contract)).toEqual(candidateInvariantContracts);
    expect(expectedModules.map(([filename]) => filename)).toHaveLength(18);
    expect(candidateInvariantContracts.map(({ id }) => id)).toEqual(candidateInvariantScenarioIds);
    expect(
      candidateInvariantContracts.map(
        ({ negativeControl }) => negativeControl.expectedDifferencePointer
      )
    ).toEqual(candidateInvariantNegativeControlPointers);
  });

  it('keeps every contract concrete closed sanitized and recursively frozen', () => {
    for (const contract of candidateInvariantContracts) {
      expect(candidateInvariantContractGuard.safeParse(contract).success).toBe(true);
      expect(contract.positiveControl.kind).toBe('positive');
      expect(contract.positiveControl.expectedDifferencePointer).toBeNull();
      expect(contract.negativeControl.kind).toBe('negative');
      expect(contract.negativeControl.expectedDifferencePointer).not.toBeNull();
      expect(Object.keys(contract.livePrecondition).length).toBeGreaterThan(0);
      expect(Object.keys(contract.perturbation).length).toBeGreaterThan(0);
      expect(Object.keys(contract.cleanup).length).toBeGreaterThan(0);
      expect(Object.keys(contract.sanitizedProjection).length).toBeGreaterThan(0);
      expect(recursivelyFrozen(contract)).toBe(true);
      expect(() => {
        assertEvidenceIsSanitized(contract);
      }).not.toThrow();
    }
  });

  it.each(['oracle', 'candidate', 'differences', 'compare', 'oracleComparison'] as const)(
    'rejects recursively nested %s vocabulary with the fixed contract diagnostic',
    (field) => {
      const canonical = candidateInvariantContracts[0];
      const invalid = {
        ...canonical,
        livePrecondition: { ...canonical.livePrecondition, nested: { [field]: true } },
      } as unknown as CandidateInvariantContract;

      expect(() => defineCandidateInvariant(invalid)).toThrow(
        /^Invalid phase 1 candidate invariant contract$/u
      );
    }
  );

  it('clones input graphs so later caller mutation cannot alter a contract', () => {
    const source = {
      ...candidateInvariantContracts[0],
      livePrecondition: { kind: 'mutable-source' },
    } as CandidateInvariantContract;
    const defined = defineCandidateInvariant(source);
    (source.livePrecondition as Record<string, unknown>).kind = 'changed-after-definition';

    expect(defined.livePrecondition).toEqual({ kind: 'mutable-source' });
  });

  it('locks redacted request and worker reaper observations', () => {
    const projection = projectionFor('reaper.activity-visibility-redaction');
    const observations = list(projection.observations).map((observation) => record(observation));

    expect(observations.map(({ roleClass }) => roleClass)).toEqual(['request', 'worker']);
    expect(observations).toEqual([
      {
        roleClass: 'request',
        backendClass: 'client',
        stateClass: 'in-transaction',
        timingClass: 'overdue',
        terminated: true,
      },
      {
        roleClass: 'worker',
        backendClass: 'client',
        stateClass: 'in-transaction',
        timingClass: 'overdue',
        terminated: true,
      },
    ]);
    expect(projection.summary).toEqual({ eligible: 2, terminated: 2, missed: 0 });
    expect(reaperActivityVisibilityRedaction.expectedPublicOutcome).toEqual({
      boundedObservationCount: 2,
      terminatedCount: 2,
      sentinelMatches: 0,
    });
  });

  it('locks the bounded reference-ledger verifier case matrix', () => {
    const verifier = record(projectionFor('keystore.reference-ledger-verifier-boundary').verifier);
    const cases = list(verifier.cases).map((candidate) => record(candidate));

    expect(verifier).toMatchObject({
      fenceHeld: true,
      deploymentMatched: true,
      maximumEntries: 32,
      mismatchCount: 0,
      disclosedTenantIds: [],
      dmlCount: 0,
    });
    expect(cases.map(({ caseClass }) => caseClass)).toEqual([
      'successful-admin',
      'non-admin-denial',
      'oversized-denial',
      'malformed-denial',
      'runtime-role-denial',
    ]);
    expect(cases).toEqual([
      {
        caseClass: 'successful-admin',
        callerClass: 'aster-admin',
        inputClass: 'sorted-unique-bounded',
        inputCount: 2,
        resultClass: 'matched',
        denialClass: null,
      },
      {
        caseClass: 'non-admin-denial',
        callerClass: 'non-admin',
        inputClass: 'sorted-unique-bounded',
        inputCount: 2,
        resultClass: 'denied',
        denialClass: 'caller-not-admin',
      },
      {
        caseClass: 'oversized-denial',
        callerClass: 'aster-admin',
        inputClass: 'oversized',
        inputCount: 33,
        resultClass: 'denied',
        denialClass: 'input-too-large',
      },
      {
        caseClass: 'malformed-denial',
        callerClass: 'aster-admin',
        inputClass: 'malformed',
        inputCount: 2,
        resultClass: 'denied',
        denialClass: 'input-malformed',
      },
      {
        caseClass: 'runtime-role-denial',
        callerClass: 'aster-key-runtime',
        inputClass: 'sorted-unique-bounded',
        inputCount: 2,
        resultClass: 'denied',
        denialClass: 'runtime-role-denied',
      },
    ]);
  });

  it('locks the complete database owner-role catalog and memberships', () => {
    const roles = record(projectionFor('database.owner-role-membership-boundary').roles);

    expect(Object.keys(roles)).toEqual([
      'aster_request',
      'aster_worker',
      'aster_admin',
      'aster_maintainer',
      'aster_control_resolver',
      'aster_key_runtime',
      'aster_migrator',
      'aster_owner',
      'aster_key_control_owner',
      'aster_key_usage_owner',
      'aster_key_lifecycle_owner',
      'aster_reaper_owner',
    ]);
    expect(roles.aster_migrator).toMatchObject({
      login: true,
      inherit: false,
      bypassRls: false,
      setRoleOwner: true,
      ownerMembershipGrantable: true,
    });
    for (const name of [
      'aster_owner',
      'aster_key_control_owner',
      'aster_key_usage_owner',
      'aster_key_lifecycle_owner',
      'aster_reaper_owner',
    ]) {
      expect(roles[name]).toMatchObject({ login: false, bypassRls: false });
    }
    expect(record(roles.aster_reaper_owner).memberOf).toEqual([
      'pg_signal_backend',
      'pg_read_all_stats',
    ]);
  });

  it('locks the complete audit-disable and safe artifact projection', () => {
    const projection = projectionFor('reaper.object-audit-disabled');

    expect(record(projection.settings)).toMatchObject({
      logStatement: 'none',
      logDuration: false,
      minimumErrorStatement: 'panic',
      minimumDuration: 'disabled',
      minimumSampleDuration: 'disabled',
      statementSampleRate: 0,
      parameterLogging: false,
      parameterMaximumLength: 0,
      errorParameterMaximumLength: 0,
      autoExplain: { minimumDuration: 'disabled', parameterMaximumLength: 0 },
      pgauditLog: 'none',
      pgauditStatement: false,
      pgauditParameter: false,
      pgauditRole: 'empty',
      objectAudit: { membershipClosure: 'clear', reachableAsterRelations: 0 },
      managedAuditPolicy: {
        requestWorkerRolesExcluded: true,
        statementCapture: false,
        parameterCapture: false,
      },
    });
    for (const artifact of list(projection.artifacts)) {
      expect(record(artifact)).toMatchObject({ matches: [] });
      expect(record(artifact).sha256).toMatch(/^sha256:[0-9a-f]{64}$/u);
    }
  });

  it('locks metadata before/after deltas and immutable fields', () => {
    const semanticState = record(projectionFor('keystore.metadata-dml-boundary').semanticState);
    const before = record(semanticState.before);
    const after = record(semanticState.after);

    for (const field of [
      'activeGeneration',
      'lifecycle',
      'tenant',
      'materialRelationship',
      'publicFingerprint',
    ]) {
      expect(after[field]).toEqual(before[field]);
    }
    expect(before).toMatchObject({ lastSignedAt: 'baseline', lastSealedAt: 'baseline' });
    expect(after).toMatchObject({
      lastSignedAt: 'advanced-by-database',
      lastSealedAt: 'advanced-by-database',
    });
    expect(semanticState.allowedColumnDeltas).toEqual(['lastSignedAt', 'lastSealedAt']);
    expect(list(semanticState.deniedOperations)).toHaveLength(6);
  });

  it('locks live/tombstone IDs stale reload and readable-set categories', () => {
    const liveLedger = record(projectionFor('keystore.live-ledger-limit-and-tombstone').liveLedger);
    expect(list(liveLedger.liveIds)).toHaveLength(32);
    expect(liveLedger.liveCount).toBe(32);
    expect(liveLedger.tombstoneIds).toEqual(['<wrapping-key.old>']);
    expect(liveLedger.reusedTombstoneId).toBeNull();

    const staleReplica = record(projectionFor('keystore.stale-keyring-rejoin-rejected').replica);
    expect(staleReplica).toMatchObject({
      loadedGeneration: 1,
      minimumGeneration: 2,
      fullReloadRequired: true,
      readiness: 'not-ready',
      preReload: { heartbeat: 'rejected', readiness: 'not-ready' },
      postReload: { loadedGeneration: 2, heartbeat: 'accepted', readiness: 'ready' },
    });
    for (const field of [
      'loadedSetFingerprint',
      'allowedSetFingerprint',
      'requiredSetFingerprint',
    ]) {
      expect(staleReplica[field]).toMatch(/^sha256:[0-9a-f]{64}$/u);
    }

    const readableReplica = record(projectionFor('keystore.required-readable-key-set').replica);
    expect(readableReplica.requiredReadable).toEqual([
      '<key.active>',
      '<key.old-referenced>',
      '<key.rollback-retained>',
    ]);
    expect(readableReplica.optionalAccepted).toEqual([
      '<key.staged-optional>',
      '<key.removable-optional>',
    ]);
    expect(record(readableReplica.negativeCategories)).toMatchObject({
      unknown: { accepted: false },
      tombstoned: { accepted: false },
      nonLive: { accepted: false },
    });
  });

  it('locks the exact connector SAML and script host topology', () => {
    const hosts = list(projectionFor('hosts.unavailable-pkce-independent').hosts).map((host) =>
      record(host)
    );

    expect(hosts.map(({ kind }) => kind)).toEqual(['connector', 'saml', 'script']);
    expect(hosts).toEqual([
      { kind: 'connector', availability: 'unavailable', errorClass: 'host-unavailable' },
      { kind: 'saml', availability: 'rejected', errorClass: 'peer-identity-invalid' },
      { kind: 'script', availability: 'rejected', errorClass: 'protocol-version-invalid' },
    ]);
  });
});

/* eslint-enable @silverhand/fp/no-mutation, @typescript-eslint/ban-types, @typescript-eslint/consistent-type-assertions */
