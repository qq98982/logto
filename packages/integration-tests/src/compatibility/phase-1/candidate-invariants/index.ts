/* eslint-disable @typescript-eslint/ban-types, complexity -- The canonical registry checks hostile array descriptors and recursively frozen module identities before accepting the exact tuple. */
import {
  candidateInvariantContractGuard,
  candidateInvariantScenarioIdGuard,
  candidateInvariantScenarioIds,
  snapshotDensePlainArray,
  type CandidateInvariantContract,
  type CandidateInvariantScenarioId,
} from '../model.js';

import { databaseOwnerRoleMembershipBoundary } from './database-owner-role-membership-boundary.js';
import { assertCandidateInvariantProjectionIsSanitized } from './evidence.js';
import { hostsUnavailablePkceIndependent } from './hosts-unavailable-pkce-independent.js';
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

export const candidateInvariantContracts = Object.freeze([
  tenantCrossTenantReadRejected,
  tenantSuspendedEpochRejected,
  tenantAdminOperationBinding,
  tenantAdminOperationStatusMatrix,
  databaseOwnerRoleMembershipBoundary,
  reaperActivityVisibilityRedaction,
  reaperObjectAuditDisabled,
  keystoreUnwrapFailureRollsBackCode,
  keystoreWrappingFenceLateCommit,
  keystoreSignSealDuringRewrap,
  keystoreMetadataDmlBoundary,
  keystoreForcedRlsOwnerBoundary,
  keystoreReferenceCountLedger,
  keystoreReferenceLedgerVerifierBoundary,
  keystoreLiveLedgerLimitAndTombstone,
  keystoreStaleKeyringRejoinRejected,
  keystoreRequiredReadableKeySet,
  hostsUnavailablePkceIndependent,
] as const satisfies readonly CandidateInvariantContract[]);

/** Compatibility alias for the pre-Task-14 registry export. */
export const candidateInvariantAuthorities = candidateInvariantContracts;

const diagnostic = 'Invalid phase 1 candidate invariant registry';
const contractById = new Map(
  candidateInvariantContracts.map((contract) => [contract.id, contract] as const)
);

const isRecursivelyFrozen = (value: unknown, visited: WeakSet<object> = new WeakSet()): boolean => {
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
          isRecursivelyFrozen(descriptor.value, visited)
      );
    })
  );
};

export const assertExactCandidateInvariantRegistry = (registry: unknown): void => {
  try {
    const snapshot = snapshotDensePlainArray<CandidateInvariantContract>(registry);

    if (
      !snapshot ||
      !Array.isArray(registry) ||
      snapshot.length !== candidateInvariantContracts.length ||
      new Set(snapshot.map(({ id }) => id)).size !== snapshot.length
    ) {
      throw new TypeError(diagnostic);
    }
    for (const [index, contract] of snapshot.entries()) {
      const expected = candidateInvariantContracts[index];
      const descriptor = Object.getOwnPropertyDescriptor(registry, String(index));

      if (
        !expected ||
        candidateInvariantScenarioIds[index] !== expected.id ||
        contract.id !== expected.id ||
        !descriptor ||
        !Object.hasOwn(descriptor, 'value') ||
        descriptor.value !== expected ||
        !candidateInvariantContractGuard.safeParse(contract).success ||
        !isRecursivelyFrozen(expected)
      ) {
        throw new TypeError(diagnostic);
      }
      assertCandidateInvariantProjectionIsSanitized(expected);
    }
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const getCandidateInvariantContract = (id: unknown): CandidateInvariantContract => {
  try {
    const parsed = candidateInvariantScenarioIdGuard.parse(id);
    const contract = contractById.get(parsed);

    if (!contract) {
      throw new TypeError(diagnostic);
    }

    return contract;
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const candidateInvariantRegistryIds: readonly CandidateInvariantScenarioId[] = Object.freeze(
  candidateInvariantContracts.map(({ id }) => id)
);

assertExactCandidateInvariantRegistry(candidateInvariantContracts);

/* eslint-enable @typescript-eslint/ban-types, complexity */
