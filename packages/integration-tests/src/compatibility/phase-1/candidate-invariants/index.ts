import {
  candidateInvariantAuthorityGuard,
  candidateInvariantScenarioIds,
  cloneAndDeepFreeze,
  snapshotDensePlainArray,
  type CandidateInvariantAuthority,
} from '../model.js';

export const candidateInvariantAuthorities: readonly CandidateInvariantAuthority[] =
  cloneAndDeepFreeze(
    candidateInvariantScenarioIds.map(
      (id): CandidateInvariantAuthority => ({
        id,
        evidenceKind: 'candidate-invariant',
        implementation: 'contract-pending',
      })
    )
  );

const diagnostic = 'Invalid phase 1 candidate invariant registry';

export const assertExactCandidateInvariantRegistry = (
  registry: readonly CandidateInvariantAuthority[]
): void => {
  try {
    const snapshot = snapshotDensePlainArray<CandidateInvariantAuthority>(registry);

    if (!snapshot || snapshot.length !== candidateInvariantAuthorities.length) {
      throw new TypeError(diagnostic);
    }
    for (const [index, authority] of snapshot.entries()) {
      const expected = candidateInvariantAuthorities[index];

      if (
        !expected ||
        !candidateInvariantAuthorityGuard.safeParse(authority).success ||
        authority.id !== expected.id
      ) {
        throw new TypeError(diagnostic);
      }
    }
  } catch {
    throw new TypeError(diagnostic);
  }
};

assertExactCandidateInvariantRegistry(candidateInvariantAuthorities);
