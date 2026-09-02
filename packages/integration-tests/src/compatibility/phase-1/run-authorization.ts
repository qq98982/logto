/* eslint-disable no-restricted-syntax -- WeakSet identity brands require controlled object-to-record casts at the authorization boundary. */
import type {
  Phase1ProvenanceResult,
  Phase1ProtectedExecutionAuthorization,
} from './profile-semantics.js';
import type { Phase1Profile } from './profile-types.js';

export type Phase1RunMode = 'review-candidate' | 'mirror-control' | 'runtime-candidate';

export type Phase1RunControls = Readonly<{
  recordOracle: boolean;
  observationControls: boolean;
  discoveryExtraControl: boolean;
  candidateInvariantControls: boolean;
}>;

export type Phase1RunAuthorization = Readonly<{
  mode: Phase1RunMode;
  profile: Readonly<Phase1Profile>;
  profileSha256: string;
  schemaSha256: string;
  provenance: Phase1ProvenanceResult;
  protectedExecution: Phase1ProtectedExecutionAuthorization | undefined;
  controls: Phase1RunControls;
}>;

const diagnostic = 'Phase 1 run authorization failed.';
const verifiedRunAuthorizations = new WeakSet<Record<string, unknown>>();

export const mintPhase1RunAuthorization = (
  authorization: Phase1RunAuthorization
): Phase1RunAuthorization => {
  verifiedRunAuthorizations.add(authorization as unknown as Record<string, unknown>);

  return authorization;
};

export function assertAuthorizedPhase1Run(value: unknown): asserts value is Phase1RunAuthorization {
  if (
    typeof value !== 'object' ||
    value === null ||
    !verifiedRunAuthorizations.has(value as Record<string, unknown>)
  ) {
    throw new TypeError(diagnostic);
  }
}

export const authorizePhase1RunForTesting = (
  authorization: Phase1RunAuthorization
): Phase1RunAuthorization => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError(diagnostic);
  }

  return mintPhase1RunAuthorization(authorization);
};

/* eslint-enable no-restricted-syntax */
