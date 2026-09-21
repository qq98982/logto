import { defineCandidateInvariant, type CandidateInvariantContract } from '../model.js';

const positiveProjection = {
  verifier: {
    fenceHeld: true,
    deploymentMatched: true,
    maximumEntries: 32,
    cases: [
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
    ],
    mismatchCount: 0,
    disclosedTenantIds: [],
    dmlCount: 0,
  },
};
const negativeProjection = {
  verifier: { ...positiveProjection.verifier, disclosedTenantIds: ['tenant-a'] },
};

export const keystoreReferenceLedgerVerifierBoundary = defineCandidateInvariant({
  id: 'keystore.reference-ledger-verifier-boundary',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { kind: 'global-fence-and-matching-deployment-identity' },
  perturbation: { kind: 'admin-and-non-admin-bounded-verifier-input-cases', maximumEntries: 32 },
  expectedPublicOutcome: {
    caseCount: 5,
    successfulAdmin: true,
    denialCount: 4,
    disclosedTenantIds: [],
  },
  expectedPersistedOutcome: { dmlCount: 0 },
  forbiddenOutcome: {
    tenantDisclosure: true,
    ciphertextDisclosure: true,
    oversizedAccepted: true,
    runtimeExecution: true,
    dml: true,
  },
  cleanup: { kind: 'release-fence-and-rollback-verifier-fixtures' },
  sanitizedProjection: {
    fields: [
      'verifier.fenceHeld',
      'verifier.deploymentMatched',
      'verifier.maximumEntries',
      'verifier.cases.caseClass',
      'verifier.cases.callerClass',
      'verifier.cases.inputClass',
      'verifier.cases.inputCount',
      'verifier.cases.resultClass',
      'verifier.cases.denialClass',
      'verifier.mismatchCount',
      'verifier.disclosedTenantIds',
      'verifier.dmlCount',
    ],
    boundedOutput: true,
  },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'bounded admin verifier returns no tenant or ciphertext data',
    input: { variant: 'positive' },
    expectedProjection: positiveProjection,
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'verifier discloses a logical tenant identifier',
    input: {
      variant: 'negative',
      fault: { operation: 'add', path: '/verifier/disclosedTenantIds/0', value: 'tenant-a' },
    },
    expectedProjection: negativeProjection,
    expectedDifferencePointer: '/verifier/disclosedTenantIds/0',
  },
} satisfies CandidateInvariantContract);

export default keystoreReferenceLedgerVerifierBoundary;
