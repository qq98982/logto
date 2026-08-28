import {
  capabilityManifestGuard,
  observationGuard,
  runEvidenceGuard,
  scenarioEvidenceGuard,
} from './model.js';

const referenceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';

describe('compatibility evidence model', () => {
  it('accepts the reference capability manifest', () => {
    expect(
      capabilityManifestGuard.safeParse({
        schemaVersion: 1,
        referenceCommit,
        capabilities: [
          {
            id: 'users.create',
            surface: 'management-api',
            source: 'packages/core/src/routes/users/index.ts',
            existingEvidence: ['packages/integration-tests/src/tests/api/user.test.ts'],
          },
        ],
      }).success
    ).toBe(true);
  });

  it('accepts sanitized JWT claims observations', () => {
    expect(
      observationGuard.safeParse({
        stepId: 'inspect-access-token',
        kind: 'jwt-claims',
        value: { sub: '<user.primary>', tokenLifetimeSeconds: 3600 },
      }).success
    ).toBe(true);
  });

  it('rejects scenario evidence without oracle and candidate evidence', () => {
    expect(
      scenarioEvidenceGuard.safeParse({
        schemaVersion: 1,
        scenarioId: 'management-api.users.create',
        differences: [],
      }).success
    ).toBe(false);
  });

  it('accepts run evidence with immutable image identities and summarized differences', () => {
    expect(
      runEvidenceGuard.safeParse({
        schemaVersion: 1,
        referenceCommit,
        oracleImageDigest: `sha256:${'a'.repeat(64)}`,
        candidateImageDigest: `sha256:${'b'.repeat(64)}`,
        scenarios: [
          { scenarioId: 'management-api.users.create', differenceCount: 0 },
          { scenarioId: 'negative-control.changed-claim', differenceCount: 1 },
        ],
        negativeControl: { differencePath: '/observations/0/value/tokenLifetimeSeconds' },
      }).success
    ).toBe(true);
  });
});
