import {
  capabilityManifestGuard,
  jsonValueGuard,
  observationGuard,
  runEvidenceGuard,
  scenarioEvidenceGuard,
  targetConfigGuard,
} from './model.js';

const referenceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';

describe('compatibility evidence model', () => {
  it('accepts nested JSON values without changing their structure', () => {
    const value = {
      string: 'value',
      number: 42.5,
      boolean: true,
      null: null,
      nested: [{ enabled: false }, ['leaf']],
    };

    expect(jsonValueGuard.safeParse(value)).toEqual({ success: true, data: value });
  });

  it.each([Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    'rejects nested non-finite number %p',
    (value) => {
      expect(jsonValueGuard.safeParse({ nested: [value] }).success).toBe(false);
    }
  );

  it('rejects RegExp values instead of converting them to records', () => {
    expect(jsonValueGuard.safeParse({ nested: /not-json/ }).success).toBe(false);
  });

  it('rejects Uint8Array values instead of converting them to records', () => {
    expect(jsonValueGuard.safeParse({ nested: new Uint8Array([1, 2, 3]) }).success).toBe(false);
  });

  it.each(['http://localhost:3001', 'https://logto.example.com'])(
    'accepts HTTP target URL %s',
    (url) => {
      expect(
        targetConfigGuard.safeParse({ label: 'oracle', coreUrl: url, adminUrl: url }).success
      ).toBe(true);
    }
  );

  it('rejects non-HTTP target URLs', () => {
    expect(
      targetConfigGuard.safeParse({
        label: 'candidate',
        coreUrl: 'ftp://logto.example.com',
        adminUrl: 'https://logto.example.com',
      }).success
    ).toBe(false);
  });

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
