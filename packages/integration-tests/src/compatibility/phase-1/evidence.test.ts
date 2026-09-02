import {
  assertPhase1EvidenceIsSanitized,
  createCandidateInvariantEvidence,
  createDifferentialEvidence,
  phase1EvidenceGuard,
  runObservationNegativeControl,
} from './evidence.js';
import { oracleCommit, phase0HarnessCommit } from './model.js';

const provenance = {
  referenceCommit: oracleCommit,
  harnessCommit: phase0HarnessCommit,
} as const;

const target = <Label extends 'oracle' | 'candidate'>(label: Label) => ({
  target: label,
  observations: [{ stepId: 'request', kind: 'http' as const, value: { status: 200 } }],
});

const createCandidateEvidenceForOutcome = (outcome: unknown) =>
  createCandidateInvariantEvidence({
    scenarioId: 'keystore.unwrap-failure-rolls-back-code',
    provenance,
    candidate: { outcome },
    positiveControl: { passed: true, differences: [] },
    negativeControl: {
      passed: true,
      differences: [{ path: '/semanticState/code/consumed', actual: true }],
    },
  });

describe('phase 1 evidence', () => {
  it('creates strict sanitized differential evidence', () => {
    const evidence = createDifferentialEvidence({
      scenarioId: 'discovery.config',
      provenance,
      oracle: target('oracle'),
      candidate: target('candidate'),
      differences: [],
    });

    expect(phase1EvidenceGuard.parse(evidence)).toEqual(evidence);
    expect(() => phase1EvidenceGuard.parse({ ...evidence, extra: true })).toThrow();
    const observedValue = evidence.oracle.observations[0]?.value;
    expect(Object.isFrozen(observedValue)).toBe(true);
    if (typeof observedValue !== 'object' || observedValue === null) {
      throw new Error('expected object evidence');
    }
    expect(Reflect.set(observedValue, 'accessToken', 'private-token')).toBe(false);
  });

  it('candidate evidence rejects every nested comparison vocabulary', () => {
    const evidence = createCandidateInvariantEvidence({
      scenarioId: 'tenant.cross-tenant-read-rejected',
      provenance,
      candidate: { outcome: { accepted: false } },
      positiveControl: { passed: true, differences: [] },
      negativeControl: {
        passed: true,
        differences: [{ path: '/outcome/crossTenantRows/0', expected: false, actual: true }],
      },
    });

    expect(phase1EvidenceGuard.safeParse(evidence).success).toBe(true);
    const forbiddenPayloads = ['oracle', 'candidate', 'differences', 'compare', 'oracleComparison'];
    const hostileValues = forbiddenPayloads.map((field) => ({
      ...evidence,
      candidate: { outcome: { nested: { [field]: 'forbidden' } } },
    }));
    for (const hostile of [
      { ...evidence, oracle: {} },
      ...hostileValues,
      {
        ...evidence,
        negativeControl: {
          passed: true,
          differences: [{ path: '/control', expected: { or_acle: false }, actual: true }],
        },
      },
      {
        ...evidence,
        negativeControl: {
          passed: true,
          differences: [{ path: '/control', oracle: false, candidate: true }],
        },
      },
    ]) {
      expect(phase1EvidenceGuard.safeParse(hostile).success).toBe(false);
    }
  });

  it('accepts only bounded boolean signing sealing and consumed-code state metadata', () => {
    const safe = createCandidateEvidenceForOutcome({
      semanticState: { code: { consumed: false } },
      availability: { tokenSigning: true, cookieSealing: true, cookieVerification: true },
    });

    expect(() => {
      assertPhase1EvidenceIsSanitized(safe);
    }).not.toThrow();
    expect(() => {
      assertPhase1EvidenceIsSanitized({
        semanticState: { code: { consumed: false } },
        availability: { tokenSigning: 'opaque-private-value' },
      });
    }).toThrow('Invalid phase 1 evidence');
    for (const invalid of [
      { semanticState: { code: 'raw-value' } },
      { availability: { tokenSigning: 'yes' } },
      { availability: { cookieSealing: 'yes' } },
      { jwk: { kty: 'EC', crv: 'P-256', x: 'public-x', y: 'public-y', d: 'private' } },
      { kty: 'oct', k: 'private' },
      { keys: [{ kty: 'EC', crv: 'P-256', x: 'public-x', y: 'public-y', d: 'private' }] },
      [{ kty: 'RSA', n: 'public-n', e: 'AQAB', p: 'private' }],
      { jwk: { nested: { kty: 'EC', d: 'private' } } },
      { state: 'oauth-state-value' },
      { nonce: 'oauth-nonce-value' },
      { codeVerifier: 'oauth-verifier-value' },
      { codeChallenge: 'oauth-challenge-value' },
      { verificationId: 'verification-id-value' },
      { verificationCredential: 'verification-credential-value' },
      { verificationToken: 'verification-token-value' },
      { nested: [{ code_verifier: 'oauth-verifier-value' }] },
    ]) {
      expect(() => createCandidateEvidenceForOutcome(invalid)).toThrow(
        'Invalid phase 1 candidate invariant evidence'
      );
    }

    expect(() =>
      createCandidateEvidenceForOutcome({
        jwk: { kty: 'EC', crv: 'P-256', x: 'public-x', y: 'public-y' },
        measurement: { d: 1, p: 2, q: 3 },
      })
    ).not.toThrow();
  });

  it('requires one successful positive control and one scenario-bound negative difference', () => {
    const valid: Parameters<typeof createCandidateInvariantEvidence>[0] = {
      scenarioId: 'tenant.cross-tenant-read-rejected',
      provenance,
      candidate: { outcome: { accepted: false } },
      positiveControl: { passed: true, differences: [] },
      negativeControl: {
        passed: true,
        differences: [{ path: '/outcome/crossTenantRows/0', expected: false, actual: true }],
      },
    };

    expect(() => createCandidateInvariantEvidence(valid)).not.toThrow();
    for (const invalid of [
      { ...valid, positiveControl: { passed: false, differences: [] } },
      {
        ...valid,
        positiveControl: {
          passed: true,
          differences: [{ path: '/outcome/crossTenantRows/0', actual: true }],
        },
      },
      {
        ...valid,
        negativeControl: { passed: false, differences: valid.negativeControl.differences },
      },
      { ...valid, negativeControl: { passed: true, differences: [] } },
      {
        ...valid,
        negativeControl: {
          passed: true,
          differences: [
            ...valid.negativeControl.differences,
            { path: '/outcome/crossTenantRows/1', actual: true },
          ],
        },
      },
      {
        ...valid,
        negativeControl: {
          passed: true,
          differences: [{ path: '/activation/accepted', expected: false, actual: true }],
        },
      },
    ]) {
      expect(() => createCandidateInvariantEvidence(invalid as never)).toThrow(
        'Invalid phase 1 candidate invariant evidence'
      );
    }
  });

  it.each([
    ['http', { status: 200 }, '/value/status'],
    ['redirect', { path: '/callback' }, '/value/path'],
    ['cookie-metadata', { sameSite: 'Lax' }, '/value/sameSite'],
    ['jwt-header', { alg: 'RS256' }, '/value/alg'],
    ['jwt-claims', { aud: 'urn:api' }, '/value/aud'],
    ['semantic-state', { grants: [{ scopes: ['read'] }] }, '/value/grants/0/scopes/0'],
  ] as const)('detects the exact %s negative-control pointer', (kind, value, suffix) => {
    expect(runObservationNegativeControl({ stepId: 'step', kind, value }).differencePath).toBe(
      `/observations/0${suffix}`
    );
  });

  it('detects the separate discovery extra-field pointer', () => {
    expect(
      runObservationNegativeControl({
        stepId: 'discovery',
        kind: 'http',
        value: { status: 200, body: { issuer: 'https://issuer.example' } },
        control: 'discovery-extra-field',
      }).differencePath
    ).toBe('/observations/0/value/body/aster_extra_field');
  });

  it('requires token family generated IDs to remain logical symbols', () => {
    expect(() => {
      assertPhase1EvidenceIsSanitized({ generatedIds: { tokenFamily: '<token-family.1>' } });
    }).not.toThrow();
    expect(() => {
      assertPhase1EvidenceIsSanitized({ generatedIds: { tokenFamily: 'runtime-family-value' } });
    }).toThrow('Invalid phase 1 evidence');
  });
});
