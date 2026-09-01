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

  it('candidate evidence can never parse an oracle field', () => {
    const evidence = createCandidateInvariantEvidence({
      scenarioId: 'tenant.cross-tenant-read-rejected',
      provenance,
      candidate: { outcome: { accepted: false } },
      positiveControl: { passed: true, differences: [] },
      negativeControl: {
        passed: true,
        differences: [{ path: '/control/accepted', expected: false, actual: true }],
      },
    });

    expect(phase1EvidenceGuard.safeParse(evidence).success).toBe(true);
    for (const hostile of [
      { ...evidence, oracle: {} },
      { ...evidence, candidate: { outcome: { nested: { oracle: 'forbidden' } } } },
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
