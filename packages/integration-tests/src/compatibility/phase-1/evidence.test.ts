import type { JsonValue } from '../normalize.js';
import { SymbolTable } from '../symbol-table.js';

import { createPhase1ProjectionEnvelope } from './evidence-envelope.js';
import {
  assertPhase1EvidenceIsSanitized,
  createCandidateInvariantEvidence,
  createDifferentialEvidence,
  createVerifiedTokenObservations,
  omitVerifiedIdTokenEmailPair,
  phase1EvidenceGuard,
  runObservationNegativeControl,
  verifyObservedJwt,
} from './evidence.js';
import { oracleCommit, phase0HarnessCommit } from './model.js';
import {
  createTokenTestSigner,
  tokenTestTarget,
} from './scenarios/positive-oidc-token.test-helpers.js';

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
  it('derives only a paired email omission from a verified ID Token observation', async () => {
    const signer = await createTokenTestSigner();
    const issuedAt = Math.floor(Date.now() / 1000);
    const signed = await signer.sign({
      iss: 'https://oracle.example/oidc',
      sub: 'subject',
      aud: 'client',
      iat: issuedAt,
      exp: issuedAt + 3600,
      name: 'Retained',
      email: null,
      email_verified: false,
    });
    const proof = await verifyObservedJwt(signed, { keys: [signer.jwk] });
    const context = {
      target: tokenTestTarget,
      symbols: new SymbolTable(),
      nativeSurfaceImplementation: 'oracle' as const,
    };
    const observed = createVerifiedTokenObservations(
      { access_token: 'opaque-access', id_token: signed, token_type: 'Bearer' },
      context,
      { boundedClaimTimestampPaths: [], proofs: [proof] }
    );
    const derived = omitVerifiedIdTokenEmailPair(observed.tokens, 1);

    expect(derived[0]).toEqual(observed.tokens[0]);
    expect(derived[1]).toMatchObject({
      kind: 'id',
      format: 'jwt',
      signatureVerified: true,
      claims: { name: 'Retained', sub: 'subject' },
    });
    expect(derived[1]).not.toHaveProperty('claims.email');
    expect(derived[1]).not.toHaveProperty('claims.email_verified');
    expect(observed.tokens[1]).toHaveProperty('claims.email', null);
    expect(() => createPhase1ProjectionEnvelope('oracle', { tokens: derived })).not.toThrow();

    const unverified = JSON.parse(JSON.stringify(observed.tokens)) as readonly JsonValue[];
    expect(() => omitVerifiedIdTokenEmailPair(unverified, 1)).toThrow();
    expect(() => omitVerifiedIdTokenEmailPair(observed.tokens, 0)).toThrow();
    expect(() => omitVerifiedIdTokenEmailPair(derived, 1)).toThrow();

    const invalidVerification = await signer.sign({
      iss: 'https://oracle.example/oidc',
      sub: 'subject',
      aud: 'client',
      iat: issuedAt,
      exp: issuedAt + 3600,
      email: null,
      email_verified: null,
    });
    const invalidProof = await verifyObservedJwt(invalidVerification, { keys: [signer.jwk] });
    const malformed = createVerifiedTokenObservations(
      { access_token: 'opaque-access', id_token: invalidVerification, token_type: 'Bearer' },
      context,
      { boundedClaimTimestampPaths: [], proofs: [invalidProof] }
    );
    expect(() => omitVerifiedIdTokenEmailPair(malformed.tokens, 1)).toThrow();
  });
  it.each([42, ''])('rejects a verified ID Token with malformed email %p', async (email) => {
    const signer = await createTokenTestSigner();
    const issuedAt = Math.floor(Date.now() / 1000);
    const signed = await signer.sign({
      iss: 'https://oracle.example/oidc',
      sub: 'subject',
      aud: 'client',
      iat: issuedAt,
      exp: issuedAt + 3600,
      email,
      email_verified: false,
    });
    const proof = await verifyObservedJwt(signed, { keys: [signer.jwk] });
    const observed = createVerifiedTokenObservations(
      { access_token: 'opaque-access', id_token: signed, token_type: 'Bearer' },
      {
        target: tokenTestTarget,
        symbols: new SymbolTable(),
        nativeSurfaceImplementation: 'oracle',
      },
      { boundedClaimTimestampPaths: [], proofs: [proof] }
    );

    expect(() => omitVerifiedIdTokenEmailPair(observed.tokens, 1)).toThrow(
      'Invalid phase 1 verified ID Token email pair'
    );
  });
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
