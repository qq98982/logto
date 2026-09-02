import {
  createPhase1EvidenceProvenance,
  createPhase1ProjectionEnvelope,
  hashCanonicalPhase1Json,
} from './evidence-envelope.js';

const provenance = {
  harnessCommit: '1'.repeat(40),
  profileSha256: '2'.repeat(64),
  schemaSha256: '3'.repeat(64),
  imageDigest: `sha256:${'4'.repeat(64)}`,
};

describe('Phase 1 evidence envelopes', () => {
  it('hashes canonical JSON with bytewise object keys and preserved array order', () => {
    expect(hashCanonicalPhase1Json({ b: 2, a: { y: 2, x: 1 } })).toBe(
      '7d18070743e5a89438758e4f5d12b96e094b6dee334b2ef013cb082964d1b472'
    );
    expect(hashCanonicalPhase1Json({ b: 2, a: { y: 2, x: 1 } })).toBe(
      hashCanonicalPhase1Json({ a: { x: 1, y: 2 }, b: 2 })
    );
    expect(hashCanonicalPhase1Json({ values: [1, 2] })).not.toBe(
      hashCanonicalPhase1Json({ values: [2, 1] })
    );
  });

  it('creates closed frozen provenance and projection envelopes', () => {
    const closedProvenance = createPhase1EvidenceProvenance(provenance);
    const envelope = createPhase1ProjectionEnvelope('candidate-only', {
      outcome: { accepted: true },
    });

    expect(closedProvenance).toEqual(provenance);
    expect(Object.keys(closedProvenance)).toEqual([
      'harnessCommit',
      'profileSha256',
      'schemaSha256',
      'imageDigest',
    ]);
    expect(Object.isFrozen(closedProvenance)).toBe(true);
    expect(envelope).toEqual({
      label: 'candidate-only',
      projectionSha256: hashCanonicalPhase1Json(envelope.value),
      value: { outcome: { accepted: true } },
    });
    expect(Object.isFrozen(envelope)).toBe(true);
    expect(Object.isFrozen(envelope.value)).toBe(true);
  });

  it('rejects malformed provenance labels non-object projections and credential shapes', () => {
    for (const invalid of [
      { ...provenance, harnessCommit: 'not-a-commit' },
      { ...provenance, profileSha256: 'A'.repeat(64) },
      { ...provenance, extra: true },
    ]) {
      expect(() => createPhase1EvidenceProvenance(invalid as never)).toThrow(
        /^Invalid phase 1 evidence envelope$/u
      );
    }

    for (const [label, value] of [
      ['', { accepted: true }],
      ['valid-label', []],
      ['valid-label', { accessToken: 'private-token-value' }],
      ['valid-label', { jwk: { kty: 'oct', k: 'private-key-value' } }],
      [
        'adapter-control',
        {
          tokens: [
            {
              kind: 'access',
              format: 'jwt',
              signatureVerified: true,
              header: { alg: 'RS256' },
              claims: { iss: 'https://issuer.example', aud: 'urn:api' },
            },
          ],
        },
      ],
    ] as const) {
      expect(() => createPhase1ProjectionEnvelope(label, value)).toThrow(
        /^Invalid phase 1 evidence envelope$/u
      );
    }
  });
});
