import { compareJson } from '../../compare.js';
import type { JsonObject, JsonValue } from '../../normalize.js';

import { projectPhase1HttpCompatibility } from './http-compatibility.js';

const hash = 'a'.repeat(64);
const otherHash = 'b'.repeat(64);

const keyed = (stepId: string, value: JsonValue): JsonObject => {
  const step: JsonObject = { value };
  const steps: JsonObject = { [stepId]: step };

  return { steps };
};

describe('Phase 1 HTTP compatibility projection', () => {
  it('removes only the exact oracle HTTP/1 persistence headers missing from the candidate', () => {
    const oracle = keyed('token', {
      headers: {
        connection: ['keep-alive'],
        'keep-alive': ['timeout=5'],
        'x-stable': ['value'],
      },
    });
    const candidate = keyed('token', { headers: { 'x-stable': ['value'] } });
    const projected = projectPhase1HttpCompatibility('token.authorization-code', oracle, candidate);

    expect(compareJson(projected.oracle, projected.candidate)).toEqual([]);
    expect(oracle).toHaveProperty(['steps', 'token', 'value', 'headers', 'connection']);
    expect(candidate).not.toHaveProperty(['steps', 'token', 'value', 'headers', 'connection']);

    const wrongValue = projectPhase1HttpCompatibility(
      'token.authorization-code',
      keyed('token', { headers: { 'keep-alive': ['timeout=6'] } }),
      keyed('token', { headers: {} })
    );
    expect(compareJson(wrongValue.oracle, wrongValue.candidate)).toEqual([
      {
        path: '/steps/token/value/headers/keep-alive',
        oracle: ['timeout=6'],
      },
    ]);

    const partialCandidateHeaders: readonly JsonObject[] = [
      { connection: ['keep-alive'] },
      { 'keep-alive': ['timeout=5'] },
    ];

    for (const candidateHeaders of partialCandidateHeaders) {
      const partial = projectPhase1HttpCompatibility(
        'token.authorization-code',
        keyed('token', {
          headers: { connection: ['keep-alive'], 'keep-alive': ['timeout=5'] },
        }),
        keyed('token', { headers: candidateHeaders })
      );

      expect(compareJson(partial.oracle, partial.candidate)).toHaveLength(1);
    }
  });

  it('projects only registered exact candidate cache hardening additions', () => {
    const noStore = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', { headers: {} }),
      keyed('account', { headers: { 'cache-control': ['no-store'] } })
    );
    expect(compareJson(noStore.oracle, noStore.candidate)).toEqual([]);

    const discovery = projectPhase1HttpCompatibility(
      'discovery.config',
      keyed('oidc-discovery', { headers: {} }),
      keyed('oidc-discovery', {
        headers: { 'cache-control': ['no-cache, max-age=0, must-revalidate'] },
      })
    );
    expect(compareJson(discovery.oracle, discovery.candidate)).toEqual([]);

    for (const [scenarioId, stepId] of [
      ['authorization.password-pkce-consent', 'consent-get'],
      ['interaction.consent-session-boundary', 'get-valid-b'],
    ] as const) {
      const consent = projectPhase1HttpCompatibility(
        scenarioId,
        keyed(stepId, { headers: {} }),
        keyed(stepId, { headers: { 'cache-control': ['no-store'] } })
      );

      expect(compareJson(consent.oracle, consent.candidate)).toEqual([]);
    }

    const unlisted = projectPhase1HttpCompatibility(
      'token.authorization-code',
      keyed('token', { headers: {} }),
      keyed('token', { headers: { 'cache-control': ['no-store'] } })
    );
    expect(compareJson(unlisted.oracle, unlisted.candidate)).toHaveLength(1);

    const wrongValue = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', { headers: {} }),
      keyed('account', { headers: { 'cache-control': ['private'] } })
    );
    expect(compareJson(wrongValue.oracle, wrongValue.candidate)).toHaveLength(1);
  });

  it('projects only registered body-bound ETag omission and strength differences', () => {
    const omitted = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('account', { headers: { 'cache-control': ['no-store'] } })
    );
    expect(compareJson(omitted.oracle, omitted.candidate)).toEqual([]);

    const missingCacheClosure = projectPhase1HttpCompatibility(
      'account.admin-operator-read',
      keyed('account', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('account', { headers: {} })
    );
    expect(compareJson(missingCacheClosure.oracle, missingCacheClosure.candidate)).toHaveLength(1);

    const weakened = projectPhase1HttpCompatibility(
      'management.application-read',
      keyed('first-party', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('first-party', {
        headers: { etag: [{ weak: true, normalizedBodySha256: hash }] },
      })
    );
    expect(compareJson(weakened.oracle, weakened.candidate)).toEqual([]);
    expect(weakened.oracle).toHaveProperty(
      ['steps', 'first-party', 'value', 'headers', 'etag'],
      [{ weak: true, normalizedBodySha256: hash }]
    );

    const wrongHash = projectPhase1HttpCompatibility(
      'management.application-read',
      keyed('first-party', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('first-party', {
        headers: { etag: [{ weak: true, normalizedBodySha256: otherHash }] },
      })
    );
    expect(compareJson(wrongHash.oracle, wrongHash.candidate)).toHaveLength(2);

    const unlisted = projectPhase1HttpCompatibility(
      'token.authorization-code',
      keyed('token', {
        headers: { etag: [{ weak: false, normalizedBodySha256: hash }] },
      }),
      keyed('token', { headers: {} })
    );
    expect(compareJson(unlisted.oracle, unlisted.candidate)).toHaveLength(1);
  });

  it('handles the registered nested outcome ETag without changing sibling fields', () => {
    const oracle = keyed('submit', {
      headers: {},
      outcomes: [
        {
          authority: 'accepted',
          response: {
            headers: {
              'cache-control': ['no-store'],
              etag: [{ weak: false, normalizedBodySha256: hash }],
            },
            status: 303,
          },
        },
      ],
    });
    const candidate = keyed('submit', {
      headers: {},
      outcomes: [
        {
          authority: 'accepted',
          response: { headers: { 'cache-control': ['no-store'] }, status: 303 },
        },
      ],
    });
    const projected = projectPhase1HttpCompatibility(
      'authorization.password-pkce-consent',
      oracle,
      candidate
    );

    expect(compareJson(projected.oracle, projected.candidate)).toEqual([]);
    expect(oracle).toHaveProperty([
      'steps',
      'submit',
      'value',
      'outcomes',
      '0',
      'response',
      'headers',
      'etag',
    ]);
  });
});
