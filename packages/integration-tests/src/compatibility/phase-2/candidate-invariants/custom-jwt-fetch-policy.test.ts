/* eslint-disable @silverhand/fp/no-mutating-methods -- Tests record ordered lifecycle calls and consume fixture queues. */
import {
  customJwtFetchPolicyCandidateInvariantIds,
  customJwtFetchPolicyExpectedProjection,
  runCustomJwtFetchPolicyCandidateInvariant,
  runCustomJwtFetchPolicyControls,
  type CustomJwtFetchPolicyPort,
} from './custom-jwt-fetch-policy.js';

const receipt = () => ({
  method: 'GET',
  path: '/text',
  headerMatches: true,
  bodyMatches: true,
});

const port = (
  input: Readonly<{
    receipts?: readonly unknown[];
    claims?: readonly unknown[];
    failRestore?: boolean;
  }> = {}
): Readonly<{ capability: CustomJwtFetchPolicyPort; calls: string[] }> => {
  const calls: string[] = [];
  const receipts = [...(input.receipts ?? [[], [receipt()], [], [], []])];
  const claims = [...(input.claims ?? ['bounded-response', 'caught-TypeError'])];
  return Object.freeze({
    calls,
    capability: Object.freeze({
      installCustomizer: async (kind: 'allowed-fetch' | 'denied-origin') => {
        calls.push(`install:${kind}`);
      },
      assertDeniedOriginReachable: async () => {
        calls.push('denied-origin-reachable');
      },
      issueM2MAndVerifyClaim: async () => {
        calls.push('issue');
        return claims.shift();
      },
      readAndResetSanitizedReceipts: async () => {
        calls.push('receipts');
        return receipts.shift();
      },
      restoreConfiguration: async () => {
        calls.push('restore');
        if (input.failRestore) {
          throw new Error('private cleanup detail');
        }
      },
    }),
  });
};

describe('custom JWT fetch policy candidate invariant', () => {
  it('proves one allowed GET and a denied origin with no observer receipt', async () => {
    const { capability, calls } = port();
    const evidence = await runCustomJwtFetchPolicyCandidateInvariant(capability);

    expect(evidence).toEqual({
      id: 'custom-jwt.fetch-policy-boundary',
      candidate: customJwtFetchPolicyExpectedProjection(
        customJwtFetchPolicyCandidateInvariantIds[0]
      ),
      positiveControl: { detected: true },
      negativeControl: { detected: true, pointer: '/denied/requests' },
    });
    expect(calls).toEqual([
      'receipts',
      'install:allowed-fetch',
      'issue',
      'receipts',
      'receipts',
      'denied-origin-reachable',
      'install:denied-origin',
      'issue',
      'receipts',
      'receipts',
      'restore',
    ]);
    expect(JSON.stringify(evidence)).not.toMatch(
      /(?:https?:|\/text|access_token|script|receipt(?:File|Path)|private|token)/iu
    );
  });

  it.each([
    ['missing receipt result', [undefined]],
    ['hostile receipt container', [new Proxy([], {})]],
    ['extra positive receipt', [[], [receipt(), receipt()]]],
    ['malformed positive receipt', [[], [{ ...receipt(), method: 'POST' }]]],
    ['extra receipt field', [[], [{ ...receipt(), url: 'https://private.invalid' }]]],
  ] as const)('fails closed on %s and restores configuration', async (_name, receipts) => {
    const { capability, calls } = port({ receipts });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls.slice(-2)).toEqual(['receipts', 'restore']);
  });

  it('rejects cross-case stale receipts before installing the denied customizer', async () => {
    const { capability, calls } = port({ receipts: [[], [receipt()], [receipt()]] });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls).not.toContain('install:denied-origin');
    expect(calls.slice(-2)).toEqual(['receipts', 'restore']);
  });

  it('rejects a denied-origin observer receipt', async () => {
    const { capability, calls } = port({ receipts: [[], [receipt()], [], [receipt()]] });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls.slice(-2)).toEqual(['receipts', 'restore']);
  });

  it.each([
    ['allowed claim', ['wrong']],
    ['denied claim', ['bounded-response', 'wrong']],
  ] as const)('rejects the %s and restores configuration', async (_name, claims) => {
    const { capability, calls } = port({ claims });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls.slice(-2)).toEqual(['receipts', 'restore']);
  });

  it('masks cleanup failure after otherwise successful execution', async () => {
    const { capability, calls } = port({ failRestore: true });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls.slice(-2)).toEqual(['receipts', 'restore']);
  });

  it('attempts cleanup when the first receipt reset fails', async () => {
    const { capability, calls } = port({ receipts: [undefined] });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls).toEqual(['receipts', 'receipts', 'restore']);
  });

  it.each(['wrong-claim', 'throw'] as const)(
    'drains an appended allowed receipt and restores after allowed issuance %s',
    async (failure) => {
      const calls: string[] = [];
      const pendingReceipts: unknown[] = [[], [receipt()]];
      const capability: CustomJwtFetchPolicyPort = Object.freeze({
        installCustomizer: async (kind) => {
          calls.push(`install:${kind}`);
        },
        assertDeniedOriginReachable: async () => {
          calls.push('denied-origin-reachable');
        },
        issueM2MAndVerifyClaim: async () => {
          calls.push('issue');
          if (failure === 'throw') {
            throw new Error('private issuance detail');
          }
          return 'wrong';
        },
        readAndResetSanitizedReceipts: async () => {
          calls.push('receipts');
          return pendingReceipts.shift();
        },
        restoreConfiguration: async () => {
          calls.push('restore');
        },
      });
      await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
        'Invalid Phase 2 custom JWT fetch policy candidate invariant'
      );
      expect(calls).toEqual(['receipts', 'install:allowed-fetch', 'issue', 'receipts', 'restore']);
      expect(pendingReceipts).toEqual([]);
    }
  );

  it('attempts restoration when cleanup receipt draining fails', async () => {
    const calls: string[] = [];
    const receiptReads: unknown[] = [];
    const capability: CustomJwtFetchPolicyPort = Object.freeze({
      installCustomizer: async () => {
        throw new Error('private primary detail');
      },
      assertDeniedOriginReachable: async () => {
        void calls.length;
      },
      issueM2MAndVerifyClaim: async () => 'unreachable',
      readAndResetSanitizedReceipts: async () => {
        calls.push('receipts');
        receiptReads.push(true);
        if (receiptReads.length > 1) {
          throw new Error('private drain detail');
        }
        return [];
      },
      restoreConfiguration: async () => {
        calls.push('restore');
      },
    });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls).toEqual(['receipts', 'receipts', 'restore']);
  });

  it('requires denied-origin reachability before accepting policy rejection', async () => {
    const { capability: base, calls } = port();
    const capability: CustomJwtFetchPolicyPort = Object.freeze({
      ...base,
      assertDeniedOriginReachable: async () => {
        calls.push('denied-origin-reachable');
        throw new Error('private DNS or TLS detail');
      },
    });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls).not.toContain('install:denied-origin');
    expect(calls.slice(-2)).toEqual(['receipts', 'restore']);
  });

  it('fails closed and restores when an injected capability throws undefined', async () => {
    const calls: string[] = [];
    const capability: CustomJwtFetchPolicyPort = Object.freeze({
      installCustomizer: async () => {
        // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Hostile ports may reject without an Error value.
        throw undefined;
      },
      assertDeniedOriginReachable: async () => {
        void calls.length;
      },
      issueM2MAndVerifyClaim: async () => 'unreachable',
      readAndResetSanitizedReceipts: async () => [],
      restoreConfiguration: async () => {
        calls.push('restore');
      },
    });
    await expect(runCustomJwtFetchPolicyCandidateInvariant(capability)).rejects.toThrow(
      'Invalid Phase 2 custom JWT fetch policy candidate invariant'
    );
    expect(calls).toEqual(['restore']);
  });

  it('detects the deliberate negative-control mutation and rejects projection shape changes', () => {
    const expected = customJwtFetchPolicyExpectedProjection(
      customJwtFetchPolicyCandidateInvariantIds[0]
    );
    expect(
      runCustomJwtFetchPolicyControls(customJwtFetchPolicyCandidateInvariantIds[0], expected)
    ).toMatchObject({ negativeControl: { detected: true, pointer: '/denied/requests' } });
    expect(() =>
      runCustomJwtFetchPolicyControls(customJwtFetchPolicyCandidateInvariantIds[0], {
        ...expected,
        denied: { ...expected.denied, requests: 'present' },
      })
    ).toThrow('Invalid Phase 2 custom JWT fetch policy candidate invariant');
    expect(() =>
      runCustomJwtFetchPolicyControls(customJwtFetchPolicyCandidateInvariantIds[0], {
        ...expected,
        url: 'https://private.invalid',
      })
    ).toThrow('Invalid Phase 2 custom JWT fetch policy candidate invariant');
  });
});

/* eslint-enable @silverhand/fp/no-mutating-methods */
