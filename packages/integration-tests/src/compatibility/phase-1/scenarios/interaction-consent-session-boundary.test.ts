/* eslint-disable max-lines, complexity, max-params, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment -- The complete 14-request matrix, opaque store relationships, and adversarial factory override stay in one structural harness. */
import { SymbolTable } from '../../symbol-table.js';
import { MemoryProtocolSecretStore, type ProtocolRequestOptions } from '../clients/oidc.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import {
  runInteractionConsentSessionBoundary,
  type ConsentBoundaryScenarioOptions,
} from './interaction-consent-session-boundary.js';

const target = {
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
};
const foreignTarget = {
  label: 'oracle' as const,
  coreUrl: 'https://foreign.example/',
  adminUrl: 'https://foreign-admin.example/',
};
const dataAllocationId = 'consent-data-allocation';
const foreignAllocationId = 'consent-foreign-allocation';
const fixtureMap = {
  schemaVersion: 1 as const,
  recipe: 'consentBoundary' as const,
  allocations: [
    {
      allocationId: dataAllocationId,
      role: 'data' as const,
      target: 'primary' as const,
      isolation: {
        persistenceId: 'data-persistence',
        cookieKeyId: 'data-cookie-key',
        signingKeyId: 'data-signing-key',
      },
      entities: [
        { kind: 'tenant' as const, logicalId: 'default', runtimeId: 'default' },
        { kind: 'user' as const, logicalId: 'phase1-user', runtimeId: 'runtime-user-a' },
        {
          kind: 'application' as const,
          logicalId: 'phase1-browser',
          runtimeId: 'runtime-client-a',
        },
        {
          kind: 'user' as const,
          logicalId: 'consent.primary.user-b',
          runtimeId: 'runtime-user-b',
        },
        {
          kind: 'application' as const,
          logicalId: 'consent.primary.client-b',
          runtimeId: 'runtime-client-b',
        },
      ],
    },
    {
      allocationId: foreignAllocationId,
      role: 'foreign' as const,
      target: 'foreign' as const,
      isolation: {
        persistenceId: 'foreign-persistence',
        cookieKeyId: 'foreign-cookie-key',
        signingKeyId: 'foreign-signing-key',
      },
      entities: [
        { kind: 'tenant' as const, logicalId: 'default', runtimeId: 'default' },
        {
          kind: 'user' as const,
          logicalId: 'consent.foreign.user-b',
          runtimeId: 'runtime-foreign-user',
        },
        {
          kind: 'application' as const,
          logicalId: 'consent.foreign.client-b',
          runtimeId: 'runtime-foreign-client',
        },
      ],
    },
  ],
};
const profile = {
  fixtures: {
    dataTenant: {
      subject: { id: 'phase1-user', username: 'phase1-user' },
      applications: [
        {
          id: 'phase1-browser',
          isThirdParty: true,
          oidcClientMetadata: { redirectUris: ['https://client.example/callback'] },
        },
      ],
    },
  },
  oidc: { authorizationPath: '/oidc/auth', issuerPath: '/oidc' },
};
const baselineState = {
  body: { observed: true },
  semanticState: {
    interactions: { a: 'missing', b: 'present', foreign: 'present' },
    principals: { a: 'active', b: 'active', foreign: 'active' },
  },
  persistedState: {
    a: { grants: 1, issuances: 1, sessionExtensions: 1, firstConsentBindings: 1 },
    b: { grants: 0, issuances: 0, sessionExtensions: 0, firstConsentBindings: 0 },
    foreign: { grants: 0, issuances: 0, sessionExtensions: 0, firstConsentBindings: 0 },
  },
  generatedIds: {},
  sideEffects: {
    grantDelta: 0,
    issuanceDelta: 0,
    sessionExtensionDelta: 0,
    firstConsentBindingDelta: 0,
  },
};
const acceptedBState = {
  ...baselineState,
  persistedState: {
    ...baselineState.persistedState,
    b: { grants: 1, issuances: 0, sessionExtensions: 1, firstConsentBindings: 1 },
  },
  sideEffects: {
    grantDelta: 1,
    issuanceDelta: 0,
    sessionExtensionDelta: 1,
    firstConsentBindingDelta: 1,
  },
};
const resumedBState = {
  ...acceptedBState,
  semanticState: {
    ...acceptedBState.semanticState,
    interactions: { a: 'missing', b: 'missing', foreign: 'present' },
  },
  persistedState: {
    ...acceptedBState.persistedState,
    b: { ...acceptedBState.persistedState.b, issuances: 1 },
  },
  sideEffects: { ...acceptedBState.sideEffects, issuanceDelta: 1 },
};

const response = (
  status: number,
  body: unknown = '',
  headers: ReadonlyArray<readonly [string, string]> = []
) => ({ status, headers, body: typeof body === 'string' ? body : JSON.stringify(body) });

const readInteractionPair = (header: string | undefined) => {
  const entries = (header ?? '').split(';').flatMap((item) => {
    const separator = item.indexOf('=');

    return separator < 1
      ? []
      : ([[item.slice(0, separator).trim(), item.slice(separator + 1).trim()]] as const);
  });
  const values = new Map(entries);

  return Object.freeze({
    interaction: values.get('_interaction'),
    signature: values.get('_interaction.sig'),
    count: values.size,
  });
};

type HarnessOptions = Readonly<{
  mutateState?: (
    stepId: string,
    state: typeof baselineState | typeof acceptedBState | typeof resumedBState
  ) => unknown;
  mutateCallback?: (callback: URL) => URL;
  encodedLeak?: 'verification' | 'cookie';
}>;

const encodeAll = (value: string) =>
  Buffer.from(value, 'utf8')
    .toString('hex')
    .match(/.{2}/gu)
    ?.map((byte) => `%${byte}`)
    .join('') ?? '';

const createHarness = ({ mutateState, mutateCallback, encodedLeak }: HarnessOptions = {}) => {
  const sourceStores = new Map<string, MemoryProtocolSecretStore>();
  const authorizationStates = new Map<string, string>();
  const setupRequests: Array<Readonly<{ label: string; operation: string }>> = [];
  const derivedRequests: Array<
    Readonly<{
      operation: string;
      store: MemoryProtocolSecretStore;
      options: ProtocolRequestOptions;
    }>
  > = [];
  const createClients: NonNullable<ConsentBoundaryScenarioOptions['createClients']> = ({
    label,
    target: sessionTarget,
    store,
  }) => {
    sourceStores.set(label, store);
    const oidc = {
      store,
      request: import.meta.jest.fn(
        async (operation: string, path: string, _options?: ProtocolRequestOptions) => {
          setupRequests.push({ label, operation });
          if (operation.endsWith('-authorization')) {
            const authorizationState = new URL(path, sessionTarget.coreUrl).searchParams.get(
              'state'
            );

            if (!authorizationState) {
              throw new Error('authorization state unavailable');
            }
            authorizationStates.set(label, authorizationState);
            store.setCookie(
              `_interaction=login-${label}-private; Path=/; HttpOnly`,
              new URL(sessionTarget.coreUrl)
            );
            store.setCookie(
              `_interaction.sig=login-signature-${label}-private; Path=/; HttpOnly`,
              new URL(sessionTarget.coreUrl)
            );
            return response(303, '', [['location', '/sign-in']]);
          }
          if (operation.endsWith('-bridge')) {
            store.setCookie(
              `_interaction=consent-${label}-private; Path=/; HttpOnly`,
              new URL(sessionTarget.coreUrl)
            );
            store.setCookie(
              `_interaction.sig=consent-signature-${label}-private; Path=/; HttpOnly`,
              new URL(sessionTarget.coreUrl)
            );
            return response(303, '', [['location', `/consent?app_id=runtime-client-${label}`]]);
          }
          if (operation === 'consent-boundary-a-resume') {
            if (label !== 'a') {
              throw new Error('unexpected A resume client');
            }

            return response(303, '', [
              ['location', 'https://client.example/callback?code=private'],
            ]);
          }
          if (operation === 'consent-boundary-b-resume') {
            if (label !== 'b') {
              throw new Error('unexpected B resume client');
            }
            const authorizationState = authorizationStates.get('b');

            if (!authorizationState) {
              throw new Error('authorization state unavailable');
            }

            const callback = new URL('https://client.example/callback');
            callback.searchParams.set('code', 'authorization-code-b-private');
            callback.searchParams.set('state', authorizationState);
            callback.searchParams.set('iss', 'https://oracle.example/oidc');

            return response(303, '', [['location', (mutateCallback?.(callback) ?? callback).href]]);
          }
          throw new Error(`unexpected oidc operation ${operation}`);
        }
      ),
    };
    const experience = {
      store,
      requestExperience: import.meta.jest.fn(
        async (operation: string, _path: string, _options?: ProtocolRequestOptions) => {
          setupRequests.push({ label, operation });

          if (operation.endsWith('-bootstrap') || operation.endsWith('-identify')) {
            return response(204);
          }
          if (operation.endsWith('-password')) {
            return response(200, { verificationId: `verification-${label}-private` }, [
              ['content-type', 'application/json'],
            ]);
          }
          if (operation.endsWith('-submit')) {
            return response(
              200,
              { redirectTo: `${sessionTarget.coreUrl}oidc/auth/login-${label}-resume-private` },
              [['content-type', 'application/json']]
            );
          }
          throw new Error(`unexpected experience operation ${operation}`);
        }
      ),
    };
    const consent = {
      store,
      requestConsent: import.meta.jest.fn(
        async (operation: string, _path: string, _options?: ProtocolRequestOptions) => {
          setupRequests.push({ label, operation });
          if (operation === 'consent-boundary-a-accept') {
            return response(
              200,
              { redirectTo: `${sessionTarget.coreUrl}oidc/auth/consent-a-resume-private` },
              [['content-type', 'application/json']]
            );
          }
          if (operation === 'consent-boundary-get-valid-b') {
            return response(
              200,
              {
                application: { id: 'runtime-client-b', name: 'Client B' },
                user: { id: 'runtime-user-b', username: 'phase1-user_boundary_b' },
                organizations: [],
                missingOIDCScope: [],
                missingResourceScopes: [],
                redirectUri: 'https://client.example/callback',
              },
              [['content-type', 'application/json']]
            );
          }
          if (operation === 'consent-boundary-post-valid-b') {
            return response(
              200,
              { redirectTo: `${sessionTarget.coreUrl}oidc/auth/consent-b-resume-private` },
              [['content-type', 'application/json']]
            );
          }
          throw new Error(`unexpected consent operation ${operation}`);
        }
      ),
    };

    return { oidc, experience, consent };
  };
  const requestDerivedConsent: NonNullable<
    ConsentBoundaryScenarioOptions['requestDerivedConsent']
  > = async ({ operation, store, options }) => {
    derivedRequests.push({ operation, store, options });
    const variant = operation.replace(/^consent-boundary-(?:get|post)-/u, '');
    const primaryConsentUrl = new URL('/api/interaction/consent', target.coreUrl);
    const foreignConsentUrl = new URL('/api/interaction/consent', foreignTarget.coreUrl);
    const sourceA = sourceStores.get('a');
    const sourceB = sourceStores.get('b');
    const sourceForeign = sourceStores.get('foreign');

    if (!sourceA || !sourceB || !sourceForeign) {
      throw new Error('consent source stores unavailable');
    }
    const pairA = readInteractionPair(sourceA.getCookieHeader(primaryConsentUrl));
    const pairB = readInteractionPair(sourceB.getCookieHeader(primaryConsentUrl));
    const pairForeign = readInteractionPair(sourceForeign.getCookieHeader(foreignConsentUrl));
    const derived = readInteractionPair(store.getCookieHeader(primaryConsentUrl));
    const isExpectedVariant =
      pairA.interaction !== undefined &&
      pairA.signature !== undefined &&
      pairB.signature !== undefined &&
      pairB.signature !== pairA.signature &&
      pairForeign.interaction !== undefined &&
      pairForeign.signature !== undefined &&
      (variant === 'absent'
        ? derived.count === 0
        : variant === 'partial'
          ? derived.count === 1 &&
            derived.interaction === pairA.interaction &&
            derived.signature === undefined
          : variant === 'tampered'
            ? derived.count === 2 &&
              derived.interaction === `${pairA.interaction}~` &&
              derived.signature === pairA.signature
            : variant === 'spliced'
              ? derived.count === 2 &&
                derived.interaction === pairA.interaction &&
                derived.signature === pairB.signature
              : variant === 'replayed'
                ? derived.count === 2 &&
                  derived.interaction === pairA.interaction &&
                  derived.signature === pairA.signature
                : variant === 'foreign'
                  ? derived.count === 2 &&
                    derived.interaction === pairForeign.interaction &&
                    derived.signature === pairForeign.signature
                  : false);

    if (!isExpectedVariant) {
      throw new Error('consent cookie variant wiring is invalid');
    }
    const replayed = variant === 'replayed';
    const clears = ['tampered', 'spliced', 'foreign'].includes(variant);
    const leaked =
      operation === 'consent-boundary-get-absent'
        ? encodedLeak === 'verification'
          ? encodeAll('verification-a-private')
          : encodedLeak === 'cookie'
            ? encodeAll('consent-a-private')
            : undefined
        : undefined;

    return response(
      400,
      {
        code: 'session.not_found',
        message: 'Session not found. Please go back and sign in again.',
        error: 'invalid_request',
        error_description: replayed
          ? 'interaction session not found'
          : 'interaction session id cookie not found',
      },
      [
        ['content-type', 'application/json; charset=utf-8'],
        ...(leaked ? ([['x-credential-leak', leaked]] as const) : []),
        ...(clears
          ? ([
              [
                'set-cookie',
                '_interaction.sig=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; httponly',
              ],
            ] as const)
          : []),
      ]
    );
  };
  const symbols = new SymbolTable();

  for (const entity of fixtureMap.allocations[0]!.entities) {
    symbols.bind(`${entity.kind}.${entity.logicalId}`, entity.runtimeId);
  }
  const projectScenarioState = import.meta.jest.fn(async ({ stepId }: { stepId: string }) => {
    const state =
      stepId === 'state'
        ? resumedBState
        : stepId === 'post-valid-b'
          ? acceptedBState
          : baselineState;

    return (mutateState?.(stepId, state) ?? state) as never;
  });
  const context = {
    profile: profile as never,
    target,
    fixture: {
      public: fixtureMap,
      foreignTarget,
      withSecretLease: async <Result>(
        use: (lease: { getPassword(id: string): string }) => Promise<Result>
      ) => use({ getPassword: (id) => `${id}-password-private` }),
    } as never,
    signal: new AbortController().signal,
    protocol: {
      publicOidc: {},
      publicSymbols: new SymbolTable(),
      forAllocation: () => ({}),
      symbolsFor: () => symbols,
    } as never,
    projectFixtureState: async () =>
      ({ schemaVersion: 1, recipe: 'consentBoundary', allocations: [] }) as never,
    projectScenarioState,
  } as unknown as Phase1ScenarioRunContext;

  return {
    context,
    options: { createClients, requestDerivedConsent },
    sourceStores,
    setupRequests,
    derivedRequests,
    projectScenarioState,
  };
};

describe('interaction.consent-session-boundary', () => {
  it('uses fresh rejection jars and permits only the valid B persisted delta', async () => {
    const harness = createHarness();
    const steps = await runInteractionConsentSessionBoundary(harness.context, harness.options);

    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'get-absent',
      'get-partial',
      'get-tampered',
      'get-spliced',
      'get-replayed',
      'get-foreign',
      'post-absent',
      'post-partial',
      'post-tampered',
      'post-spliced',
      'post-replayed',
      'post-foreign',
      'get-valid-b',
      'post-valid-b',
      'state',
    ]);
    expect(harness.derivedRequests).toHaveLength(12);
    expect(new Set(harness.derivedRequests.map(({ store }) => store))).toHaveProperty('size', 12);
    expect(
      harness.derivedRequests
        .filter(({ operation }) => operation.includes('-post-'))
        .every(({ options }) => options.body === JSON.stringify({}))
    ).toBe(true);
    expect(steps.find(({ stepId }) => stepId === 'get-absent')?.value.cookies).toEqual([]);
    expect(steps.find(({ stepId }) => stepId === 'get-tampered')?.value.cookies).toMatchObject([
      { name: '_interaction.sig', path: '/', httpOnly: true },
    ]);
    expect(steps.find(({ stepId }) => stepId === 'get-spliced')?.value.status).toBe(400);
    expect(steps.find(({ stepId }) => stepId === 'get-replayed')?.value.error).toMatchObject({
      error_description: 'interaction session not found',
    });
    expect(steps.find(({ stepId }) => stepId === 'post-valid-b')?.value).toMatchObject({
      status: 200,
      error: null,
      redirect: { resumeCredential: expect.any(String) },
    });
    expect(
      harness.setupRequests.filter(({ operation }) => operation === 'consent-boundary-b-resume')
    ).toEqual([{ label: 'b', operation: 'consent-boundary-b-resume' }]);
    expect(steps.find(({ stepId }) => stepId === 'state')?.value).toMatchObject({
      semanticState: {
        interactions: { a: 'missing', b: 'missing', foreign: 'present' },
      },
      persistedState: {
        b: { grants: 1, issuances: 1, sessionExtensions: 1, firstConsentBindings: 1 },
      },
      sideEffects: { issuanceDelta: 1 },
    });
    expect(harness.projectScenarioState).toHaveBeenCalledTimes(15);
    for (const label of ['a', 'b', 'foreign']) {
      const source = harness.sourceStores.get(label);
      expect(source).toBeInstanceOf(MemoryProtocolSecretStore);
      expect(() =>
        source?.deriveInteractionCookieStore(
          new URL(
            '/api/interaction/consent',
            label === 'foreign' ? foreignTarget.coreUrl : target.coreUrl
          ),
          new URL('/api/interaction/consent', target.coreUrl),
          'exact'
        )
      ).not.toThrow();
    }
  });

  it('rejects a spliced jar wired with the source signature', async () => {
    const original = MemoryProtocolSecretStore.prototype.deriveInteractionCookieStore;
    const derive = import.meta.jest
      .spyOn(MemoryProtocolSecretStore.prototype, 'deriveInteractionCookieStore')
      .mockImplementation(function (
        this: MemoryProtocolSecretStore,
        sourceUrl,
        destinationUrl,
        variant,
        peer
      ) {
        return original.call(
          this,
          sourceUrl,
          destinationUrl,
          variant === 'spliced' ? 'exact' : variant,
          peer
        );
      });
    const harness = createHarness();

    try {
      await expect(
        runInteractionConsentSessionBoundary(harness.context, harness.options)
      ).rejects.toThrow('consent cookie variant wiring is invalid');
    } finally {
      derive.mockRestore();
    }
  });

  it.each([
    [
      'wrong state',
      (callback: URL) => {
        callback.searchParams.set('state', 'wrong-state-private');
        return callback;
      },
    ],
    [
      'wrong issuer',
      (callback: URL) => {
        callback.searchParams.set('iss', 'https://wrong-issuer.example/oidc');
        return callback;
      },
    ],
    [
      'wrong redirect origin',
      (callback: URL) =>
        new URL(`${callback.pathname}${callback.search}`, 'https://wrong-client.example'),
    ],
    [
      'wrong redirect path',
      (callback: URL) => new URL(`/wrong-callback${callback.search}`, callback.origin),
    ],
    [
      'missing code',
      (callback: URL) => {
        callback.searchParams.delete('code');
        return callback;
      },
    ],
    [
      'duplicate code',
      (callback: URL) => {
        callback.searchParams.append('code', 'second-authorization-code-private');
        return callback;
      },
    ],
    [
      'OAuth error',
      (callback: URL) => {
        callback.searchParams.set('error', 'access_denied');
        return callback;
      },
    ],
  ] as const)('rejects a B callback with %s', async (_name, mutateCallback) => {
    const harness = createHarness({ mutateCallback });

    await expect(
      runInteractionConsentSessionBoundary(harness.context, harness.options)
    ).rejects.toThrow('Phase 1 consent boundary B callback is invalid');
  });

  it.each([
    [
      'A replay baseline',
      (state: typeof baselineState) => ({
        ...state,
        persistedState: { ...state.persistedState, a: { ...state.persistedState.a, grants: 2 } },
      }),
    ],
    [
      'foreign boundary',
      (state: typeof baselineState) => ({
        ...state,
        persistedState: {
          ...state.persistedState,
          foreign: { ...state.persistedState.foreign, grants: 1 },
        },
      }),
    ],
  ])('rejects mutation of the %s during a rejection', async (_name, mutate) => {
    const harness = createHarness({
      mutateState: (stepId, state) =>
        stepId === 'get-absent' ? mutate(state as typeof baselineState) : state,
    });

    await expect(
      runInteractionConsentSessionBoundary(harness.context, harness.options)
    ).rejects.toThrow('Phase 1 consent boundary state is invalid');
  });

  it.each(['verification', 'cookie'] as const)(
    'rejects a fully percent-encoded %s leak in a rejection response header',
    async (encodedLeak) => {
      const harness = createHarness({ encodedLeak });

      await expect(
        runInteractionConsentSessionBoundary(harness.context, harness.options)
      ).rejects.toThrow('Phase 1 consent rejection projection failed: get-absent');
    }
  );
});

/* eslint-enable max-lines, complexity, max-params, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment */
