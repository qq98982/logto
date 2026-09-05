/* eslint-disable @typescript-eslint/ban-types, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-explicit-any, @typescript-eslint/no-loop-func, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/restrict-plus-operands, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, max-nested-callbacks, unicorn/consistent-function-scoping, unicorn/no-array-for-each -- The full 22-row authority uses deliberate runtime mutations so every individual field is proven authoritative. */
import { createHash } from 'node:crypto';

import {
  assertExactScenarioContracts,
  assertExactScenarioProjectionSchema,
  commonNormalizationPointers,
  compileScenarioContract,
  compileScenarioNormalizablePointers,
  phase1ScenarioContracts,
  type Phase1ScenarioContract,
} from './scenario-contracts.js';

const expectedRows = [
  {
    id: 'discovery.config',
    steps: ['oidc-discovery:http', 'oauth-discovery:http', 'jwks:http'],
    explicit: [
      '/steps/jwks/value/body/keys/*/kid',
      '/steps/jwks/value/body/keys/*/publicKeyFingerprint',
    ],
  },
  {
    id: 'authorization.password-pkce-consent',
    steps: [
      'authorize:redirect+cookie-metadata',
      'experience-bootstrap:http+cookie-metadata',
      'password:http+cookie-metadata',
      'identify:http+cookie-metadata',
      'submit:http+cookie-metadata',
      'consent-get:http+cookie-metadata',
      'consent-post:http+redirect+cookie-metadata',
      'resume:redirect+cookie-metadata',
      'callback:redirect',
      'state:semantic-state',
    ],
    explicit: [
      '/steps/authorize/value/generatedIds/interaction',
      '/steps/consent-post/value/redirect/resumeCredential',
      '/steps/state/value/semanticState/session/updatedAt',
    ],
  },
  {
    id: 'token.authorization-code',
    steps: ['token:http+jwt-header+jwt-claims', 'state:semantic-state'],
    explicit: [
      '/steps/token/value/tokens/*/claims/iat',
      '/steps/token/value/tokens/*/claims/exp',
      '/steps/token/value/tokens/*/claims/auth_time',
      '/steps/token/value/tokens/*/claims/created_at',
      '/steps/token/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'token.refresh-rotation',
    steps: [
      'code-token:http',
      'refresh-token:http+jwt-header+jwt-claims',
      'family-state:semantic-state',
    ],
    explicit: [
      '/steps/refresh-token/value/tokens/*/claims/iat',
      '/steps/refresh-token/value/tokens/*/claims/exp',
      '/steps/refresh-token/value/tokens/*/claims/created_at',
      '/steps/refresh-token/value/tokens/*/claims/updated_at',
      '/steps/family-state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'userinfo.openid',
    steps: ['userinfo:http', 'state:semantic-state'],
    explicit: ['/steps/userinfo/value/body/created_at', '/steps/userinfo/value/body/updated_at'],
  },
  {
    id: 'management.application-read',
    steps: ['first-party:http', 'third-party:http', 'saml:http', 'state:semantic-state'],
    explicit: [
      '/steps/first-party/value/body/*/createdAt',
      '/steps/third-party/value/body/*/createdAt',
    ],
  },
  {
    id: 'management.user-read',
    steps: ['users:http', 'state:semantic-state'],
    explicit: ['/steps/users/value/body/*/createdAt', '/steps/users/value/body/*/updatedAt'],
  },
  {
    id: 'console.admin-auth-resource-refresh',
    steps: [
      'authorize:redirect+cookie-metadata',
      'code-token:http',
      'management-refresh:http+jwt-header+jwt-claims',
      'state:semantic-state',
    ],
    explicit: [
      '/steps/authorize/value/generatedIds/interaction',
      '/steps/management-refresh/value/tokens/*/claims/iat',
      '/steps/management-refresh/value/tokens/*/claims/exp',
      '/steps/management-refresh/value/tokens/*/claims/created_at',
      '/steps/management-refresh/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'console.admin-organization-token-refresh',
    steps: ['organization-refresh:http+jwt-header+jwt-claims', 'state:semantic-state'],
    explicit: [
      '/steps/organization-refresh/value/tokens/*/claims/iat',
      '/steps/organization-refresh/value/tokens/*/claims/exp',
      '/steps/organization-refresh/value/tokens/*/claims/created_at',
      '/steps/organization-refresh/value/tokens/*/claims/updated_at',
    ],
  },
  {
    id: 'account.admin-operator-read',
    steps: ['account:http', 'state:semantic-state'],
    explicit: [
      '/steps/account/value/body/createdAt',
      '/steps/account/value/body/updatedAt',
      '/steps/account/value/body/lastSignInAt',
    ],
  },
  {
    id: 'cors.management-list',
    steps: [
      'applications-preflight:http',
      'users-preflight:http',
      'applications-get:http',
      'users-get:http',
    ],
    explicit: [],
  },
  {
    id: 'cookie.localhost-port-interleaving',
    steps: [
      'admin-start:redirect+cookie-metadata',
      'data-start:redirect+cookie-metadata',
      'admin-finish:redirect+cookie-metadata',
      'data-finish:redirect+cookie-metadata',
      'data-start-reverse:redirect+cookie-metadata',
      'admin-start-reverse:redirect+cookie-metadata',
      'data-finish-reverse:redirect+cookie-metadata',
      'admin-finish-reverse:redirect+cookie-metadata',
      'state:semantic-state',
    ],
    explicit: ['/steps/*/value/generatedIds/interaction'],
  },
  {
    id: 'authorization.redirect-uri-rejected',
    steps: ['authorize:http+cookie-metadata', 'state:semantic-state'],
    explicit: [],
  },
  {
    id: 'authorization.pkce-method-rejected',
    steps: ['authorize:http+redirect+cookie-metadata', 'state:semantic-state'],
    explicit: [],
  },
  {
    id: 'token.pkce-verifier-rejected',
    steps: ['bad-verifier:http', 'valid-verifier-probe:http', 'state:semantic-state'],
    explicit: ['/steps/state/value/generatedIds/tokenFamily'],
  },
  {
    id: 'token.code-reuse-rejected',
    steps: ['first-exchange:http+jwt-header+jwt-claims', 'replay:http', 'state:semantic-state'],
    explicit: [
      '/steps/first-exchange/value/tokens/*/claims/iat',
      '/steps/first-exchange/value/tokens/*/claims/exp',
      '/steps/first-exchange/value/tokens/*/claims/created_at',
      '/steps/first-exchange/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'interaction.password-rejected',
    steps: [
      'experience-bootstrap:http+cookie-metadata',
      'password:http+cookie-metadata',
      'state:semantic-state',
    ],
    explicit: ['/steps/experience-bootstrap/value/generatedIds/interaction'],
  },
  {
    id: 'interaction.consent-session-boundary',
    steps: [
      'get-absent:http+cookie-metadata',
      'get-partial:http+cookie-metadata',
      'get-tampered:http+cookie-metadata',
      'get-spliced:http+cookie-metadata',
      'get-replayed:http+cookie-metadata',
      'get-foreign:http+cookie-metadata',
      'post-absent:http+cookie-metadata',
      'post-partial:http+cookie-metadata',
      'post-tampered:http+cookie-metadata',
      'post-spliced:http+cookie-metadata',
      'post-replayed:http+cookie-metadata',
      'post-foreign:http+cookie-metadata',
      'get-valid-b:http+cookie-metadata',
      'post-valid-b:http+redirect+cookie-metadata',
      'state:semantic-state',
    ],
    explicit: [
      '/steps/post-valid-b/value/redirect/resumeCredential',
      '/steps/state/value/semanticState/session/updatedAt',
    ],
  },
  {
    id: 'token.refresh-reuse-rejected',
    steps: [
      'code-token:http',
      'rotate:http',
      'replay-old:http',
      'probe-descendant:http',
      'state:semantic-state',
    ],
    explicit: [
      '/steps/rotate/value/tokens/*/claims/iat',
      '/steps/rotate/value/tokens/*/claims/exp',
      '/steps/rotate/value/tokens/*/claims/created_at',
      '/steps/rotate/value/tokens/*/claims/updated_at',
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'token.issuer-audience-scope-rejected',
    steps: [
      'wrong-issuer:http',
      'wrong-audience:http',
      'missing-scope:http',
      'state:semantic-state',
    ],
    explicit: [],
  },
  {
    id: 'token.concurrent-code-single-winner',
    steps: ['attempt-a:http', 'attempt-b:http', 'race:semantic-state', 'state:semantic-state'],
    explicit: ['/steps/race/value/outcomes'],
  },
  {
    id: 'token.concurrent-refresh-single-winner',
    steps: ['attempt-a:http', 'attempt-b:http', 'race:semantic-state', 'state:semantic-state'],
    explicit: [
      '/steps/race/value/outcomes',
      '/steps/state/value/generatedIds/tokenFamily',
      '/steps/*/value/tokens/*/claims/iat',
      '/steps/*/value/tokens/*/claims/exp',
      '/steps/*/value/tokens/*/claims/created_at',
      '/steps/*/value/tokens/*/claims/updated_at',
    ],
  },
] as const;

const stepText = (contract: Phase1ScenarioContract) =>
  contract.orderedSteps.map(({ id, kinds }) => `${id}:${kinds.join('+')}`);

const allKinds = [
  'http',
  'redirect',
  'cookie-metadata',
  'jwt-header',
  'jwt-claims',
  'semantic-state',
] as const;

const mutate = (
  contract: Phase1ScenarioContract,
  update: (copy: any) => void
): Phase1ScenarioContract => {
  const copy = structuredClone(contract) as any;
  update(copy);
  return copy as Phase1ScenarioContract;
};

const expectedKindRuleSignatures = {
  http: [
    'exact status',
    'exact mediaType/**',
    'exact mediaType/type',
    'exact mediaType/subtype',
    'exact mediaType/parameters/*/*',
    'exact error/**',
    'target-symbol error/iss',
    'target-symbol error/issuer',
    'exact headers/*/*',
    'bounded-timestamp headers/date/*',
    'sanitized-body-byte-length headers/content-length/*',
    'exact body/**',
    'target-symbol body/iss',
    'target-symbol body/issuer',
    'exact sideEffects/**',
    'exact urls/*/**',
    'exact urls/*/scheme',
    'target-symbol urls/*/origin',
    'exact urls/*/path',
    'exact urls/*/query/*/*',
    'generated-id urls/*/query/app_id/*',
    'target-symbol urls/*/query/iss/*',
    'exact urls/*/fragment',
  ],
  redirect: [
    'exact redirect/**',
    'exact redirect/scheme',
    'target-symbol redirect/origin',
    'exact redirect/path',
    'exact redirect/query/*/*',
    'generated-id redirect/query/app_id/*',
    'target-symbol redirect/query/iss/*',
    'exact redirect/fragment',
  ],
  'cookie-metadata': [
    'exact cookies/*/**',
    'exact cookies/*/name',
    'exact cookies/*/httpOnly',
    'exact cookies/*/secure',
    'exact cookies/*/sameSite',
    'exact cookies/*/path',
    'exact cookies/*/domain',
    'exact cookies/*/maxAge',
    'bounded-timestamp cookies/*/expires',
  ],
  'jwt-header': [
    'exact tokens/*/header/**',
    'exact tokens/*/header/alg',
    'generated-id tokens/*/header/kid',
  ],
  'jwt-claims': [
    'exact tokens/*/claims/**',
    'target-symbol tokens/*/claims/iss',
    'exact tokens/*/claims/aud',
    'exact tokens/*/claims/scope',
    'bounded-timestamp tokens/*/claims/iat',
    'bounded-timestamp tokens/*/claims/exp',
    'bounded-timestamp tokens/*/claims/auth_time',
    'generated-id tokens/*/claims/jti',
    'generated-id tokens/*/claims/sid',
  ],
  'semantic-state': ['exact **', 'exact persistedState/**', 'exact sideEffects/**'],
} as const;

const goldenDigest = (...parts: readonly string[]) => parts.join('');

const expectedScenarioAuthorityDigests = {
  'discovery.config': '849bedae16eab47b34128f8b8f7b7aff80db40d55f230c99a6ef37e62a38556b',
  'authorization.password-pkce-consent':
    '54087afde0b2bdd68622a8de1b8327ce86629362c490750a6c3c58bfe2c72aa6',
  'token.authorization-code': goldenDigest(
    '59826f21de2bbb8e',
    '2e49eda89fee1fc6',
    'c91c2cbcbd9b0359',
    '0dc70633841f2c66'
  ),
  'token.refresh-rotation': goldenDigest(
    '4520fa374d877b27',
    'fbd44e70e4e9cc9e',
    'c8459e3af1b16513',
    'ab95d2a6adfe2329'
  ),
  'userinfo.openid': 'e3694ee8b1518679e0d4ed589581dff962b1fcdcb74c0c71ea03ef4cd91dd1bb',
  'management.application-read': '616e978e50c7fd4fdd4c2094c7719f130a738efa7aedd3b1b9f12c5513216a4a',
  'management.user-read': 'a5a56d5748ac4ef7fc02b7b13cda98560942c8645c60c9e07f248c748c6f5652',
  'console.admin-auth-resource-refresh':
    '9aeeacaa5925665bb0c7d7ec15c258f8d6f8b2fa18062698a9a8accee199bffd',
  'console.admin-organization-token-refresh':
    '0e6d4d97e1e3eb85d886230e0711d030e210e45512650f32108084d9b37b2f0f',
  'account.admin-operator-read': 'd2ec1a35292a0925b6414ce17ccba9e18418884fd23132ad5a6f241e90200ccc',
  'cors.management-list': 'c6408d82d5980f6bc877fd7f8a4103821325ec896cbf1a1c0eaedb909a512e18',
  'cookie.localhost-port-interleaving':
    '5dcef7e3c51903adb5a6269d646a8ca21d139772319210da44d8e234540fd681',
  'authorization.redirect-uri-rejected':
    '0d7dd564d31aa4a122023355a19c5a619a3bc5aeb294e92f2c5072e50b288394',
  'authorization.pkce-method-rejected':
    'cf47390ba1854c7edebeb8581cf085baec6795b31e7e10e20adeb1155e5d2b66',
  'token.pkce-verifier-rejected':
    '8f5585a5e8fe73789fb052453895c66d44f1f80cf73560ba3504c036462d891c',
  'token.code-reuse-rejected': goldenDigest(
    'a5a422589a416865',
    'c5a3173c783a8a09',
    'cca8c6bb970661b6',
    'ab86d7751f4f90f0'
  ),
  'interaction.password-rejected':
    '4223430804f75f4c7e1fe8e250a1513c87614d477e4bc178b6b7b58082ec9292',
  'interaction.consent-session-boundary':
    '8ac08dbae83e12bb1975626c33a439598987ae14d4d6feb0f01b325d99f854c7',
  'token.refresh-reuse-rejected':
    '1b1cd8788f6af5549e9ad10e818846ee8e55b6df32e768ad8fcc788d07c7f096',
  'token.issuer-audience-scope-rejected':
    '7ab2d12fef9b3748a59d552105ce43d2ab2775fb13fd1881c94e712dd4eb8bc8',
  'token.concurrent-code-single-winner':
    'e72dacabad66a0a3e17291aaa37909be1696d61dd0469c7cc0dda255ac053be3',
  'token.concurrent-refresh-single-winner':
    'c70fc94d8b8242956ff0b80288ac82947b91e1d520b3b4e5e54ca9d77a2539a2',
} as const satisfies Record<Phase1ScenarioContract['id'], string>;

describe('phase 1 observation and normalization contract', () => {
  const malformedArrays = <Value>(valid: readonly Value[]): readonly unknown[] => {
    const holeAt = (index: number) => {
      const value = [...valid];
      Reflect.deleteProperty(value, String(index));
      return value;
    };
    const extra = [...valid];
    Object.defineProperty(extra, 'extra', { enumerable: true, value: true });
    const symbol = [...valid];
    Object.defineProperty(symbol, Symbol('extra'), { enumerable: true, value: true });
    const accessor = [...valid];
    Object.defineProperty(accessor, '0', { enumerable: true, get: () => valid[0] });
    const wrongPrototype = [...valid];
    Object.setPrototypeOf(wrongPrototype, null);

    return [
      holeAt(0),
      holeAt(Math.floor(valid.length / 2)),
      holeAt(valid.length - 1),
      { 0: valid[0], length: valid.length, some: Array.prototype.some },
      extra,
      symbol,
      accessor,
      new Proxy([...valid], {
        ownKeys: () => {
          throw new Error('must not escape');
        },
      }),
      new Proxy([...valid], {
        getOwnPropertyDescriptor: () => {
          throw new Error('must not escape');
        },
      }),
      wrongPrototype,
    ];
  };

  const malformedRecords = <Value extends object>(
    valid: Value,
    accessorKey: keyof Value & string
  ): readonly unknown[] => {
    const extra = { ...valid, injected: true };
    const nonEnumerable = { ...valid };
    Object.defineProperty(nonEnumerable, 'injected', { enumerable: false, value: true });
    const symbol = { ...valid };
    Object.defineProperty(symbol, Symbol('injected'), { enumerable: true, value: true });
    const accessor = { ...valid };
    Object.defineProperty(accessor, accessorKey, {
      enumerable: true,
      get: () => valid[accessorKey],
    });
    const wrongPrototype = { ...valid };
    Object.setPrototypeOf(wrongPrototype, null);

    return [
      extra,
      nonEnumerable,
      symbol,
      accessor,
      new Proxy({ ...valid }, {}),
      new Proxy(
        { ...valid },
        {
          getOwnPropertyDescriptor: () => {
            throw new Error('must not escape');
          },
        }
      ),
      wrongPrototype,
    ];
  };

  it('rejects malformed arrays at both scenario contract validator boundaries', () => {
    expect(() =>
      assertExactScenarioContracts(Object.freeze([...phase1ScenarioContracts]))
    ).not.toThrow();
    const discoverySchema = compileScenarioContract(phase1ScenarioContracts[0]!).projectionSchema;
    expect(() =>
      assertExactScenarioProjectionSchema('discovery.config', Object.freeze([...discoverySchema]))
    ).not.toThrow();

    for (const invalid of malformedArrays(phase1ScenarioContracts)) {
      expect(() => assertExactScenarioContracts(invalid as never)).toThrow(
        /^Invalid phase 1 scenario contract registry$/u
      );
    }
    for (const invalid of malformedArrays(discoverySchema)) {
      expect(() =>
        assertExactScenarioProjectionSchema('discovery.config', invalid as never)
      ).toThrow(/^Invalid phase 1 projection schema$/u);
    }
  });

  it('rejects unsafe root nested-step and projection-rule records before comparison', () => {
    const canonical = phase1ScenarioContracts[0]!;

    for (const malformed of malformedRecords(canonical, 'id')) {
      const registry = [malformed, ...phase1ScenarioContracts.slice(1)];
      expect(() => assertExactScenarioContracts(registry as never)).toThrow(
        /^Invalid phase 1 scenario contract registry$/u
      );
      expect(() => compileScenarioContract(malformed as never)).toThrow(
        /^Invalid phase 1 scenario contract$/u
      );
    }
    const firstStep = canonical.orderedSteps[0]!;
    for (const malformed of malformedRecords(firstStep, 'id')) {
      const contract = {
        ...canonical,
        orderedSteps: [malformed, ...canonical.orderedSteps.slice(1)],
      };
      expect(() =>
        assertExactScenarioContracts([contract, ...phase1ScenarioContracts.slice(1)] as never)
      ).toThrow(/^Invalid phase 1 scenario contract registry$/u);
    }
    const schema = compileScenarioContract(canonical).projectionSchema;
    const firstRule = schema[0]!;
    for (const malformed of malformedRecords(firstRule, 'path')) {
      expect(() =>
        assertExactScenarioProjectionSchema('discovery.config', [
          malformed,
          ...schema.slice(1),
        ] as never)
      ).toThrow(/^Invalid phase 1 projection schema$/u);
    }
  });

  it('encodes every row with exact ordered step IDs kinds and explicit pointers', () => {
    expect(phase1ScenarioContracts).toHaveLength(22);
    expect(phase1ScenarioContracts.map(({ id }) => id)).toEqual(expectedRows.map(({ id }) => id));

    expectedRows.forEach((expected, index) => {
      const actual = phase1ScenarioContracts[index];

      expect(actual?.id).toBe(expected.id);
      expect(actual && stepText(actual)).toEqual(expected.steps);
      expect(actual?.explicitNormalizablePointers).toEqual(expected.explicit);
    });
  });

  it('locks the complete reusable pointer vocabulary in plan order', () => {
    expect(commonNormalizationPointers).toEqual([
      '/steps/*/value/headers/date/*',
      '/steps/*/value/headers/content-length/*',
      '/steps/*/value/cookies/*/expires',
      '/steps/*/value/error/iss',
      '/steps/*/value/error/issuer',
      '/steps/*/value/body/iss',
      '/steps/*/value/body/issuer',
      '/steps/*/value/redirect/origin',
      '/steps/*/value/redirect/query/app_id/*',
      '/steps/*/value/redirect/query/iss/*',
      '/steps/*/value/urls/*/origin',
      '/steps/*/value/urls/*/query/app_id/*',
      '/steps/*/value/urls/*/query/iss/*',
      '/steps/*/value/tokens/*/header/kid',
      '/steps/*/value/tokens/*/claims/iss',
      '/steps/*/value/tokens/*/claims/iat',
      '/steps/*/value/tokens/*/claims/exp',
      '/steps/*/value/tokens/*/claims/auth_time',
      '/steps/*/value/tokens/*/claims/jti',
      '/steps/*/value/tokens/*/claims/sid',
    ]);
  });

  it('compiles every canonical pointer to at least one projection path', () => {
    for (const contract of phase1ScenarioContracts) {
      const compiled = compileScenarioContract(contract);
      const coveredPaths = new Set(Object.values(compiled.resolvedProjectionPaths).flat());

      expect(compiled.normalizablePointers.length).toBeGreaterThan(0);
      for (const paths of Object.values(compiled.resolvedProjectionPaths)) {
        expect(paths.length).toBeGreaterThan(0);
      }
      for (const leaf of compiled.projectionSchema) {
        if (leaf.normalization !== 'exact') {
          expect(coveredPaths.has(leaf.path)).toBe(true);
        }
      }
    }
  });

  it('classifies Account last-sign-in time as a bounded timestamp', () => {
    const account = phase1ScenarioContracts.find(({ id }) => id === 'account.admin-operator-read');

    expect(account).toBeDefined();
    expect(
      compileScenarioContract(account!).projectionSchema.find(
        ({ path }) => path === '/steps/account/value/body/lastSignInAt'
      )
    ).toEqual({
      path: '/steps/account/value/body/lastSignInAt',
      normalization: 'bounded-timestamp',
    });
  });

  it('defines a closed classified projection leaf schema for every step kind', () => {
    for (const contract of phase1ScenarioContracts) {
      const schema = compileScenarioContract(contract).projectionSchema;

      for (const step of contract.orderedSteps) {
        const prefix = `/steps/${step.id}/value/`;
        const actualSignatures = schema
          .filter(({ path }) => path.startsWith(prefix))
          .map(({ path, normalization }) => `${normalization} ${path.slice(prefix.length)}`);

        for (const kind of step.kinds) {
          for (const signature of expectedKindRuleSignatures[kind]) {
            expect(actualSignatures).toContain(signature);
          }
        }
      }
    }
  });

  it('locks all 22 assembled authorities with independent golden digests', () => {
    for (const contract of phase1ScenarioContracts) {
      const compiled = compileScenarioContract(contract);
      const payload = {
        id: contract.id,
        orderedSteps: contract.orderedSteps,
        observationContract: contract.observationContract,
        normalizablePointers: contract.normalizablePointers,
        explicitNormalizablePointers: contract.explicitNormalizablePointers,
        projectionSchema: compiled.projectionSchema,
        resolvedProjectionPaths: compiled.resolvedProjectionPaths,
      };
      const digest = createHash('sha256').update(JSON.stringify(payload)).digest('hex');

      expect(digest).toBe(expectedScenarioAuthorityDigests[contract.id]);
    }
  });

  it('allows only kind-owned rules or exact scenario-specific resolved leaves', () => {
    for (const contract of phase1ScenarioContracts) {
      const compiled = compileScenarioContract(contract);
      const explicitPaths = new Set(
        contract.explicitNormalizablePointers.flatMap(
          (pointer) => compiled.resolvedProjectionPaths[pointer] ?? []
        )
      );

      for (const rule of compiled.projectionSchema) {
        const segments = rule.path.split('/');
        const stepId = segments[2];
        const step = contract.orderedSteps.find(({ id }) => id === stepId);
        const suffix = segments.slice(4).join('/');
        const signature = `${rule.normalization} ${suffix}`;
        const kindOwned =
          step?.kinds.some((kind) =>
            expectedKindRuleSignatures[kind].includes(signature as never)
          ) ?? false;

        expect(kindOwned || explicitPaths.has(rule.path)).toBe(true);
      }
    }
  });

  it('rejects deletion or reclassification of every required structural domain control', () => {
    const mutations = [
      ['discovery.config', '/steps/oidc-discovery/value/body/**', 'delete'],
      ['discovery.config', '/steps/oidc-discovery/value/mediaType/parameters/*/*', 'delete'],
      ['discovery.config', '/steps/oidc-discovery/value/headers/*/*', 'delete'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/cookies/*/secure', 'delete'],
      [
        'authorization.password-pkce-consent',
        '/steps/authorize/value/cookies/*/sameSite',
        'delete',
      ],
      [
        'authorization.password-pkce-consent',
        '/steps/authorize/value/redirect/query/*/*',
        'delete',
      ],
      ['authorization.password-pkce-consent', '/steps/authorize/value/redirect/fragment', 'delete'],
      ['authorization.password-pkce-consent', '/steps/state/value/sideEffects/**', 'delete'],
      ['token.authorization-code', '/steps/token/value/tokens/*/header/alg', 'reclassify'],
      ['token.authorization-code', '/steps/token/value/tokens/*/claims/iss', 'reclassify'],
      ['token.authorization-code', '/steps/token/value/tokens/*/claims/aud', 'reclassify'],
      ['token.authorization-code', '/steps/token/value/tokens/*/claims/scope', 'reclassify'],
    ] as const;

    for (const [id, path, operation] of mutations) {
      const contract = phase1ScenarioContracts.find((candidate) => candidate.id === id)!;
      const schema = compileScenarioContract(contract).projectionSchema;
      expect(schema.some((rule) => rule.path === path)).toBe(true);
      const mutated =
        operation === 'delete'
          ? schema.filter((rule) => rule.path !== path)
          : schema.map((rule) =>
              rule.path === path ? { ...rule, normalization: 'generated-id' as const } : rule
            );

      expect(() => assertExactScenarioProjectionSchema(id, mutated)).toThrow(
        /^Invalid phase 1 projection schema$/u
      );
    }
  });

  it('resolves every scenario-specific pointer inside the locked authority', () => {
    expectedRows.forEach((expected, index) => {
      const contract = phase1ScenarioContracts[index]!;
      const compiled = compileScenarioContract(contract);
      const nonExactPaths = new Set(
        compiled.projectionSchema
          .filter(({ normalization }) => normalization !== 'exact')
          .map(({ path }) => path)
      );

      for (const pointer of expected.explicit) {
        const resolved = compiled.resolvedProjectionPaths[pointer];

        expect(resolved?.length).toBeGreaterThan(0);
        expect(resolved?.every((path) => nonExactPaths.has(path))).toBe(true);
      }
    });
  });

  it('fails when a required generated timestamp or target leaf loses all pointer coverage', () => {
    for (const contract of phase1ScenarioContracts) {
      const compiled = compileScenarioContract(contract);
      const uniquelyRequiredPointer = contract.normalizablePointers.find((pointer) => {
        const paths = compiled.resolvedProjectionPaths[pointer] ?? [];

        return paths.some((path) =>
          contract.normalizablePointers.every(
            (other) =>
              other === pointer || !(compiled.resolvedProjectionPaths[other] ?? []).includes(path)
          )
        );
      });

      expect(uniquelyRequiredPointer).toBeDefined();
      expect(() =>
        compileScenarioNormalizablePointers(
          contract.id,
          contract.normalizablePointers.filter((pointer) => pointer !== uniquelyRequiredPointer)
        )
      ).toThrow(/^Invalid phase 1 scenario contract$/u);
    }
  });

  it('derives accepted status media header cookie and redirect observations exactly from kinds', () => {
    for (const contract of phase1ScenarioContracts) {
      const http = contract.orderedSteps
        .filter(({ kinds }) => kinds.includes('http'))
        .map(({ id }) => id);
      const cookies = contract.orderedSteps
        .filter(({ kinds }) => kinds.includes('cookie-metadata'))
        .map(({ id }) => id);
      const redirects = contract.orderedSteps
        .filter(({ kinds }) => kinds.includes('redirect'))
        .map(({ id }) => id);

      expect(contract.observationContract).toEqual({
        status: http,
        mediaType: http,
        headers: http,
        cookies,
        redirects,
      });
    }
  });

  it('rejects every ID step kind and explicit pointer mutation', () => {
    phase1ScenarioContracts.forEach((contract, contractIndex) => {
      expect(() =>
        assertExactScenarioContracts(
          phase1ScenarioContracts.map((item, index) =>
            index === contractIndex
              ? mutate(item, (copy) => {
                  copy.id = `${copy.id}.mutated`;
                })
              : item
          )
        )
      ).toThrow(/^Invalid phase 1 scenario contract registry$/u);

      contract.orderedSteps.forEach((step, stepIndex) => {
        expect(() =>
          assertExactScenarioContracts(
            phase1ScenarioContracts.map((item, index) =>
              index === contractIndex
                ? mutate(item, (copy) => {
                    copy.orderedSteps[stepIndex].id += '-mutated';
                  })
                : item
            )
          )
        ).toThrow(/^Invalid phase 1 scenario contract registry$/u);

        step.kinds.forEach((_kind, kindIndex) => {
          expect(() =>
            assertExactScenarioContracts(
              phase1ScenarioContracts.map((item, index) =>
                index === contractIndex
                  ? mutate(item, (copy) => {
                      copy.orderedSteps[stepIndex].kinds[kindIndex] = allKinds.find(
                        (candidate) => !copy.orderedSteps[stepIndex].kinds.includes(candidate)
                      );
                    })
                  : item
              )
            )
          ).toThrow(/^Invalid phase 1 scenario contract registry$/u);
        });
      });

      for (const property of ['status', 'mediaType', 'headers', 'cookies', 'redirects'] as const) {
        contract.observationContract[property].forEach((_stepId, observationIndex) => {
          expect(() =>
            assertExactScenarioContracts(
              phase1ScenarioContracts.map((item, index) =>
                index === contractIndex
                  ? mutate(item, (copy) => {
                      copy.observationContract[property][observationIndex] += '-mutated';
                    })
                  : item
              )
            )
          ).toThrow(/^Invalid phase 1 scenario contract registry$/u);
        });
      }

      contract.normalizablePointers.forEach((_pointer, pointerIndex) => {
        expect(() =>
          assertExactScenarioContracts(
            phase1ScenarioContracts.map((item, index) =>
              index === contractIndex
                ? mutate(item, (copy) => {
                    copy.normalizablePointers[pointerIndex] = '/steps/unknown/value/status';
                  })
                : item
            )
          )
        ).toThrow(/^Invalid phase 1 scenario contract registry$/u);
      });

      contract.explicitNormalizablePointers.forEach((_pointer, pointerIndex) => {
        expect(() =>
          assertExactScenarioContracts(
            phase1ScenarioContracts.map((item, index) =>
              index === contractIndex
                ? mutate(item, (copy) => {
                    copy.explicitNormalizablePointers[pointerIndex] = '/steps/unknown/value/status';
                  })
                : item
            )
          )
        ).toThrow(/^Invalid phase 1 scenario contract registry$/u);
      });
    });
  });

  it('rejects normalizers for status media error algorithm audience scope and unknown fields', () => {
    const forbidden = [
      ['discovery.config', '/steps/oidc-discovery/value/status'],
      ['discovery.config', '/steps/oidc-discovery/value/mediaType'],
      ['discovery.config', '/steps/oidc-discovery/value/error/code'],
      ['discovery.config', '/steps/oidc-discovery/value/headers/content-type/*'],
      ['discovery.config', '/steps/oidc-discovery/value/sideEffects/count'],
      ['discovery.config', '/steps/oidc-discovery/value/tokens/*/claims/iat'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/cookies/*/secure'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/cookies/*/sameSite'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/redirect/query/*/*'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/redirect/fragment'],
      ['authorization.password-pkce-consent', '/steps/state/value/tokens/*/claims/iat'],
      ['token.authorization-code', '/steps/token/value/tokens/*/header/alg'],
      ['token.authorization-code', '/steps/token/value/tokens/*/claims/aud'],
      ['token.authorization-code', '/steps/token/value/tokens/*/claims/scope'],
      ['discovery.config', '/steps/oidc-discovery/value/unknown'],
    ] as const;

    for (const [id, pointer] of forbidden) {
      expect(() => compileScenarioNormalizablePointers(id, [pointer])).toThrow(
        /^Invalid phase 1 scenario contract$/u
      );
    }
  });

  it('rejects a table pointer that is absent from the selected scenario schema', () => {
    const foreignPointer = phase1ScenarioContracts
      .find(({ id }) => id === 'token.authorization-code')
      ?.normalizablePointers.find((pointer) => pointer.includes('/tokens/'));

    expect(foreignPointer).toBeDefined();
    expect(() =>
      compileScenarioNormalizablePointers('discovery.config', [foreignPointer!])
    ).toThrow(/^Invalid phase 1 scenario contract$/u);
  });

  it('rejects empty missing duplicate extra reordered and cross-kind registries', () => {
    const first = phase1ScenarioContracts[0]!;
    const second = phase1ScenarioContracts[1]!;
    const crossKind = mutate(first, (copy) => {
      copy.id = 'tenant.cross-tenant-read-rejected';
    });
    const variants = [
      [],
      phase1ScenarioContracts.slice(0, -1),
      [...phase1ScenarioContracts, first],
      [first, first, ...phase1ScenarioContracts.slice(2)],
      [second, first, ...phase1ScenarioContracts.slice(2)],
      [crossKind, ...phase1ScenarioContracts.slice(1)],
    ];

    for (const variant of variants) {
      expect(() => assertExactScenarioContracts(variant)).toThrow(
        /^Invalid phase 1 scenario contract registry$/u
      );
    }
  });

  it('returns recursively frozen contracts and compiled projection evidence', () => {
    expect(Object.isFrozen(phase1ScenarioContracts)).toBe(true);
    for (const contract of phase1ScenarioContracts) {
      expect(Object.isFrozen(contract)).toBe(true);
      expect(Object.isFrozen(contract.orderedSteps)).toBe(true);
      expect(Object.isFrozen(contract.orderedSteps[0]?.kinds)).toBe(true);
      expect(Object.isFrozen(contract.observationContract)).toBe(true);
      expect(Object.isFrozen(contract.normalizablePointers)).toBe(true);
      expect(Object.isFrozen(contract.explicitNormalizablePointers)).toBe(true);
      const compiled = compileScenarioContract(contract);
      expect(Object.isFrozen(compiled)).toBe(true);
      expect(Object.isFrozen(compiled.projectionSchema)).toBe(true);
      expect(compiled.projectionSchema.every((leaf) => Object.isFrozen(leaf))).toBe(true);
    }
  });
});

/* eslint-enable @typescript-eslint/ban-types, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-explicit-any, @typescript-eslint/no-loop-func, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/restrict-plus-operands, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, max-nested-callbacks, unicorn/consistent-function-scoping, unicorn/no-array-for-each */
