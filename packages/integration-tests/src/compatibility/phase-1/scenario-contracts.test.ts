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
      '/steps/state/value/generatedIds/tokenFamily',
    ],
  },
  {
    id: 'console.admin-organization-token-refresh',
    steps: ['organization-refresh:http+jwt-header+jwt-claims', 'state:semantic-state'],
    explicit: [
      '/steps/organization-refresh/value/tokens/*/claims/iat',
      '/steps/organization-refresh/value/tokens/*/claims/exp',
    ],
  },
  {
    id: 'account.admin-operator-read',
    steps: ['account:http', 'state:semantic-state'],
    explicit: ['/steps/account/value/body/createdAt', '/steps/account/value/body/updatedAt'],
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
    'exact headers/*/*',
    'bounded-timestamp headers/date/*',
    'sanitized-body-byte-length headers/content-length/*',
    'exact body/**',
    'exact sideEffects/**',
    'exact urls/*/**',
    'exact urls/*/scheme',
    'target-symbol urls/*/origin',
    'exact urls/*/path',
    'exact urls/*/query/*/*',
    'exact urls/*/fragment',
  ],
  redirect: [
    'exact redirect/**',
    'exact redirect/scheme',
    'exact redirect/origin',
    'exact redirect/path',
    'exact redirect/query/*/*',
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
    'exact tokens/*/claims/iss',
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
  'discovery.config': '4c81e3314f3fdee33a7f9b7d0e443ab013f5b0d9adc98c241eaca608cbc81056',
  'authorization.password-pkce-consent':
    'd497886476efea56d4ab9e45828f64b48ade7c90903acdf21cb7065536f67651',
  'token.authorization-code': goldenDigest(
    '7f6ade1b642dfc43',
    'e7b2a659260d5c66',
    'ff076141954081cd',
    '69d83c0ee5a16faf'
  ),
  'token.refresh-rotation': goldenDigest(
    '25480c5b3734db7c',
    '3ae16b94e969e0aa',
    'f60c4f56a10fde70',
    '6179d057e12a2125'
  ),
  'userinfo.openid': 'ea14f29a082935dae44dc718d5dc2be3cc43d1371ecbb4d1fc690899dfc15222',
  'management.application-read': '0740e1a9002404bba5464f8d8c54f27f0f166b0e0d5339abe2b89be0f376befa',
  'management.user-read': '87ecd541a2e0950a8a1c8fd4cbc9deb49b351cd90f10aa0877625d8375a1a63b',
  'console.admin-auth-resource-refresh':
    '3d65bf558d7c95aa5c5334fb1a733b3fd23ca77822da91d41688b7b659acf613',
  'console.admin-organization-token-refresh':
    'f80bd1a322622f939816fc6304666c257b9ef853df30166bd9cd840c1ecd48c8',
  'account.admin-operator-read': '2a75c6eb164b26d596fe88b052046b92c0d0a6c895822d912383445f5f50dbaf',
  'cors.management-list': '0344d0e5c4f2cc3cd609cbe8756d56f270ffc5a9d7c299d5dc3d5b0fd9bcc699',
  'cookie.localhost-port-interleaving':
    '100063bb17e6f516221b62241b015b156f0c975575dbe9793431fd6fbd029e7b',
  'authorization.redirect-uri-rejected':
    '7b1ee0311283a9753c085a18806d7c4cc07962c9d3397a38eb4b02ca6fa49e37',
  'authorization.pkce-method-rejected':
    '30e99586ce7d7c9406392bc3c1cfe14f3da5cdcf9d59029445976676646be941',
  'token.pkce-verifier-rejected':
    '0a85dd174d46b753defd0aee061675277188ffb3635c2818f19e6bc838877f15',
  'token.code-reuse-rejected': goldenDigest(
    '6ab5375e86074704',
    '58d48628bb1037f8',
    '76fee073180ad1c6',
    '3dadda15aa9d9a05'
  ),
  'interaction.password-rejected':
    'b8b73a3b521abc41bf6de4ddcf3b620d17cc75b5be4246b101272cc3d2ff5eb8',
  'interaction.consent-session-boundary':
    'ba903c971e14699e982583bc7ca05e138980b02f1c895d63ef88459b511f65be',
  'token.refresh-reuse-rejected':
    'e9438f3f1002b8c202c421fcdd8d551e843e85a081f597aec8d0641594071bc2',
  'token.issuer-audience-scope-rejected':
    'f9710a27167379e161a8f5fcc4515e0a5e0929a07788115055b564b2305b69b6',
  'token.concurrent-code-single-winner':
    '3fea7681d96701d472f1135f16fa628a5539b2a84a565f2c4c729197f165940b',
  'token.concurrent-refresh-single-winner':
    '5d06cb9754010d871bf08b2d957265e4f218794e75a23dcdbfe688819bba2c5e',
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
      '/steps/*/value/urls/*/origin',
      '/steps/*/value/tokens/*/header/kid',
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

  it('rejects normalizers for status media error algorithm issuer audience scope and unknown fields', () => {
    const forbidden = [
      ['discovery.config', '/steps/oidc-discovery/value/status'],
      ['discovery.config', '/steps/oidc-discovery/value/mediaType'],
      ['discovery.config', '/steps/oidc-discovery/value/error/code'],
      ['discovery.config', '/steps/oidc-discovery/value/headers/content-type/*'],
      ['discovery.config', '/steps/oidc-discovery/value/body/issuer'],
      ['discovery.config', '/steps/oidc-discovery/value/sideEffects/count'],
      ['discovery.config', '/steps/oidc-discovery/value/tokens/*/claims/iat'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/cookies/*/secure'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/cookies/*/sameSite'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/redirect/query/*/*'],
      ['authorization.password-pkce-consent', '/steps/authorize/value/redirect/fragment'],
      ['authorization.password-pkce-consent', '/steps/state/value/tokens/*/claims/iat'],
      ['token.authorization-code', '/steps/token/value/tokens/*/header/alg'],
      ['token.authorization-code', '/steps/token/value/tokens/*/claims/iss'],
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
