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
      'submit:http+redirect+cookie-metadata',
      'consent-get:http+cookie-metadata',
      'consent-post:http+redirect+cookie-metadata',
      'resume:redirect+cookie-metadata',
      'callback:redirect',
      'state:semantic-state',
    ],
    explicit: [
      '/steps/authorize/value/generatedIds/interaction',
      '/steps/submit/value/redirect/resumeCredential',
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
      'rotate:http+jwt-header+jwt-claims',
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
    steps: [
      'attempt-a:http+jwt-header+jwt-claims',
      'attempt-b:http+jwt-header+jwt-claims',
      'race:semantic-state',
      'state:semantic-state',
    ],
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
    'target-symbol headers/access-control-allow-origin/*',
    'exact body/**',
    'target-symbol body/iss',
    'target-symbol body/issuer',
    'bound-scope-token-list body/scope',
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
    'bound-scope-token-list tokens/*/claims/scope',
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
  'discovery.config': '44882ffbd5c4dc39289c091e5db05d2d063d6b57596af03530f12e6f3f8d087f',
  'authorization.password-pkce-consent':
    '06b5d7aad0203dd66cac521fedb00a27261b032d0937f78f43da8675549770e6',
  'token.authorization-code': goldenDigest(
    'dda63aad3155dc29',
    '4d1d48b59253ae68',
    '262cf11e5c2fe863',
    '1c2e29039aa8bfaa'
  ),
  'token.refresh-rotation': goldenDigest(
    '6f281295eb0fe80d',
    'c7955d5ab0296b6e',
    '394915f5e856fa21',
    'f462f15e68f8d8e2'
  ),
  'userinfo.openid': '0c9f5f1f9d9fb05fdc05526f44e647e1a91b909d7cfde26f2a9535dd6b111514',
  'management.application-read': '45a237444f7432bd4734bcf037db1b382650c7b9e848028187e2249a4c211e03',
  'management.user-read': 'c990af1ec2ed45990343d52320049c8c5aad42c15e0c5ba2493714a5c615e781',
  'console.admin-auth-resource-refresh':
    '0b7a553c85505bfc4e981788f0e8cd4b0141002af94035d6a1c48b67fe1c1bc8',
  'console.admin-organization-token-refresh':
    '96859293fc2e129c5e911b84a5dc5bdc65ead469aca463fad6227e56a9062b53',
  'account.admin-operator-read': '0af97344128ba671118d54bbf27d30e53812f655326b9e602b4af6c99a8027d2',
  'cors.management-list': '8803ebb420e27515bf9ee8ee9dcbd883f1ed105b791e5962a495373dd89374f2',
  'cookie.localhost-port-interleaving':
    '5dcef7e3c51903adb5a6269d646a8ca21d139772319210da44d8e234540fd681',
  'authorization.redirect-uri-rejected':
    '87619a1cf72423c25ef515954442edf3c7424f7d77c2121eeb1abf3f138286b6',
  'authorization.pkce-method-rejected':
    'f1fbcb6ac0861796cdc80599102179fdf0d3137ac35d89c37035df223a4e817d',
  'token.pkce-verifier-rejected':
    '117a8e4eb1069492e499cc730df30fecd0ecf01c58f80ce161e36d853c55b55d',
  'token.code-reuse-rejected': goldenDigest(
    'c1e8402582cd93c8',
    'cf3de7ec2c65e67e',
    '38a56fae8ab955f9',
    '40cebcf298c8155d'
  ),
  'interaction.password-rejected':
    'c0c96b2db1d995e010fcae80a182d5042e819100719c8b034faec057a860c91e',
  'interaction.consent-session-boundary':
    'a9803fd9a9857f9b5d2988f4b5043aa5bef07800609b7959547644e8813deff0',
  'token.refresh-reuse-rejected':
    '1f9e5a0b8bee3ba4056d45872461a9178955014e19c8fc127dcd99b9dbaf3e30',
  'token.issuer-audience-scope-rejected':
    '9baebe480e95b9dffdb4f8bc0effb3bb5d55ac7170c5b091682114ca2db2a640',
  'token.concurrent-code-single-winner':
    '23d837360bfe7ca6119766a6cf16f1df22c674386d1548c0f4cfc488c265495c',
  'token.concurrent-refresh-single-winner':
    '92721a81681f17ead40fe83b5b93ff84d1d28b34a53d16529f1a330e1995eeb9',
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
      '/steps/*/value/headers/access-control-allow-origin/*',
      '/steps/*/value/cookies/*/expires',
      '/steps/*/value/error/iss',
      '/steps/*/value/error/issuer',
      '/steps/*/value/body/iss',
      '/steps/*/value/body/issuer',
      '/steps/*/value/body/scope',
      '/steps/*/value/redirect/origin',
      '/steps/*/value/redirect/query/app_id/*',
      '/steps/*/value/redirect/query/iss/*',
      '/steps/*/value/urls/*/origin',
      '/steps/*/value/urls/*/query/app_id/*',
      '/steps/*/value/urls/*/query/iss/*',
      '/steps/*/value/tokens/*/header/kid',
      '/steps/*/value/tokens/*/claims/iss',
      '/steps/*/value/tokens/*/claims/scope',
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
