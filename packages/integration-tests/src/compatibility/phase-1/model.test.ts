/* eslint-disable @typescript-eslint/no-explicit-any, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, unicorn/consistent-function-scoping -- Runtime-boundary mutation tests intentionally bypass static types and create dangerous own keys. */
import {
  candidateInvariantContractGuard,
  candidateInvariantScenarioIdGuard,
  candidateInvariantScenarioIds,
  cloneAndDeepFreeze,
  defineCandidateInvariant,
  defineDifferentialScenario,
  differentialScenarioIdGuard,
  differentialScenarioIds,
  phase1FixtureRecipes,
  snapshotDensePlainArray,
  snapshotClosedDataGraph,
  type CandidateInvariantContract,
  type Phase1DifferentialScenario,
} from './model.js';

const oracleCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const phase0HarnessCommit = '40135e37201f36ac05ece1eff82e37bb6d9649f1';

const expectedDifferentialIds = [
  'discovery.config',
  'authorization.password-pkce-consent',
  'token.authorization-code',
  'token.refresh-rotation',
  'userinfo.openid',
  'management.application-read',
  'management.user-read',
  'console.admin-auth-resource-refresh',
  'console.admin-organization-token-refresh',
  'account.admin-operator-read',
  'cors.management-list',
  'cookie.localhost-port-interleaving',
  'authorization.redirect-uri-rejected',
  'authorization.pkce-method-rejected',
  'token.pkce-verifier-rejected',
  'token.code-reuse-rejected',
  'interaction.password-rejected',
  'interaction.consent-session-boundary',
  'token.refresh-reuse-rejected',
  'token.issuer-audience-scope-rejected',
  'token.concurrent-code-single-winner',
  'token.concurrent-refresh-single-winner',
] as const;

const expectedCandidateIds = [
  'tenant.cross-tenant-read-rejected',
  'tenant.suspended-epoch-rejected',
  'tenant.admin-operation-binding',
  'tenant.admin-operation-status-matrix',
  'database.owner-role-membership-boundary',
  'reaper.activity-visibility-redaction',
  'reaper.object-audit-disabled',
  'keystore.unwrap-failure-rolls-back-code',
  'keystore.wrapping-fence-late-commit',
  'keystore.sign-seal-during-rewrap',
  'keystore.metadata-dml-boundary',
  'keystore.forced-rls-owner-boundary',
  'keystore.reference-count-ledger',
  'keystore.reference-ledger-verifier-boundary',
  'keystore.live-ledger-limit-and-tombstone',
  'keystore.stale-keyring-rejoin-rejected',
  'keystore.required-readable-key-set',
  'hosts.unavailable-pkce-independent',
] as const;

const differentialFixture = (): Phase1DifferentialScenario => ({
  id: 'discovery.config',
  evidenceKind: 'differential',
  fixture: 'none',
  sourceEvidence: [
    {
      commit: phase0HarnessCommit,
      path: 'packages/integration-tests/src/compatibility/scenarios/discovery.ts',
    },
    {
      commit: oracleCommit,
      path: 'packages/integration-tests/src/tests/api/oidc/discovery.test.ts',
    },
  ],
  orderedSteps: [{ id: 'oidc-discovery', kinds: ['http'] }],
  observationContract: {
    status: ['oidc-discovery'],
    mediaType: ['oidc-discovery'],
    headers: ['oidc-discovery'],
    cookies: [],
    redirects: [],
  },
  normalizablePointers: ['/steps/*/value/headers/date/*'],
  semanticProjectionVersion: 1,
  cleanup: 'fresh-fixture-reverse-cleanup',
  run: async () => [],
});

const candidateFixture = (): CandidateInvariantContract => ({
  id: 'tenant.cross-tenant-read-rejected',
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { description: 'two active tenant fixtures' },
  perturbation: { description: 'query a caller-supplied foreign relationship' },
  expectedPublicOutcome: { visibleTenant: 'bound' },
  expectedPersistedOutcome: { mutationCount: 0 },
  forbiddenOutcome: { crossTenantRows: ['foreign'] },
  cleanup: { description: 'rollback fixture transactions' },
  sanitizedProjection: { fields: ['visibleTenant', 'mutationCount'] },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'bound tenant only',
    input: { includeForeign: false },
    expectedProjection: { visibleTenant: 'bound' },
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'foreign row leak',
    input: { includeForeign: true },
    expectedProjection: { crossTenantRows: ['foreign'] },
    expectedDifferencePointer: '/outcome/crossTenantRows/0',
  },
});

const assertCandidateInvariantCompileTimeBoundary = (): void => {
  const contract = candidateFixture();
  const withOracle = { ...contract, oracle: {} };
  const withCandidate = { ...contract, candidate: {} };
  const withDifferences = { ...contract, differences: [] };
  const withCompare = { ...contract, compare: () => true };
  const withOracleComparison = { ...contract, oracleComparison: {} };
  // @ts-expect-error -- Candidate evidence must not acquire an oracle authority field.
  void (withOracle satisfies CandidateInvariantContract);
  // @ts-expect-error -- Candidate evidence must not acquire a comparison target field.
  void (withCandidate satisfies CandidateInvariantContract);
  // @ts-expect-error -- Candidate evidence must not acquire Phase 0 difference output.
  void (withDifferences satisfies CandidateInvariantContract);
  // @ts-expect-error -- Candidate evidence must not acquire a comparison callback.
  void (withCompare satisfies CandidateInvariantContract);
  // @ts-expect-error -- The explicit never field rejects oracle comparison metadata.
  void (withOracleComparison satisfies CandidateInvariantContract);
};

void assertCandidateInvariantCompileTimeBoundary;

describe('phase 1 closed model', () => {
  it('pins the exact fixture recipe vocabulary', () => {
    expect(phase1FixtureRecipes).toEqual([
      'none',
      'dataProtocol',
      'adminConsole',
      'fullPhase1',
      'corsBoundary',
      'consentBoundary',
    ]);
  });

  it('snapshots only bounded dense plain arrays without invoking array-like behavior', () => {
    const valid = Object.freeze(['first', 'middle', 'last']);
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
    Object.defineProperty(accessor, '1', { enumerable: true, get: () => 'middle' });
    const wrongPrototype = [...valid];
    Object.setPrototypeOf(wrongPrototype, null);
    const arrayLike = {
      0: 'first',
      1: 'middle',
      2: 'last',
      length: 3,
      some: Array.prototype.some,
    };
    const ownKeysProxy = new Proxy([...valid], {
      ownKeys: () => {
        throw new Error('must not escape');
      },
    });
    const descriptorProxy = new Proxy([...valid], {
      getOwnPropertyDescriptor: () => {
        throw new Error('must not escape');
      },
    });
    const oversized = Array.from({ length: 4097 }, (_, index) => index);

    const snapshot = snapshotDensePlainArray<string>(valid);
    expect(snapshot).toEqual(valid);
    expect(snapshot).not.toBe(valid);
    expect(Object.isFrozen(snapshot)).toBe(true);

    for (const invalid of [
      holeAt(0),
      holeAt(1),
      holeAt(2),
      arrayLike,
      extra,
      symbol,
      accessor,
      ownKeysProxy,
      descriptorProxy,
      wrongPrototype,
      oversized,
    ]) {
      expect(snapshotDensePlainArray(invalid)).toBeUndefined();
    }
  });

  it('recursively snapshots enumerable plain data and requires explicit function authority', () => {
    const valid = Object.freeze({
      id: 'entry',
      nested: Object.freeze({ values: Object.freeze(['exact']) }),
    });
    const extra = { ...valid, extra: true };
    const nonEnumerable = { ...valid };
    Object.defineProperty(nonEnumerable, 'extra', { enumerable: false, value: true });
    const symbol = { ...valid };
    Object.defineProperty(symbol, Symbol('extra'), { enumerable: true, value: true });
    const accessor = { ...valid };
    Object.defineProperty(accessor, 'id', { enumerable: true, get: () => 'entry' });
    const wrongPrototype = { ...valid };
    Object.setPrototypeOf(wrongPrototype, null);
    const transparentProxy = new Proxy({ ...valid }, {});
    const descriptorProxy = new Proxy(
      { ...valid },
      {
        getOwnPropertyDescriptor: () => {
          throw new Error('must not escape');
        },
      }
    );

    const snapshot = snapshotClosedDataGraph<typeof valid>(valid);
    expect(snapshot).toEqual(valid);
    expect(snapshot).not.toBe(valid);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot?.nested)).toBe(true);
    expect(Object.isFrozen(snapshot?.nested.values)).toBe(true);
    expect(snapshotClosedDataGraph(extra)).toEqual(extra);

    for (const invalid of [
      nonEnumerable,
      symbol,
      accessor,
      wrongPrototype,
      transparentProxy,
      descriptorProxy,
    ]) {
      expect(snapshotClosedDataGraph(invalid)).toBeUndefined();
    }
    const run = () => true;
    expect(snapshotClosedDataGraph({ run })).toBeUndefined();
    expect(
      snapshotClosedDataGraph(
        { run },
        { allowFunction: (path, value) => path === '/run' && value === run }
      )
    ).toEqual({ run });
  });

  it('locks the exact ordered 22 differential and 18 candidate IDs', () => {
    expect(differentialScenarioIds).toEqual(expectedDifferentialIds);
    expect(candidateInvariantScenarioIds).toEqual(expectedCandidateIds);
    expect(new Set(differentialScenarioIds).size).toBe(22);
    expect(new Set(candidateInvariantScenarioIds).size).toBe(18);
    expect(Object.isFrozen(differentialScenarioIds)).toBe(true);
    expect(Object.isFrozen(candidateInvariantScenarioIds)).toBe(true);
  });

  it('rejects unknown and cross-kind IDs at the runtime boundary', () => {
    expect(differentialScenarioIdGuard.safeParse('unknown').success).toBe(false);
    expect(candidateInvariantScenarioIdGuard.safeParse('unknown').success).toBe(false);

    for (const id of candidateInvariantScenarioIds) {
      expect(differentialScenarioIdGuard.safeParse(id).success).toBe(false);
    }

    for (const id of differentialScenarioIds) {
      expect(candidateInvariantScenarioIdGuard.safeParse(id).success).toBe(false);
    }
  });

  it('validates and recursively freezes differential definitions', () => {
    const definition = defineDifferentialScenario(differentialFixture());

    expect(Object.isFrozen(definition)).toBe(true);
    expect(Object.isFrozen(definition.sourceEvidence)).toBe(true);
    expect(Object.isFrozen(definition.sourceEvidence[0])).toBe(true);
    expect(Object.isFrozen(definition.orderedSteps[0]?.kinds)).toBe(true);
    expect(Object.isFrozen(definition.observationContract)).toBe(true);
  });

  it('uses fixed differential diagnostics and rejects every unknown root key', () => {
    const invalid = { ...differentialFixture(), unexpectedSecret: 'never echo me' };

    expect(() => defineDifferentialScenario(invalid as Phase1DifferentialScenario)).toThrow(
      /^Invalid phase 1 differential scenario contract$/u
    );
  });

  it('requires the exact evidence kind and rejects invalid source authority', () => {
    const wrongKind = { ...differentialFixture(), evidenceKind: 'candidate-invariant' };
    const wrongCommit = differentialFixture();
    (wrongCommit.sourceEvidence as any)[0] = {
      commit: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      path: 'packages/integration-tests/src/compatibility/scenarios/discovery.ts',
    };
    const absolutePath = differentialFixture();
    (absolutePath.sourceEvidence as any)[0] = {
      commit: phase0HarnessCommit,
      path: '/tmp/source.ts',
    };

    for (const invalid of [wrongKind, wrongCommit, absolutePath]) {
      expect(() => defineDifferentialScenario(invalid as Phase1DifferentialScenario)).toThrow(
        /^Invalid phase 1 differential scenario contract$/u
      );
    }
  });

  it('rejects unknown keys at every closed differential metadata boundary', () => {
    const source = differentialFixture();
    Object.defineProperty(source.sourceEvidence[0]!, 'unknown', {
      configurable: true,
      enumerable: true,
      value: 'never echo me',
    });
    const step = differentialFixture();
    Object.defineProperty(step.orderedSteps[0]!, 'unknown', {
      configurable: true,
      enumerable: true,
      value: 'never echo me',
    });
    const observation = differentialFixture();
    Object.defineProperty(observation.observationContract, 'unknown', {
      configurable: true,
      enumerable: true,
      value: ['never echo me'],
    });

    for (const invalid of [source, step, observation]) {
      expect(() => defineDifferentialScenario(invalid)).toThrow(
        /^Invalid phase 1 differential scenario contract$/u
      );
    }
  });

  it('rejects descriptor and symbol smuggling at closed differential boundaries', () => {
    const nonEnumerable = differentialFixture();
    Object.defineProperty(nonEnumerable.sourceEvidence[0]!, 'unknown', {
      configurable: true,
      enumerable: false,
      value: 'never echo me',
    });
    const symbol = differentialFixture();
    Object.defineProperty(symbol.orderedSteps[0]!, Symbol('unknown'), {
      configurable: true,
      enumerable: true,
      value: 'never echo me',
    });
    const accessor = differentialFixture();
    Object.defineProperty(accessor.sourceEvidence[0]!, 'path', {
      configurable: true,
      enumerable: true,
      get: () => 'packages/integration-tests/src/compatibility/scenarios/discovery.ts',
    });

    const proxy = differentialFixture();
    (proxy.sourceEvidence as any)[0] = new Proxy(proxy.sourceEvidence[0]!, {});
    const sparse = differentialFixture();
    (sparse.orderedSteps as any).length = 2;

    for (const invalid of [nonEnumerable, symbol, accessor, proxy, sparse]) {
      expect(() => defineDifferentialScenario(invalid)).toThrow(
        /^Invalid phase 1 differential scenario contract$/u
      );
    }
  });

  it('validates and recursively freezes candidate contracts without claiming execution', () => {
    const definition = defineCandidateInvariant(candidateFixture());

    expect(candidateInvariantContractGuard.safeParse(definition).success).toBe(true);
    expect(Object.isFrozen(definition)).toBe(true);
    expect(Object.isFrozen(definition.livePrecondition)).toBe(true);
    expect(Object.isFrozen(definition.positiveControl.input)).toBe(true);
    expect(Object.isFrozen(definition.negativeControl)).toBe(true);
  });

  it.each(['oracle', 'candidate', 'differences', 'compare', 'oracleComparison'] as const)(
    'rejects the forbidden candidate property %s even after a TypeScript bypass',
    (property) => {
      const invalid = candidateFixture() as CandidateInvariantContract & Record<string, unknown>;
      Object.defineProperty(invalid, property, {
        configurable: true,
        enumerable: true,
        value: property === 'oracleComparison' ? undefined : { secret: 'never echo me' },
      });

      expect(() => defineCandidateInvariant(invalid)).toThrow(
        /^Invalid phase 1 candidate invariant contract$/u
      );
    }
  );

  it('rejects candidate unknown keys cross-kind IDs and evidence kinds with fixed diagnostics', () => {
    const unknown = { ...candidateFixture(), extra: 'never echo me' };
    const crossKind = { ...candidateFixture(), id: differentialScenarioIds[0] };
    const wrongKind = { ...candidateFixture(), evidenceKind: 'differential' };

    for (const invalid of [unknown, crossKind, wrongKind]) {
      expect(() => defineCandidateInvariant(invalid as CandidateInvariantContract)).toThrow(
        /^Invalid phase 1 candidate invariant contract$/u
      );
    }
  });

  it('rejects unknown keys inside closed candidate controls', () => {
    const positive = candidateFixture();
    Object.defineProperty(positive.positiveControl, 'unknown', {
      configurable: true,
      enumerable: true,
      value: 'never echo me',
    });
    const negative = candidateFixture();
    Object.defineProperty(negative.negativeControl, 'unknown', {
      configurable: true,
      enumerable: true,
      value: 'never echo me',
    });

    for (const invalid of [positive, negative]) {
      expect(() => defineCandidateInvariant(invalid)).toThrow(
        /^Invalid phase 1 candidate invariant contract$/u
      );
    }
  });

  it('rejects descriptor and symbol smuggling inside candidate contracts', () => {
    const nonEnumerable = candidateFixture();
    Object.defineProperty(nonEnumerable.positiveControl, 'unknown', {
      configurable: true,
      enumerable: false,
      value: 'never echo me',
    });
    const symbol = candidateFixture();
    Object.defineProperty(symbol.negativeControl, Symbol('unknown'), {
      configurable: true,
      enumerable: true,
      value: 'never echo me',
    });
    const accessor = candidateFixture();
    Object.defineProperty(accessor.livePrecondition, 'description', {
      configurable: true,
      enumerable: true,
      get: () => 'mutable precondition',
    });

    const proxy = candidateFixture();
    (proxy as any).sanitizedProjection = new Proxy(proxy.sanitizedProjection, {});
    const sparse = candidateFixture();
    (sparse.sanitizedProjection as any).fields.length = 3;

    for (const invalid of [nonEnumerable, symbol, accessor, proxy, sparse]) {
      expect(() => defineCandidateInvariant(invalid)).toThrow(
        /^Invalid phase 1 candidate invariant contract$/u
      );
    }
  });

  it('deep-freezes cycles and preserves dangerous own keys without prototype mutation', () => {
    const value = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(value, '__proto__', {
      configurable: true,
      enumerable: true,
      writable: true,
      value: { preserved: true },
    });
    Object.defineProperty(value, 'constructor', {
      configurable: true,
      enumerable: true,
      writable: true,
      value: { preserved: true },
    });
    value.self = value;

    const frozen = cloneAndDeepFreeze(value);

    expect(frozen).not.toBe(value);
    expect(frozen.self).toBe(frozen);
    expect(Object.hasOwn(frozen, '__proto__')).toBe(true);
    const frozenPrototypeValue = Object.getOwnPropertyDescriptor(frozen, '__proto__')?.value as
      | Record<string, unknown>
      | undefined;

    expect(frozenPrototypeValue?.preserved).toBe(true);
    expect((frozen.constructor as unknown as Record<string, unknown>).preserved).toBe(true);
    expect(Object.getPrototypeOf(frozen)).toBeNull();
    expect(Object.isFrozen(frozen)).toBe(true);
    expect(Object.isFrozen(frozenPrototypeValue)).toBe(true);
  });

  it('preserves dangerous JSON keys inside a constructed candidate contract', () => {
    const contract = candidateFixture();
    const projection = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(projection, '__proto__', {
      configurable: true,
      enumerable: true,
      writable: true,
      value: { marker: 'safe' },
    });
    (contract as any).sanitizedProjection = projection;

    const frozen = defineCandidateInvariant(contract);

    expect(Object.hasOwn(frozen.sanitizedProjection, '__proto__')).toBe(true);
    const frozenProjectionPrototype = Object.getOwnPropertyDescriptor(
      frozen.sanitizedProjection,
      '__proto__'
    )?.value as Record<string, unknown> | undefined;

    expect(frozenProjectionPrototype?.marker).toBe('safe');
    expect(Object.isFrozen(frozenProjectionPrototype)).toBe(true);
  });
});

/* eslint-enable @typescript-eslint/no-explicit-any, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-lines, unicorn/consistent-function-scoping */
