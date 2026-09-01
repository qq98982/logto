/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutating-methods, max-lines, no-await-in-loop -- Runtime-boundary tests deliberately mutate closed projections, retain dynamic Jest matchers, and record lifecycle events across the complete runner boundary. */
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import type { TargetConfig } from '../model.js';
import { SymbolTable } from '../symbol-table.js';

import { MemoryProtocolSecretStore, type OidcClient } from './clients/oidc.js';
import { createPhase1FixtureMap, type Phase1FixtureAllocationRole } from './fixture-map.js';
import {
  createProvisionedPhase1Fixture,
  type Phase1FixtureProvisioner,
  type ProvisionedPhase1Fixture,
} from './fixtures.js';
import {
  defineDifferentialScenario,
  oracleCommit,
  phase0HarnessCommit,
  type Phase1DifferentialScenario,
  type Phase1FixtureRecipe,
  type Phase1ObservationKind,
  type Phase1ScenarioRun,
} from './model.js';
import type { Phase1Profile } from './profile-types.js';
import {
  projectTokenObservation,
  verifyObservedJwt,
  type Phase1HttpProjection,
} from './projections/index.js';
import {
  runPhase1ScenarioForTarget,
  validateExactPhase1ScenarioSteps,
  type Phase1ProtocolSession,
  type Phase1AllocationProtocolClients,
  type Phase1ScenarioStateProjectionInput,
} from './scenario-runtime.js';

const target: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'http://localhost:3001/',
  adminUrl: 'http://localhost:3002/',
});
const profile = Object.freeze({}) as unknown as Phase1Profile;
const noCleanup = async (): Promise<void> => {
  await Promise.resolve();
};
const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const createNoneFixture = (): ProvisionedPhase1Fixture =>
  createProvisionedPhase1Fixture({
    public: createPhase1FixtureMap({ schemaVersion: 1, recipe: 'none', allocations: [] }),
    passwords: [],
    clientSecrets: [],
  });

const createDataFixture = (): ProvisionedPhase1Fixture =>
  createProvisionedPhase1Fixture({
    public: createPhase1FixtureMap({
      schemaVersion: 1,
      recipe: 'dataProtocol',
      allocations: [
        {
          allocationId: 'data-allocation',
          role: 'data',
          target: 'primary',
          isolation: {
            persistenceId: 'data-persistence',
            cookieKeyId: 'data-cookie-key',
            signingKeyId: 'data-signing-key',
          },
          entities: [
            { kind: 'tenant', logicalId: 'tenant', runtimeId: 'runtime-tenant' },
            { kind: 'user', logicalId: 'user', runtimeId: 'runtime-user' },
            { kind: 'application', logicalId: 'app-a', runtimeId: 'runtime-app-a' },
            { kind: 'application', logicalId: 'app-b', runtimeId: 'runtime-app-b' },
            { kind: 'resource', logicalId: 'resource', runtimeId: 'runtime-resource' },
            { kind: 'scope', logicalId: 'scope', runtimeId: 'runtime-scope' },
            { kind: 'role', logicalId: 'role', runtimeId: 'runtime-role' },
          ],
        },
      ],
    }),
    passwords: [],
    clientSecrets: [],
  });

const observationContractFor = (
  steps: ReadonlyArray<Readonly<{ id: string; kinds: readonly Phase1ObservationKind[] }>>
) => {
  const forKind = (kind: Phase1ObservationKind) =>
    steps.filter(({ kinds }) => kinds.includes(kind)).map(({ id }) => id);
  const http = forKind('http');

  return {
    status: http,
    mediaType: http,
    headers: http,
    cookies: forKind('cookie-metadata'),
    redirects: forKind('redirect'),
  };
};

const createScenario = (
  steps: ReadonlyArray<Readonly<{ id: string; kinds: readonly Phase1ObservationKind[] }>>,
  run: Phase1ScenarioRun,
  fixture: Phase1FixtureRecipe = 'none'
): Phase1DifferentialScenario =>
  defineDifferentialScenario({
    id: 'discovery.config',
    evidenceKind: 'differential',
    fixture,
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
    orderedSteps: steps,
    observationContract: observationContractFor(steps),
    normalizablePointers: [],
    semanticProjectionVersion: 1,
    cleanup: 'fresh-fixture-reverse-cleanup',
    run,
  });

const httpProjection = (): Phase1HttpProjection => ({
  status: 200,
  mediaType: null,
  error: null,
  headers: {},
  body: { ok: true },
  redirect: null,
  cookies: [],
  urls: [],
  tokens: [],
  generatedIds: {},
  persistedState: {},
  semanticState: {},
  sideEffects: {},
  outcomes: [],
});

const stateProjection = (): Phase1ScenarioStateProjectionInput => ({
  body: { observed: true },
  semanticState: { grants: [] },
  sideEffects: { writes: 0 },
  persistedState: { grants: [] },
  generatedIds: { tokenFamily: '<token-family.1>' },
  outcomes: [],
});

const protocolSession = (publicSymbols = new SymbolTable()): Phase1ProtocolSession => {
  const publicOidc: Pick<OidcClient, 'request' | 'allocationRole'> = {
    allocationRole: undefined,
    request: async () => {
      throw new Error('Public OIDC is not used by this runtime test');
    },
  };

  return {
    publicOidc,
    publicSymbols,
    forAllocation: () => {
      throw new Error('No allocation exists for the none fixture');
    },
    symbolsFor: () => publicSymbols,
  };
};

const allocationClients = (store: MemoryProtocolSecretStore): Phase1AllocationProtocolClients => ({
  oidc: {
    store,
    request: async () => {
      throw new Error('unexpected OIDC request');
    },
  },
  experience: {
    store,
    requestExperience: async () => {
      throw new Error('unexpected Experience request');
    },
  },
  consent: {
    store,
    requestConsent: async () => {
      throw new Error('unexpected Consent request');
    },
  },
  management: {
    store,
    requestManagement: async () => {
      throw new Error('unexpected Management request');
    },
  },
  account: {
    store,
    requestAccount: async () => {
      throw new Error('unexpected Account request');
    },
  },
  state: {
    store,
    requestState: async () => {
      throw new Error('unexpected State request');
    },
  },
});

describe('phase 1 scenario runtime', () => {
  it('injects one isolated target runtime and cleans its fixture after exact ordered steps', async () => {
    const events: string[] = [];
    const fixture = createNoneFixture();
    const publicSymbols = new SymbolTable();
    const session = protocolSession(publicSymbols);
    const projectedFixtureState = Object.freeze({
      schemaVersion: 1 as const,
      recipe: 'none' as const,
      allocations: Object.freeze([]),
    });
    const probeProjection: Phase1HttpProjection = {
      ...httpProjection(),
      body: { nested: { values: ['fixed'] } },
    };
    const provisioner: Phase1FixtureProvisioner = {
      provision: async (recipe) => {
        events.push(`provision:${recipe}`);
        return fixture;
      },
      projectState: async (activeFixture) => {
        expect(activeFixture).toBe(fixture);
        events.push('fixture-state');
        return projectedFixtureState;
      },
      cleanup: async (activeFixture) => {
        expect(activeFixture).toBe(fixture);
        events.push('cleanup');
      },
    };
    const projectedState = stateProjection();
    const scenario = createScenario(
      [
        { id: 'probe', kinds: ['http'] },
        { id: 'state', kinds: ['semantic-state'] },
      ],
      async (context) => {
        events.push('scenario');
        expect(context.profile).toBe(profile);
        expect(context.target).toEqual(target);
        expect(context.fixture).toBe(fixture);
        expect(context.protocol).not.toBe(session);
        expect(context.protocol.publicSymbols).toBe(publicSymbols);
        expect(context.signal.aborted).toBe(false);
        await expect(context.projectFixtureState()).resolves.toBe(projectedFixtureState);
        const state = await context.projectScenarioState({
          scenarioId: 'discovery.config',
          stepId: 'state',
          fixture,
        });

        return [
          { stepId: 'probe', value: probeProjection },
          { stepId: 'state', value: { ...httpProjection(), ...state } },
        ];
      }
    );

    const result = await runPhase1ScenarioForTarget(scenario, {
      profile,
      target,
      provisioner,
      createProtocolSession: (input) => {
        events.push('protocol');
        expect(input).toEqual({ target, fixture, signal: expect.any(AbortSignal) });
        return session;
      },
      projectScenarioState: async (input) => {
        events.push('scenario-state');
        expect(input).toEqual({
          scenarioId: 'discovery.config',
          stepId: 'state',
          fixture,
          target,
          signal: expect.any(AbortSignal),
        });
        return projectedState;
      },
    });

    expect(events).toEqual([
      'provision:none',
      'protocol',
      'scenario',
      'fixture-state',
      'scenario-state',
      'cleanup',
    ]);
    expect(result).toEqual({
      target: 'oracle',
      steps: [
        { stepId: 'probe', value: probeProjection },
        { stepId: 'state', value: { ...httpProjection(), ...projectedState } },
      ],
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.steps)).toBe(true);
    expect(Object.isFrozen(result.steps[0]?.value)).toBe(true);
    expect(Object.isFrozen(result.steps[1]?.value)).toBe(true);
    expect(result.steps[0]?.value).toBe(probeProjection);
    expect(Object.isFrozen(probeProjection.body)).toBe(true);
    const nestedBody = probeProjection.body;
    if (!isRecord(nestedBody) || !isRecord(nestedBody.nested)) {
      throw new TypeError('Expected nested projection body');
    }
    const { values } = nestedBody.nested;
    if (!Array.isArray(values)) {
      throw new TypeError('Expected nested projection values');
    }
    expect(Object.isFrozen(nestedBody.nested)).toBe(true);
    expect(Object.isFrozen(values)).toBe(true);
    expect(Reflect.set(nestedBody.nested, 'extra', true)).toBe(false);
    expect(Reflect.set(values, '0', 'mutated')).toBe(false);
    expect(values).toEqual(['fixed']);
  });

  it('pins allocation clients once so credential registration and publication checks share a store', async () => {
    const fixture = createDataFixture();
    const firstStore = new MemoryProtocolSecretStore();
    const laterStore = new MemoryProtocolSecretStore();
    const firstClients = allocationClients(firstStore);
    const laterClients = allocationClients(laterStore);
    const symbols = new SymbolTable();
    const secret = 'runtime-opaque-credential';
    const forAllocation = import.meta.jest
      .fn<Phase1AllocationProtocolClients, [Phase1FixtureAllocationRole]>()
      .mockReturnValueOnce(firstClients)
      .mockReturnValue(laterClients);
    const scenario = createScenario(
      [{ id: 'probe', kinds: ['http'] }],
      async (context) => {
        context.protocol.forAllocation('data').oidc.store.registerSecret(secret);

        return [{ stepId: 'probe', value: { ...httpProjection(), body: { note: secret } } }];
      },
      'dataProtocol'
    );
    const provisioner: Phase1FixtureProvisioner = {
      provision: async () => fixture,
      projectState: async () => ({
        schemaVersion: 1,
        recipe: 'dataProtocol',
        allocations: [],
      }),
      cleanup: noCleanup,
    };

    await expect(
      runPhase1ScenarioForTarget(scenario, {
        profile,
        target,
        provisioner,
        createProtocolSession: () => ({
          publicOidc: protocolSession().publicOidc,
          publicSymbols: new SymbolTable(),
          forAllocation,
          symbolsFor: () => symbols,
        }),
        projectScenarioState: async () => stateProjection(),
      })
    ).rejects.toThrow(/^Invalid phase 1 scenario step results$/u);
    expect(forAllocation).toHaveBeenCalledTimes(1);
  });

  it('validates one full projection per exact ordered step and every declared kind surface', async () => {
    const kinds = [
      'http',
      'redirect',
      'cookie-metadata',
      'jwt-header',
      'jwt-claims',
      'semantic-state',
    ] as const;
    const scenario = createScenario([{ id: 'complete', kinds }], async () => []);
    const { privateKey, publicKey } = await generateKeyPair('ES384');
    const publicJwk = { ...(await exportJWK(publicKey)), kid: 'runtime-key', alg: 'ES384' };
    const compact = await new SignJWT({
      iss: 'https://issuer.example',
      aud: 'phase1-app',
      iat: 1000,
      exp: 4600,
    })
      .setProtectedHeader({ alg: 'ES384', kid: 'runtime-key' })
      .sign(privateKey);
    const proof = await verifyObservedJwt(compact, { keys: [publicJwk] });
    const tokenProjection = projectTokenObservation(
      {
        status: 200,
        headers: [],
        body: { access_token: compact, token_type: 'Bearer' },
        semanticState: { grants: [] },
        sideEffects: { writes: 0 },
      },
      { target, symbols: new SymbolTable() },
      { verifiedJwts: [proof] }
    );
    const complete: Phase1HttpProjection = {
      ...tokenProjection,
      redirect: {
        scheme: 'https',
        origin: 'https://client.example',
        path: '/callback',
        query: {},
        fragment: '',
        redactedParameters: [],
      },
      cookies: [{ name: 'interaction', httpOnly: true, secure: true, extensions: [] }],
      semanticState: { grants: [] },
      sideEffects: { writes: 0 },
    };

    expect(
      validateExactPhase1ScenarioSteps(scenario, [{ stepId: 'complete', value: complete }])
    ).toEqual([{ stepId: 'complete', value: complete }]);

    const invalidValues = [
      { ...complete, status: undefined },
      { ...complete, redirect: null },
      { ...complete, cookies: undefined },
      { ...complete, tokens: [{ claims: { aud: 'phase1-app' } }] },
      { ...complete, tokens: [{ header: { alg: 'ES384' } }] },
      { ...complete, semanticState: undefined },
    ];

    for (const value of invalidValues) {
      expect(() =>
        validateExactPhase1ScenarioSteps(scenario, [{ stepId: 'complete', value }])
      ).toThrow(/^Invalid phase 1 scenario step results$/u);
    }
  });

  it('rejects missing extra reordered duplicate sparse and accessor-backed step results', () => {
    const scenario = createScenario(
      [
        { id: 'first', kinds: ['http'] },
        { id: 'second', kinds: ['http'] },
      ],
      async () => []
    );
    const first = { stepId: 'first', value: httpProjection() };
    const second = { stepId: 'second', value: httpProjection() };
    const sparse = [first, second];
    Reflect.deleteProperty(sparse, '0');
    const accessor = { stepId: 'first', value: httpProjection() };
    Object.defineProperty(accessor, 'stepId', { enumerable: true, get: () => 'first' });

    for (const value of [
      [],
      [first],
      [first, second, second],
      [second, first],
      [first, first],
      sparse,
      [accessor, second],
      [{ ...first, extra: true }, second],
    ]) {
      expect(() => validateExactPhase1ScenarioSteps(scenario, value)).toThrow(
        /^Invalid phase 1 scenario step results$/u
      );
    }
  });

  it('accepts only closed sanitized semantic-state envelopes for the active scenario step', async () => {
    const fixture = createNoneFixture();
    const provisioner: Phase1FixtureProvisioner = {
      provision: async () => fixture,
      projectState: async () => ({ schemaVersion: 1, recipe: 'none', allocations: [] }),
      cleanup: noCleanup,
    };
    const scenario = createScenario(
      [{ id: 'state', kinds: ['semantic-state'] }],
      async (context) => [
        {
          stepId: 'state',
          value: {
            ...httpProjection(),
            ...(await context.projectScenarioState({
              scenarioId: 'discovery.config',
              stepId: 'state',
              fixture,
            })),
          },
        },
      ]
    );
    const run = async (value: unknown) =>
      runPhase1ScenarioForTarget(scenario, {
        profile,
        target,
        provisioner,
        createProtocolSession: () => protocolSession(),
        projectScenarioState: async () => value,
      });

    await expect(run(stateProjection())).resolves.toMatchObject({ target: 'oracle' });
    for (const invalid of [
      { ...stateProjection(), status: 200 },
      { ...stateProjection(), headers: {} },
      { ...stateProjection(), redirect: null },
      { ...stateProjection(), tokens: [] },
      { ...stateProjection(), authorization: 'Bearer private-state-token' },
      {
        ...stateProjection(),
        body: { nested: { access_token_value: 'opaque-private-value' } },
      },
      { ...stateProjection(), body: { note: 'opaque-private-value' } },
      { ...stateProjection(), generatedIds: { tokenFamily: 'raw-runtime-family' } },
      { body: {}, semanticState: {}, sideEffects: {}, outcomes: {} },
      { body: {}, semanticState: {}, sideEffects: new Date() },
    ]) {
      await expect(run(invalid)).rejects.toThrow(/^Invalid phase 1 scenario state projection$/u);
    }
  });

  it('accepts every declared state read and rejects spoofed scenario fixture or unknown steps', async () => {
    const fixture = createNoneFixture();
    const otherFixture = createNoneFixture();
    const provisioner: Phase1FixtureProvisioner = {
      provision: async () => fixture,
      projectState: async () => ({ schemaVersion: 1, recipe: 'none', allocations: [] }),
      cleanup: noCleanup,
    };
    const run = async (input: Readonly<{ scenarioId: any; stepId: string; fixture: any }>) => {
      const scenario = createScenario(
        [
          { id: 'probe', kinds: ['http'] },
          { id: 'state', kinds: ['semantic-state'] },
        ],
        async (context) => {
          await context.projectScenarioState(input);
          return [
            { stepId: 'probe', value: httpProjection() },
            { stepId: 'state', value: { ...httpProjection(), ...stateProjection() } },
          ];
        }
      );

      return runPhase1ScenarioForTarget(scenario, {
        profile,
        target,
        provisioner,
        createProtocolSession: () => protocolSession(),
        projectScenarioState: async () => stateProjection(),
      });
    };

    await expect(
      run({ scenarioId: 'discovery.config', stepId: 'probe', fixture })
    ).resolves.toMatchObject({ target: 'oracle' });
    for (const input of [
      { scenarioId: 'token.authorization-code', stepId: 'state', fixture },
      { scenarioId: 'discovery.config', stepId: 'unknown', fixture },
      { scenarioId: 'discovery.config', stepId: 'state', fixture: otherFixture },
    ]) {
      await expect(run(input)).rejects.toThrow(/^Invalid phase 1 scenario state request$/u);
    }
  });
});

/* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutating-methods, max-lines, no-await-in-loop */
