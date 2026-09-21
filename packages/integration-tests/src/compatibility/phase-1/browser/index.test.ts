/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Runner tests build exact provisioned fixtures, use intentionally inert narrow session methods, inject closed flow registries, and record lifecycle order. */
import type { TargetConfig } from '../../model.js';
import type { JsonObject } from '../../normalize.js';
import { createPhase1FixtureMap } from '../fixture-map.js';
import { createProvisionedPhase1Fixture } from '../fixtures.js';
import { oracleCommit } from '../model.js';
import type { Phase1Profile } from '../profile-types.js';

import type { Phase1BrowserFixtureProvisioner } from './activity-reader.js';
import type {
  Phase1BrowserFlowModule,
  Phase1BrowserGroupObserver,
  Phase1BrowserSession,
} from './contracts.js';
import {
  canonicalBrowserFlows,
  canonicalBrowserSourcePaths,
  runPhase1BrowserFlows,
  runPhase1BrowserFlowsForTesting,
  validatePhase1BrowserRegistry,
} from './index.js';

const target: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'https://core.example/',
  adminUrl: 'https://admin.example/',
});

const profile = (modules: readonly Phase1BrowserFlowModule[] = canonicalBrowserFlows) =>
  ({
    reference: { oracleCommit },
    browserFlows: modules.map(({ id, executionGroup, sourcePaths }) => ({
      id,
      executionGroup,
      sourceEvidence: [...sourcePaths],
    })),
    browserExecutionGroups: [
      { id: 'experience', orderedFlows: ['experience.password-pkce-consent'] },
      {
        id: 'console',
        orderedFlows: [
          'console.clean-authentication',
          'console.application-read',
          'console.user-read',
        ],
      },
    ],
  }) as unknown as Phase1Profile;

const fullMap = (sequence: number) =>
  createPhase1FixtureMap({
    schemaVersion: 1,
    recipe: 'fullPhase1',
    allocations: [
      {
        allocationId: `data-${sequence}`,
        role: 'data',
        target: 'primary',
        isolation: {
          persistenceId: `data-persistence-${sequence}`,
          cookieKeyId: `data-cookie-${sequence}`,
          signingKeyId: `data-signing-${sequence}`,
        },
        entities: [
          { kind: 'tenant', logicalId: 'default', runtimeId: `data-tenant-${sequence}` },
          { kind: 'user', logicalId: 'phase1-user', runtimeId: `data-user-${sequence}` },
          { kind: 'application', logicalId: 'phase1-app', runtimeId: `app-${sequence}` },
          {
            kind: 'application',
            logicalId: 'phase1-browser',
            runtimeId: `browser-${sequence}`,
          },
          { kind: 'resource', logicalId: 'phase1-api', runtimeId: `resource-${sequence}` },
          {
            kind: 'scope',
            logicalId: 'phase1-read-profile',
            runtimeId: `scope-${sequence}`,
          },
          { kind: 'role', logicalId: 'phase1-reader', runtimeId: `reader-${sequence}` },
        ],
      },
      {
        allocationId: `admin-${sequence}`,
        role: 'admin',
        target: 'primary',
        isolation: {
          persistenceId: `admin-persistence-${sequence}`,
          cookieKeyId: `admin-cookie-${sequence}`,
          signingKeyId: `admin-signing-${sequence}`,
        },
        entities: [
          { kind: 'tenant', logicalId: 'admin', runtimeId: 'admin' },
          { kind: 'user', logicalId: 'phase1-admin', runtimeId: `admin-user-${sequence}` },
          { kind: 'application', logicalId: 'admin-console', runtimeId: 'admin-console' },
          ...Array.from({ length: 3 }, (_value, index) => ({
            kind: 'resource',
            logicalId: `admin.resource.${index + 1}`,
            runtimeId: `admin-resource-${sequence}-${index + 1}`,
          })),
          ...Array.from({ length: 2 }, (_value, index) => ({
            kind: 'role',
            logicalId: index === 0 ? 'default:admin' : 'user',
            runtimeId: `admin-role-${sequence}-${index + 1}`,
          })),
          { kind: 'organization', logicalId: 't-default', runtimeId: 't-default' },
          {
            kind: 'organization-role',
            logicalId: 'admin',
            runtimeId: `organization-role-${sequence}`,
          },
        ],
      },
    ],
  });

const createHarness = (
  modules: readonly Phase1BrowserFlowModule[] = canonicalBrowserFlows,
  failingFlow?: Phase1BrowserFlowModule['id']
) => {
  const events: string[] = [];
  const sessions: Phase1BrowserSession[] = [];
  let sequence = 0;
  let provisionCount = 0;
  let launchCount = 0;
  const provisioner: Phase1BrowserFixtureProvisioner = {
    provision: async () => {
      provisionCount += 1;
      sequence += 1;
      events.push(`provision-${sequence}`);
      return createProvisionedPhase1Fixture({
        public: fullMap(sequence),
        passwords: [
          { logicalId: 'phase1-user', value: `data-password-${sequence}` },
          { logicalId: 'phase1-admin', value: `admin-password-${sequence}` },
        ],
        clientSecrets: [],
      });
    },
    projectState: async (fixture) => ({
      schemaVersion: 1,
      recipe: fixture.public.recipe,
      allocations: [],
    }),
    readUserActivityState: async () => ({ lastSignInState: 'never' }),
    cleanup: async (fixture) => {
      events.push(`cleanup-${fixture.public.allocations[0]?.allocationId ?? 'missing'}`);
    },
  };
  const observer: Phase1BrowserGroupObserver = {
    runInFreshContext: async (groupId, _signal, _target, use) => {
      launchCount += 1;
      events.push(`open-${groupId}`);
      const session = Object.freeze({
        preloadDemoConfiguration: async () => {},
        navigate: async () => {},
        waitForRoute: async () => {},
        waitForExactRoute: async () => {},
        assertRoute: async () => {},
        assertExactRoute: async () => {},
        fill: async () => {},
        click: async () => {},
        expectText: async () => {},
        expectCount: async () => {},
        clickAndObserveObject: async () => Object.freeze({}),
        waitForNetworkFacts: async () =>
          Object.freeze({
            signIns: [],
            callbacks: [],
            endpointDiscoveries: [],
            exchanges: [],
            accountReads: [],
            applicationReads: [],
            userReads: [],
          }),
      }) as Phase1BrowserSession;
      sessions.push(session);
      try {
        return await use(session);
      } finally {
        events.push(`close-${groupId}`);
      }
    },
  };
  const executableModules = modules.map((module) =>
    Object.freeze({
      ...module,
      run: async (context: Parameters<Phase1BrowserFlowModule['run']>[0]) => {
        events.push(`flow-${module.id}`);
        const sessionIndex = sessions.indexOf(context.session);
        if (failingFlow === module.id) {
          throw new Error('Fixed synthetic browser flow failure');
        }
        return Object.freeze({ completed: true, sessionIndex }) as JsonObject;
      },
    })
  );

  return {
    events,
    executableModules,
    observer,
    provisioner,
    sessions,
    counts: () => ({ launchCount, provisionCount }),
  };
};

describe('Phase 1 ordered browser runner', () => {
  it('rejects a structurally compatible observer before secrets are provisioned', async () => {
    const harness = createHarness();

    await expect(
      runPhase1BrowserFlows({
        profile: profile(),
        target,
        provisioner: harness.provisioner,
        observer: harness.observer,
        signal: new AbortController().signal,
      })
    ).rejects.toThrow('Invalid Phase 1 browser observer');
    expect(harness.counts()).toEqual({ launchCount: 0, provisionCount: 0 });
  });

  it('runs two isolated groups and shares only the ordered Console session', async () => {
    const harness = createHarness();
    const result = await runPhase1BrowserFlowsForTesting(
      {
        profile: profile(),
        target,
        provisioner: harness.provisioner,
        observer: harness.observer,
        signal: new AbortController().signal,
      },
      { modules: harness.executableModules }
    );

    expect(harness.counts()).toEqual({ launchCount: 2, provisionCount: 2 });
    expect(harness.sessions).toHaveLength(2);
    expect(result.groups.map(({ id }) => id)).toEqual(['experience', 'console']);
    expect(result.groups.flatMap(({ flows }) => flows.map(({ id }) => id))).toEqual(
      canonicalBrowserFlows.map(({ id }) => id)
    );
    expect(result.groups[0]?.flows[0]?.observation).toEqual({ completed: true, sessionIndex: 0 });
    expect(result.groups[1]?.flows.map(({ observation }) => observation.sessionIndex)).toEqual([
      1, 1, 1,
    ]);
    expect(result.groups[0]?.flows[0]?.sourceEvidence[0]?.commit).toBe(oracleCommit);
    expect(harness.events).toEqual([
      'provision-1',
      'open-experience',
      'flow-experience.password-pkce-consent',
      'close-experience',
      'cleanup-data-1',
      'provision-2',
      'open-console',
      'flow-console.clean-authentication',
      'flow-console.application-read',
      'flow-console.user-read',
      'close-console',
      'cleanup-data-2',
    ]);
  });

  it.each([
    ['omitted', (modules: Phase1BrowserFlowModule[]) => modules.slice(0, -1)],
    [
      'duplicate',
      (modules: Phase1BrowserFlowModule[]) => [modules[0]!, modules[1]!, modules[2]!, modules[2]!],
    ],
    [
      'reordered',
      (modules: Phase1BrowserFlowModule[]) => [modules[0]!, modules[2]!, modules[1]!, modules[3]!],
    ],
    [
      'cross-assigned',
      (modules: Phase1BrowserFlowModule[]) => [
        modules[0]!,
        { ...modules[1]!, executionGroup: 'experience' as const },
        modules[2]!,
        modules[3]!,
      ],
    ],
    [
      'source-reordered',
      (modules: Phase1BrowserFlowModule[]) => [
        {
          ...modules[0]!,
          sourcePaths: [
            modules[0]!.sourcePaths[1]!,
            modules[0]!.sourcePaths[0]!,
            ...modules[0]!.sourcePaths.slice(2),
          ],
        },
        ...modules.slice(1),
      ],
    ],
  ] as const)('rejects a %s registry before provision or launch', async (_name, mutate) => {
    const mutated = mutate([...canonicalBrowserFlows]);
    const harness = createHarness(mutated);

    await expect(
      runPhase1BrowserFlowsForTesting(
        {
          profile: profile(),
          target,
          provisioner: harness.provisioner,
          observer: harness.observer,
          signal: new AbortController().signal,
        },
        { modules: harness.executableModules }
      )
    ).rejects.toThrow('Invalid Phase 1 browser registry');
    expect(harness.counts()).toEqual({ launchCount: 0, provisionCount: 0 });
  });

  it('closes the Console context and fixture after a middle-flow failure', async () => {
    const harness = createHarness(canonicalBrowserFlows, 'console.application-read');

    await expect(
      runPhase1BrowserFlowsForTesting(
        {
          profile: profile(),
          target,
          provisioner: harness.provisioner,
          observer: harness.observer,
          signal: new AbortController().signal,
        },
        { modules: harness.executableModules }
      )
    ).rejects.toThrow('Fixed synthetic browser flow failure');
    expect(harness.events).toContain('close-console');
    expect(harness.events).toContain('cleanup-data-2');
    expect(harness.events).not.toContain('flow-console.user-read');
  });

  it('locks the four source arrays and their 25-path first-occurrence union', () => {
    expect(canonicalBrowserFlows.map(({ sourcePaths }) => sourcePaths.length)).toEqual([
      8, 11, 7, 6,
    ]);
    expect(new Set(canonicalBrowserFlows.flatMap(({ sourcePaths }) => sourcePaths)).size).toBe(25);
    expect(canonicalBrowserSourcePaths).toEqual([
      ...new Set(canonicalBrowserFlows.flatMap(({ sourcePaths }) => sourcePaths)),
    ]);
    expect(Object.isFrozen(canonicalBrowserSourcePaths)).toBe(true);
    expect(() => validatePhase1BrowserRegistry(profile())).not.toThrow();
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
