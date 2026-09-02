/* eslint-disable no-use-extend-native/no-use-extend-native -- The exact registry ordering assertion uses the standard ES2023 non-mutating array method. */
import type { JsonValue } from '../../normalize.js';
import { SymbolTable } from '../../symbol-table.js';
import type { Phase1BrowserFixtureProvisioner } from '../browser/activity-reader.js';
import { assertPhase1EvidenceIsSanitized, createVerifiedTokenObservations } from '../evidence.js';
import { differentialScenarioIds, type Phase1ScenarioStepResult } from '../model.js';
import type { Phase1EvidenceRuntimeContext } from '../snapshots/runtime-context.js';

import {
  runPhase1DifferentialRuntimeForTesting,
  type Phase1DifferentialRuntimeDependencies,
} from './runtime.js';

const digest = `sha256:${'1'.repeat(64)}`;
const harnessCommit = '2'.repeat(40);

const context = (mode: 'review-candidate' | 'mirror-control' | 'runtime-candidate') =>
  ({
    authorization: {
      mode,
      profile: {
        phase1Harness: { commit: harnessCommit },
        differentialScenarios: differentialScenarioIds,
      },
      profileSha256: '3'.repeat(64),
      schemaSha256: '4'.repeat(64),
    },
    oracleImageDigest: digest,
    candidateImageDigest: mode === 'runtime-candidate' ? `sha256:${'5'.repeat(64)}` : digest,
    evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
    oracleSnapshotPath: '/var/tmp/henry-build/phase1/oracle-snapshots.json',
    repositoryRoot: '/home/henry/repo/logto',
    conformanceRoot: '/var/tmp/henry-build/phase1/conformance',
    targets: {
      oracle: {
        primary: {
          label: 'oracle',
          coreUrl: 'http://localhost:3311/',
          adminUrl: 'http://localhost:3411/',
        },
        foreign: {
          label: 'oracle',
          coreUrl: 'http://localhost:3312/',
          adminUrl: 'http://localhost:3412/',
        },
      },
      candidate: {
        primary: {
          label: 'candidate',
          coreUrl: 'http://localhost:3321/',
          adminUrl: 'http://localhost:3421/',
        },
        foreign: {
          label: 'candidate',
          coreUrl: 'http://localhost:3322/',
          adminUrl: 'http://localhost:3422/',
        },
      },
    },
    isolationAttestations: {
      oracle: {
        data: { persistenceId: 'op', cookieKeyId: 'odc', signingKeyId: 'ods' },
        admin: { persistenceId: 'op', cookieKeyId: 'oac', signingKeyId: 'oas' },
        foreign: { persistenceId: 'ofp', cookieKeyId: 'ofc', signingKeyId: 'ofs' },
      },
      candidate: {
        data: { persistenceId: 'cp', cookieKeyId: 'cdc', signingKeyId: 'cds' },
        admin: { persistenceId: 'cp', cookieKeyId: 'cac', signingKeyId: 'cas' },
        foreign: { persistenceId: 'cfp', cookieKeyId: 'cfc', signingKeyId: 'cfs' },
      },
    },
  }) as unknown as Phase1EvidenceRuntimeContext;

const projection = (stepId: string, status = 200): Phase1ScenarioStepResult => ({
  stepId,
  value: {
    status,
    mediaType: null,
    error: null,
    headers: {},
    body: { observed: true },
    redirect: null,
    cookies: [],
    urls: [],
    tokens: [],
    generatedIds: {},
    persistedState: { observed: true },
    semanticState: { observed: true },
    sideEffects: { observed: true },
    outcomes: [],
  },
});

const provisioner: Phase1BrowserFixtureProvisioner = Object.freeze({
  provision: async () => {
    throw new Error('not used by the injected scenario runner');
  },
  projectState: async () => {
    throw new Error('not used by the injected scenario runner');
  },
  readUserActivityState: async () => {
    throw new Error('not used by the injected scenario runner');
  },
  cleanup: async () => {
    await Promise.resolve();
  },
});

const dependencies = (
  mutateCandidate?: (
    scenarioId: string,
    steps: readonly Phase1ScenarioStepResult[]
  ) => readonly Phase1ScenarioStepResult[]
): Phase1DifferentialRuntimeDependencies => ({
  createReferenceProvisioner: () => provisioner,
  createSessionBinding: () => {
    throw new Error('the injected scenario runner does not create protocol sessions');
  },
  createReferenceProjector: () => {
    throw new Error('the injected scenario runner does not project state');
  },
  loadContainerGraph: () => ({
    projectName: 'aster-phase1-0123456789abcdef',
    oracle: { primary: '1'.repeat(64), foreign: '2'.repeat(64) },
    candidate: { primary: '3'.repeat(64), foreign: '4'.repeat(64) },
  }),
  runScenario: async (scenario, runtime) => {
    const steps = scenario.orderedSteps.map(({ id }) => projection(id));
    const output =
      runtime.target.label === 'candidate' && mutateCandidate
        ? mutateCandidate(scenario.id, steps)
        : steps;

    return { target: runtime.target.label, steps: output };
  },
});

describe('Phase 1 differential runtime', () => {
  it.each(['review-candidate', 'mirror-control'] as const)(
    'builds an exact sorted zero-difference 22-scenario artifact in %s mode',
    async (mode) => {
      const result = await runPhase1DifferentialRuntimeForTesting(context(mode), dependencies());

      expect(Object.keys(result)).toEqual([
        'schemaVersion',
        'mode',
        'provenance',
        'sanitizerSuccess',
        'scenarios',
      ]);
      expect(result.scenarios).toHaveLength(22);
      expect(result.scenarios.map(({ id }) => id)).toEqual([...differentialScenarioIds].toSorted());
      expect(result.scenarios.every(({ differences }) => differences.length === 0)).toBe(true);
      expect(result.scenarios[0]?.oracle.label).toBe('oracle');
      expect(result.scenarios[0]?.candidate.label).toBe('candidate');
      expect(Object.keys(result.scenarios[0]?.oracle.value.steps ?? {})).toEqual(expect.any(Array));
      expect(
        Object.keys(
          result.scenarios.find(({ id }) => id === 'authorization.password-pkce-consent')?.oracle
            .value.steps ?? {}
        )
      ).toContain('password');
      expect(JSON.stringify(result)).not.toMatch(/bearer|private-value/iu);
    }
  );

  it('retains an exact keyed-step difference instead of hiding a candidate mismatch', async () => {
    const result = await runPhase1DifferentialRuntimeForTesting(
      context('mirror-control'),
      dependencies((scenarioId, steps) =>
        scenarioId === 'discovery.config'
          ? [{ ...steps[0]!, value: { ...steps[0]!.value, status: 201 } }, ...steps.slice(1)]
          : steps
      )
    );
    const discovery = result.scenarios.find(({ id }) => id === 'discovery.config');

    expect(discovery?.differences).toEqual([
      { path: '/steps/oidc-discovery/value/status', oracle: 200, candidate: 201 },
    ]);
  });

  it('preserves verified non-empty token provenance through keyed projection cloning', async () => {
    const runtimeContext = context('mirror-control');
    const verified = createVerifiedTokenObservations(
      { refresh_token: 'runtime-refresh-value' },
      { target: runtimeContext.targets.oracle.primary, symbols: new SymbolTable() },
      { boundedClaimTimestampPaths: [], proofs: [] }
    );
    const base = dependencies();
    const result = await runPhase1DifferentialRuntimeForTesting(runtimeContext, {
      ...base,
      runScenario: async (scenario, runtime) => {
        const evidence = await base.runScenario(scenario, runtime);

        return scenario.id === 'token.refresh-rotation'
          ? {
              ...evidence,
              steps: evidence.steps.map((step) =>
                step.stepId === 'code-token'
                  ? {
                      ...step,
                      value: {
                        ...step.value,
                        body: verified.body,
                        tokens: verified.tokens,
                      },
                    }
                  : step
              ),
            }
          : evidence;
      },
    });
    const rotation = result.scenarios.find(({ id }) => id === 'token.refresh-rotation');
    const steps = rotation?.oracle.value.steps;
    const codeToken =
      typeof steps === 'object' && steps !== null && !Array.isArray(steps)
        ? steps['code-token']
        : undefined;

    expect(codeToken).toMatchObject({
      value: {
        body: { refresh: { $observation: 0 } },
        tokens: [{ kind: 'refresh', format: 'opaque', present: true }],
      },
    });
    expect(() => {
      assertPhase1EvidenceIsSanitized(result);
    }).not.toThrow();
  });

  it('refuses runtime-candidate and a non-mirror review image before invoking adapters', async () => {
    const createReferenceProvisioner = import.meta.jest.fn(() => provisioner);
    const blocked = {
      ...dependencies(),
      createReferenceProvisioner,
    };

    await expect(
      runPhase1DifferentialRuntimeForTesting(context('runtime-candidate'), blocked)
    ).rejects.toThrow(/^Phase 1 candidate differential adapter is unavailable$/u);
    await expect(
      runPhase1DifferentialRuntimeForTesting(
        {
          ...context('review-candidate'),
          candidateImageDigest: `sha256:${'6'.repeat(64)}`,
        },
        blocked
      )
    ).rejects.toThrow(/^Phase 1 candidate differential adapter is unavailable$/u);
    expect(createReferenceProvisioner).not.toHaveBeenCalled();
  });

  it('rejects credential-shaped scenario output before artifact publication', async () => {
    await expect(
      runPhase1DifferentialRuntimeForTesting(
        context('mirror-control'),
        dependencies((_scenarioId, steps) => [
          {
            ...steps[0]!,
            value: {
              ...steps[0]!.value,
              body: { accessToken: 'private-value' } satisfies JsonValue,
            },
          },
          ...steps.slice(1),
        ])
      )
    ).rejects.toThrow(/^Invalid Phase 1 differential runtime$/u);
  });
});

/* eslint-enable no-use-extend-native/no-use-extend-native */
