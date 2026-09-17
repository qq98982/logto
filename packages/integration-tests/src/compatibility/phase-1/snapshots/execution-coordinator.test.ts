/* eslint-disable max-lines, no-await-in-loop, no-use-extend-native/no-use-extend-native, unicorn/no-await-expression-member, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Adversarial controls mutate isolated JSON clones, injected sink state, and ordered async failure matrices. */
import { chmod, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { JsonValue } from '../../normalize.js';
import { canonicalPhase1ArtifactBytes } from '../artifact-contract.js';
import { phase1BrowserFlowIds } from '../browser/contracts.js';
import { candidateInvariantContracts } from '../candidate-invariants/index.js';
import { runPhase1CandidateControlRuntime } from '../candidate-invariants/runtime.js';
import { authorizePhase1RunForTesting } from '../cli.js';
import { createPhase1ProjectionEnvelope, hashCanonicalPhase1Json } from '../evidence-envelope.js';
import { snapshotPhase1EvidencePreservingVerifiedTokens } from '../evidence.js';
import {
  candidateInvariantScenarioIds,
  differentialScenarioIds,
  phase1ObservationKinds,
} from '../model.js';
import type { Phase1Profile } from '../profile-types.js';
import { phase1ScenarioContracts } from '../scenario-contracts.js';
import { createSecureEvidenceSink } from '../secure-evidence-sink.js';

import {
  executeAuthorizedPhase1DifferentialGate,
  executeAuthorizedPhase1Run,
  executePhase1BrowserGateForTesting,
  executePhase1CandidateInvariantGateForTesting,
  executePhase1DifferentialGateForTesting,
  executePhase1EvidenceForTesting,
  loadPhase1RuntimeIsolationAttestations,
  runPhase1ExecutionCoordinatorCli,
  validatePhase1EvidenceArtifactForTesting,
  type Phase1EvidenceExecutionPorts,
} from './execution-coordinator.js';
import {
  createPhase1EvidenceRuntimeContext,
  type Phase1EvidenceRuntimeContext,
} from './runtime-context.js';

const roots = new Set<string>();
const createRoot = async (): Promise<string> => {
  const runRoot = path.join(
    '/var/tmp/henry-build',
    `task15-coordinator-${process.pid}-${Date.now()}-${roots.size}`
  );
  const evidence = path.join(runRoot, 'evidence');
  const snapshots = path.join(runRoot, 'snapshots');
  await mkdir(evidence, { recursive: true, mode: 0o700 });
  await mkdir(snapshots, { mode: 0o700 });
  await chmod(runRoot, 0o700);
  await chmod(evidence, 0o700);
  roots.add(runRoot);
  return evidence;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const harnessCommit = '1'.repeat(40);
const digest = `sha256:${'2'.repeat(64)}`;
const candidateDigest = `sha256:${'6'.repeat(64)}`;
const runtimeEnvironment = Object.freeze({
  ASTER_PHASE1_ORACLE_URL: 'http://localhost:3311',
  ASTER_PHASE1_ORACLE_ADMIN_URL: 'http://localhost:3411',
  ASTER_PHASE1_ORACLE_FOREIGN_URL: 'http://localhost:3312',
  ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL: 'http://localhost:3412',
  ASTER_PHASE1_CANDIDATE_URL: 'http://localhost:3321',
  ASTER_PHASE1_CANDIDATE_ADMIN_URL: 'http://localhost:3421',
  ASTER_PHASE1_CANDIDATE_FOREIGN_URL: 'http://localhost:3322',
  ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL: 'http://localhost:3422',
  ASTER_PHASE1_ORACLE_PRIMARY_POSTGRES_CONTAINER_ID: '1'.repeat(64),
  ASTER_PHASE1_ORACLE_FOREIGN_POSTGRES_CONTAINER_ID: '2'.repeat(64),
  ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID: '3'.repeat(64),
  ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID: '4'.repeat(64),
  ASTER_PHASE1_ORACLE_DATA_COOKIE_KEY_SET_SHA256: '5'.repeat(64),
  ASTER_PHASE1_ORACLE_DATA_SIGNING_KEY_SET_SHA256: '6'.repeat(64),
  ASTER_PHASE1_ORACLE_ADMIN_COOKIE_KEY_SET_SHA256: '7'.repeat(64),
  ASTER_PHASE1_ORACLE_ADMIN_SIGNING_KEY_SET_SHA256: '8'.repeat(64),
  ASTER_PHASE1_ORACLE_FOREIGN_COOKIE_KEY_SET_SHA256: '9'.repeat(64),
  ASTER_PHASE1_ORACLE_FOREIGN_SIGNING_KEY_SET_SHA256: 'a'.repeat(64),
  ASTER_PHASE1_CANDIDATE_DATA_COOKIE_KEY_SET_SHA256: 'b'.repeat(64),
  ASTER_PHASE1_CANDIDATE_DATA_SIGNING_KEY_SET_SHA256: 'c'.repeat(64),
  ASTER_PHASE1_CANDIDATE_ADMIN_COOKIE_KEY_SET_SHA256: 'd'.repeat(64),
  ASTER_PHASE1_CANDIDATE_ADMIN_SIGNING_KEY_SET_SHA256: 'e'.repeat(64),
  ASTER_PHASE1_CANDIDATE_FOREIGN_COOKIE_KEY_SET_SHA256: 'f'.repeat(64),
  ASTER_PHASE1_CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256: '0'.repeat(64),
});
const profile = Object.freeze({
  phase1Harness: Object.freeze({ commit: harnessCommit }),
  differentialScenarios: differentialScenarioIds,
  browserFlows: phase1BrowserFlowIds.map((id) => Object.freeze({ id })),
  candidateInvariantScenarios: candidateInvariantScenarioIds,
  conformance: Object.freeze({
    plans: Object.freeze([
      Object.freeze({ testPlanName: 'oidcc-basic-certification-test-plan' }),
      Object.freeze({ testPlanName: 'oidcc-config-certification-test-plan' }),
    ]),
  }),
}) as unknown as Phase1Profile;

const context = (directory: string, recordOracle = true): Phase1EvidenceRuntimeContext => {
  const authorization = authorizePhase1RunForTesting(
    Object.freeze({
      mode: 'review-candidate',
      profile,
      profileSha256: '3'.repeat(64),
      schemaSha256: '4'.repeat(64),
      provenance: Object.freeze({
        kind: 'review-candidate',
        harnessCommit,
        publishable: false,
      }),
      protectedExecution: undefined,
      controls: Object.freeze({
        recordOracle,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
    })
  );

  return createPhase1EvidenceRuntimeContext(
    {
      authorization,
      oracleImageDigest: digest,
      candidateImageDigest: digest,
      evidenceDirectory: directory,
      oracleSnapshotPath: path.join(path.dirname(directory), 'snapshots', 'oracle-snapshots.json'),
      repositoryRoot: '/home/henry/repo/logto',
      conformanceRoot: '/var/tmp/henry-build/phase1-conformance',
      isolationAttestations: loadPhase1RuntimeIsolationAttestations(runtimeEnvironment),
    },
    runtimeEnvironment
  );
};

const candidateGateContext = (directory: string): Phase1EvidenceRuntimeContext => {
  const authorization = authorizePhase1RunForTesting(
    Object.freeze({
      mode: 'runtime-candidate',
      profile,
      profileSha256: '3'.repeat(64),
      schemaSha256: '4'.repeat(64),
      provenance: Object.freeze({
        kind: 'review-candidate',
        harnessCommit,
        publishable: false,
      }),
      protectedExecution: undefined,
      controls: Object.freeze({
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
      candidateInvariantGate: true,
    })
  );

  return createPhase1EvidenceRuntimeContext(
    {
      authorization,
      oracleImageDigest: digest,
      candidateImageDigest: candidateDigest,
      evidenceDirectory: directory,
      oracleSnapshotPath: path.join(path.dirname(directory), 'snapshots', 'oracle-snapshots.json'),
      repositoryRoot: '/home/henry/repo/logto',
      conformanceRoot: '/var/tmp/henry-build/phase1-conformance',
      isolationAttestations: loadPhase1RuntimeIsolationAttestations(runtimeEnvironment),
    },
    runtimeEnvironment
  );
};

const browserGateContext = (directory: string): Phase1EvidenceRuntimeContext => {
  const authorization = authorizePhase1RunForTesting(
    Object.freeze({
      mode: 'runtime-candidate',
      profile,
      profileSha256: '3'.repeat(64),
      schemaSha256: '4'.repeat(64),
      provenance: Object.freeze({
        kind: 'review-candidate',
        harnessCommit,
        publishable: false,
      }),
      protectedExecution: undefined,
      controls: Object.freeze({
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
      browserGate: true,
    })
  );

  return createPhase1EvidenceRuntimeContext(
    {
      authorization,
      oracleImageDigest: digest,
      candidateImageDigest: candidateDigest,
      evidenceDirectory: directory,
      oracleSnapshotPath: path.join(path.dirname(directory), 'snapshots', 'oracle-snapshots.json'),
      repositoryRoot: '/home/henry/repo/logto',
      conformanceRoot: '/var/tmp/henry-build/phase1-conformance',
      isolationAttestations: loadPhase1RuntimeIsolationAttestations(runtimeEnvironment),
    },
    runtimeEnvironment
  );
};

const provenance = (runtime: Phase1EvidenceRuntimeContext) => ({
  harnessCommit,
  profileSha256: runtime.authorization.profileSha256,
  schemaSha256: runtime.authorization.schemaSha256,
  imageDigest: runtime.oracleImageDigest,
});

const comparable = (id: string, oracleLabel: string, candidateLabel: string) => ({
  id,
  oracle: createPhase1ProjectionEnvelope(oracleLabel, { id, accepted: true }),
  candidate: createPhase1ProjectionEnvelope(candidateLabel, { id, accepted: true }),
  differences: [],
});

const scenarioStepValue = () => ({
  status: 200,
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
});

const boundedTimestamp = (value: number) => ({ $timestamp: value, $toleranceSeconds: 30 });

const scenarioComparable = (id: string) => {
  const contract = phase1ScenarioContracts.find((candidate) => candidate.id === id);

  if (!contract) {
    throw new TypeError('missing scenario contract');
  }
  const value = {
    steps: Object.fromEntries(
      contract.orderedSteps.map(({ id: stepId }) => [stepId, { value: scenarioStepValue() }])
    ),
  };

  return {
    id,
    oracle: createPhase1ProjectionEnvelope('oracle', value),
    candidate: createPhase1ProjectionEnvelope('candidate', value),
    differences: [],
  };
};

const differential = (runtime: Phase1EvidenceRuntimeContext): JsonValue => ({
  schemaVersion: 1,
  mode: runtime.authorization.mode,
  provenance: provenance(runtime),
  sanitizerSuccess: true,
  scenarios: [...differentialScenarioIds].toSorted().map((id) => scenarioComparable(id)),
});

const differentialWithAccountTimestamps = (
  runtime: Phase1EvidenceRuntimeContext,
  timestamp: number,
  observed = true
): JsonValue => {
  type MutableScenario = {
    id: string;
    oracle: ReturnType<typeof createPhase1ProjectionEnvelope>;
    candidate: ReturnType<typeof createPhase1ProjectionEnvelope>;
  };
  const artifact = JSON.parse(JSON.stringify(differential(runtime))) as {
    scenarios: MutableScenario[];
  };
  const scenario = artifact.scenarios.find(
    (candidate) => candidate.id === 'account.admin-operator-read'
  );

  if (!scenario) {
    throw new TypeError('missing Account scenario');
  }
  const projection = JSON.parse(JSON.stringify(scenario.oracle.value)) as Record<string, any>;
  const account = projection.steps.account.value;

  account.headers.date = [boundedTimestamp(timestamp)];
  account.body = {
    ...account.body,
    observed,
    createdAt: boundedTimestamp(timestamp),
    updatedAt: boundedTimestamp(timestamp + 1),
    lastSignInAt: boundedTimestamp(timestamp + 2),
  };
  scenario.oracle = createPhase1ProjectionEnvelope('oracle', projection);
  scenario.candidate = createPhase1ProjectionEnvelope('candidate', projection);

  return artifact as JsonValue;
};

const browser = (runtime: Phase1EvidenceRuntimeContext): JsonValue => ({
  schemaVersion: 1,
  mode: runtime.authorization.mode,
  provenance: provenance(runtime),
  sanitizerSuccess: true,
  flows: [...phase1BrowserFlowIds]
    .toSorted()
    .map((id) => comparable(id, 'oracle-browser', 'candidate-browser')),
});

const conformance = (runtime: Phase1EvidenceRuntimeContext): JsonValue => ({
  schemaVersion: 1,
  mode: runtime.authorization.mode,
  provenance: provenance(runtime),
  sanitizerSuccess: true,
  adapterControls: ['oidf-basic-1', 'oidf-basic-2', 'oidf-post-1'].map((id) => ({
    id,
    detected: true,
    result: createPhase1ProjectionEnvelope('adapter-control', {
      configured: true,
      redirectUriMatches: true,
    }),
  })),
  officialResultIds: [],
  planResults: [],
});

const ports = (): Phase1EvidenceExecutionPorts => ({
  differential: async (runtime) => differential(runtime),
  browser: async (runtime) => browser(runtime),
  candidateControls: async (runtime) => runPhase1CandidateControlRuntime(runtime),
  conformance: async (runtime) => conformance(runtime),
});

const runtimeCandidateControls = async (candidate: Phase1EvidenceRuntimeContext) =>
  runPhase1CandidateControlRuntime(candidate, {
    runLiveInvariant: async (id) => {
      const contract = candidateInvariantContracts.find((value) => value.id === id);

      if (!contract) {
        throw new TypeError('missing candidate invariant contract');
      }

      return { id, projection: contract.positiveControl.expectedProjection };
    },
  });

const executeForTesting = async (
  runtime: Phase1EvidenceRuntimeContext,
  executionPorts: Phase1EvidenceExecutionPorts
) =>
  executePhase1EvidenceForTesting(runtime, executionPorts, {
    createSink: async (root, names, authority) =>
      createSecureEvidenceSink(root, names, {}, authority),
  });

describe('Phase 1 evidence execution coordinator', () => {
  it('publishes only one validated differential gate artifact', async () => {
    const root = await createRoot();
    const runtime = context(root);
    const published = await executePhase1DifferentialGateForTesting(
      runtime,
      async (candidate) => differential(candidate),
      {
        createSink: async (directory, names, authority) =>
          createSecureEvidenceSink(directory, names, {}, authority),
      }
    );

    expect(published).toEqual([path.join(root, 'phase-1-differential.json')]);
    expect(await readdir(root)).toEqual(['phase-1-differential.json']);
    await expect(
      executePhase1DifferentialGateForTesting(
        runtime,
        async (candidate) => differential(candidate),
        {
          createSink: async (directory, names, authority) =>
            createSecureEvidenceSink(directory, names, {}, authority),
        }
      )
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
  });

  it('publishes one candidate-bound artifact with eighteen live outcomes and seven controls', async () => {
    const root = await createRoot();
    const runtime = candidateGateContext(root);
    const published = await executePhase1CandidateInvariantGateForTesting(
      runtime,
      runtimeCandidateControls,
      {
        createSink: async (directory, names, authority) =>
          createSecureEvidenceSink(directory, names, {}, authority),
      }
    );

    expect(published).toEqual([path.join(root, 'phase-1-candidate-invariants.json')]);
    expect(await readdir(root)).toEqual(['phase-1-candidate-invariants.json']);
    const artifact = JSON.parse(
      await readFile(path.join(root, 'phase-1-candidate-invariants.json'), 'utf8')
    ) as {
      provenance: { imageDigest: string };
      outcomes: unknown[];
      observationNegativeControls: unknown[];
      discoveryExtraControl: unknown;
    };

    expect(artifact.provenance.imageDigest).toBe(candidateDigest);
    expect(artifact.outcomes).toHaveLength(18);
    expect(artifact.observationNegativeControls).toHaveLength(6);
    expect(artifact.discoveryExtraControl).toBeDefined();
  });

  it('publishes one browser artifact with four zero-difference flows', async () => {
    const root = await createRoot();
    const runtime = browserGateContext(root);
    const published = await executePhase1BrowserGateForTesting(
      runtime,
      async (candidate) => browser(candidate),
      {
        createSink: async (directory, names, authority) =>
          createSecureEvidenceSink(directory, names, {}, authority),
      }
    );

    expect(published).toEqual([path.join(root, 'phase-1-browser.json')]);
    expect(await readdir(root)).toEqual(['phase-1-browser.json']);
    const artifact = JSON.parse(
      await readFile(path.join(root, 'phase-1-browser.json'), 'utf8')
    ) as { provenance: { imageDigest: string }; flows: Array<{ differences: unknown[] }> };

    expect(artifact.provenance.imageDigest).toBe(digest);
    expect(artifact.flows).toHaveLength(4);
    expect(artifact.flows.every(({ differences }) => differences.length === 0)).toBe(true);
  });

  it('rejects non-runtime authorization before the differential live port', async () => {
    const root = await createRoot();
    const runtime = context(root);

    await expect(
      executeAuthorizedPhase1DifferentialGate(runtime.authorization, '/home/henry/repo/logto', {
        ...runtimeEnvironment,
        ASTER_PHASE1_MODE: 'review-candidate',
      })
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it('publishes exactly four complete validated results only after every port succeeds', async () => {
    const root = await createRoot();
    const runtime = context(root);
    const fake = ports();
    const candidateControls = await fake.candidateControls(runtime);

    expect(() =>
      validatePhase1EvidenceArtifactForTesting(
        'phase-1-differential.json',
        differential(runtime),
        runtime
      )
    ).not.toThrow();
    expect(() =>
      validatePhase1EvidenceArtifactForTesting('phase-1-browser.json', browser(runtime), runtime)
    ).not.toThrow();
    expect(() =>
      validatePhase1EvidenceArtifactForTesting(
        'phase-1-candidate-invariants.json',
        candidateControls,
        runtime
      )
    ).not.toThrow();
    expect(() =>
      validatePhase1EvidenceArtifactForTesting(
        'phase-1-conformance.json',
        conformance(runtime),
        runtime
      )
    ).not.toThrow();
    const published = await executeForTesting(runtime, fake);

    expect(published).toHaveLength(4);
    expect(await readdir(root)).toEqual([
      'phase-1-browser.json',
      'phase-1-candidate-invariants.json',
      'phase-1-conformance.json',
      'phase-1-differential.json',
    ]);
    const controls = JSON.parse(
      await readFile(path.join(root, 'phase-1-candidate-invariants.json'), 'utf8')
    ) as { outcomes: unknown[]; observationNegativeControls: unknown[] };
    expect(controls.outcomes).toHaveLength(18);
    expect(controls.observationNegativeControls).toHaveLength(phase1ObservationKinds.length);
    await expect(stat(path.join(root, 'phase-1-browser.json'))).resolves.toMatchObject({
      nlink: 1,
    });
  });

  it('reuses the immutable oracle snapshot without rewriting it', async () => {
    const firstEvidence = await createRoot();
    const runRoot = path.dirname(firstEvidence);
    await executeForTesting(context(firstEvidence), ports());
    const snapshotPath = path.join(runRoot, 'snapshots', 'oracle-snapshots.json');
    const before = await stat(snapshotPath);
    const secondEvidence = path.join(runRoot, 'evidence-verify');
    await mkdir(secondEvidence, { mode: 0o700 });

    await expect(executeForTesting(context(secondEvidence, false), ports())).resolves.toHaveLength(
      4
    );
    const after = await stat(snapshotPath);
    expect(after.ino).toBe(before.ino);
    expect(after.mtimeMs).toBe(before.mtimeMs);
    expect(after.mode % 0o1000).toBe(0o400);
  });

  it('replays when only declared bounded timestamp values advance between runs', async () => {
    const firstEvidence = await createRoot();
    const runRoot = path.dirname(firstEvidence);
    const firstPorts = ports();

    await executeForTesting(context(firstEvidence), {
      ...firstPorts,
      differential: async (runtime) => differentialWithAccountTimestamps(runtime, 1_700_000_000),
    });
    const snapshotPath = path.join(runRoot, 'snapshots', 'oracle-snapshots.json');
    const before = await stat(snapshotPath);
    const secondEvidence = path.join(runRoot, 'evidence-bounded-time-replay');
    await mkdir(secondEvidence, { mode: 0o700 });
    const secondPorts = ports();

    await expect(
      executeForTesting(context(secondEvidence, false), {
        ...secondPorts,
        differential: async (runtime) => differentialWithAccountTimestamps(runtime, 1_800_000_000),
      })
    ).resolves.toHaveLength(4);
    const after = await stat(snapshotPath);
    expect(after.ino).toBe(before.ino);
    expect(after.mtimeMs).toBe(before.mtimeMs);

    const changedEvidence = path.join(runRoot, 'evidence-nontime-change');
    await mkdir(changedEvidence, { mode: 0o700 });
    const changedPorts = ports();
    await expect(
      executeForTesting(context(changedEvidence, false), {
        ...changedPorts,
        differential: async (runtime) =>
          differentialWithAccountTimestamps(runtime, 1_900_000_000, false),
      })
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    await expect(readdir(changedEvidence)).resolves.toEqual([]);
  });

  it('leaves the evidence directory empty when the final port fails', async () => {
    const root = await createRoot();
    const fake = ports();
    let invocations = 0;

    await expect(
      executeForTesting(context(root), {
        ...fake,
        differential: async (runtime) => {
          invocations += 1;
          return fake.differential(runtime);
        },
        browser: async (runtime) => {
          invocations += 1;
          return fake.browser(runtime);
        },
        candidateControls: async (runtime) => {
          invocations += 1;
          return fake.candidateControls(runtime);
        },
        conformance: async () => {
          invocations += 1;
          throw new Error('private-final-port-failure');
        },
      })
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    expect(invocations).toBe(4);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it.each(['third-write', 'final-scan'] as const)(
    'rolls back every published artifact after a %s failure',
    async (failure) => {
      const root = await createRoot();
      let writes = 0;

      await expect(
        executePhase1EvidenceForTesting(context(root), ports(), {
          createSink: async () => ({
            write: async (name, value) => {
              writes += 1;
              if (failure === 'third-write' && writes === 3) {
                throw new Error('injected-write-failure');
              }
              const output = path.join(root, name);
              await writeFile(output, `${JSON.stringify(value)}\n`, { mode: 0o600 });
              return output;
            },
            scan: async () => {
              if (failure === 'final-scan') {
                throw new Error('injected-scan-failure');
              }
              return (await readdir(root)).map((name) => path.join(root, name)).toSorted();
            },
            rollback: async (name) => {
              await rm(path.join(root, name));
            },
          }),
        })
      ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
      await expect(readdir(root)).resolves.toEqual([]);
    }
  );

  it('binds one-use authority to the exact artifact filename', async () => {
    const root = await createRoot();
    const written: string[] = [];

    await expect(
      executePhase1EvidenceForTesting(context(root), ports(), {
        createSink: async (_directory, _names, authority) => ({
          write: async (name, value) => {
            const snapshot = snapshotPhase1EvidencePreservingVerifiedTokens<JsonValue>(value);
            const serialized = Buffer.from(canonicalPhase1ArtifactBytes(snapshot)).toString('utf8');

            authority.consume({
              name: name === 'phase-1-browser.json' ? 'phase-1-conformance.json' : name,
              source: value,
              snapshot,
              serialized,
            });
            const output = path.join(root, name);
            written.push(output);
            return output;
          },
          scan: async () => written.toSorted(),
          rollback: async () => {
            await Promise.resolve();
          },
        }),
      })
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it('rejects forged envelope hashes, undeclared differences, and extra roots', async () => {
    for (const mutate of [
      (value: Record<string, any>) => {
        value.flows[0].oracle.projectionSha256 = 'f'.repeat(64);
      },
      (value: Record<string, any>) => {
        value.flows[0].differences = [{ path: '/accepted', oracle: true, candidate: false }];
      },
      (value: Record<string, any>) => {
        value.privateReviewer = 'not-allowed';
      },
    ]) {
      const root = await createRoot();
      const fake = ports();
      const invalidBrowser = JSON.parse(JSON.stringify(browser(context(root)))) as Record<
        string,
        any
      >;
      mutate(invalidBrowser);

      await expect(
        executeForTesting(context(root), {
          ...fake,
          browser: async () => invalidBrowser as JsonValue,
        })
      ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
      await expect(readdir(root)).resolves.toEqual([]);
    }
  });

  it.each(['empty steps', 'borrowed step'] as const)(
    'rejects a differential projection with %s',
    (mutation) => {
      const runtime = context('/var/tmp/henry-build/phase1-unused-evidence');
      const artifact = JSON.parse(JSON.stringify(differential(runtime))) as Record<string, any>;
      const scenario = artifact.scenarios[0];
      const steps =
        mutation === 'empty steps'
          ? {}
          : {
              ...scenario.oracle.value.steps,
              password: { value: scenarioStepValue() },
            };
      scenario.oracle = createPhase1ProjectionEnvelope('oracle', { steps });
      scenario.candidate = createPhase1ProjectionEnvelope('candidate', { steps });

      expect(() =>
        validatePhase1EvidenceArtifactForTesting('phase-1-differential.json', artifact, runtime)
      ).toThrow(/^Phase 1 evidence execution failed\.$/u);
    }
  );

  it('rejects oversized evidence before the secure sink is created', async () => {
    const root = await createRoot();
    const runtime = context(root);
    const oversized = differential(runtime) as Record<string, any>;
    const first = oversized.scenarios[0];
    const value = JSON.parse(JSON.stringify(first.oracle.value)) as Record<string, any>;
    const firstStep = Object.values(value.steps)[0] as Record<string, any>;
    firstStep.value.body.padding = 'x'.repeat(600_000);
    first.oracle = createPhase1ProjectionEnvelope('oracle', value);
    first.candidate = createPhase1ProjectionEnvelope('candidate', value);
    let sinkCreated = false;

    await expect(
      executePhase1EvidenceForTesting(
        runtime,
        { ...ports(), differential: async () => oversized },
        {
          createSink: async () => {
            sinkCreated = true;
            throw new Error('must-not-create-sink');
          },
        }
      )
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    expect(sinkCreated).toBe(false);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it('rejects hollow or comparison-bearing observation controls with valid recomputed hashes', async () => {
    for (const mutate of [
      (projection: Record<string, any>) => {
        Reflect.deleteProperty(projection, 'baseline');
      },
      (projection: Record<string, any>) => {
        projection.injected = 599;
      },
      (projection: Record<string, any>) => {
        projection.oracle = true;
      },
    ]) {
      const root = await createRoot();
      const runtime = context(root);
      const artifact = JSON.parse(
        JSON.stringify(await runPhase1CandidateControlRuntime(runtime))
      ) as Record<string, any>;
      const envelope = artifact.observationNegativeControls[0].observation;
      mutate(envelope.value);
      envelope.projectionSha256 = hashCanonicalPhase1Json(envelope.value);

      await expect(
        executeForTesting(runtime, {
          ...ports(),
          candidateControls: async () => artifact,
        })
      ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
      await expect(readdir(root)).resolves.toEqual([]);
    }
  });

  it('rejects a false conformance adapter result despite a valid envelope hash', async () => {
    const root = await createRoot();
    const runtime = context(root);
    const artifact = conformance(runtime) as Record<string, any>;
    artifact.adapterControls[0].result = createPhase1ProjectionEnvelope('adapter-control', {
      configured: false,
      redirectUriMatches: true,
    });

    await expect(
      executeForTesting(runtime, { ...ports(), conformance: async () => artifact })
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it('rejects an unbranded cloned context before invoking the first port', async () => {
    const root = await createRoot();
    const forged = { ...context(root) } as Phase1EvidenceRuntimeContext;
    let touched = false;
    const fake = ports();

    await expect(
      executeForTesting(forged, {
        ...fake,
        differential: async (runtime) => {
          touched = true;
          return fake.differential(runtime);
        },
      })
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    expect(touched).toBe(false);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it('derives measured topology attestations and rejects malformed key evidence', () => {
    const attestations = loadPhase1RuntimeIsolationAttestations(runtimeEnvironment);

    expect(attestations.oracle.data.persistenceId).toBe(attestations.oracle.admin.persistenceId);
    expect(attestations.oracle.foreign.persistenceId).not.toBe(
      attestations.oracle.data.persistenceId
    );
    expect(
      new Set([
        attestations.oracle.data.cookieKeyId,
        attestations.oracle.admin.cookieKeyId,
        attestations.candidate.data.cookieKeyId,
      ]).size
    ).toBe(3);
    expect(() =>
      loadPhase1RuntimeIsolationAttestations({
        ...runtimeEnvironment,
        ASTER_PHASE1_ORACLE_DATA_COOKIE_KEY_SET_SHA256: '../forged',
      })
    ).toThrow(/^Phase 1 evidence execution failed\.$/u);
  });

  it('fails before live ports when the same-process execution environment is incomplete', async () => {
    const root = await createRoot();

    await expect(
      executeAuthorizedPhase1Run(context(root).authorization, '/home/henry/repo/logto', {})
    ).rejects.toThrow(/^Phase 1 evidence execution failed\.$/u);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it('denies direct coordinator execution because authorization identity is process-local', async () => {
    const errors: string[] = [];
    const original = console.error;
    console.error = (message: string) => errors.push(message);
    try {
      await expect(runPhase1ExecutionCoordinatorCli()).resolves.toBe(1);
    } finally {
      console.error = original;
    }
    expect(errors).toEqual(['Direct Phase 1 coordinator execution is unavailable.']);
  });
});

/* eslint-enable max-lines, no-await-in-loop, no-use-extend-native/no-use-extend-native, unicorn/no-await-expression-member, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
