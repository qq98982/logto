/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Narrow inert adapters and local event arrays isolate browser evidence composition from live infrastructure. */
import type { TargetConfig } from '../../model.js';
import type { JsonObject } from '../../normalize.js';
import {
  authorizePhase1RunForTesting,
  type Phase1RunAuthorization,
  type Phase1RunMode,
} from '../cli.js';
import type { Phase1Profile } from '../profile-types.js';
import {
  createPhase1EvidenceRuntimeContext,
  createPhase1EvidenceRuntimeContextForTesting,
  type Phase1EvidenceRuntimeContext,
  type Phase1RuntimeIsolationAttestations,
} from '../snapshots/runtime-context.js';

import type { Phase1BrowserFixtureProvisioner } from './activity-reader.js';
import type {
  phase1BrowserFlowIds,
  Phase1BrowserGroupObserver,
  Phase1BrowserRunEvidence,
} from './contracts.js';
import {
  runPhase1BrowserRuntimeForTesting,
  type Phase1BrowserRuntimeDependencies,
} from './runtime.js';

const harnessCommit = '1'.repeat(40);
const digest = `sha256:${'2'.repeat(64)}`;
const environment = Object.freeze({
  ASTER_PHASE1_ORACLE_URL: 'http://localhost:3311',
  ASTER_PHASE1_ORACLE_ADMIN_URL: 'http://localhost:3411',
  ASTER_PHASE1_ORACLE_FOREIGN_URL: 'http://localhost:3312',
  ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL: 'http://localhost:3412',
  ASTER_PHASE1_CANDIDATE_URL: 'http://localhost:3321',
  ASTER_PHASE1_CANDIDATE_ADMIN_URL: 'http://localhost:3421',
  ASTER_PHASE1_CANDIDATE_FOREIGN_URL: 'http://localhost:3322',
  ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL: 'http://localhost:3422',
});

const attestation = (prefix: string, primaryDatabase: string) => ({
  data: {
    persistenceId: primaryDatabase,
    cookieKeyId: `${prefix}-data-cookie`,
    signingKeyId: `${prefix}-data-signing`,
  },
  admin: {
    persistenceId: primaryDatabase,
    cookieKeyId: `${prefix}-admin-cookie`,
    signingKeyId: `${prefix}-admin-signing`,
  },
  foreign: {
    persistenceId: `${prefix}-foreign-database`,
    cookieKeyId: `${prefix}-foreign-cookie`,
    signingKeyId: `${prefix}-foreign-signing`,
  },
});

const isolationAttestations: Phase1RuntimeIsolationAttestations = {
  oracle: attestation('oracle', 'oracle-primary-database'),
  candidate: attestation('candidate', 'candidate-primary-database'),
};

const authorization = (mode: Phase1RunMode): Phase1RunAuthorization => {
  const provenance = Object.freeze(
    mode === 'review-candidate'
      ? { kind: 'review-candidate' as const, harnessCommit, publishable: false as const }
      : {
          kind: 'accepted-harness' as const,
          harnessCommit,
          protectedBranch: 'phase1-acceptance-lock',
          pullRequestNumber: 17,
          publishable: true as const,
        }
  );

  return authorizePhase1RunForTesting(
    Object.freeze({
      mode,
      profile: Object.freeze({
        phase1Harness: Object.freeze({ commit: harnessCommit }),
      }) as Phase1Profile,
      profileSha256: '3'.repeat(64),
      schemaSha256: '4'.repeat(64),
      provenance,
      protectedExecution:
        mode === 'review-candidate' ? undefined : Object.freeze({ mode, provenance }),
      controls: Object.freeze({
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
    }) as unknown as Phase1RunAuthorization
  );
};

const context = (mode: Phase1RunMode = 'mirror-control'): Phase1EvidenceRuntimeContext =>
  (() => {
    const input = {
      authorization: authorization(mode),
      oracleImageDigest: digest,
      candidateImageDigest: mode === 'mirror-control' ? digest : `sha256:${'5'.repeat(64)}`,
      evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
      oracleSnapshotPath: '/var/tmp/henry-build/phase1/oracle-snapshots.json',
      repositoryRoot: '/home/henry/repo/logto',
      conformanceRoot: '/var/tmp/henry-build/phase1/conformance',
      isolationAttestations,
    };

    return mode === 'review-candidate'
      ? createPhase1EvidenceRuntimeContext(input, environment)
      : createPhase1EvidenceRuntimeContextForTesting(input, environment, {
          assertRunAuthorization: (value): asserts value is Phase1RunAuthorization => {
            expect(value).toBe(input.authorization);
          },
          authorizeProtectedExecution: (acceptedMode, provenance) =>
            Object.freeze({ mode: acceptedMode, provenance }),
        });
  })();

const provisioner = (): Phase1BrowserFixtureProvisioner => ({
  provision: async () => {
    throw new Error('not used by the injected browser runner');
  },
  projectState: async () => {
    throw new Error('not used by the injected browser runner');
  },
  readUserActivityState: async () => {
    throw new Error('not used by the injected browser runner');
  },
  cleanup: async () => {},
});

const observation = (id: (typeof phase1BrowserFlowIds)[number]): JsonObject => ({
  flow: id,
  accepted: true,
  nested: { stable: true },
});

const runEvidence = (mutateApplicationFlow = false): Phase1BrowserRunEvidence => ({
  groups: [
    {
      id: 'experience',
      flows: [
        {
          id: 'experience.password-pkce-consent',
          executionGroup: 'experience',
          sourceEvidence: [],
          observation: observation('experience.password-pkce-consent'),
        },
      ],
    },
    {
      id: 'console',
      flows: [
        {
          id: 'console.clean-authentication',
          executionGroup: 'console',
          sourceEvidence: [],
          observation: observation('console.clean-authentication'),
        },
        {
          id: 'console.application-read',
          executionGroup: 'console',
          sourceEvidence: [],
          observation: mutateApplicationFlow
            ? { ...observation('console.application-read'), accepted: false }
            : observation('console.application-read'),
        },
        {
          id: 'console.user-read',
          executionGroup: 'console',
          sourceEvidence: [],
          observation: observation('console.user-read'),
        },
      ],
    },
  ],
});

const dependencies = (mutateCandidate = false) => {
  type ReferenceProvisionerInput = Parameters<
    Phase1BrowserRuntimeDependencies['createReferenceProvisioner']
  >[0];
  const targetOrder: Array<TargetConfig['label']> = [];
  const provisionerInputs: ReferenceProvisionerInput[] = [];
  const adapter = provisioner();
  const observer: Phase1BrowserGroupObserver = {
    runInFreshContext: async () => {
      throw new Error('not used by the injected browser runner');
    },
  };
  const value: Phase1BrowserRuntimeDependencies = {
    createObserver: () => observer,
    createReferenceProvisioner: (input) => {
      provisionerInputs.push(input);
      return adapter;
    },
    runBrowserFlows: async (input) => {
      targetOrder.push(input.target.label);
      return runEvidence(mutateCandidate && input.target.label === 'candidate');
    },
  };

  return { value, targetOrder, provisionerInputs };
};

describe('Phase 1 browser production runtime', () => {
  it('runs oracle then candidate and emits exact sorted zero-difference mirror evidence', async () => {
    const runtimeContext = context();
    const harness = dependencies();
    const result = await runPhase1BrowserRuntimeForTesting(runtimeContext, harness.value);

    expect(harness.targetOrder).toEqual(['oracle', 'candidate']);
    expect(harness.provisionerInputs).toHaveLength(2);
    expect(harness.provisionerInputs[0]).toMatchObject({
      target: runtimeContext.targets.oracle.primary,
      foreignTarget: runtimeContext.targets.oracle.foreign,
      isolation: runtimeContext.isolationAttestations.oracle,
      applicationRedirectUriMode: 'target',
      signInExperienceBrandingMode: 'clear',
    });
    expect(harness.provisionerInputs[1]).toMatchObject({
      target: runtimeContext.targets.candidate.primary,
      foreignTarget: runtimeContext.targets.candidate.foreign,
      isolation: runtimeContext.isolationAttestations.candidate,
      applicationRedirectUriMode: 'target',
      signInExperienceBrandingMode: 'clear',
    });
    expect(Object.keys(result)).toEqual([
      'schemaVersion',
      'mode',
      'provenance',
      'sanitizerSuccess',
      'flows',
    ]);
    expect(result).toMatchObject({
      schemaVersion: 1,
      mode: 'mirror-control',
      provenance: {
        harnessCommit,
        profileSha256: '3'.repeat(64),
        schemaSha256: '4'.repeat(64),
        imageDigest: digest,
      },
      sanitizerSuccess: true,
    });
    expect(result.flows.map(({ id }) => id)).toEqual([
      'console.application-read',
      'console.clean-authentication',
      'console.user-read',
      'experience.password-pkce-consent',
    ]);
    expect(result.flows.every(({ differences }) => differences.length === 0)).toBe(true);
    expect(result.flows[0]?.oracle.label).toBe('oracle-browser');
    expect(result.flows[0]?.candidate.label).toBe('candidate-browser');
    expect(result.flows[0]?.oracle.projectionSha256).toMatch(/^[0-9a-f]{64}$/u);
    expect(result.flows[0]?.oracle.projectionSha256).toBe(
      result.flows[0]?.candidate.projectionSha256
    );
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.flows[0]?.oracle.value)).toBe(true);
  });

  it('refuses runtime-candidate before constructing any browser or fixture adapter', async () => {
    const harness = dependencies();

    await expect(
      runPhase1BrowserRuntimeForTesting(context('runtime-candidate'), harness.value)
    ).rejects.toThrow(/^Phase 1 candidate browser fixture adapter is unavailable$/u);
    expect(harness.targetOrder).toEqual([]);
    expect(harness.provisionerInputs).toEqual([]);
  });

  it('rejects a candidate browser observation difference instead of publishing false parity', async () => {
    const harness = dependencies(true);

    await expect(runPhase1BrowserRuntimeForTesting(context(), harness.value)).rejects.toThrow(
      /^Invalid Phase 1 browser runtime$/u
    );
    expect(harness.targetOrder).toEqual(['oracle', 'candidate']);
  });
});

/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
