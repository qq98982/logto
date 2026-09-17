import {
  authorizePhase1RunForTesting,
  type Phase1RunAuthorization,
  type Phase1RunMode,
} from '../cli.js';
import type { Phase1Profile } from '../profile-types.js';

import {
  createPhase1EvidenceRuntimeContext,
  createPhase1EvidenceRuntimeContextForTesting,
  assertValidatedPhase1EvidenceRuntimeContext,
  loadPhase1RuntimeTargetGraph,
  type Phase1RuntimeIsolationAttestations,
} from './runtime-context.js';

const harnessCommit = '1'.repeat(40);
const oracleImageDigest = `sha256:${'2'.repeat(64)}`;
const candidateImageDigest = `sha256:${'3'.repeat(64)}`;

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

const isolation = (): Phase1RuntimeIsolationAttestations => ({
  oracle: {
    data: {
      persistenceId: 'oracle-primary-database',
      cookieKeyId: 'oracle-data-cookie-key',
      signingKeyId: 'oracle-data-signing-key',
    },
    admin: {
      persistenceId: 'oracle-primary-database',
      cookieKeyId: 'oracle-admin-cookie-key',
      signingKeyId: 'oracle-admin-signing-key',
    },
    foreign: {
      persistenceId: 'oracle-foreign-database',
      cookieKeyId: 'oracle-foreign-cookie-key',
      signingKeyId: 'oracle-foreign-signing-key',
    },
  },
  candidate: {
    data: {
      persistenceId: 'candidate-primary-database',
      cookieKeyId: 'candidate-data-cookie-key',
      signingKeyId: 'candidate-data-signing-key',
    },
    admin: {
      persistenceId: 'candidate-primary-database',
      cookieKeyId: 'candidate-admin-cookie-key',
      signingKeyId: 'candidate-admin-signing-key',
    },
    foreign: {
      persistenceId: 'candidate-foreign-database',
      cookieKeyId: 'candidate-foreign-cookie-key',
      signingKeyId: 'candidate-foreign-signing-key',
    },
  },
});

const authorization = (mode: Phase1RunMode): Phase1RunAuthorization => {
  const provenance = Object.freeze(
    mode === 'review-candidate'
      ? {
          kind: 'review-candidate' as const,
          harnessCommit,
          publishable: false as const,
        }
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
      profileSha256: '4'.repeat(64),
      schemaSha256: '5'.repeat(64),
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

const contextInput = (mode: Phase1RunMode = 'review-candidate') => ({
  authorization: authorization(mode),
  oracleImageDigest,
  candidateImageDigest: mode === 'mirror-control' ? oracleImageDigest : candidateImageDigest,
  evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
  oracleSnapshotPath: '/var/tmp/henry-build/phase1/oracle-snapshots.json',
  repositoryRoot: '/home/henry/repo/logto',
  conformanceRoot: '/var/tmp/henry-build/phase1/conformance',
  isolationAttestations: isolation(),
});

const differentialGateInput = () => {
  const provenance = Object.freeze({
    kind: 'review-candidate' as const,
    harnessCommit,
    publishable: false as const,
  });
  const gateAuthorization = authorizePhase1RunForTesting(
    Object.freeze({
      mode: 'runtime-candidate' as const,
      profile: Object.freeze({
        phase1Harness: Object.freeze({ commit: harnessCommit }),
      }) as Phase1Profile,
      profileSha256: '4'.repeat(64),
      schemaSha256: '5'.repeat(64),
      provenance,
      protectedExecution: undefined,
      controls: Object.freeze({
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
      differentialGate: true as const,
    })
  );

  return { ...contextInput('runtime-candidate'), authorization: gateAuthorization };
};

const candidateInvariantGateInput = () => {
  const base = differentialGateInput();
  const { mode, profile, profileSha256, schemaSha256, provenance, protectedExecution, controls } =
    base.authorization;
  const authorization = authorizePhase1RunForTesting(
    Object.freeze({
      mode,
      profile,
      profileSha256,
      schemaSha256,
      provenance,
      protectedExecution,
      controls,
      candidateInvariantGate: true as const,
    })
  );

  return { ...base, authorization };
};

describe('Phase 1 evidence runtime context', () => {
  it('loads the exact separated primary and foreign target graph', () => {
    const targets = loadPhase1RuntimeTargetGraph(environment);

    expect(targets).toEqual({
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
    });
    expect(Object.isFrozen(targets)).toBe(true);
    expect(Object.isFrozen(targets.oracle.primary)).toBe(true);
  });

  it('creates a closed context retaining the accepted authorization and non-secret attestations', () => {
    const input = contextInput();
    const context = createPhase1EvidenceRuntimeContext(input, environment);

    expect(Object.keys(context)).toEqual([
      'authorization',
      'oracleImageDigest',
      'candidateImageDigest',
      'evidenceDirectory',
      'oracleSnapshotPath',
      'repositoryRoot',
      'conformanceRoot',
      'targets',
      'isolationAttestations',
    ]);
    expect(context.authorization).toBe(input.authorization);
    expect(context.isolationAttestations).toEqual(input.isolationAttestations);
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.isolationAttestations.candidate.foreign)).toBe(true);
    expect(() => {
      assertValidatedPhase1EvidenceRuntimeContext(context);
    }).not.toThrow();
    expect(() => {
      assertValidatedPhase1EvidenceRuntimeContext({ ...context });
    }).toThrow(/^Invalid Phase 1 evidence runtime context$/u);
  });

  it('accepts review provenance only for an explicit runtime differential gate', () => {
    const input = differentialGateInput();
    const context = createPhase1EvidenceRuntimeContext(input, environment);

    expect(context.authorization).toBe(input.authorization);
    expect(context.authorization).toMatchObject({
      mode: 'runtime-candidate',
      differentialGate: true,
      protectedExecution: undefined,
      provenance: { kind: 'review-candidate', publishable: false },
    });
    const withoutMarker = authorizePhase1RunForTesting(
      Object.freeze({
        ...input.authorization,
        differentialGate: undefined,
      }) as Phase1RunAuthorization
    );

    expect(() =>
      createPhase1EvidenceRuntimeContext({ ...input, authorization: withoutMarker }, environment)
    ).toThrow(/^Invalid Phase 1 evidence runtime context$/u);
  });

  it('accepts review provenance only for an explicit runtime candidate invariant gate', () => {
    const input = candidateInvariantGateInput();
    const context = createPhase1EvidenceRuntimeContext(input, environment);

    expect(context.authorization).toBe(input.authorization);
    expect(context.authorization).toMatchObject({
      mode: 'runtime-candidate',
      candidateInvariantGate: true,
      protectedExecution: undefined,
      provenance: { kind: 'review-candidate', publishable: false },
    });
    const bothMarkers = authorizePhase1RunForTesting(
      Object.freeze({
        ...input.authorization,
        differentialGate: true,
      }) as Phase1RunAuthorization
    );

    expect(() =>
      createPhase1EvidenceRuntimeContext({ ...input, authorization: bothMarkers }, environment)
    ).toThrow(/^Invalid Phase 1 evidence runtime context$/u);
  });

  it('rejects a structurally valid protected authorization that lacks accepted provenance identity', () => {
    expect(() =>
      createPhase1EvidenceRuntimeContext(contextInput('mirror-control'), environment)
    ).toThrow(/^Invalid Phase 1 evidence runtime context$/u);
  });

  it('rechecks the supplied protected execution against the accepted authority result', () => {
    const input = contextInput('mirror-control');
    const context = createPhase1EvidenceRuntimeContextForTesting(input, environment, {
      assertRunAuthorization: (value): asserts value is Phase1RunAuthorization => {
        expect(value).toBe(input.authorization);
      },
      authorizeProtectedExecution: (mode, provenance) => Object.freeze({ mode, provenance }),
    });

    expect(context.authorization).toBe(input.authorization);
    expect(context.oracleImageDigest).toBe(context.candidateImageDigest);
  });

  it('rejects any aliased target origin across implementations or primary and foreign stacks', () => {
    expect(() =>
      loadPhase1RuntimeTargetGraph({
        ...environment,
        ASTER_PHASE1_CANDIDATE_FOREIGN_URL: environment.ASTER_PHASE1_ORACLE_URL,
      })
    ).toThrow(/^Invalid Phase 1 evidence runtime context$/u);
  });

  it.each([
    [
      'extra field',
      (value: Phase1RuntimeIsolationAttestations) => ({
        ...value,
        oracle: {
          ...value.oracle,
          data: { ...value.oracle.data, privateValue: 'not-allowed' },
        },
      }),
    ],
    [
      'split primary persistence',
      (value: Phase1RuntimeIsolationAttestations) => ({
        ...value,
        oracle: {
          ...value.oracle,
          admin: { ...value.oracle.admin, persistenceId: 'different-primary-database' },
        },
      }),
    ],
    [
      'cross-target key reuse',
      (value: Phase1RuntimeIsolationAttestations) => ({
        ...value,
        candidate: {
          ...value.candidate,
          data: {
            ...value.candidate.data,
            cookieKeyId: value.oracle.data.cookieKeyId,
          },
        },
      }),
    ],
  ] as const)('rejects invalid isolation metadata: %s', (_name, mutate) => {
    const input = contextInput();

    expect(() =>
      createPhase1EvidenceRuntimeContext(
        { ...input, isolationAttestations: mutate(isolation()) as never },
        environment
      )
    ).toThrow(/^Invalid Phase 1 evidence runtime context$/u);
  });
});
