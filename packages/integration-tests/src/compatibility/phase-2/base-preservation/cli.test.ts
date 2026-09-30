/* eslint-disable max-lines, no-await-in-loop, unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The CLI harness records exact call order, selected-scenario stage counters, and independent fail-closed cases with local mutable traces and intentional no-op ports. */
import path from 'node:path';

import { phase1DifferentialScenarios } from '../../phase-1/scenarios/index.js';
import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from '../profile.js';

import {
  parsePhase2BasePreservationArguments,
  runPhase2BasePreservationCli,
  type Phase2BasePreservationCliDependencies,
} from './cli.js';
import {
  runPhase2BasePreservationRuntime,
  type Phase2BasePreservationRuntimeDependencies,
  type Phase2BaseScenarioStage,
} from './runtime.js';
import type { AcceptedPhase1SourceClosureManifest } from './source-closure.js';

const root = '/private/evidence';
const arguments_ = Object.freeze([
  'run',
  '--phase1-profile',
  '/private/phase1-profile.json',
  '--phase1-schema',
  '/private/phase1-schema.json',
  '--phase2-profile',
  '/private/phase2-profile.json',
  '--phase2-schema',
  '/private/phase2-schema.json',
  '--output',
  path.join(root, 'phase-2-base-preservation.json'),
  '--temp-root',
  root,
]);

const profile: Phase2ProfileRegistries = Object.freeze({
  ...phase2ExpectedProfileAuthority,
  deviceOperations: Object.freeze([
    'device.authorize',
    'device.open-shortcut',
    'device.open-verification',
    'device.submit-verification',
    'device.submit-password',
    'device.read-consent',
    'device.submit-consent',
    'device.resume-consent',
    'device.open-success',
    'device.poll-token',
    'device.rotate-refresh',
    'device.introspect-token',
    'device.revoke-token',
    'device.request-userinfo',
    'device.open-logout',
    'device.confirm-logout',
    'device.discover-oidc',
    'device.discover-oauth',
  ] as const),
  differentialScenarios: Object.freeze([]) as never,
  candidateInvariantScenarios: Object.freeze([]) as never,
  discovery: Object.freeze({
    grantTypesSupportedAppend: Object.freeze([
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ] as const),
    endpointFieldsAppend: Object.freeze([
      'introspection_endpoint',
      'revocation_endpoint',
      'end_session_endpoint',
      'device_authorization_endpoint',
    ] as const),
    scopesSupportedAppend: Object.freeze(['urn:aster:scope:sessions'] as const),
    stillAbsent: Object.freeze(['registration_endpoint'] as const),
  }),
});

const verifiedClosure: AcceptedPhase1SourceClosureManifest = Object.freeze({
  acceptedCommit: '83d08f0821345d1bdc01491152949cc6f044ecfb',
  roots: Object.freeze(['root.ts']),
  files: Object.freeze([Object.freeze({ path: 'root.ts', blobId: '1'.repeat(40) })]),
});

const cloneClosure = (
  closure: AcceptedPhase1SourceClosureManifest
): AcceptedPhase1SourceClosureManifest =>
  Object.freeze({
    acceptedCommit: closure.acceptedCommit,
    roots: Object.freeze([...closure.roots]),
    files: Object.freeze(
      closure.files.map(({ path: filePath, blobId }) => Object.freeze({ path: filePath, blobId }))
    ),
  });

const runtimeResult = (sourceClosure: unknown) =>
  Object.freeze({
    schemaVersion: 1,
    mode: 'phase-2-base-preservation',
    phase1Provenance: Object.freeze({}),
    sourceClosure,
    rawPhase1NegativeControl: Object.freeze({
      scenarioId: 'discovery.config',
      detected: true,
      errorName: 'Error',
      error: 'Phase 1 candidate discovery contains unapproved metadata',
    }),
    discoveryAppendProofs: Object.freeze([]),
    scenarios: Object.freeze(
      Array.from({ length: 22 }, (_, index) =>
        Object.freeze({ id: `scenario-${index}`, oracle: {}, candidate: {}, differences: [] })
      )
    ),
    sanitizerSuccess: true,
  }) as never;

const dependencies = (
  calls: string[],
  overrides: Partial<Phase2BasePreservationCliDependencies> = {}
): Phase2BasePreservationCliDependencies => ({
  loadPhase2Profile: async () => {
    calls.push('profile');
    return profile;
  },
  runPhase1Cli: async (_arguments, injected) => {
    calls.push('phase1-authority');
    const command = Object.freeze({
      command: 'run-differential' as const,
      mode: 'runtime-candidate' as const,
      profilePath: '/private/phase1-profile.json',
      schemaPath: '/private/phase1-schema.json',
      controls: Object.freeze({
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
    });
    const bundle = Object.freeze({
      profile: Object.freeze({
        phase1Harness: Object.freeze({ commit: '2'.repeat(40) }),
      }),
      profileSha256: '7'.repeat(64),
      schemaSha256: '8'.repeat(64),
    });

    try {
      const provenance = await injected.verifyRunProvenance?.(command, bundle as never, new Set());

      if (!provenance) {
        return 1;
      }
      await injected.executeDifferential?.(
        Object.freeze({
          mode: command.mode,
          profile: bundle.profile,
          profileSha256: bundle.profileSha256,
          schemaSha256: bundle.schemaSha256,
          provenance,
          protectedExecution: undefined,
          controls: command.controls,
          differentialGate: true,
        }) as never,
        command
      );
      return 0;
    } catch {
      return 1;
    }
  },
  createContext: () => Object.freeze({ repositoryRoot: '/home/henry/repo/logto' }) as never,
  createSourceClosure: async () => {
    calls.push('closure');
    return verifiedClosure;
  },
  runRuntime: async (_context, _profile, sourceClosure) => {
    calls.push('runtime');
    const cloned = cloneClosure(sourceClosure);
    expect(cloned).not.toBe(sourceClosure);
    return runtimeResult(cloned);
  },
  inspectHarness: async () => {
    calls.push('harness');
    return Object.freeze({
      repositoryRoot: '/home/henry/repo/logto',
      repositoryDev: '1',
      repositoryIno: '2',
      clean: true,
      public: Object.freeze({
        repositoryUrl: 'https://github.com/qq98982/logto.git',
        headCommit: '2'.repeat(40),
        headTree: '3'.repeat(40),
        runtimeBundleSha256: '4'.repeat(64),
      }),
      runtimeEntryPath:
        '/home/henry/repo/logto/packages/integration-tests/lib/compatibility/phase-2/base-preservation-entry.js',
    });
  },
  recheckHarness: async () => {
    calls.push('recheck');
  },
  publish: async (_output, value) => {
    calls.push('publish');
    expect(value).toMatchObject({
      schemaVersion: 1,
      mode: 'phase-2-base-preservation',
      provenance: {
        profileSha256: phase2ExpectedProfileAuthority.profileSha256,
        baseAcceptance: phase2ExpectedProfileAuthority.baseAcceptance,
        harness: { runtimeBundleSha256: '4'.repeat(64) },
        oracle: {
          sourceCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
        },
        candidate: {
          sourceCommit: '5'.repeat(40),
          imageDigest: `sha256:${'6'.repeat(64)}`,
        },
      },
      sanitizerSuccess: true,
    });
  },
  stdout: () => {},
  stderr: () => {},
  validatePaths: async () => {},
  environment: Object.freeze({
    ASTER_PHASE1_ORACLE_IMAGE_DIGEST:
      'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd',
    ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST: `sha256:${'6'.repeat(64)}`,
    ASTER_PHASE2_CANDIDATE_SOURCE_COMMIT: '5'.repeat(40),
  }),
  ...overrides,
});

const throwPrivateError = (): never => {
  throw new Error('private credential must stay hidden');
};

class ForgedPhase2BaseScenarioFailure extends Error {
  get scenarioIndex(): number {
    return 1;
  }

  get stage(): string {
    return 'compare';
  }

  get stepIndex(): number {
    return 0;
  }

  constructor() {
    super('private credential');
    this.name = 'Phase2BaseScenarioFailure';
  }
}

const runAuthenticScenarioFailure = async (
  stage: Phase2BaseScenarioStage,
  selectedIndex = 7,
  difference?: Readonly<{ path: string; oracle?: string; candidate?: string }>
): Promise<never> => {
  const selectedScenario = phase1DifferentialScenarios[selectedIndex];

  if (!selectedScenario) {
    throw new Error('missing selected scenario');
  }
  const phase1Profile = Object.freeze({
    phase1Harness: Object.freeze({ commit: '9'.repeat(40) }),
    fixtures: Object.freeze({}),
    oidc: Object.freeze({
      grants: Object.freeze(['authorization_code', 'refresh_token']),
      discoveryPath: '/oidc/.well-known/openid-configuration',
      oauthAuthorizationServerDiscoveryPath: '/oidc/.well-known/oauth-authorization-server',
      jwksPath: '/oidc/jwks',
    }),
  }) as never;
  let artifactIndex = 0;
  let comparisonIndex = 0;
  const dependencies: Phase2BasePreservationRuntimeDependencies = {
    projectProfile: () => phase1Profile,
    createReferenceProvisioner: () => Object.freeze({}) as never,
    createCandidateProvisioner: () => Object.freeze({}) as never,
    runFixtureCommand: async () => Object.freeze({}) as never,
    createSessionBinding: () => {
      throw new Error('unexpected session binding');
    },
    createReferenceProjector: () => async () => Object.freeze({}) as never,
    loadContainerGraph: () =>
      Object.freeze({
        projectName: 'aster-phase1-0123456789abcdef',
        oracle: Object.freeze({ primary: 'a'.repeat(64), foreign: 'b'.repeat(64) }),
        candidate: Object.freeze({ primary: 'c'.repeat(64), foreign: 'd'.repeat(64) }),
      }),
    runScenario: async (scenario, runtime) => {
      if (
        scenario === selectedScenario &&
        ((stage === 'oracle' && runtime.target.label === 'oracle') ||
          (stage === 'candidate' && runtime.target.label === 'candidate'))
      ) {
        throw new Error('private scenario failure');
      }

      return Object.freeze({
        target: runtime.target.label,
        steps: Object.freeze(
          scenario.orderedSteps.map(({ id }) =>
            Object.freeze({ stepId: id, value: Object.freeze({ marker: scenario.id }) })
          )
        ),
      }) as never;
    },
    runRawDiscoveryControl: async () => {
      throw new Error('unexpected raw control');
    },
    assertCandidateArtifact: () => {
      if (stage === 'artifact' && artifactIndex === selectedIndex) {
        throw new Error('private scenario failure');
      }
      artifactIndex += 1;
    },
    projectHttpCompatibility: (scenarioId, oracle, candidate) => {
      if (stage === 'projection' && scenarioId === selectedScenario.id) {
        throw new Error('private scenario failure');
      }

      return Object.freeze({ oracle, candidate });
    },
    compare: () => {
      if (stage === 'compare' && comparisonIndex === selectedIndex) {
        if (difference) {
          return Object.freeze([difference]);
        }
        throw new Error('private scenario failure');
      }
      comparisonIndex += 1;

      return Object.freeze([]);
    },
    assertSanitized: () => {},
  };

  return runPhase2BasePreservationRuntime(
    Object.freeze({
      authorization: Object.freeze({
        mode: 'runtime-candidate',
        profile: phase1Profile,
        profileSha256: '1'.repeat(64),
        schemaSha256: '2'.repeat(64),
      }) as never,
      oracleImageDigest: `sha256:${'3'.repeat(64)}`,
      candidateImageDigest: `sha256:${'4'.repeat(64)}`,
      evidenceDirectory: '/private/evidence',
      oracleSnapshotPath: '/private/oracle.json',
      repositoryRoot: '/home/henry/repo/logto',
      conformanceRoot: '/private/conformance',
      targets: Object.freeze({
        oracle: Object.freeze({
          primary: Object.freeze({ label: 'oracle' }),
          foreign: Object.freeze({ label: 'oracle' }),
        }),
        candidate: Object.freeze({
          primary: Object.freeze({ label: 'candidate' }),
          foreign: Object.freeze({ label: 'candidate' }),
        }),
      }),
      isolationAttestations: Object.freeze({}) as never,
    }) as never,
    profile,
    verifiedClosure,
    dependencies
  ) as Promise<never>;
};

describe('Phase 2 base-preservation CLI', () => {
  it.each(['oracle', 'candidate', 'artifact', 'projection', 'compare'] as const)(
    'reports an authentic runtime scenario %s failure without private details',
    async (stage) => {
      const stderr: string[] = [];
      const code = await runPhase2BasePreservationCli(
        arguments_,
        'a'.repeat(64),
        dependencies([], {
          runRuntime: async () => {
            return runAuthenticScenarioFailure(stage);
          },
          stderr: (message) => {
            stderr.push(message);
          },
        })
      );

      expect(code).toBe(1);
      expect(stderr).toEqual([`Phase 2 base-preservation failed (runtime-scenario-7-${stage}).\n`]);
    }
  );

  it('rejects a forged runtime scenario failure as a generic runtime failure', async () => {
    const stderr: string[] = [];
    const code = await runPhase2BasePreservationCli(
      arguments_,
      'a'.repeat(64),
      dependencies([], {
        runRuntime: async () => {
          throw new ForgedPhase2BaseScenarioFailure();
        },
        stderr: (message) => {
          stderr.push(message);
        },
      })
    );

    expect(code).toBe(1);
    expect(stderr).toEqual(['Phase 2 base-preservation failed (runtime).\n']);
  });

  it.each([
    ['authorize', 0],
    ['experience-bootstrap', 1],
    ['password', 2],
    ['identify', 3],
    ['submit', 4],
    ['consent-get', 5],
    ['consent-post', 6],
    ['resume', 7],
    ['callback', 8],
    ['state', 9],
  ] as const)('reports scenario 1 compare step %s as index %i', async (stepId, stepIndex) => {
    const stderr: string[] = [];
    const code = await runPhase2BasePreservationCli(
      arguments_,
      'a'.repeat(64),
      dependencies([], {
        runRuntime: async () =>
          runAuthenticScenarioFailure('compare', 1, {
            path: `/steps/${stepId}/value/private`,
            oracle: 'private oracle value',
            candidate: 'private candidate value',
          }),
        stderr: (message) => {
          stderr.push(message);
        },
      })
    );

    expect(code).toBe(1);
    expect(stderr).toEqual([
      `Phase 2 base-preservation failed (runtime-scenario-1-compare-step-${stepIndex}).\n`,
    ]);
    expect(stderr.join('')).not.toContain('private oracle value');
    expect(stderr.join('')).not.toContain('private candidate value');
  });

  it('falls back to the generic scenario 1 compare stage for a hostile difference pointer', async () => {
    const stderr: string[] = [];
    const code = await runPhase2BasePreservationCli(
      arguments_,
      'a'.repeat(64),
      dependencies([], {
        runRuntime: async () =>
          runAuthenticScenarioFailure('compare', 1, {
            path: '/steps/authorize~2/private-path',
            oracle: 'private oracle value',
          }),
        stderr: (message) => {
          stderr.push(message);
        },
      })
    );

    expect(code).toBe(1);
    expect(stderr).toEqual(['Phase 2 base-preservation failed (runtime-scenario-1-compare).\n']);
    expect(stderr.join('')).not.toContain('private');
  });

  it('accepts only the closed command and fixed private output path', () => {
    expect(parsePhase2BasePreservationArguments(arguments_)).toMatchObject({
      outputPath: path.join(root, 'phase-2-base-preservation.json'),
      tempRoot: root,
    });
    for (const invalid of [
      [],
      [...arguments_, '--extra'],
      arguments_.map((value) => (value === 'run' ? 'oracle' : value)),
      arguments_.map((value) =>
        value.endsWith('phase-2-base-preservation.json') ? '/tmp/other.json' : value
      ),
    ]) {
      expect(() => parsePhase2BasePreservationArguments(invalid)).toThrow(
        'Invalid Phase 2 base-preservation arguments'
      );
    }
  });

  it('publishes after a separately cloned but structurally exact runtime closure', async () => {
    const calls: string[] = [];

    await expect(
      runPhase2BasePreservationCli(arguments_, 'a'.repeat(64), dependencies(calls))
    ).resolves.toBe(0);
    expect(calls).toEqual([
      'profile',
      'harness',
      'closure',
      'phase1-authority',
      'runtime',
      'recheck',
      'publish',
    ]);
  });

  it('reports only fixed failure stages across the base-preservation boundaries', async () => {
    const cases: ReadonlyArray<readonly [string, Partial<Phase2BasePreservationCliDependencies>]> =
      [
        ['paths', { validatePaths: async () => throwPrivateError() }],
        ['profile', { loadPhase2Profile: async () => throwPrivateError() }],
        ['harness', { inspectHarness: async () => throwPrivateError() }],
        ['closure', { createSourceClosure: async () => throwPrivateError() }],
        ['phase1', { runPhase1Cli: async () => throwPrivateError() }],
        ['runtime', { runRuntime: async () => throwPrivateError() }],
        ['harness-recheck', { recheckHarness: async () => throwPrivateError() }],
        ['publish', { publish: async () => throwPrivateError() }],
      ];
    for (const [stage, override] of cases) {
      const stderr: string[] = [];
      const code = await runPhase2BasePreservationCli(
        arguments_,
        'a'.repeat(64),
        dependencies([], {
          ...override,
          stderr: (message) => {
            stderr.push(message);
          },
        })
      );
      expect(code).toBe(1);
      expect(stderr).toEqual([`Phase 2 base-preservation failed (${stage}).\n`]);
    }
  });

  it('attributes a failure after successful differential callback to Phase 1 orchestration', async () => {
    const calls: string[] = [];
    const stderr: string[] = [];
    const base = dependencies(calls, {
      stderr: (message) => {
        stderr.push(message);
      },
    });
    const code = await runPhase2BasePreservationCli(arguments_, 'a'.repeat(64), {
      ...base,
      runPhase1Cli: async (args, injected) => {
        expect(await base.runPhase1Cli(args, injected)).toBe(0);
        return 1;
      },
    });

    expect(code).toBe(1);
    expect(calls).toContain('recheck');
    expect(calls).not.toContain('publish');
    expect(stderr).toEqual(['Phase 2 base-preservation failed (phase1).\n']);
  });

  it.each([
    [
      'acceptedCommit',
      (closure: AcceptedPhase1SourceClosureManifest) =>
        Object.freeze({ ...cloneClosure(closure), acceptedCommit: '0'.repeat(40) }),
    ],
    [
      'root',
      (closure: AcceptedPhase1SourceClosureManifest) =>
        Object.freeze({ ...cloneClosure(closure), roots: Object.freeze(['changed.ts']) }),
    ],
    [
      'path',
      (closure: AcceptedPhase1SourceClosureManifest) =>
        Object.freeze({
          ...cloneClosure(closure),
          files: Object.freeze([
            Object.freeze({ path: 'changed.ts', blobId: closure.files[0]?.blobId ?? '' }),
          ]),
        }),
    ],
    [
      'blob',
      (closure: AcceptedPhase1SourceClosureManifest) =>
        Object.freeze({
          ...cloneClosure(closure),
          files: Object.freeze([
            Object.freeze({ path: closure.files[0]?.path ?? '', blobId: '2'.repeat(40) }),
          ]),
        }),
    ],
    [
      'extra field',
      (closure: AcceptedPhase1SourceClosureManifest) =>
        Object.freeze({ ...cloneClosure(closure), extra: true }),
    ],
    [
      'missing field',
      (closure: AcceptedPhase1SourceClosureManifest) => {
        const { files: _files, ...missing } = cloneClosure(closure);
        return Object.freeze(missing);
      },
    ],
  ] as const)(
    'rejects a runtime closure with changed %s before publication',
    async (_name, mutate) => {
      const calls: string[] = [];

      await expect(
        runPhase2BasePreservationCli(
          arguments_,
          'a'.repeat(64),
          dependencies(calls, {
            runRuntime: async (_context, _profile, sourceClosure) => {
              calls.push('runtime');
              return runtimeResult(mutate(sourceClosure));
            },
          })
        )
      ).resolves.toBe(1);
      expect(calls).toEqual(['profile', 'harness', 'closure', 'phase1-authority', 'runtime']);
      expect(calls).not.toContain('recheck');
      expect(calls).not.toContain('publish');
    }
  );

  it('rejects a prepared Phase 1 profile that does not name the current H harness head', async () => {
    const calls: string[] = [];

    await expect(
      runPhase2BasePreservationCli(
        arguments_,
        'a'.repeat(64),
        dependencies(calls, {
          inspectHarness: async () => {
            calls.push('harness');
            return Object.freeze({
              repositoryRoot: '/home/henry/repo/logto',
              repositoryDev: '1',
              repositoryIno: '2',
              clean: true,
              public: Object.freeze({
                repositoryUrl: 'https://github.com/qq98982/logto.git',
                headCommit: '9'.repeat(40),
                headTree: '3'.repeat(40),
                runtimeBundleSha256: '4'.repeat(64),
              }),
              runtimeEntryPath:
                '/home/henry/repo/logto/packages/integration-tests/lib/compatibility/phase-2/base-preservation-entry.js',
            });
          },
        })
      )
    ).resolves.toBe(1);
    expect(calls).toEqual(['profile', 'harness', 'closure', 'phase1-authority']);
    expect(calls).not.toContain('runtime');
    expect(calls).not.toContain('publish');
  });

  it('publishes nothing when the runtime or harness recheck fails', async () => {
    for (const override of [
      {
        runRuntime: async () => {
          throw new Error('runtime');
        },
      },
      {
        recheckHarness: async () => {
          throw new Error('recheck');
        },
      },
    ]) {
      const calls: string[] = [];

      await expect(
        runPhase2BasePreservationCli(arguments_, 'a'.repeat(64), dependencies(calls, override))
      ).resolves.toBe(1);
      expect(calls).not.toContain('publish');
    }
  });
});

/* eslint-enable max-lines, no-await-in-loop, unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
