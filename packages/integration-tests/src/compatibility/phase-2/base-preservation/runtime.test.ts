/* eslint-disable max-lines -- The complete base-preservation lifecycle fixture remains one ordered verification contract. */
import type {
  Phase1TargetRuntime,
  Phase1TargetStepEvidence,
} from '../../phase-1/scenario-runtime.js';
import { phase1DifferentialScenarios } from '../../phase-1/scenarios/index.js';
/* eslint-disable unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The 22-scenario fake runtime intentionally tracks mutable projection state, destructive-control ordering, call order, and no-op validation ports. */
import { SymbolTable } from '../../symbol-table.js';
import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from '../profile.js';

import {
  phase2BasePreservationRunnerIdentities,
  runPhase2BasePreservationRuntime,
  type Phase2BasePreservationRuntimeDependencies,
} from './runtime.js';

const phase2Profile: Phase2ProfileRegistries = Object.freeze({
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

const currentHarnessCommit = '9'.repeat(40);
const phase1Profile = Object.freeze({
  phase1Harness: Object.freeze({ commit: currentHarnessCommit }),
  fixtures: Object.freeze({}),
  oidc: Object.freeze({
    grants: Object.freeze(['authorization_code', 'refresh_token']),
    discoveryPath: '/oidc/.well-known/openid-configuration',
    oauthAuthorizationServerDiscoveryPath: '/oidc/.well-known/oauth-authorization-server',
    jwksPath: '/oidc/jwks',
  }),
}) as never;

const targetGraph = Object.freeze({
  oracle: Object.freeze({
    primary: Object.freeze({
      label: 'oracle' as const,
      coreUrl: 'http://localhost:3311/',
      adminUrl: 'http://localhost:3411/',
    }),
    foreign: Object.freeze({
      label: 'oracle' as const,
      coreUrl: 'http://localhost:3312/',
      adminUrl: 'http://localhost:3412/',
    }),
  }),
  candidate: Object.freeze({
    primary: Object.freeze({
      label: 'candidate' as const,
      coreUrl: 'http://localhost:3321/',
      adminUrl: 'http://localhost:3421/',
    }),
    foreign: Object.freeze({
      label: 'candidate' as const,
      coreUrl: 'http://localhost:3322/',
      adminUrl: 'http://localhost:3422/',
    }),
  }),
});

const runtimeContext = Object.freeze({
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
  targets: targetGraph,
  isolationAttestations: Object.freeze({}) as never,
});

const sourceClosure = Object.freeze({
  acceptedCommit: '83d08f0821345d1bdc01491152949cc6f044ecfb',
  roots: Object.freeze(['root.ts']),
  files: Object.freeze([Object.freeze({ path: 'root.ts', blobId: '5'.repeat(40) })]),
});

const rawDiscovery = Object.freeze({
  issuer: 'http://localhost:3321/oidc',
  introspection_endpoint: 'http://localhost:3321/oidc/token/introspection',
  revocation_endpoint: 'http://localhost:3321/oidc/token/revocation',
  end_session_endpoint: 'http://localhost:3321/oidc/session/end',
  device_authorization_endpoint: 'http://localhost:3321/oidc/device/auth',
  scopes_supported: Object.freeze(['openid', 'urn:aster:scope:sessions']),
  grant_types_supported: Object.freeze([
    'authorization_code',
    'refresh_token',
    'client_credentials',
    'urn:ietf:params:oauth:grant-type:device_code',
  ]),
});

const response = (body: unknown, mediaType = 'application/json') => {
  const text = JSON.stringify(body);

  return Object.freeze({
    status: 200,
    headers: Object.freeze([
      Object.freeze(['content-type', mediaType] as const),
      Object.freeze(['content-length', String(Buffer.byteLength(text))] as const),
    ]),
    body: text,
  });
};

type DestructiveControlLifecycle = {
  events: string[];
  candidateMetadataAvailable: boolean;
  rawControlCalls: number;
};

const createDependencies = (
  calls: Array<Readonly<{ scenarioId: string; target: string; projected: boolean }>>,
  lifecycle?: DestructiveControlLifecycle
): Phase2BasePreservationRuntimeDependencies => {
  const createSessionBinding = (input: { target: { label: string } }) => {
    const request = async (operation: string) =>
      operation === 'discovery-jwks'
        ? response({ keys: [] }, 'application/jwk-set+json')
        : response(rawDiscovery);
    const session = Object.freeze({
      publicOidc: Object.freeze({ request, allocationRole: undefined }),
      publicSymbols: new SymbolTable(),
      forAllocation: () => {
        throw new Error('unexpected allocation');
      },
      symbolsFor: () => {},
    });

    return Object.freeze({ session, symbols: new Map() as never });
  };
  const runScenario = async (
    scenario: (typeof phase1DifferentialScenarios)[number],
    runtime: Phase1TargetRuntime
  ): Promise<Phase1TargetStepEvidence> => {
    if (lifecycle && !lifecycle.candidateMetadataAvailable) {
      throw new Error('candidate protocol metadata was destroyed');
    }
    lifecycle?.events.push(`scenario:${scenario.id}:${runtime.target.label}`);
    const session = runtime.createProtocolSession({
      target: runtime.target,
      fixture: Object.freeze({
        public: Object.freeze({ allocations: Object.freeze([]) }),
      }) as never,
      signal: new AbortController().signal,
    });
    let projected = false;

    if (scenario.id === 'discovery.config' && runtime.target.label === 'candidate') {
      const openid = await session.publicOidc.request(
        'discovery-openid',
        'oidc/.well-known/openid-configuration'
      );
      const grants = (JSON.parse(openid.body) as { grant_types_supported: string[] })
        .grant_types_supported;
      projected = grants.length === 2;
      if (!projected) {
        throw new TypeError('Phase 1 scenario execution failed');
      }
      await session.publicOidc.request(
        'discovery-oauth-authorization-server',
        'oidc/.well-known/oauth-authorization-server'
      );
      await session.publicOidc.request('discovery-jwks', 'oidc/jwks');
    }
    calls.push(Object.freeze({ scenarioId: scenario.id, target: runtime.target.label, projected }));

    return Object.freeze({
      target: runtime.target.label,
      steps: Object.freeze(
        scenario.orderedSteps.map(({ id }) =>
          Object.freeze({ stepId: id, value: Object.freeze({ marker: scenario.id }) })
        )
      ),
    }) as never;
  };

  return Object.freeze({
    projectProfile: () => phase1Profile,
    createReferenceProvisioner: () => Object.freeze({}) as never,
    createCandidateProvisioner: () => Object.freeze({}) as never,
    runFixtureCommand: async () => Object.freeze({}) as never,
    createSessionBinding: createSessionBinding as never,
    createReferenceProjector: () => async () => Object.freeze({}) as never,
    loadContainerGraph: () =>
      Object.freeze({
        projectName: 'aster-phase1-0123456789abcdef',
        oracle: Object.freeze({ primary: 'a'.repeat(64), foreign: 'b'.repeat(64) }),
        candidate: Object.freeze({ primary: 'c'.repeat(64), foreign: 'd'.repeat(64) }),
      }),
    runScenario,
    runRawDiscoveryControl: async () => {
      if (lifecycle) {
        lifecycle.events.push('raw-control-cleanup');
        lifecycle.rawControlCalls += 1;
        lifecycle.candidateMetadataAvailable = false;
      }
      return Object.freeze({
        scenarioId: 'discovery.config' as const,
        detected: true as const,
        errorName: 'Error' as const,
        error: 'Phase 1 candidate discovery contains unapproved metadata' as const,
      });
    },
    assertCandidateArtifact: () => {},
    projectHttpCompatibility: (_id, oracle, candidate) => ({ oracle, candidate }),
    compare: () => Object.freeze([]),
    assertSanitized: () => {
      lifecycle?.events.push('sanitized');
    },
  });
};

describe('Phase 2 base-preservation runtime', () => {
  it.each(['oracle', 'candidate', 'artifact', 'projection', 'compare'] as const)(
    'attributes a selected scenario failure to the %s stage',
    async (stage) => {
      const calls: Array<Readonly<{ scenarioId: string; target: string; projected: boolean }>> = [];
      const dependencies = createDependencies(calls);
      const selectedIndex = 7;
      const selectedScenario = phase1DifferentialScenarios[selectedIndex];

      if (!selectedScenario) {
        throw new Error('missing selected scenario');
      }
      let artifactIndex = 0;
      let comparisonIndex = 0;
      const error = new Error('private scenario failure');

      await expect(
        runPhase2BasePreservationRuntime(runtimeContext, phase2Profile, sourceClosure, {
          ...dependencies,
          runScenario: async (scenario, runtime) => {
            if (
              scenario === selectedScenario &&
              ((stage === 'oracle' && runtime.target.label === 'oracle') ||
                (stage === 'candidate' && runtime.target.label === 'candidate'))
            ) {
              throw error;
            }

            return dependencies.runScenario(scenario, runtime);
          },
          assertCandidateArtifact: (value) => {
            if (stage === 'artifact' && artifactIndex === selectedIndex) {
              throw error;
            }
            artifactIndex += 1;
            dependencies.assertCandidateArtifact(value);
          },
          projectHttpCompatibility: (scenarioId, oracle, candidate) => {
            if (stage === 'projection' && scenarioId === selectedScenario.id) {
              throw error;
            }

            return dependencies.projectHttpCompatibility(scenarioId, oracle, candidate);
          },
          compare: (oracle, candidate) => {
            if (stage === 'compare' && comparisonIndex === selectedIndex) {
              throw error;
            }
            comparisonIndex += 1;

            return dependencies.compare(oracle, candidate);
          },
        })
      ).rejects.toMatchObject({
        scenarioIndex: selectedIndex,
        stage,
        message: 'Phase 2 base-preservation scenario failed',
      });
    }
  );

  it('attributes a nonzero comparison to the selected scenario compare stage', async () => {
    const calls: Array<Readonly<{ scenarioId: string; target: string; projected: boolean }>> = [];
    const dependencies = createDependencies(calls);
    const selectedIndex = 11;
    let comparisonIndex = 0;

    await expect(
      runPhase2BasePreservationRuntime(runtimeContext, phase2Profile, sourceClosure, {
        ...dependencies,
        compare: (oracle, candidate) => {
          const differences =
            comparisonIndex === selectedIndex
              ? Object.freeze([{ path: '/changed', expected: 1, actual: 2 }])
              : dependencies.compare(oracle, candidate);
          comparisonIndex += 1;

          return differences;
        },
      })
    ).rejects.toMatchObject({
      scenarioIndex: selectedIndex,
      stage: 'compare',
    });
  });

  it('reuses all accepted Phase 1 runners and adapts only candidate discovery', async () => {
    const calls: Array<Readonly<{ scenarioId: string; target: string; projected: boolean }>> = [];
    const result = await runPhase2BasePreservationRuntime(
      {
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
            primary: Object.freeze({
              label: 'oracle',
              coreUrl: 'http://localhost:3311/',
              adminUrl: 'http://localhost:3411/',
            }),
            foreign: Object.freeze({
              label: 'oracle',
              coreUrl: 'http://localhost:3312/',
              adminUrl: 'http://localhost:3412/',
            }),
          }),
          candidate: Object.freeze({
            primary: Object.freeze({
              label: 'candidate',
              coreUrl: 'http://localhost:3321/',
              adminUrl: 'http://localhost:3421/',
            }),
            foreign: Object.freeze({
              label: 'candidate',
              coreUrl: 'http://localhost:3322/',
              adminUrl: 'http://localhost:3422/',
            }),
          }),
        }),
        isolationAttestations: Object.freeze({}) as never,
      },
      phase2Profile,
      Object.freeze({
        acceptedCommit: '83d08f0821345d1bdc01491152949cc6f044ecfb',
        roots: Object.freeze(['root.ts']),
        files: Object.freeze([Object.freeze({ path: 'root.ts', blobId: '5'.repeat(40) })]),
      }),
      createDependencies(calls)
    );

    expect(result.scenarios.map(({ id }) => id)).toEqual(
      phase1DifferentialScenarios.map(({ id }) => id)
    );
    expect(result.scenarios).toHaveLength(22);
    expect(result.scenarios.every(({ differences }) => differences.length === 0)).toBe(true);
    expect(result.discoveryAppendProofs).toHaveLength(2);
    expect(result.rawPhase1NegativeControl).toEqual({
      scenarioId: 'discovery.config',
      detected: true,
      errorName: 'Error',
      error: 'Phase 1 candidate discovery contains unapproved metadata',
    });
    expect(result.phase1Provenance.harnessCommit).toBe(currentHarnessCommit);
    expect(result.sourceClosure.acceptedCommit).toBe('83d08f0821345d1bdc01491152949cc6f044ecfb');
    expect(calls).toHaveLength(44);
    expect(calls.filter(({ projected }) => projected)).toEqual([
      { scenarioId: 'discovery.config', target: 'candidate', projected: true },
    ]);
    for (const [index, scenario] of phase1DifferentialScenarios.entries()) {
      expect(phase2BasePreservationRunnerIdentities[index]).toBe(scenario.run);
    }
  });

  it('fails closed on any unapproved comparison', async () => {
    const calls: Array<Readonly<{ scenarioId: string; target: string; projected: boolean }>> = [];
    const dependencies = createDependencies(calls);

    await expect(
      runPhase2BasePreservationRuntime(
        {
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
          targets: targetGraph,
          isolationAttestations: Object.freeze({}) as never,
        },
        phase2Profile,
        Object.freeze({
          acceptedCommit: '83d08f0821345d1bdc01491152949cc6f044ecfb',
          roots: Object.freeze(['root.ts']),
          files: Object.freeze([Object.freeze({ path: 'root.ts', blobId: '5'.repeat(40) })]),
        }),
        { ...dependencies, compare: () => [{ path: '/changed', expected: 1, actual: 2 }] }
      )
    ).rejects.toMatchObject({
      scenarioIndex: 0,
      stage: 'compare',
    });
  });

  it('fails closed unless the raw discovery control proves the exact Phase 1 rejection', async () => {
    const calls: Array<Readonly<{ scenarioId: string; target: string; projected: boolean }>> = [];
    const dependencies = createDependencies(calls);

    await expect(
      runPhase2BasePreservationRuntime(
        {
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
          targets: targetGraph,
          isolationAttestations: Object.freeze({}) as never,
        },
        phase2Profile,
        Object.freeze({
          acceptedCommit: '83d08f0821345d1bdc01491152949cc6f044ecfb',
          roots: Object.freeze(['root.ts']),
          files: Object.freeze([Object.freeze({ path: 'root.ts', blobId: '5'.repeat(40) })]),
        }),
        {
          ...dependencies,
          runRawDiscoveryControl: async () =>
            Object.freeze({
              scenarioId: 'discovery.config',
              detected: true,
              errorName: 'TypeError',
              error: 'Phase 1 scenario execution failed',
            }) as never,
        }
      )
    ).rejects.toThrow('Invalid Phase 2 base-preservation runtime');
    expect(calls).toHaveLength(44);
  });

  it('runs destructive raw discovery cleanup only after every adapted scenario execution', async () => {
    const calls: Array<Readonly<{ scenarioId: string; target: string; projected: boolean }>> = [];
    const lifecycle: DestructiveControlLifecycle = {
      events: [],
      candidateMetadataAvailable: true,
      rawControlCalls: 0,
    };

    await expect(
      runPhase2BasePreservationRuntime(
        {
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
              primary: Object.freeze({
                label: 'oracle',
                coreUrl: 'http://localhost:3311/',
                adminUrl: 'http://localhost:3411/',
              }),
              foreign: Object.freeze({
                label: 'oracle',
                coreUrl: 'http://localhost:3312/',
                adminUrl: 'http://localhost:3412/',
              }),
            }),
            candidate: Object.freeze({
              primary: Object.freeze({
                label: 'candidate',
                coreUrl: 'http://localhost:3321/',
                adminUrl: 'http://localhost:3421/',
              }),
              foreign: Object.freeze({
                label: 'candidate',
                coreUrl: 'http://localhost:3322/',
                adminUrl: 'http://localhost:3422/',
              }),
            }),
          }),
          isolationAttestations: Object.freeze({}) as never,
        },
        phase2Profile,
        Object.freeze({
          acceptedCommit: '83d08f0821345d1bdc01491152949cc6f044ecfb',
          roots: Object.freeze(['root.ts']),
          files: Object.freeze([Object.freeze({ path: 'root.ts', blobId: '5'.repeat(40) })]),
        }),
        createDependencies(calls, lifecycle)
      )
    ).resolves.toMatchObject({ rawPhase1NegativeControl: { detected: true } });
    expect(calls).toHaveLength(44);
    expect(lifecycle.rawControlCalls).toBe(1);
    expect(lifecycle.events).toHaveLength(46);
    expect(lifecycle.events.slice(0, 44).every((event) => event.startsWith('scenario:'))).toBe(
      true
    );
    expect(lifecycle.events[44]).toBe('raw-control-cleanup');
    expect(lifecycle.events[45]).toBe('sanitized');
    expect(lifecycle.events.slice(45).some((event) => event.startsWith('scenario:'))).toBe(false);
  });
});

/* eslint-enable unicorn/consistent-function-scoping, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
/* eslint-enable max-lines */
