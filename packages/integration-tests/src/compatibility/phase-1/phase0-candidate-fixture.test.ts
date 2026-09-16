/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- Typed fakes record one lifecycle and use one intentionally minimal profile projection. */
import type { TargetConfig } from '../model.js';
import type { ScenarioContext } from '../scenario.js';
import type {
  PasswordCodeFixtureLifecycle,
  PasswordCodeFixtureSession,
} from '../scenarios/password-code.js';
import { SymbolTable } from '../symbol-table.js';
import { TargetClient } from '../target-client.js';

import type { Phase1BrowserFixtureProvisioner } from './browser/activity-reader.js';
import {
  createCommandPhase1FixtureProvisioner,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from './clients/command-provisioner.js';
import { getPhase1FixtureRuntimeUsername } from './fixture-map.js';
import type { ProvisionedPhase1Fixture } from './fixtures.js';
import type { Phase1FixtureRecipe } from './model.js';
import { createCandidatePhase0FixtureLifecycle } from './phase0-candidate-fixture.js';
import type { Phase1Profile } from './profile-types.js';

const candidateTarget = Object.freeze({
  label: 'candidate' as const,
  coreUrl: 'http://localhost:3341/',
  adminUrl: 'http://localhost:3441/',
});
const oracleTarget = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'http://localhost:3331/',
  adminUrl: 'http://localhost:3431/',
});
const profile = Object.freeze({
  fixtures: Object.freeze({
    dataTenant: Object.freeze({
      subject: Object.freeze({ id: 'phase1-user', username: 'phase1-user' }),
      applications: Object.freeze([
        Object.freeze({ id: 'phase1-app', isThirdParty: false as const }),
        Object.freeze({ id: 'phase1-browser', isThirdParty: true as const }),
      ]),
    }),
  }),
}) as Pick<Phase1Profile, 'fixtures'>;
const runtimeUsername = getPhase1FixtureRuntimeUsername('phase1-user', 'allocation');

class ReadOnlyTargetClient extends TargetClient {
  readonly operations: string[] = [];

  override async getUser(userId: string): Promise<never> {
    this.operations.push(`get:${userId}`);

    return {
      id: userId,
      username: runtimeUsername,
      hasPassword: true,
      passwordAlgorithm: 'Argon2id',
      isSuspended: false,
      profile: {},
      customData: {},
      identities: {},
      createdAt: 1_700_000_000_000,
      updatedAt: 1_700_000_001_000,
      lastSignInAt: null,
    } as never;
  }

  override async setUsernamePasswordExperience(): Promise<never> {
    throw new Error('Management mutation was called');
  }

  override async createUser(): Promise<never> {
    throw new Error('Management mutation was called');
  }

  override async deleteUser(): Promise<never> {
    throw new Error('Management mutation was called');
  }
}

const fixture = (): ProvisionedPhase1Fixture =>
  Object.freeze({
    public: Object.freeze({
      schemaVersion: 1 as const,
      recipe: 'dataProtocol' as const,
      allocations: Object.freeze([
        Object.freeze({
          allocationId: 'allocation',
          role: 'data' as const,
          target: 'primary' as const,
          isolation: Object.freeze({
            persistenceId: 'persistence',
            cookieKeyId: 'cookie',
            signingKeyId: 'signing',
          }),
          entities: Object.freeze([
            Object.freeze({
              kind: 'user' as const,
              logicalId: 'phase1-user',
              runtimeId: 'user-id',
            }),
            Object.freeze({
              kind: 'application' as const,
              logicalId: 'phase1-app',
              runtimeId: 'app-id',
            }),
          ]),
        }),
      ]),
    }),
    withSecretLease: async <Result>(
      use: Parameters<ProvisionedPhase1Fixture['withSecretLease']>[0]
    ): Promise<Result> =>
      use(
        Object.freeze({
          getPassword: (logicalId: string) => {
            if (logicalId !== 'phase1-user') {
              throw new Error('wrong logical user');
            }
            return 'private-candidate-password';
          },
          getClientSecret: () => new Map<string, string>().get('missing'),
          toJSON: (): never => {
            throw new TypeError('forbidden');
          },
        })
      ) as Promise<Result>,
  });

const context = (target: TargetConfig = candidateTarget) => {
  const client = new ReadOnlyTargetClient(target);

  return {
    client,
    context: Object.freeze({
      target,
      client,
      symbols: new SymbolTable(),
      observe: (_observation) => {
        void _observation;
      },
    }),
  } satisfies Readonly<{ client: ReadOnlyTargetClient; context: ScenarioContext }>;
};

const unavailableManagementLifecycle: PasswordCodeFixtureLifecycle = async () => {
  throw new Error('oracle lifecycle must not run');
};

const commandResult = (): CommandRunnerResult =>
  Object.freeze({
    exitCode: 0,
    signal: null,
    stdout: '',
    stderr: '',
    timedOut: false,
    killed: false,
    reaped: true,
  });

describe('candidate Phase 0 fixture lifecycle', () => {
  it('uses dataProtocol runtime identifiers and one scoped secret lease', async () => {
    const provisionCalls: string[] = [];
    let cleanupCalls = 0;
    const provisioned = fixture();
    const provisioner: Phase1BrowserFixtureProvisioner = Object.freeze({
      provision: async (recipe: Phase1FixtureRecipe) => {
        provisionCalls.push(recipe);
        return provisioned;
      },
      projectState: async () => {
        throw new Error('not used');
      },
      readUserActivityState: async () => {
        throw new Error('not used');
      },
      cleanup: async (candidate: ProvisionedPhase1Fixture) => {
        expect(candidate).toBe(provisioned);
        cleanupCalls += 1;
      },
    });
    const managementLifecycle = unavailableManagementLifecycle;
    const lifecycle = createCandidatePhase0FixtureLifecycle({
      profile,
      target: candidateTarget,
      fixtureSocket: '/private/phase0.sock',
      managementLifecycle,
      createProvisioner: () => provisioner,
    });
    const candidate = context();
    const result = await lifecycle(
      candidate.context,
      async (session: PasswordCodeFixtureSession) => {
        expect(session).toMatchObject({
          username: runtimeUsername,
          password: 'private-candidate-password',
          applicationId: 'app-id',
        });
        expect(session.createdUser).toMatchObject({ id: 'user-id' });
        await expect(session.readUser()).resolves.toMatchObject({ id: 'user-id' });
        await session.cleanup();
        return 'complete';
      }
    );

    expect(result).toBe('complete');
    expect(provisionCalls).toEqual(['dataProtocol']);
    expect(candidate.client.operations).toEqual(['get:user-id', 'get:user-id']);
    expect(cleanupCalls).toBe(1);
  });

  it('delegates oracle setup and cleans candidate setup after callback failure', async () => {
    const managementCalls: string[] = [];
    const managementLifecycle: PasswordCodeFixtureLifecycle = async (_context, use) => {
      managementCalls.push('management');
      return use({} as PasswordCodeFixtureSession);
    };
    let cleanupCalls = 0;
    const provisioner: Phase1BrowserFixtureProvisioner = Object.freeze({
      provision: async () => fixture(),
      projectState: async () => {
        throw new Error('not used');
      },
      readUserActivityState: async () => {
        throw new Error('not used');
      },
      cleanup: async () => {
        cleanupCalls += 1;
      },
    });
    const lifecycle = createCandidatePhase0FixtureLifecycle({
      profile,
      target: candidateTarget,
      fixtureSocket: '/private/phase0.sock',
      managementLifecycle,
      createProvisioner: () => provisioner,
    });

    await expect(lifecycle(context(oracleTarget).context, async () => 'oracle')).resolves.toBe(
      'oracle'
    );
    await expect(
      lifecycle(context().context, async () => {
        throw new Error('private-candidate-password');
      })
    ).rejects.toThrow(/^Candidate Phase 0 fixture failed$/u);
    expect(managementCalls).toEqual(['management']);
    expect(cleanupCalls).toBe(1);
  });

  it('strips hostile child authority down to PATH and the dedicated socket', async () => {
    const provisioner = Object.freeze({
      provision: async () => fixture(),
      projectState: async () => {
        throw new Error('not used');
      },
      readUserActivityState: async () => {
        throw new Error('not used');
      },
      cleanup: async () => {
        await Promise.resolve();
      },
    }) satisfies Phase1BrowserFixtureProvisioner;
    const optionCalls: Array<Parameters<typeof createCommandPhase1FixtureProvisioner>[0]> = [];
    const createProvisioner: typeof createCommandPhase1FixtureProvisioner = (options) => {
      optionCalls.push(options);
      return provisioner;
    };
    const commandCalls: CommandRunnerRequest[] = [];
    const runFixtureCommand = async (
      request: CommandRunnerRequest
    ): Promise<CommandRunnerResult> => {
      commandCalls.push(request);
      return commandResult();
    };

    createCandidatePhase0FixtureLifecycle({
      profile,
      target: candidateTarget,
      fixtureSocket: '/private/phase0.sock',
      managementLifecycle: unavailableManagementLifecycle,
      createProvisioner,
      runFixtureCommand,
      environment: { PATH: '/approved/bin' },
    });
    const [options] = optionCalls;

    expect(options?.environment).toEqual({
      PATH: '/approved/bin',
      ASTER_FIXTURE_SOCKET: '/private/phase0.sock',
    });
    await options?.runner?.({
      command: 'aster-admin',
      args: Object.freeze(['fixture', 'apply']),
      stdin: '{}',
      env: Object.freeze({
        PATH: '/hostile/bin',
        DATABASE_URL: 'postgres://forbidden',
        ASTER_ADMIN_DATABASE_URL: 'postgres://forbidden',
        ASTER_FIXTURE_SOCKET: '/wrong.sock',
      }),
      timeoutMs: 1,
      maxStdoutBytes: 1,
      maxStderrBytes: 1,
      shell: false,
    });

    expect(commandCalls).toHaveLength(1);
    expect(commandCalls[0]?.env).toEqual({
      PATH: '/approved/bin',
      ASTER_FIXTURE_SOCKET: '/private/phase0.sock',
    });
  });

  it.each(['relative.sock', '/private/../phase0.sock', '/private/phase0.sock\n'])(
    'rejects unsafe socket path %s before constructing a provisioner',
    (fixtureSocket) => {
      const createProvisioner = import.meta.jest.fn(createCommandPhase1FixtureProvisioner);

      expect(() =>
        createCandidatePhase0FixtureLifecycle({
          profile,
          target: candidateTarget,
          fixtureSocket,
          managementLifecycle: unavailableManagementLifecycle,
          createProvisioner,
        })
      ).toThrow(/^Candidate Phase 0 fixture failed$/u);
      expect(createProvisioner).not.toHaveBeenCalled();
    }
  );
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
