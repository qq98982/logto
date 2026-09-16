/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake CLI records exact stage order and one invocation flag inside an isolated test boundary. */
import { chmod, mkdir, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { phase0HarnessCommit } from './model.js';
import { reproducePhase0EvidenceForTesting } from './phase0-reproducer.js';
import type { Phase0EvidenceReproductionRequest } from './profile-semantics.js';
import type { Phase1Profile } from './profile-types.js';

const roots = new Set<string>();
const createRoot = async () => {
  const root = path.join(
    '/var/tmp/henry-build',
    `phase0-reproducer-${process.pid}-${Date.now()}-${roots.size}`
  );
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  roots.add(root);
  return root;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const request: Phase0EvidenceReproductionRequest = Object.freeze({
  repository: 'https://github.com/qq98982/logto.git',
  commit: phase0HarnessCommit,
  lifecyclePath: '.scripts/compatibility/run.sh',
  files: Object.freeze([
    'discovery.json',
    'negative-control.json',
    'password-code.json',
    'run.json',
  ] as const),
  fixtureProfile: Object.freeze({
    fixtures: Object.freeze({
      dataTenant: Object.freeze({
        subject: Object.freeze({ id: 'phase1-user', username: 'phase1-user' }),
        applications: Object.freeze([
          Object.freeze({ id: 'phase1-app', isThirdParty: false as const }),
          Object.freeze({ id: 'phase1-browser', isThirdParty: true as const }),
        ]),
      }),
    }),
  }) as Pick<Phase1Profile, 'fixtures'>,
});

const environment = (root: string, buildRoot = '/var/tmp/henry-build') => ({
  ASTER_PHASE1_BUILD_ROOT: buildRoot,
  ASTER_PHASE1_CONFORMANCE_ROOT: root,
  ASTER_PHASE1_ORACLE_URL: 'http://localhost:3311',
  ASTER_PHASE1_ORACLE_ADMIN_URL: 'http://localhost:3411',
  ASTER_PHASE1_ORACLE_FOREIGN_URL: 'http://localhost:3312',
  ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL: 'http://localhost:3412',
  ASTER_PHASE1_CANDIDATE_URL: 'http://localhost:3321',
  ASTER_PHASE1_CANDIDATE_ADMIN_URL: 'http://localhost:3421',
  ASTER_PHASE1_CANDIDATE_FOREIGN_URL: 'http://localhost:3322',
  ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL: 'http://localhost:3422',
  ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://localhost:3331',
  ASTER_PHASE1_PHASE0_ORACLE_ADMIN_URL: 'http://localhost:3431',
  ASTER_PHASE1_PHASE0_CANDIDATE_URL: 'http://localhost:3341',
  ASTER_PHASE1_PHASE0_CANDIDATE_ADMIN_URL: 'http://localhost:3441',
  ASTER_PHASE1_PHASE0_CANDIDATE_FIXTURE_SOCKET: '/private/phase0-fixture.sock',
  ASTER_PHASE1_ORACLE_IMAGE_DIGEST: `sha256:${'1'.repeat(64)}`,
  ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST: `sha256:${'1'.repeat(64)}`,
});

describe('live Phase 0 evidence reproducer', () => {
  it('runs positive, negative, and finalize stages and returns exact private bytes', async () => {
    const root = await createRoot();
    const calls: string[] = [];
    const result = await reproducePhase0EvidenceForTesting(request, environment(root), {
      runCli: async (arguments_ = [], cliEnvironment = {}) => {
        calls.push(arguments_.join(' ') || 'positive');
        const evidence = cliEnvironment.ASTER_EVIDENCE_DIR ?? '';

        await Promise.all(
          [
            evidence,
            cliEnvironment.ASTER_ORACLE_MESSAGE_DIR ?? '',
            cliEnvironment.ASTER_CANDIDATE_MESSAGE_DIR ?? '',
          ].map(async (directory) => {
            expect(directory.startsWith(`${root}${path.sep}phase0-reproduction.`)).toBe(true);
            await expect(realpath(directory)).resolves.toBe(directory);
          })
        );

        if (arguments_.length === 0) {
          await writeFile(path.join(evidence, 'discovery.json'), '{"kind":"discovery"}\n', {
            mode: 0o600,
          });
          await writeFile(path.join(evidence, 'password-code.json'), '{"kind":"password"}\n', {
            mode: 0o600,
          });
          return 0;
        }
        if (arguments_[0] === '--fault-injection') {
          await writeFile(path.join(evidence, 'negative-control.json'), '{"detected":true}\n', {
            mode: 0o600,
          });
          return 2;
        }
        await writeFile(path.join(evidence, 'run.json'), '{"complete":true}\n', { mode: 0o600 });
        return 0;
      },
    });

    expect(calls).toEqual([
      'positive',
      '--fault-injection discovery-issuer',
      '--finalize-run --negative-control-path /observations/0/value/issuer',
    ]);
    expect(result.files).toHaveLength(4);
    expect(result.commit).toBe(phase0HarnessCommit);
    expect(result.files.map(({ name }) => name)).toEqual(request.files);
    await expect(readdir(root)).resolves.toEqual([]);
  });

  it('rejects an unpinned request before invoking the CLI', async () => {
    const root = await createRoot();
    let touched = false;

    await expect(
      reproducePhase0EvidenceForTesting(
        { ...request, commit: '1'.repeat(40) as typeof phase0HarnessCommit },
        environment(root),
        {
          runCli: async () => {
            touched = true;
            return 0;
          },
        }
      )
    ).rejects.toThrow(/^Phase 0 reproduction failed\.$/u);
    expect(touched).toBe(false);
  });

  it('uses only dedicated Phase 0 targets and rejects a measured-stack alias', async () => {
    const root = await createRoot();
    const observedTargets: unknown[] = [];
    const mutatedOrigins = new Set<string>();

    await reproducePhase0EvidenceForTesting(request, environment(root), {
      runCli: async (arguments_ = [], cliEnvironment = {}) => {
        observedTargets.push({
          oracle: cliEnvironment.ASTER_ORACLE_URL,
          oracleAdmin: cliEnvironment.ASTER_ORACLE_ADMIN_URL,
          candidate: cliEnvironment.ASTER_CANDIDATE_URL,
          candidateAdmin: cliEnvironment.ASTER_CANDIDATE_ADMIN_URL,
        });
        for (const target of [
          cliEnvironment.ASTER_ORACLE_URL,
          cliEnvironment.ASTER_ORACLE_ADMIN_URL,
          cliEnvironment.ASTER_CANDIDATE_URL,
          cliEnvironment.ASTER_CANDIDATE_ADMIN_URL,
        ]) {
          if (target) {
            mutatedOrigins.add(target);
          }
        }
        const evidence = cliEnvironment.ASTER_EVIDENCE_DIR ?? '';

        if (arguments_.length === 0) {
          await writeFile(path.join(evidence, 'discovery.json'), '{}\n', { mode: 0o600 });
          await writeFile(path.join(evidence, 'password-code.json'), '{}\n', { mode: 0o600 });
          return 0;
        }
        if (arguments_[0] === '--fault-injection') {
          await writeFile(path.join(evidence, 'negative-control.json'), '{}\n', { mode: 0o600 });
          return 2;
        }
        await writeFile(path.join(evidence, 'run.json'), '{}\n', { mode: 0o600 });
        return 0;
      },
    });
    expect(observedTargets).toEqual(
      Array.from({ length: 3 }, () => ({
        oracle: 'http://localhost:3331',
        oracleAdmin: 'http://localhost:3431',
        candidate: 'http://localhost:3341',
        candidateAdmin: 'http://localhost:3441',
      }))
    );
    expect(mutatedOrigins).toEqual(
      new Set([
        'http://localhost:3331',
        'http://localhost:3431',
        'http://localhost:3341',
        'http://localhost:3441',
      ])
    );

    const measuredAliases = [
      'http://localhost:3311',
      'http://localhost:3411',
      'http://localhost:3312',
      'http://localhost:3412',
      'http://localhost:3321',
      'http://localhost:3421',
      'http://localhost:3322',
      'http://localhost:3422',
    ];
    await Promise.all(
      measuredAliases.map(async (alias) => {
        let touched = false;

        await expect(
          reproducePhase0EvidenceForTesting(
            request,
            {
              ...environment(root),
              ASTER_PHASE1_PHASE0_ORACLE_URL: alias,
            },
            {
              runCli: async () => {
                touched = true;
                return 0;
              },
            }
          )
        ).rejects.toThrow(/^Phase 0 reproduction failed\.$/u);
        expect(touched).toBe(false);
      })
    );
  });

  it('rejects a measured fixture-socket alias before invoking the CLI', async () => {
    const root = await createRoot();
    let touched = false;

    await expect(
      reproducePhase0EvidenceForTesting(
        request,
        {
          ...environment(root),
          ASTER_FIXTURE_SOCKET: '/private/shared.sock',
          ASTER_PHASE1_PHASE0_CANDIDATE_FIXTURE_SOCKET: '/private/shared.sock',
        },
        {
          runCli: async () => {
            touched = true;
            return 0;
          },
        }
      )
    ).rejects.toThrow(/^Phase 0 reproduction failed\.$/u);
    expect(touched).toBe(false);
  });

  it.each([
    [
      'case and trailing-slash measured alias',
      { ASTER_PHASE1_PHASE0_ORACLE_URL: 'HTTP://LOCALHOST:3311/' },
    ],
    ['cross-Phase-0 alias', { ASTER_PHASE1_PHASE0_CANDIDATE_URL: 'HTTP://LOCALHOST:3331/' }],
    ['default-port target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://localhost:80/' }],
    ['missing-port target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://localhost/' }],
    ['HTTPS target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'https://localhost:3331/' }],
    ['numeric-loopback target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://127.0.0.1:3331/' }],
    ['credential-bearing target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://user@localhost:3331' }],
    ['query-bearing target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://localhost:3331/?a=1' }],
    ['fragment target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://localhost:3331/#fragment' }],
    ['non-root path target', { ASTER_PHASE1_PHASE0_ORACLE_URL: 'http://localhost:3331/oidc' }],
  ] as const)('rejects %s before invoking the Phase 0 CLI', async (_name, override) => {
    const root = await createRoot();
    let touched = false;

    await expect(
      reproducePhase0EvidenceForTesting(
        request,
        { ...environment(root), ...override },
        {
          runCli: async () => {
            touched = true;
            return 0;
          },
        }
      )
    ).rejects.toThrow(/^Phase 0 reproduction failed\.$/u);
    expect(touched).toBe(false);
  });

  it('canonicalizes valid dedicated localhost endpoints before CLI handoff', async () => {
    const root = await createRoot();
    const observed: Array<Readonly<Record<string, string | undefined>>> = [];

    await reproducePhase0EvidenceForTesting(
      request,
      {
        ...environment(root),
        ASTER_PHASE1_PHASE0_ORACLE_URL: 'HTTP://LOCALHOST:3351/',
      },
      {
        runCli: async (arguments_ = [], cliEnvironment = {}) => {
          observed.push(cliEnvironment);
          const evidence = cliEnvironment.ASTER_EVIDENCE_DIR ?? '';

          if (arguments_.length === 0) {
            await writeFile(path.join(evidence, 'discovery.json'), '{}\n', { mode: 0o600 });
            await writeFile(path.join(evidence, 'password-code.json'), '{}\n', { mode: 0o600 });
            return 0;
          }
          if (arguments_[0] === '--fault-injection') {
            await writeFile(path.join(evidence, 'negative-control.json'), '{}\n', { mode: 0o600 });
            return 2;
          }
          await writeFile(path.join(evidence, 'run.json'), '{}\n', { mode: 0o600 });
          return 0;
        },
      }
    );
    expect(
      observed.every(({ ASTER_ORACLE_URL }) => ASTER_ORACLE_URL === 'http://localhost:3351')
    ).toBe(true);
  });

  it('accepts a private reproduction root beneath a custom safe build root', async () => {
    const buildRoot = path.join(
      '/var/tmp',
      `aster-portable-reproducer-${process.pid}-${Date.now()}-${roots.size}`
    );
    const root = path.join(buildRoot, 'private');
    await mkdir(root, { recursive: true, mode: 0o700 });
    await chmod(buildRoot, 0o700);
    await chmod(root, 0o700);
    roots.add(buildRoot);

    await expect(
      reproducePhase0EvidenceForTesting(request, environment(root, buildRoot), {
        runCli: async (arguments_ = [], cliEnvironment = {}) => {
          const evidence = cliEnvironment.ASTER_EVIDENCE_DIR ?? '';

          if (arguments_.length === 0) {
            await writeFile(path.join(evidence, 'discovery.json'), '{}\n', { mode: 0o600 });
            await writeFile(path.join(evidence, 'password-code.json'), '{}\n', { mode: 0o600 });
            return 0;
          }
          if (arguments_[0] === '--fault-injection') {
            await writeFile(path.join(evidence, 'negative-control.json'), '{}\n', { mode: 0o600 });
            return 2;
          }
          await writeFile(path.join(evidence, 'run.json'), '{}\n', { mode: 0o600 });
          return 0;
        },
      })
    ).resolves.toMatchObject({ commit: phase0HarnessCommit });
  });

  it('rejects an unsafe configurable build root before invoking the CLI', async () => {
    const root = await createRoot();
    let touched = false;

    await expect(
      reproducePhase0EvidenceForTesting(request, environment(root, '/var/tmp'), {
        runCli: async () => {
          touched = true;
          return 0;
        },
      })
    ).rejects.toThrow(/^Phase 0 reproduction failed\.$/u);
    expect(touched).toBe(false);
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
