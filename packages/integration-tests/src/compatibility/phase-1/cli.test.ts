/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, unicorn/consistent-function-scoping -- CLI controls use isolated mutable captures and hostile argument matrices. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  assertAuthorizedPhase1Run,
  consumePreparedReviewCapabilityForTesting,
  inspectGitFileForTesting,
  parsePhase1Arguments,
  parseStrictAuthorityJsonForTesting,
  phase1BrowserSourceEvidence,
  phase1RegistrySourceEvidence,
  phase1ReviewSourceCommit,
  preparePhase1ReviewProfileForTesting,
  runPhase1Cli,
  type Phase1CliDependencies,
  type Phase1PrepareReviewProfileCommand,
  type Phase1ReviewPreparationDependencies,
  type Phase1RunAuthorization,
} from './cli.js';
import { snapshotClosedDataGraph } from './model.js';
import { asterNativeSurfaceContract } from './native-surface.js';
import { phase1ProfileSchemaLock } from './profile-lock.js';
import type { Phase1Profile } from './profile-types.js';
import type { Phase1ProfileBundle } from './profile.js';

const roots = new Set<string>();
const executeFile = promisify(execFile);

const createRoot = async (prefix: string) => {
  await mkdir('/var/tmp/henry-build', { recursive: true });
  const root = await mkdtemp(`/var/tmp/henry-build/${prefix}-`);
  await chmod(root, 0o700);
  roots.add(root);
  return root;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const runArguments = [
  'run',
  '--mode',
  'review-candidate',
  '--profile',
  '/private/profile.json',
  '--schema',
  '/private/schema.json',
] as const;

const prepareArguments = [
  'prepare-review-profile',
  '--source-profile',
  '/aster/compatibility/phase-1-profile.json',
  '--schema',
  '/aster/compatibility/phase-1-profile.schema.json',
  '--harness-commit',
  'a'.repeat(40),
  '--output',
  '/private/review-profile.json',
] as const;

const profileFixture = (): Phase1Profile =>
  ({
    schemaVersion: 2,
    profileId: 'aster.phase-1.password-pkce',
    asterNativeSurface: structuredClone(asterNativeSurfaceContract),
    reference: {
      oracleRepository: 'https://github.com/qq98982/logto.git',
      oracleCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
      phase0HarnessCommit: '40135e37201f36ac05ece1eff82e37bb6d9649f1',
    },
    profileSchema: {
      repository: 'aster',
      path: 'compatibility/phase-1-profile.schema.json',
      sourceCommit: null,
      sha256: null,
      lockState:
        'design-unlocked; the canonical schema source commit and SHA-256 must be pinned before the Phase 1 harness is pinned',
    },
    phase1Harness: {
      repository: 'https://github.com/qq98982/logto.git',
      baseCommit: '40135e37201f36ac05ece1eff82e37bb6d9649f1',
      commit: 'a'.repeat(40),
      lockState: 'locked; commit pins the reviewed Phase 1 harness descendant',
    },
  }) as unknown as Phase1Profile;

const designProfileFixture = (): Phase1Profile => {
  const profile = structuredClone(profileFixture()) as Phase1Profile;

  return {
    ...profile,
    profileSchema: {
      ...profile.profileSchema,
      sourceCommit: null,
      sha256: null,
      lockState:
        'design-unlocked; the canonical schema source commit and SHA-256 must be pinned before the Phase 1 harness is pinned',
    },
    phase1Harness: {
      ...profile.phase1Harness,
      commit: null,
      lockState:
        'design-unlocked; a reviewed descendant commit must be pinned before Rust behavior implementation',
    },
  };
};

const lockedProfileFixture = (): Phase1Profile => {
  const profile = structuredClone(profileFixture()) as Phase1Profile;

  return {
    ...profile,
    profileSchema: {
      ...profile.profileSchema,
      sourceCommit: phase1ProfileSchemaLock.sourceCommit,
      sha256: phase1ProfileSchemaLock.sha256,
      lockState: 'locked; sourceCommit and sha256 pin the sole canonical Phase 1 profile schema',
    },
    phase1Harness: {
      ...profile.phase1Harness,
      commit: 'b'.repeat(40),
      lockState: 'locked; commit pins the reviewed Phase 1 harness descendant',
    },
  };
};

const bundleFor = (
  profile: Phase1Profile,
  profileBytes = Buffer.from(`${JSON.stringify(profile)}\n`),
  schemaBytes = Buffer.from('{"schema":true}\n')
): Phase1ProfileBundle =>
  Object.freeze({
    profile,
    profileSha256: createHash('sha256').update(profileBytes).digest('hex'),
    schemaSha256: phase1ProfileSchemaLock.sha256,
    readProfileBytes: () => Buffer.from(profileBytes),
    readSchemaBytes: () => Buffer.from(schemaBytes),
  });

const createCliHarness = (
  overrides: Partial<Phase1CliDependencies> = {}
): Readonly<{
  dependencies: Partial<Phase1CliDependencies>;
  stdout: string[];
  stderr: string[];
  authorizations: Phase1RunAuthorization[];
  differentialAuthorizations: Phase1RunAuthorization[];
  candidateInvariantAuthorizations: Phase1RunAuthorization[];
  browserAuthorizations: Phase1RunAuthorization[];
}> => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const authorizations: Phase1RunAuthorization[] = [];
  const differentialAuthorizations: Phase1RunAuthorization[] = [];
  const candidateInvariantAuthorizations: Phase1RunAuthorization[] = [];
  const browserAuthorizations: Phase1RunAuthorization[] = [];
  const profile = profileFixture();
  const dependencies: Phase1CliDependencies = {
    loadRunBundle: async () => ({
      bundle: bundleFor(profile),
      baselineCapabilityIds: new Set(['safe-capability']),
    }),
    verifyRunProvenance: async () => ({
      kind: 'review-candidate',
      harnessCommit: 'a'.repeat(40),
      publishable: false,
    }),
    authorizeProtectedExecution: () => {
      throw new Error('unbranded accepted provenance');
    },
    executeRun: async (authorization) => {
      authorizations.push(authorization);
    },
    executeDifferential: async (authorization) => {
      differentialAuthorizations.push(authorization);
    },
    executeCandidateInvariants: async (authorization) => {
      candidateInvariantAuthorizations.push(authorization);
    },
    executeBrowser: async (authorization) => {
      browserAuthorizations.push(authorization);
    },
    prepareReviewProfile: async () => {
      await Promise.resolve();
    },
    stdout: (message) => {
      stdout.push(message);
    },
    stderr: (message) => {
      stderr.push(message);
    },
    ...overrides,
  };

  return {
    dependencies,
    stdout,
    stderr,
    authorizations,
    differentialAuthorizations,
    candidateInvariantAuthorizations,
    browserAuthorizations,
  };
};

describe('Phase 1 CLI grammar', () => {
  it('binds provenance to the deduplicated canonical browser source union', () => {
    expect(phase1BrowserSourceEvidence).toHaveLength(25);
    expect(new Set(phase1BrowserSourceEvidence.map(({ path }) => path)).size).toBe(25);
    expect(new Set(phase1BrowserSourceEvidence.map(({ commit }) => commit))).toEqual(
      new Set(['6852a7b8c8984c5c12b2061e8c51faa310a36412'])
    );
    expect(Object.isFrozen(phase1BrowserSourceEvidence)).toBe(true);
  });

  it('binds provenance to the ordered unique scenario source union', () => {
    const keys = phase1RegistrySourceEvidence.map(({ commit, path }) => `${commit}\u0000${path}`);

    expect(phase1RegistrySourceEvidence).toHaveLength(67);
    expect(new Set(keys).size).toBe(keys.length);
    expect(
      phase1BrowserSourceEvidence.every(({ commit, path }) =>
        keys.includes(`${commit}\u0000${path}`)
      )
    ).toBe(true);
    expect(new Set(phase1RegistrySourceEvidence.map(({ commit }) => commit))).toEqual(
      new Set([
        '6852a7b8c8984c5c12b2061e8c51faa310a36412',
        '40135e37201f36ac05ece1eff82e37bb6d9649f1',
      ])
    );
    expect(phase1RegistrySourceEvidence.every((source) => Object.isFrozen(source))).toBe(true);
    expect(Object.isFrozen(phase1RegistrySourceEvidence)).toBe(true);
  });

  it('returns a plain closed graph after strict duplicate-key validation', () => {
    const source = '{"nested":{"value":1},"items":[{"id":"fixture"}]}';
    const parsed = parseStrictAuthorityJsonForTesting(source);

    expect(snapshotClosedDataGraph(parsed)).toEqual(JSON.parse(source));
    expect(() => parseStrictAuthorityJsonForTesting('{"value":1,"value":2}')).toThrow(
      'Phase 1 run failed.'
    );
  });

  it('contains no private Aster Phase 0 evidence path or reader', async () => {
    const source = await readFile(
      path.resolve(process.cwd(), 'src/compatibility/phase-1/cli.ts'),
      'utf8'
    );

    expect(source).not.toContain(['phase', '0', 'evidence'].join('-'));
    expect(source).not.toMatch(/asterRoot[\s\S]{0,160}readFile/u);
  });

  it('parses the exact run DTO and all four frozen controls', () => {
    const command = parsePhase1Arguments([
      ...runArguments,
      '--record-oracle',
      '--observation-controls',
      '--discovery-extra-control',
      '--candidate-invariant-controls',
    ]);

    expect(command).toEqual({
      command: 'run',
      mode: 'review-candidate',
      profilePath: '/private/profile.json',
      schemaPath: '/private/schema.json',
      controls: {
        recordOracle: true,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      },
    });
    expect(Object.isFrozen(command)).toBe(true);
    expect(Object.isFrozen(command.command === 'run' ? command.controls : null)).toBe(true);
  });

  it('parses only the closed runtime-candidate differential gate command', () => {
    const command = parsePhase1Arguments([
      'run-differential',
      '--mode',
      'runtime-candidate',
      '--profile',
      '/private/profile.json',
      '--schema',
      '/private/schema.json',
      '--observation-controls',
      '--discovery-extra-control',
      '--candidate-invariant-controls',
    ]);

    expect(command).toEqual({
      command: 'run-differential',
      mode: 'runtime-candidate',
      profilePath: '/private/profile.json',
      schemaPath: '/private/schema.json',
      controls: {
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      },
    });
    for (const invalid of [
      ['run-differential', '--mode', 'mirror-control'],
      ['run-differential', '--mode', 'review-candidate'],
      ['run-differential', '--mode', 'runtime-candidate', '--record-oracle'],
      ['run-differential', '--mode', 'runtime-candidate', '--observation-controls'],
    ]) {
      expect(() =>
        parsePhase1Arguments([
          ...invalid,
          '--profile',
          '/private/profile.json',
          '--schema',
          '/private/schema.json',
        ])
      ).toThrow('Invalid Phase 1 arguments.');
    }
  });

  it('authorizes the differential gate without invoking the complete run port', async () => {
    const harness = createCliHarness();

    await expect(
      runPhase1Cli(
        [
          'run-differential',
          '--mode',
          'runtime-candidate',
          '--profile',
          '/private/profile.json',
          '--schema',
          '/private/schema.json',
          '--observation-controls',
          '--discovery-extra-control',
          '--candidate-invariant-controls',
        ],
        harness.dependencies
      )
    ).resolves.toBe(0);
    expect(harness.authorizations).toEqual([]);
    expect(harness.differentialAuthorizations).toHaveLength(1);
    expect(harness.differentialAuthorizations[0]).toMatchObject({
      mode: 'runtime-candidate',
      differentialGate: true,
      protectedExecution: undefined,
      provenance: { kind: 'review-candidate', publishable: false },
      controls: {
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      },
    });
    expect(harness.stdout).toEqual(['Phase 1 differential gate authorized.']);
  });

  it('authorizes only the closed runtime candidate invariant gate command', async () => {
    const arguments_ = [
      'run-candidate-invariants',
      '--mode',
      'runtime-candidate',
      '--profile',
      '/private/profile.json',
      '--schema',
      '/private/schema.json',
      '--observation-controls',
      '--discovery-extra-control',
      '--candidate-invariant-controls',
    ] as const;
    expect(parsePhase1Arguments(arguments_)).toMatchObject({
      command: 'run-candidate-invariants',
      mode: 'runtime-candidate',
    });
    const harness = createCliHarness();

    await expect(runPhase1Cli(arguments_, harness.dependencies)).resolves.toBe(0);
    expect(harness.authorizations).toEqual([]);
    expect(harness.differentialAuthorizations).toEqual([]);
    expect(harness.candidateInvariantAuthorizations).toHaveLength(1);
    expect(harness.candidateInvariantAuthorizations[0]).toMatchObject({
      mode: 'runtime-candidate',
      candidateInvariantGate: true,
      protectedExecution: undefined,
      provenance: { kind: 'review-candidate', publishable: false },
    });
    expect(harness.stdout).toEqual(['Phase 1 candidate invariant gate authorized.']);

    for (const invalid of [
      ['run-candidate-invariants', '--mode', 'mirror-control'],
      ['run-candidate-invariants', '--mode', 'review-candidate'],
      ['run-candidate-invariants', '--mode', 'runtime-candidate', '--record-oracle'],
      ['run-candidate-invariants', '--mode', 'runtime-candidate', '--observation-controls'],
    ]) {
      expect(() =>
        parsePhase1Arguments([
          ...invalid,
          '--profile',
          '/private/profile.json',
          '--schema',
          '/private/schema.json',
        ])
      ).toThrow('Invalid Phase 1 arguments.');
    }
  });

  it('authorizes only the closed runtime browser gate command', async () => {
    const arguments_ = [
      'run-browser',
      '--mode',
      'runtime-candidate',
      '--profile',
      '/private/profile.json',
      '--schema',
      '/private/schema.json',
      '--observation-controls',
      '--discovery-extra-control',
      '--candidate-invariant-controls',
    ] as const;
    expect(parsePhase1Arguments(arguments_)).toMatchObject({
      command: 'run-browser',
      mode: 'runtime-candidate',
    });
    const harness = createCliHarness();

    await expect(runPhase1Cli(arguments_, harness.dependencies)).resolves.toBe(0);
    expect(harness.authorizations).toEqual([]);
    expect(harness.differentialAuthorizations).toEqual([]);
    expect(harness.candidateInvariantAuthorizations).toEqual([]);
    expect(harness.browserAuthorizations).toHaveLength(1);
    expect(harness.browserAuthorizations[0]).toMatchObject({
      mode: 'runtime-candidate',
      browserGate: true,
      protectedExecution: undefined,
      provenance: { kind: 'review-candidate', publishable: false },
    });
    expect(harness.stdout).toEqual(['Phase 1 browser gate authorized.']);

    for (const invalid of [
      ['run-browser', '--mode', 'mirror-control'],
      ['run-browser', '--mode', 'review-candidate'],
      ['run-browser', '--mode', 'runtime-candidate', '--record-oracle'],
      ['run-browser', '--mode', 'runtime-candidate', '--observation-controls'],
    ]) {
      expect(() =>
        parsePhase1Arguments([
          ...invalid,
          '--profile',
          '/private/profile.json',
          '--schema',
          '/private/schema.json',
        ])
      ).toThrow('Invalid Phase 1 arguments.');
    }
  });

  it('accepts one pnpm script delimiter only before an exact subcommand', async () => {
    const run = createCliHarness();
    let prepared = false;
    const prepare = createCliHarness({
      prepareReviewProfile: async () => {
        prepared = true;
      },
    });
    const repeated = createCliHarness();
    let misplacedTouched = false;
    const misplaced = createCliHarness({
      loadRunBundle: async () => {
        misplacedTouched = true;
        throw new Error('misplaced delimiter reached dependencies');
      },
    });

    await expect(runPhase1Cli(['--', ...runArguments], run.dependencies)).resolves.toBe(0);
    await expect(runPhase1Cli(['--', ...prepareArguments], prepare.dependencies)).resolves.toBe(0);
    await expect(
      runPhase1Cli(['--', '--', ...prepareArguments], repeated.dependencies)
    ).resolves.toBe(1);
    await expect(
      runPhase1Cli(['run', '--', ...runArguments.slice(1)], misplaced.dependencies)
    ).resolves.toBe(1);

    expect(() => parsePhase1Arguments(['--', ...prepareArguments])).toThrow(
      'Invalid Phase 1 arguments.'
    );
    expect(prepared).toBe(true);
    expect(misplacedTouched).toBe(false);
    expect(run.stdout).toEqual(['Phase 1 run authorized.']);
    expect(prepare.stdout).toEqual(['Phase 1 review profile prepared.']);
    expect(repeated.stderr).toEqual(['Invalid Phase 1 arguments.']);
    expect(misplaced.stderr).toEqual(['Invalid Phase 1 arguments.']);
  });

  it('rejects hostile unknown repeated positional equals and cross-command arguments before dependencies', async () => {
    const marker = 'private-cli-marker';
    let touched = false;
    const harness = createCliHarness({
      loadRunBundle: async () => {
        touched = true;
        throw new Error(marker);
      },
      prepareReviewProfile: async () => {
        touched = true;
        throw new Error(marker);
      },
    });
    const invalid = [
      [],
      ['unknown'],
      ['run'],
      [...runArguments, 'positional'],
      ['run', '--mode=review-candidate', '--profile', '/p', '--schema', '/s'],
      [...runArguments, '--mode', 'review-candidate'],
      [...runArguments, '--source-profile', '/source'],
      [...prepareArguments, '--record-oracle'],
      [...prepareArguments, '--output', '/second'],
      [...runArguments.slice(0, 4), '--schema', '/s'],
      ['run', '--mode', 'mirror-control', '--profile', '/p', '--schema', '/s', '--record-oracle'],
    ];

    for (const arguments_ of invalid) {
      await expect(runPhase1Cli(arguments_, harness.dependencies)).resolves.toBe(1);
    }
    expect(touched).toBe(false);
    expect(harness.stdout).toEqual([]);
    expect(harness.stderr.every((message) => message === 'Invalid Phase 1 arguments.')).toBe(true);
    expect(harness.stderr.join('\n')).not.toContain(marker);
  });

  it('returns a closed review authorization and rejects forged accepted provenance', async () => {
    const review = createCliHarness();
    await expect(runPhase1Cli(runArguments, review.dependencies)).resolves.toBe(0);
    expect(review.authorizations).toHaveLength(1);
    expect(review.authorizations[0]).toMatchObject({
      mode: 'review-candidate',
      protectedExecution: undefined,
      provenance: { kind: 'review-candidate', publishable: false },
    });
    expect(Object.isFrozen(review.authorizations[0])).toBe(true);
    expect(() => {
      assertAuthorizedPhase1Run(review.authorizations[0]);
    }).not.toThrow();
    expect(() => {
      assertAuthorizedPhase1Run({ ...review.authorizations[0] });
    }).toThrow('Phase 1 run authorization failed.');

    const forged = createCliHarness({
      verifyRunProvenance: async () => ({
        kind: 'accepted-harness',
        harnessCommit: 'a'.repeat(40),
        protectedBranch: 'aster-phase1-harness',
        pullRequestNumber: 1,
        publishable: true,
      }),
    });
    await expect(
      runPhase1Cli(
        [
          'run',
          '--mode',
          'mirror-control',
          '--profile',
          '/private/profile.json',
          '--schema',
          '/private/schema.json',
        ],
        forged.dependencies
      )
    ).resolves.toBe(1);
    expect(forged.authorizations).toEqual([]);
    expect(forged.stderr).toEqual(['Phase 1 run failed.']);
  });

  it('keeps operation failures fixed and non-echoing', async () => {
    const marker = 'private-operation-marker';
    const run = createCliHarness({
      verifyRunProvenance: async () => {
        throw new Error(marker);
      },
    });
    const prepare = createCliHarness({
      prepareReviewProfile: async () => {
        throw new Error(marker);
      },
    });

    await expect(runPhase1Cli(runArguments, run.dependencies)).resolves.toBe(1);
    await expect(runPhase1Cli(prepareArguments, prepare.dependencies)).resolves.toBe(1);
    expect(run.stderr).toEqual(['Phase 1 run failed.']);
    expect(prepare.stderr).toEqual(['Phase 1 review profile preparation failed.']);
    expect([...run.stderr, ...prepare.stderr].join('\n')).not.toContain(marker);
  });
});

describe('preparePhase1ReviewProfile', () => {
  const createPreparationHarness = async (sourceProfile = designProfileFixture()) => {
    const asterRoot = await createRoot('phase1-cli-aster');
    const logtoRoot = await createRoot('phase1-cli-logto');
    const outputRoot = await createRoot('phase1-cli-output');
    const sourceProfilePath = path.join(asterRoot, 'phase-1-profile.json');
    const schemaPath = path.join(asterRoot, 'phase-1-profile.schema.json');
    const outputPath = path.join(outputRoot, 'review-profile.json');
    await Promise.all([
      writeFile(sourceProfilePath, '{}\n', { mode: 0o600 }),
      writeFile(schemaPath, '{}\n', { mode: 0o600 }),
      writeFile(path.join(logtoRoot, 'package.json'), '{}\n', { mode: 0o600 }),
    ]);
    const source = bundleFor(sourceProfile);
    const harnessCommit = 'a'.repeat(40);
    let publishedProfile: Phase1Profile | undefined;
    let validatedProfile: Phase1Profile | undefined;
    let rolledBack = false;
    let preparedCapability: unknown;
    const publication = Object.freeze({ path: outputPath });
    const dependencies: Phase1ReviewPreparationDependencies = {
      inspectGitFile: async (filePath) => {
        if (filePath === sourceProfilePath) {
          return {
            root: asterRoot,
            relativePath: 'compatibility/phase-1-profile.json',
            originUrl: 'https://github.com/qq98982/aster.git',
            head: phase1ReviewSourceCommit,
            blobId: 'd'.repeat(40),
            clean: true,
            bytes: source.readProfileBytes(),
          };
        }
        if (filePath === schemaPath) {
          return {
            root: asterRoot,
            relativePath: 'compatibility/phase-1-profile.schema.json',
            originUrl: 'https://github.com/qq98982/aster.git',
            head: phase1ReviewSourceCommit,
            blobId: 'e'.repeat(40),
            clean: true,
            bytes: source.readSchemaBytes(),
          };
        }
        return {
          root: logtoRoot,
          relativePath: 'packages/integration-tests/package.json',
          originUrl: 'https://github.com/qq98982/logto.git',
          head: harnessCommit,
          blobId: 'f'.repeat(40),
          clean: true,
          bytes: Buffer.from('{}\n'),
        };
      },
      logtoRoot,
      loadDesignBundle: async () => source,
      loadBaselineCapabilityIds: async () => new Set(['safe-capability']),
      assertSemantics: (profile) => {
        expect(profile.profileId).toBe('aster.phase-1.password-pkce');
      },
      validatePreparedBytes: async (profileBytes) => {
        const profile = JSON.parse(Buffer.from(profileBytes).toString('utf8')) as Phase1Profile;
        validatedProfile = profile;
        return bundleFor(profile, Buffer.from(profileBytes));
      },
      publish: async (_outputPath, capability) => {
        preparedCapability = capability;
        publishedProfile = consumePreparedReviewCapabilityForTesting(capability).profile;
        return publication;
      },
      rollback: async (value) => {
        expect(value).toBe(publication);
        rolledBack = true;
      },
      loadPublishedBundle: async () => {
        if (!publishedProfile) {
          throw new Error('not published');
        }
        return bundleFor(
          publishedProfile,
          Buffer.from(`${JSON.stringify(publishedProfile)}\n`, 'utf8')
        );
      },
    };
    const command: Phase1PrepareReviewProfileCommand = {
      command: 'prepare-review-profile',
      sourceProfilePath,
      schemaPath,
      harnessCommit,
      outputPath,
    };

    return {
      command,
      dependencies,
      asterRoot,
      logtoRoot,
      getPublishedProfile: () => publishedProfile,
      getPreparedCapability: () => preparedCapability,
      wasRolledBack: () => rolledBack,
    };
  };

  it('locks the canonical source and post-validates the exact published bytes', async () => {
    const harness = await createPreparationHarness();
    await expect(
      preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies)
    ).resolves.toBe(undefined);
    expect(harness.getPublishedProfile()).toMatchObject({
      profileSchema: {
        sourceCommit: phase1ProfileSchemaLock.sourceCommit,
        sha256: phase1ProfileSchemaLock.sha256,
        lockState: 'locked; sourceCommit and sha256 pin the sole canonical Phase 1 profile schema',
      },
      phase1Harness: {
        commit: harness.command.harnessCommit,
        lockState: 'locked; commit pins the reviewed Phase 1 harness descendant',
      },
    });
    expect(harness.wasRolledBack()).toBe(false);
  });

  it('repins an exactly locked canonical source to the current harness commit', async () => {
    const harness = await createPreparationHarness(lockedProfileFixture());

    await expect(
      preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies)
    ).resolves.toBeUndefined();
    expect(harness.getPublishedProfile()).toMatchObject({
      profileSchema: {
        sourceCommit: phase1ProfileSchemaLock.sourceCommit,
        sha256: phase1ProfileSchemaLock.sha256,
        lockState: 'locked; sourceCommit and sha256 pin the sole canonical Phase 1 profile schema',
      },
      phase1Harness: {
        commit: harness.command.harnessCommit,
        lockState: 'locked; commit pins the reviewed Phase 1 harness descendant',
      },
    });
  });

  it.each([
    ['schema source commit', { sourceCommit: 'c'.repeat(40) }],
    ['schema digest', { sha256: 'd'.repeat(64) }],
    ['schema lock state', { lockState: 'private-invalid-lock-state' }],
  ] as const)('rejects a locked source with a mismatched %s', async (_name, profileSchema) => {
    const locked = lockedProfileFixture();
    const source = {
      ...locked,
      profileSchema: { ...locked.profileSchema, ...profileSchema },
    } as unknown as Phase1Profile;
    const harness = await createPreparationHarness(source);

    await expect(
      preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies)
    ).rejects.toThrow('Phase 1 review profile preparation failed.');
    expect(harness.getPublishedProfile()).toBeUndefined();
  });

  it('rejects repository and clean-HEAD boundary violations with one fixed diagnostic', async () => {
    for (const mutate of [
      (harness: Awaited<ReturnType<typeof createPreparationHarness>>) => {
        (harness.command as unknown as { outputPath: string }).outputPath = path.join(
          harness.asterRoot,
          'review.json'
        );
      },
      (harness: Awaited<ReturnType<typeof createPreparationHarness>>) => {
        const inspect = harness.dependencies.inspectGitFile;
        (
          harness.dependencies as unknown as {
            inspectGitFile: Phase1ReviewPreparationDependencies['inspectGitFile'];
          }
        ).inspectGitFile = async (filePath: string) => {
          const authority = await inspect(filePath);

          return authority.originUrl === 'https://github.com/qq98982/aster.git'
            ? { ...authority, head: '7'.repeat(40) }
            : authority;
        };
      },
      (harness: Awaited<ReturnType<typeof createPreparationHarness>>) => {
        (harness.command as unknown as { harnessCommit: string }).harnessCommit = 'b'.repeat(40);
      },
      (harness: Awaited<ReturnType<typeof createPreparationHarness>>) => {
        const inspect = harness.dependencies.inspectGitFile;
        (
          harness.dependencies as unknown as {
            inspectGitFile: Phase1ReviewPreparationDependencies['inspectGitFile'];
          }
        ).inspectGitFile = async (filePath: string) => ({
          ...(await inspect(filePath)),
          clean: false,
        });
      },
      (harness: Awaited<ReturnType<typeof createPreparationHarness>>) => {
        const inspect = harness.dependencies.inspectGitFile;
        (
          harness.dependencies as unknown as {
            inspectGitFile: Phase1ReviewPreparationDependencies['inspectGitFile'];
          }
        ).inspectGitFile = async (filePath: string) => ({
          ...(await inspect(filePath)),
          originUrl: 'https://github.com/example/aster.git',
        });
      },
    ]) {
      const harness = await createPreparationHarness();
      mutate(harness);
      await expect(
        preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies)
      ).rejects.toThrow('Phase 1 review profile preparation failed.');
    }
  });

  it('rolls back its own publication when post-write validation fails', async () => {
    const harness = await createPreparationHarness();
    (
      harness.dependencies as unknown as {
        loadPublishedBundle: Phase1ReviewPreparationDependencies['loadPublishedBundle'];
      }
    ).loadPublishedBundle = async () => {
      throw new Error('private-post-write-marker');
    };

    await expect(
      preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies)
    ).rejects.toThrow('Phase 1 review profile preparation failed.');
    expect(harness.wasRolledBack()).toBe(true);
  });

  it.each(['head', 'blobId', 'originUrl', 'clean'] as const)(
    'rejects a %s change during canonical-source reinspection before publication',
    async (field) => {
      const harness = await createPreparationHarness();
      const inspect = harness.dependencies.inspectGitFile;
      let profileInspections = 0;
      (
        harness.dependencies as unknown as {
          inspectGitFile: Phase1ReviewPreparationDependencies['inspectGitFile'];
        }
      ).inspectGitFile = async (filePath: string) => {
        const authority = await inspect(filePath);

        if (authority.relativePath !== 'compatibility/phase-1-profile.json') {
          return authority;
        }
        profileInspections += 1;

        if (profileInspections < 2) {
          return authority;
        }

        return {
          ...authority,
          ...(field === 'head' ? { head: '9'.repeat(40) } : {}),
          ...(field === 'blobId' ? { blobId: '8'.repeat(40) } : {}),
          ...(field === 'originUrl' ? { originUrl: 'https://github.com/example/aster.git' } : {}),
          ...(field === 'clean' ? { clean: false } : {}),
        };
      };

      await expect(
        preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies)
      ).rejects.toThrow('Phase 1 review profile preparation failed.');
      expect(harness.getPublishedProfile()).toBeUndefined();
    }
  );

  it('keeps dependency injection behind the test-only preparation entry point', async () => {
    const source = await readFile(
      path.resolve(process.cwd(), 'src/compatibility/phase-1/cli.ts'),
      'utf8'
    );

    expect(source).toContain("process.env.NODE_ENV !== 'test'");
    expect(source).toContain('preparedReviewCapabilities');
    expect(source).toContain('consumePreparedReviewCapability');
    expect(source).toContain("GIT_NO_REPLACE_OBJECTS: '1'");
    expect(source).toContain("['--no-replace-objects', ...args]");
  });

  it('resolves the true pinned blobs despite a clean refs/replace commit substitution', async () => {
    const root = await createRoot('phase1-cli-replace');
    const repository = path.join(root, 'aster');
    const compatibilityRoot = path.join(repository, 'compatibility');
    const profilePath = path.join(compatibilityRoot, 'phase-1-profile.json');
    const schemaPath = path.join(compatibilityRoot, 'phase-1-profile.schema.json');
    const profile = designProfileFixture();
    const schema = {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      type: 'object',
      required: ['schemaVersion', 'profileId', 'reference', 'profileSchema', 'phase1Harness'],
    } as const;
    const substitutedProfileBytes = Buffer.from(`${JSON.stringify(profile)}\n`);
    const substitutedSchemaBytes = Buffer.from(`${JSON.stringify(schema)}\n`);
    const trueProfileBytes = Buffer.from(`${JSON.stringify(profile, undefined, 2)}\n`);
    const trueSchemaBytes = Buffer.from(`${JSON.stringify(schema, undefined, 2)}\n`);

    await mkdir(compatibilityRoot, { recursive: true });
    await executeFile('git', ['init', '--quiet', repository]);
    await executeFile('git', ['remote', 'add', 'origin', 'https://github.com/qq98982/aster.git'], {
      cwd: repository,
    });
    await Promise.all([
      writeFile(profilePath, substitutedProfileBytes, { mode: 0o600 }),
      writeFile(schemaPath, substitutedSchemaBytes, { mode: 0o600 }),
    ]);
    await executeFile('git', ['add', 'compatibility'], { cwd: repository });
    await executeFile(
      'git',
      [
        '-c',
        'user.name=Phase 1 Test',
        '-c',
        'user.email=phase1-test@example.invalid',
        'commit',
        '--quiet',
        '-m',
        'substituted source',
      ],
      { cwd: repository }
    );
    const substitutedCommitResult = await executeFile('git', ['rev-parse', 'HEAD'], {
      cwd: repository,
      encoding: 'utf8',
    });
    await Promise.all([
      writeFile(profilePath, trueProfileBytes, { mode: 0o600 }),
      writeFile(schemaPath, trueSchemaBytes, { mode: 0o600 }),
    ]);
    await executeFile('git', ['add', 'compatibility'], { cwd: repository });
    await executeFile(
      'git',
      [
        '-c',
        'user.name=Phase 1 Test',
        '-c',
        'user.email=phase1-test@example.invalid',
        'commit',
        '--quiet',
        '-m',
        'reviewed source',
      ],
      { cwd: repository }
    );
    const trueCommitResult = await executeFile('git', ['rev-parse', 'HEAD'], {
      cwd: repository,
      encoding: 'utf8',
    });
    const substitutedCommit = substitutedCommitResult.stdout.trim();
    const trueCommit = trueCommitResult.stdout.trim();
    await executeFile('git', ['replace', trueCommit, substitutedCommit], { cwd: repository });

    const relativePath = 'compatibility/phase-1-profile.json';
    const replacedBlobResult = await executeFile(
      'git',
      ['rev-parse', `${trueCommit}:${relativePath}`],
      {
        cwd: repository,
        encoding: 'utf8',
      }
    );
    const trueBlobResult = await executeFile(
      'git',
      ['--no-replace-objects', 'rev-parse', `${trueCommit}:${relativePath}`],
      {
        cwd: repository,
        encoding: 'utf8',
      }
    );
    const replacedBlob = replacedBlobResult.stdout.trim();
    const trueBlob = trueBlobResult.stdout.trim();
    expect(replacedBlob).not.toBe(trueBlob);

    const authority = await inspectGitFileForTesting(profilePath);
    const trueBytesResult = await executeFile(
      'git',
      ['--no-replace-objects', 'cat-file', 'blob', `${trueCommit}:${relativePath}`],
      { cwd: repository, encoding: 'buffer', maxBuffer: 1024 * 1024 }
    );
    const trueBytes = trueBytesResult.stdout;

    expect(authority).toMatchObject({
      originUrl: 'https://github.com/qq98982/aster.git',
      head: trueCommit,
      blobId: trueBlob,
      clean: true,
    });
    expect(Buffer.from(authority.bytes)).not.toEqual(substitutedProfileBytes);
    expect(Buffer.from(authority.bytes)).toEqual(Buffer.from(trueBytes));

    const schemaAuthority = await inspectGitFileForTesting(schemaPath);
    expect(schemaAuthority).toMatchObject({
      originUrl: 'https://github.com/qq98982/aster.git',
      head: trueCommit,
      clean: true,
    });
    expect(Buffer.from(schemaAuthority.bytes)).not.toEqual(substitutedSchemaBytes);
    expect(Buffer.from(schemaAuthority.bytes)).toEqual(trueSchemaBytes);
  });

  it('rejects forged and reused prepared-review publication capabilities', async () => {
    expect(() => consumePreparedReviewCapabilityForTesting(Object.freeze({}))).toThrow(
      'Phase 1 review profile preparation failed.'
    );
    const harness = await createPreparationHarness();
    await preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies);
    const capability = harness.getPreparedCapability();

    expect(capability).toBeDefined();
    expect(() => consumePreparedReviewCapabilityForTesting(capability)).toThrow(
      'Phase 1 review profile preparation failed.'
    );
  });

  it.each(['pinned commit', 'profile blob', 'schema blob'] as const)(
    'maps a missing %s to the fixed preparation diagnostic',
    async (missing) => {
      const harness = await createPreparationHarness();
      const inspect = harness.dependencies.inspectGitFile;
      (
        harness.dependencies as unknown as {
          inspectGitFile: Phase1ReviewPreparationDependencies['inspectGitFile'];
        }
      ).inspectGitFile = async (filePath: string) => {
        const authority = await inspect(filePath);

        if (missing === 'pinned commit' && authority.originUrl.includes('/aster.git')) {
          throw new Error('private-missing-commit');
        }
        if (
          (missing === 'profile blob' &&
            authority.relativePath === 'compatibility/phase-1-profile.json') ||
          (missing === 'schema blob' &&
            authority.relativePath === 'compatibility/phase-1-profile.schema.json')
        ) {
          return { ...authority, blobId: '', bytes: new Uint8Array() };
        }

        return authority;
      };

      await expect(
        preparePhase1ReviewProfileForTesting(harness.command, harness.dependencies)
      ).rejects.toThrow('Phase 1 review profile preparation failed.');
      expect(harness.getPublishedProfile()).toBeUndefined();
    }
  );
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, unicorn/consistent-function-scoping */
