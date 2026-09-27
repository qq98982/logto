/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-object-as-default-parameter, no-bitwise, unicorn/no-await-expression-member -- CLI tests intentionally capture ordered effects, mutate filesystem modes, and inspect awaited filesystem metadata. */
import { chmod, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { writeSecureJsonArtifact } from '../phase-1/secure-evidence-sink.js';

import {
  parsePhase2Arguments,
  readPhase2TargetDescriptor,
  runPhase2Cli,
  runPhase2CliMain,
  type Phase2CliDependencies,
} from './cli.js';
import { phase2ExpectedBaseAcceptance, type Phase2ProfileRegistries } from './profile.js';
import { validatePhase2TargetDescriptor } from './runtime.js';

const rootPrefix = '/var/tmp/henry-build/phase2-cli-';
let root = '';
let profilePath = '';
let schemaPath = '';
let oracleTargetPath = '';
let candidateTargetPath = '';

const profile: Phase2ProfileRegistries = Object.freeze({
  profileSha256: '1'.repeat(64),
  schemaSha256: '2'.repeat(64),
  baseAcceptance: phase2ExpectedBaseAcceptance,
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
  differentialScenarios: Object.freeze([
    'client-credentials.basic-explicit-resource',
    'client-credentials.post-explicit-resource',
    'client-credentials.default-resource',
    'client-credentials.resource-no-scope',
    'client-credentials.resource-partial-scope',
    'client-credentials.organization-empty-scope',
    'client-credentials.organization-scope',
    'client-credentials.organization-resource-scope',
    'client-credentials.unknown-client-basic',
    'client-credentials.unknown-client-post',
    'client-credentials.wrong-secret-basic',
    'client-credentials.wrong-secret-post',
    'client-credentials.mixed-authentication',
    'client-credentials.missing-target',
    'client-credentials.unknown-resource',
    'client-credentials.unassociated-organization',
    'client-credentials.duplicate-resource',
    'client-credentials.duplicate-scope-name',
    'client-credentials.malformed-scope-whitespace',
    'client-credentials.unsupported-parameter',
  ] as const),
  candidateInvariantScenarios: Object.freeze([
    'client-credentials.cross-tenant-authority-rejected',
    'client-credentials.request-role-write-rejected',
    'client-credentials.signing-failure-rolls-back',
    'client-credentials.user-authority-unchanged',
    'logout-session.verification-storage-closed',
  ] as const),
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

const targetDocument = (kind: 'oracle' | 'candidate') => ({
  schemaVersion: 1,
  kind,
  sourceCommit: kind === 'oracle' ? '6852a7b8c8984c5c12b2061e8c51faa310a36412' : 'a'.repeat(40),
  imageDigest:
    kind === 'oracle'
      ? 'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd'
      : `sha256:${'b'.repeat(64)}`,
  projectName: `aster-phase2-client-credentials-${(kind === 'oracle' ? '1' : '2').repeat(16)}`,
  primaryContainerId: (kind === 'oracle' ? '1' : '2').repeat(64),
  foreignContainerId: (kind === 'oracle' ? '3' : '4').repeat(64),
  target: {
    label: kind,
    coreUrl: kind === 'oracle' ? 'http://localhost:3311/' : 'http://localhost:3321/',
    adminUrl: kind === 'oracle' ? 'http://localhost:3411/' : 'http://localhost:3421/',
  },
  foreignTarget: {
    label: kind,
    coreUrl: kind === 'oracle' ? 'http://localhost:3312/' : 'http://localhost:3322/',
    adminUrl: kind === 'oracle' ? 'http://localhost:3412/' : 'http://localhost:3422/',
  },
  stateDriver: {
    path: '/usr/bin/true',
    sha256: 'c'.repeat(64),
    controlSocket: `/tmp/${kind}-state.sock`,
  },
  ...(kind === 'candidate'
    ? {
        fixtureSocket: '/tmp/candidate-fixture.sock',
        fixtureExecutable: { path: '/usr/bin/true', sha256: 'd'.repeat(64) },
        invariantDriver: {
          path: '/usr/bin/true',
          sha256: 'e'.repeat(64),
          controlSocket: '/tmp/candidate-invariant.sock',
        },
      }
    : {}),
});

beforeEach(async () => {
  root = await mkdtemp(rootPrefix);
  await chmod(root, 0o700);
  profilePath = path.join(root, 'profile.json');
  schemaPath = path.join(root, 'schema.json');
  oracleTargetPath = path.join(root, 'oracle-target.json');
  candidateTargetPath = path.join(root, 'candidate-target.json');
  await Promise.all([
    writeFile(profilePath, '{}', { mode: 0o600 }),
    writeFile(schemaPath, '{}', { mode: 0o600 }),
    writeFile(oracleTargetPath, JSON.stringify(targetDocument('oracle')), { mode: 0o600 }),
    writeFile(candidateTargetPath, JSON.stringify(targetDocument('candidate')), { mode: 0o600 }),
  ]);
});

afterEach(async () => {
  await rm(root, { force: true, recursive: true });
});

const dependencies = (
  calls: string[],
  evidence: unknown = { schemaVersion: 1, mode: 'test', sanitized: true }
): Phase2CliDependencies => ({
  loadProfile: async () => profile,
  readTarget: readPhase2TargetDescriptor,
  executeOracle: async () => {
    calls.push('oracle');
    return evidence;
  },
  executeDifferential: async () => {
    calls.push('differential');
    return evidence;
  },
  executeCandidateInvariants: async () => {
    calls.push('candidate-invariants');
    return evidence;
  },
  publish: async (outputPath, value) => {
    calls.push(`publish:${path.basename(outputPath)}`);
    await writeSecureJsonArtifact(outputPath, value);
  },
  removeSessionRoot: async (sessionRoot) => {
    await rm(sessionRoot, { force: true, recursive: true });
  },
  stdout: (message) => {
    calls.push(`stdout:${message.trim()}`);
  },
  stderr: (message) => {
    calls.push(`stderr:${message.trim()}`);
  },
  inspectHarness: async () => ({
    repositoryRoot: '/private',
    repositoryDev: '1',
    repositoryIno: '2',
    clean: true,
    public: {
      repositoryUrl: 'https://github.com/qq98982/logto.git',
      headCommit: 'f'.repeat(40),
      headTree: 'a'.repeat(40),
      runtimeBundleSha256: 'b'.repeat(64),
    },
    runtimeEntryPath: '/private/lib/compatibility/phase-2/cli.js',
  }),
  recheckHarness: async () => {
    // The fake capability remains stable for this CLI unit test.
  },
  verifyTarget: async (target) => ({
    descriptor: target,
    topology: {
      projectName: target.projectName,
      primary: {
        containerId: target.primaryContainerId,
        service: `${target.kind}-primary-core`,
        imageDigest: target.imageDigest,
      },
      foreign: {
        containerId: target.foreignContainerId,
        service: `${target.kind}-foreign-core`,
        imageDigest: target.imageDigest,
      },
    },
    stateDriver: {
      path: '/private/state',
      sha256: target.stateDriver.sha256,
      dev: '1',
      ino: '2',
      uid: 1,
      mode: 0o700,
      nlink: 1,
    },
    stateControlSocket: {
      path: '/private/state.sock',
      dev: '1',
      ino: '3',
      uid: 1,
      mode: 0o600,
      nlink: 1,
      type: 'unix-socket',
    },
    ...(target.fixtureExecutable && {
      fixtureExecutable: {
        path: '/private/fixture',
        sha256: target.fixtureExecutable.sha256,
        dev: '1',
        ino: '4',
        uid: 1,
        mode: 0o700,
        nlink: 1,
      },
    }),
    ...(target.fixtureSocket && {
      fixtureSocket: {
        path: '/private/fixture.sock',
        dev: '1',
        ino: '5',
        uid: 1,
        mode: 0o600,
        nlink: 1,
        type: 'unix-socket',
      },
    }),
    ...(target.invariantDriver && {
      invariantDriver: {
        path: '/private/invariant',
        sha256: target.invariantDriver.sha256,
        dev: '1',
        ino: '6',
        uid: 1,
        mode: 0o700,
        nlink: 1,
      },
      invariantControlSocket: {
        path: '/private/invariant.sock',
        dev: '1',
        ino: '7',
        uid: 1,
        mode: 0o600,
        nlink: 1,
        type: 'unix-socket',
      },
    }),
  }),
  prepareTarget: async (verified) => ({
    descriptor: verified.descriptor,
    topology: verified.topology,
    fence: {
      run: async <Result>(operation: () => Promise<Result>) => operation(),
      assertStable: async () => {
        // The fake target identity remains stable for this CLI unit test.
      },
    },
  }),
});

const oracleArguments = (output = path.join(root, 'phase-2-client-credentials-oracle.json')) => [
  'oracle',
  '--profile',
  profilePath,
  '--schema',
  schemaPath,
  '--target',
  oracleTargetPath,
  '--output',
  output,
  '--temp-root',
  root,
];

describe('Phase 2 CLI', () => {
  it('parses only the three exact command grammars', () => {
    expect(parsePhase2Arguments(oracleArguments())).toMatchObject({ mode: 'oracle' });
    expect(
      parsePhase2Arguments([
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-target',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-differential.json'),
        '--temp-root',
        root,
      ])
    ).toMatchObject({ mode: 'differential' });
    expect(
      parsePhase2Arguments([
        'candidate-invariants',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-candidate-invariants.json'),
        '--temp-root',
        root,
      ])
    ).toMatchObject({ mode: 'candidate-invariants' });
    for (const invalid of [
      [],
      ['run'],
      [...oracleArguments(), '--extra', 'x'],
      oracleArguments().with(1, '--profile=x'),
      oracleArguments().with(3, '--profile'),
    ]) {
      expect(() => parsePhase2Arguments(invalid)).toThrow('Invalid Phase 2 arguments.');
    }
  });

  it('publishes one exclusive mode-0600 fixed artifact and removes owned session roots', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    await runPhase2Cli(oracleArguments(output), dependencies(calls));
    expect(calls).toEqual([
      'oracle',
      'publish:phase-2-client-credentials-oracle.json',
      'stdout:Phase 2 client credentials oracle complete.',
    ]);
    expect(JSON.parse(await readFile(output, 'utf8'))).toMatchObject({
      schemaVersion: 1,
      mode: 'oracle',
      sanitizerSuccess: true,
      provenance: {
        profileSha256: '1'.repeat(64),
        schemaSha256: '2'.repeat(64),
        harness: {
          repositoryUrl: 'https://github.com/qq98982/logto.git',
          runtimeBundleSha256: 'b'.repeat(64),
        },
      },
      payload: { schemaVersion: 1, mode: 'test', sanitized: true },
    });
    expect((await lstat(output)).mode & 0o777).toBe(0o600);
    expect(
      (await readdir(root)).filter((name) => name.startsWith('phase2-client-credentials-run-'))
    ).toEqual([]);
    await expect(runPhase2Cli(oracleArguments(output), dependencies([]))).rejects.toThrow(
      'Invalid Phase 2 arguments.'
    );
  });

  it('routes differential and candidate-invariants without aliases', async () => {
    const differentialCalls: string[] = [];
    await runPhase2Cli(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-target',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-differential.json'),
        '--temp-root',
        root,
      ],
      dependencies(differentialCalls)
    );
    expect(differentialCalls[0]).toBe('differential');

    const invariantCalls: string[] = [];
    await runPhase2Cli(
      [
        'candidate-invariants',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-candidate-invariants.json'),
        '--temp-root',
        root,
      ],
      dependencies(invariantCalls)
    );
    expect(invariantCalls[0]).toBe('candidate-invariants');
  });

  it('rejects wrong filenames, non-0700 roots, symlinks, duplicate target keys, and aliased targets', async () => {
    await expect(
      runPhase2Cli(oracleArguments(path.join(root, 'wrong.json')), dependencies([]))
    ).rejects.toThrow('Invalid Phase 2 arguments.');

    await chmod(root, 0o755);
    await expect(runPhase2Cli(oracleArguments(), dependencies([]))).rejects.toThrow(
      'Invalid Phase 2 arguments.'
    );
    await chmod(root, 0o700);

    const link = path.join(root, 'target-link.json');
    await symlink(oracleTargetPath, link);
    await expect(
      runPhase2Cli(
        oracleArguments().map((value) => (value === oracleTargetPath ? link : value)),
        dependencies([])
      )
    ).rejects.toThrow('Invalid Phase 2 arguments.');

    const duplicate = path.join(root, 'duplicate.json');
    await writeFile(duplicate, '{"schemaVersion":1,"schemaVersion":1}', { mode: 0o600 });
    await expect(readPhase2TargetDescriptor(duplicate)).rejects.toThrow(
      'Invalid Phase 2 arguments.'
    );

    expect(() =>
      validatePhase2TargetDescriptor({
        ...targetDocument('candidate'),
        foreignTarget: targetDocument('candidate').target,
      })
    ).toThrow('Invalid Phase 2 runtime');
  });

  it('publishes nothing on execution or sanitizer failure and emits fixed diagnostics', async () => {
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const calls: string[] = [];
    const failing = dependencies(calls);
    const code = await runPhase2CliMain(oracleArguments(output), undefined, {
      ...failing,
      executeOracle: async () => {
        throw new Error('private detail');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain('stderr:Phase 2 client credentials command failed.');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(
      (await readdir(root)).filter((name) => name.startsWith('phase2-client-credentials-run-'))
    ).toEqual([]);

    await expect(
      runPhase2Cli(
        oracleArguments(output),
        dependencies([], { Authorization: 'Basic planted-secret' })
      )
    ).rejects.toThrow('Invalid Phase 2 client credentials projection');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('identifies the failed closed scenario without printing a credential-bearing exception', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-target',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new Error(
            'Phase 2 scenario failed: candidate/client-credentials.basic-explicit-resource'
          );
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate/client-credentials.basic-explicit-resource).'
    );
    expect(calls.join(' ')).not.toContain('private');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports a bounded public status stage without printing its private exception', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const code = await runPhase2CliMain(oracleArguments(output), undefined, {
      ...dependencies(calls),
      executeOracle: async () => {
        throw new Error('Phase 2 stage failed: oracle-status-verification: private credential');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-status-verification).'
    );
    expect(calls.join(' ')).not.toContain('private credential');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('identifies a fixed fixture failure stage without printing its private exception', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-target',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new Error('Phase 2 stage failed: candidate-fixture: private credential value');
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate-fixture).'
    );
    expect(calls.join(' ')).not.toContain('private credential value');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('preserves the execution stage when differential cleanup also fails', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-target',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        executeDifferential: async () => {
          throw new Error('private execution credential');
        },
        removeSessionRoot: async () => {
          throw new Error('private cleanup credential');
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (differential-execution).'
    );
    expect(calls.join(' ')).not.toContain('private execution credential');
    expect(calls.join(' ')).not.toContain('private cleanup credential');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports differential target verification without exposing the failure', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-target',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        output,
        '--temp-root',
        root,
      ],
      undefined,
      {
        ...dependencies(calls),
        verifyTarget: async () => {
          throw new Error('private verification detail');
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (differential-target-verify).'
    );
    expect(calls.join(' ')).not.toContain('private verification detail');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('does not publish when owned session-root removal fails', async () => {
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const calls: string[] = [];
    await expect(
      runPhase2Cli(oracleArguments(output), {
        ...dependencies(calls),
        removeSessionRoot: async () => {
          throw new Error('planted rm failure');
        },
      })
    ).rejects.toThrow('planted rm failure');
    expect(calls.some((call) => call.startsWith('publish:'))).toBe(false);
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-object-as-default-parameter, no-bitwise, unicorn/no-await-expression-member */
