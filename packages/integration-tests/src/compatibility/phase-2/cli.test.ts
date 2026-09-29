/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-object-as-default-parameter, no-bitwise, unicorn/no-await-expression-member, @typescript-eslint/consistent-type-assertions -- CLI tests intentionally capture ordered effects, mutate filesystem modes, and inspect awaited filesystem metadata. */
import {
  chmod,
  link,
  lstat,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import { writeSecureJsonArtifact } from '../phase-1/secure-evidence-sink.js';

import {
  clientCredentialsCandidateInvariantExpectedProjection,
  clientCredentialsCandidateInvariantIds,
  runClientCredentialsCandidateInvariantControls,
} from './candidate-invariants/client-credentials.js';
import {
  deviceCandidateInvariantExpectedProjection,
  deviceCandidateInvariantIds,
  runDeviceCandidateInvariantControls,
} from './candidate-invariants/device-authorization.js';
import {
  closedDeviceFailureStage,
  deviceIdClaimKeysDifferenceDiagnostic,
  deviceProjectionDifferenceField,
  deviceScenarioProjectionFailure,
  parsePhase2Arguments,
  readPhase2OracleArtifact,
  readPhase2TargetDescriptor,
  runPhase2Cli,
  runPhase2CliMain,
  type Phase2CliDependencies,
} from './cli.js';
import { phase2ExpectedBaseAcceptance, type Phase2ProfileRegistries } from './profile.js';
import { validatePhase2TargetDescriptor } from './runtime.js';

describe('device projection diagnostic fields', () => {
  it('maps a nested cookie difference to its closed root field', () => {
    expect(deviceProjectionDifferenceField('/cookies/0/name')).toBe('cookies');
    expect(deviceProjectionDifferenceField('/sequence/completion/cookies/0/options/0')).toBe(
      'completion-cookies'
    );
    expect(deviceProjectionDifferenceField('/sequence/private/cookies/0/name')).toBe('other');
    expect(deviceProjectionDifferenceField('/sequence/completion/private-token/value')).toBe(
      'other'
    );
    expect(deviceProjectionDifferenceField('/sequence/siblingAfter/headers/cache-control')).toBe(
      'sequence-siblingAfter-headers'
    );
    expect(deviceProjectionDifferenceField('/sequence/private/headers/private-token')).toBe(
      'other'
    );
    expect(deviceProjectionDifferenceField('/private-token/value')).toBe('other');
    expect(deviceProjectionDifferenceField('/id/claims/claimKeys/0')).toBe('id-claimKeys');
    expect(deviceProjectionDifferenceField('/id/claims/claimTypes/email')).toBe(
      'id-claimTypes-email'
    );
    expect(deviceProjectionDifferenceField('/id/header/alg')).toBe('id-header');
    expect(deviceProjectionDifferenceField('/id/claims/issuer')).toBe('id-issuer');
    expect(deviceProjectionDifferenceField('/id/claims/lifetimeSeconds')).toBe(
      'id-lifetimeSeconds'
    );
    expect(deviceProjectionDifferenceField('/id/lifetimeSeconds')).toBe('id-other');
    expect(deviceProjectionDifferenceField('/id/claims/claimTypes/private-token')).toBe('id-other');
    expect(deviceProjectionDifferenceField('/id/private-token/value')).toBe('id-other');
  });

  it('reports sorted allowlisted ID claim-key differences without claim values', () => {
    expect(
      deviceIdClaimKeysDifferenceDiagnostic(
        {
          id: {
            claims: {
              claimKeys: [
                'sub',
                'iss',
                'email',
                'auth_time',
                'organizations',
                'organization_roles',
              ],
              claimTypes: { private: 'oracle-secret' },
            },
          },
        },
        {
          id: {
            claims: {
              claimKeys: ['iss', 'sub', 'jti', 'client_id'],
              claimTypes: { private: 'candidate-secret' },
            },
          },
        }
      )
    ).toBe(
      'Phase 2 device ID claimKeys differ (only on oracle: auth_time,email,organization_roles,organizations; only on candidate: client_id,jti).'
    );
  });

  it('refuses an ID claim-key diagnostic outside the closed claim-name allowlist', () => {
    expect(
      deviceIdClaimKeysDifferenceDiagnostic(
        { id: { claims: { claimKeys: ['iss', 'private-token'] } } },
        { id: { claims: { claimKeys: ['iss'] } } }
      )
    ).toBeUndefined();
  });
});

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
    ...deviceCandidateInvariantIds,
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
  readOracleArtifact: async () =>
    ({
      schemaVersion: 1,
      mode: 'oracle',
      sanitizerSuccess: true,
      provenance: {
        profileSha256: profile.profileSha256,
        schemaSha256: profile.schemaSha256,
        baseAcceptance: profile.baseAcceptance,
        harness: {
          repositoryUrl: 'https://github.com/qq98982/logto.git',
          headCommit: 'f'.repeat(40),
          headTree: 'a'.repeat(40),
          runtimeBundleSha256: 'b'.repeat(64),
        },
        oracle: {
          sourceCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
          imageDigest: 'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd',
          topology: { primaryRole: 'oracle-primary-core', foreignRole: 'oracle-foreign-core' },
          drivers: { state: { role: 'state-driver', sha256: 'c'.repeat(64) } },
        },
      },
      payload: { schemaVersion: 1, mode: 'oracle', target: { target: 'oracle' } },
    }) as never,
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
    return Object.freeze({
      schemaVersion: 1,
      mode: 'candidate-invariants',
      invariants: Object.freeze([
        ...clientCredentialsCandidateInvariantIds.map((id) =>
          runClientCredentialsCandidateInvariantControls(
            id,
            clientCredentialsCandidateInvariantExpectedProjection(id)
          )
        ),
        ...deviceCandidateInvariantIds.map((id) =>
          runDeviceCandidateInvariantControls(id, deviceCandidateInvariantExpectedProjection(id))
        ),
      ]),
    });
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
  it('classifies only exact closed device failure stages', () => {
    for (const stage of [
      'lifecycle-request',
      'lifecycle-response',
      'token-response',
      'credential-lease',
    ] as const) {
      expect(
        closedDeviceFailureStage(
          new TypeError(`Invalid Phase 2 device authorization transport (${stage})`)
        )
      ).toBe(stage);
    }
    expect(
      closedDeviceFailureStage(new TypeError('Invalid Phase 2 device authorization projection'))
    ).toBe('projection');
    expect(
      closedDeviceFailureStage(new TypeError('Invalid Phase 2 device authorization scenario'))
    ).toBe('scenario');
    for (const stage of [
      'approval',
      'approval-authorize',
      'approval-capture',
      'approval-verify',
      'approval-experience-open',
      'approval-password',
      'approval-identification',
      'approval-experience-submit',
      'approval-resume-initial',
      'approval-consent-read',
      'approval-consent-write',
      'approval-resume-final',
      'transition',
      'verification-get',
      'verification-post',
    ] as const) {
      expect(
        closedDeviceFailureStage(
          new TypeError(`Invalid Phase 2 device already-used-code step (${stage})`)
        )
      ).toBe(stage);
    }
    expect(
      closedDeviceFailureStage(
        new TypeError('Invalid Phase 2 device authorization transport (unknown-marker)')
      )
    ).toBeUndefined();
    expect(
      closedDeviceFailureStage(
        new TypeError(
          'Invalid Phase 2 device authorization transport (credential-lease):private-marker'
        )
      )
    ).toBeUndefined();
    expect(closedDeviceFailureStage('lifecycle-request')).toBeUndefined();
    expect(
      closedDeviceFailureStage(
        new TypeError('Invalid Phase 2 device already-used-code step (approval):private-marker')
      )
    ).toBeUndefined();
  });

  it('parses only the three exact command grammars', () => {
    expect(parsePhase2Arguments(oracleArguments())).toMatchObject({ mode: 'oracle' });
    expect(
      parsePhase2Arguments([
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
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
        '--oracle-evidence',
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

  it('reads immutable oracle evidence and freshly prepares only the candidate', async () => {
    const calls: string[] = [];
    const base = dependencies(calls);
    const observed: string[] = [];
    await runPhase2Cli(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
        oracleTargetPath,
        '--candidate-target',
        candidateTargetPath,
        '--output',
        path.join(root, 'phase-2-client-credentials-differential.json'),
        '--temp-root',
        root,
      ],
      {
        ...base,
        readOracleArtifact: async (...arguments_) => {
          observed.push('oracle-artifact');
          return base.readOracleArtifact(...arguments_);
        },
        readTarget: async (filePath) => {
          observed.push(`target:${path.basename(filePath)}`);
          return base.readTarget(filePath);
        },
        verifyTarget: async (value) => {
          observed.push(`verify:${value.kind}`);
          return base.verifyTarget(value);
        },
        prepareTarget: async (value, sessionRoot, namespace) => {
          observed.push(`prepare:${namespace}`);
          return base.prepareTarget(value, sessionRoot, namespace);
        },
        executeOracle: async () => {
          throw new Error('oracle must not execute');
        },
      }
    );
    expect(observed).toEqual([
      'oracle-artifact',
      'target:candidate-target.json',
      'verify:candidate',
      'prepare:candidate',
    ]);
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

    const linkPath = path.join(root, 'target-link.json');
    await symlink(oracleTargetPath, linkPath);
    await expect(
      runPhase2Cli(
        oracleArguments().map((value) => (value === oracleTargetPath ? linkPath : value)),
        dependencies([])
      )
    ).rejects.toThrow('Phase 2 command stage failed: oracle-target-path');

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

    const artifactLink = path.join(root, 'oracle-artifact-link.json');
    await symlink(oracleTargetPath, artifactLink);
    const differential = (artifactPath: string) => [
      'differential',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--oracle-evidence',
      artifactPath,
      '--candidate-target',
      candidateTargetPath,
      '--output',
      path.join(root, 'phase-2-client-credentials-differential.json'),
      '--temp-root',
      root,
    ];
    await expect(runPhase2Cli(differential(artifactLink), dependencies([]))).rejects.toThrow(
      'Phase 2 command stage failed: differential-target-path'
    );
    const oversized = path.join(root, 'oversized-oracle.json');
    await writeFile(oversized, Buffer.alloc(1024 * 1024 + 1, 0x20), { mode: 0o600 });
    await expect(runPhase2Cli(differential(oversized), dependencies([]))).rejects.toThrow(
      'Phase 2 command stage failed: differential-target-path'
    );
    const hardlinkPath = path.join(root, 'oracle-artifact-hardlink.json');
    await link(oracleTargetPath, hardlinkPath);
    await expect(
      readPhase2OracleArtifact(oracleTargetPath, profile, await dependencies([]).inspectHarness())
    ).rejects.toThrow('Invalid Phase 2 arguments.');
    await rm(hardlinkPath);
    await chmod(oracleTargetPath, 0o644);
    await expect(
      readPhase2OracleArtifact(oracleTargetPath, profile, await dependencies([]).inspectHarness())
    ).rejects.toThrow('Invalid Phase 2 arguments.');
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
    expect(calls).toContain('stderr:Phase 2 client credentials command failed (oracle-execution).');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(
      (await readdir(root)).filter((name) => name.startsWith('phase2-client-credentials-run-'))
    ).toEqual([]);

    const sanitizerCalls: string[] = [];
    expect(
      await runPhase2CliMain(
        oracleArguments(output),
        undefined,
        dependencies(sanitizerCalls, { Authorization: 'Basic planted-secret' })
      )
    ).toBe(1);
    expect(sanitizerCalls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-evidence).'
    );
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('identifies generic oracle and candidate-invariant stage failures', async () => {
    const oracleCalls: string[] = [];
    const oracleBase = dependencies(oracleCalls);
    expect(
      await runPhase2CliMain(oracleArguments(), undefined, {
        ...oracleBase,
        verifyTarget: async () => {
          throw new Error('private oracle verification detail');
        },
      })
    ).toBe(1);
    expect(oracleCalls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-target-verify).'
    );

    const candidateCalls: string[] = [];
    const candidateBase = dependencies(candidateCalls);
    const candidateArguments = [
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
    ];
    expect(
      await runPhase2CliMain(candidateArguments, undefined, {
        ...candidateBase,
        executeCandidateInvariants: async () => {
          throw new Error('private candidate execution detail');
        },
      })
    ).toBe(1);
    expect(candidateCalls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate-execution).'
    );
    expect(candidateCalls.join(' ')).not.toContain('private candidate execution detail');
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
        '--oracle-evidence',
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

  it('preserves an exact closed device scenario failure for the launcher', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
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
            'Phase 2 scenario failed: candidate/device-token.concurrent-reference-multi-winner'
          );
        },
      }
    );
    expect(code).toBe(1);
    const exact =
      'Phase 2 client credentials command failed (candidate/device-token.concurrent-reference-multi-winner).';
    expect(calls).toContain(`stderr:${exact}`);
    expect(calls.join(' ')).not.toContain('private');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports only closed ID claim-key structure beside the fixed scenario failure', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const calls: string[] = [];
    const code = await runPhase2CliMain(
      [
        'differential',
        '--profile',
        profilePath,
        '--schema',
        schemaPath,
        '--oracle-evidence',
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
          throw deviceScenarioProjectionFailure(
            'device-token.refresh-organization-selection',
            '/id/claims/claimKeys/0',
            {
              id: {
                claims: {
                  claimKeys: [
                    'iss',
                    'sub',
                    'email',
                    'auth_time',
                    'organizations',
                    'organization_roles',
                  ],
                },
              },
            },
            { id: { claims: { claimKeys: ['iss', 'sub', 'client_id', 'jti'] } } }
          );
        },
      }
    );
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (candidate/device-token.refresh-organization-selection:projection-id-claimKeys).\n' +
        'Phase 2 device ID claimKeys differ (only on oracle: auth_time,email,organization_roles,organizations; only on candidate: client_id,jti).'
    );
    expect(calls.join(' ')).not.toContain('token-value');
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('reports only a closed device failure stage suffix', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const arguments_ = [
      'differential',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--oracle-evidence',
      oracleTargetPath,
      '--candidate-target',
      candidateTargetPath,
      '--output',
      output,
      '--temp-root',
      root,
    ];
    const stageCalls: string[] = [];
    expect(
      await runPhase2CliMain(arguments_, undefined, {
        ...dependencies(stageCalls),
        executeDifferential: async () => {
          throw new Error(
            'Phase 2 scenario failed: oracle/device-token.refresh-resource-selection:credential-lease'
          );
        },
      })
    ).toBe(1);
    expect(stageCalls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle/device-token.refresh-resource-selection:credential-lease).'
    );

    const hostileCalls: string[] = [];
    expect(
      await runPhase2CliMain(arguments_, undefined, {
        ...dependencies(hostileCalls),
        executeDifferential: async () => {
          throw new Error(
            'Phase 2 scenario failed: oracle/device-token.refresh-resource-selection:private credential value'
          );
        },
      })
    ).toBe(1);
    expect(hostileCalls).toContain(
      'stderr:Phase 2 client credentials command failed (differential-execution).'
    );
    expect(hostileCalls.join(' ')).not.toContain('private credential value');
  });

  it('reports only a closed device projection field suffix', async () => {
    const output = path.join(root, 'phase-2-client-credentials-differential.json');
    const arguments_ = [
      'differential',
      '--profile',
      profilePath,
      '--schema',
      schemaPath,
      '--oracle-evidence',
      oracleTargetPath,
      '--candidate-target',
      candidateTargetPath,
      '--output',
      output,
      '--temp-root',
      root,
    ];
    const runSuffix = async (suffix: string, expected: string) => {
      const calls: string[] = [];
      expect(
        await runPhase2CliMain(arguments_, undefined, {
          ...dependencies(calls),
          executeDifferential: async () => {
            throw new Error(
              `Phase 2 scenario failed: candidate/device-verification.already-used-code:${suffix}`
            );
          },
        })
      ).toBe(1);
      expect(calls).toContain(`stderr:Phase 2 client credentials command failed (${expected}).`);
      expect(calls.join(' ')).not.toContain('private-token');
    };
    await runSuffix(
      'projection-cookies',
      'candidate/device-verification.already-used-code:projection-cookies'
    );
    await runSuffix(
      'projection-completion-cookies',
      'candidate/device-verification.already-used-code:projection-completion-cookies'
    );
    await runSuffix(
      'projection-sequence-siblingAfter-headers',
      'candidate/device-verification.already-used-code:projection-sequence-siblingAfter-headers'
    );
    await runSuffix(
      'projection-id-claimKeys',
      'candidate/device-verification.already-used-code:projection-id-claimKeys'
    );
    await runSuffix(
      'projection-id-claimTypes-email_verified',
      'candidate/device-verification.already-used-code:projection-id-claimTypes-email_verified'
    );
    await runSuffix(
      'projection-id-signature',
      'candidate/device-verification.already-used-code:projection-id-signature'
    );
    await runSuffix(
      'projection-id-other',
      'candidate/device-verification.already-used-code:projection-id-other'
    );
    await Promise.all(
      [
        'approval',
        'approval-authorize',
        'approval-capture',
        'approval-verify',
        'approval-experience-open',
        'approval-password',
        'approval-identification',
        'approval-experience-submit',
        'approval-resume-initial',
        'approval-consent-read',
        'approval-consent-write',
        'approval-resume-final',
        'transition',
        'verification-get',
        'verification-post',
      ].map(async (stage) =>
        runSuffix(stage, `candidate/device-verification.already-used-code:${stage}`)
      )
    );
    await runSuffix('projection-private', 'differential-execution');
    await runSuffix('approval:private', 'differential-execution');
    await runSuffix('approval-password:private', 'differential-execution');
    await runSuffix('projection-cookies:private', 'differential-execution');
    await runSuffix('projection-completion-private', 'differential-execution');
    await runSuffix('projection-sequence-private-headers', 'differential-execution');
    await runSuffix('projection-sequence-siblingAfter-private', 'differential-execution');
    await runSuffix('projection-sequence-siblingAfter-headers:private', 'differential-execution');
    await runSuffix('projection-id-claimTypes-private-token', 'differential-execution');
    await runSuffix('projection-id-signature:private', 'differential-execution');
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

  it('reports only a closed sanitizer partition and bounded scenario index', async () => {
    const calls: string[] = [];
    const output = path.join(root, 'phase-2-client-credentials-oracle.json');
    const code = await runPhase2CliMain(oracleArguments(output), undefined, {
      ...dependencies(calls),
      executeOracle: async () => {
        throw new Error('Phase 2 stage failed: oracle-sanitizer-device-138: private credential');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain(
      'stderr:Phase 2 client credentials command failed (oracle-sanitizer-device-138).'
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
        '--oracle-evidence',
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
        '--oracle-evidence',
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
        '--oracle-evidence',
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
    ).rejects.toThrow('Phase 2 command stage failed: oracle-cleanup');
    expect(calls.some((call) => call.startsWith('publish:'))).toBe(false);
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('uses the mode-specific cleanup stage when no earlier fixed diagnostic exists', async () => {
    const calls: string[] = [];
    const base = dependencies(calls);
    const code = await runPhase2CliMain(oracleArguments(), undefined, {
      ...base,
      loadProfile: async () => {
        throw new Error('private unclassified failure');
      },
      removeSessionRoot: async () => {
        throw new Error('private cleanup failure');
      },
    });
    expect(code).toBe(1);
    expect(calls).toContain('stderr:Phase 2 client credentials command failed (oracle-cleanup).');
    expect(calls.join(' ')).not.toContain('private');
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-object-as-default-parameter, no-bitwise, unicorn/no-await-expression-member, @typescript-eslint/consistent-type-assertions */
