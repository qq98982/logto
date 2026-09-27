/* eslint-disable no-await-in-loop, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The CLI harness records exact call order and iterates independent fail-closed cases with local mutable traces and intentional no-op ports. */
import path from 'node:path';

import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from '../profile.js';

import {
  parsePhase2BasePreservationArguments,
  runPhase2BasePreservationCli,
  type Phase2BasePreservationCliDependencies,
} from './cli.js';
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

describe('Phase 2 base-preservation CLI', () => {
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

/* eslint-enable no-await-in-loop, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
