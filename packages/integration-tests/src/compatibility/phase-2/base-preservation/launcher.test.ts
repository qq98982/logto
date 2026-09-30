/* eslint-disable max-lines, max-params, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-argument -- The launcher test records lifecycle dependency calls, verifies sorted environment keys, and iterates hostile environment cases. */
import {
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  rm,
  stat,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import path from 'node:path';

import { computeRuntimeBundleManifest } from '../launcher.mjs';
import { computePhase2RuntimeBundleIdentity } from '../provenance.js';

import { phase2BasePreservationRuntimeEntryPath } from './cli.js';
import {
  basePreservationBrowserEnvironmentKeys,
  basePreservationBridgeSource,
  basePreservationRuntimeEntryPath,
  basePreservationEnvironmentKeys,
  basePreservationOptionalEnvironmentKeys,
  basePreservationRequiredEnvironmentKeys,
  cleanupBasePreservationBridgeEntry,
  createBasePreservationBridgeEntry,
  diagnosticForBasePreservationChild,
  exitCodeForBasePreservationChild,
  launchPhase2BasePreservation,
  selectBasePreservationEnvironment,
} from './launcher.mjs';

const environment = Object.freeze(
  Object.fromEntries(basePreservationEnvironmentKeys.map((key) => [key, `${key}-value`]))
);
const socketlessEnvironment = Object.freeze(
  Object.fromEntries(
    Object.entries(environment).filter(([key]) => key !== 'ASTER_PHASE1_ENGINE_SOCKET')
  )
);
const creationReceipt = Object.freeze({
  root: '/repo/packages/integration-tests',
  path: basePreservationRuntimeEntryPath,
  parent: '/repo/packages/integration-tests/lib/compatibility/phase-2',
  parentDev: 1,
  parentIno: 2,
  dev: 1,
  ino: 3,
  uid: 1000,
  mode: 0o400,
  size: Buffer.byteLength(basePreservationBridgeSource),
  nlink: 1,
  content: basePreservationBridgeSource,
});

const createBridgeFixture = async (name: string) => {
  const root = await mkdtemp(`/var/tmp/henry-build/${name}-`);
  const nestedDirectory = path.join(root, 'lib/compatibility/phase-2/base-preservation');
  const bridge = path.join(root, 'lib/compatibility/phase-2/base-preservation-entry.js');
  await mkdir(nestedDirectory, { mode: 0o700, recursive: true });
  await writeFile(path.join(nestedDirectory, 'cli.js'), 'export const marker = true;\n', {
    mode: 0o600,
  });
  const identity = await lstat(root);
  return Object.freeze({ root, bridge, dev: identity.dev, ino: identity.ino, uid: identity.uid });
};

const removeBridgeFixture = async (fixture: Awaited<ReturnType<typeof createBridgeFixture>>) => {
  const current = await lstat(fixture.root);
  if (
    !fixture.root.startsWith('/var/tmp/henry-build/') ||
    current.isSymbolicLink() ||
    !current.isDirectory() ||
    current.dev !== fixture.dev ||
    current.ino !== fixture.ino ||
    current.uid !== fixture.uid
  ) {
    throw new TypeError('Invalid bridge fixture cleanup');
  }
  await rm(fixture.root, { recursive: true });
};

describe('Phase 2 base-preservation launcher', () => {
  it.each([
    ['arguments', 40],
    ['paths', 41],
    ['profile', 42],
    ['harness', 43],
    ['closure', 44],
    ['phase1', 45],
    ['runtime', 46],
    ['harness-recheck', 47],
    ['publish', 48],
  ])('maps only an authenticated %s child stage to reserved exit code %i', (stage, exitCode) => {
    const message = `Phase 2 base-preservation failed (${stage}).\n`;
    const result = { timedOut: false, code: 1, signal: null, stdout: '', stderr: message };
    expect(diagnosticForBasePreservationChild(result)).toBe(message);
    expect(exitCodeForBasePreservationChild(result)).toBe(exitCode);
    for (const hostile of [
      { ...result, code: 0 },
      { ...result, code: exitCode },
      { ...result, timedOut: true },
      { ...result, signal: 'SIGTERM' },
      { ...result, stdout: 'private credential' },
      { ...result, stderr: `${message}private credential` },
      { ...result, stderr: `Phase 2 base-preservation failed (unknown).\n` },
    ]) {
      expect(diagnosticForBasePreservationChild(hostile)).toBe(
        'Phase 2 base-preservation launcher failed.\n'
      );
      expect(exitCodeForBasePreservationChild(hostile)).toBe(1);
    }
  });

  it('selects and forwards exactly the four inherited Phase 1 browser runtime values', () => {
    expect(basePreservationBrowserEnvironmentKeys).toEqual([
      'HOME',
      'PLAYWRIGHT_BROWSERS_PATH',
      'TMPDIR',
      'XDG_RUNTIME_DIR',
    ]);
    const source = {
      ...environment,
      UNRELATED_AMBIENT_VALUE: 'must-not-be-forwarded',
    };
    expect(selectBasePreservationEnvironment(source)).toEqual(environment);
    expect(
      Object.hasOwn(selectBasePreservationEnvironment(source), 'UNRELATED_AMBIENT_VALUE')
    ).toBe(false);
    expect(basePreservationOptionalEnvironmentKeys).toEqual(['ASTER_PHASE1_ENGINE_SOCKET']);
    expect(basePreservationRequiredEnvironmentKeys).not.toContain('ASTER_PHASE1_ENGINE_SOCKET');
    expect(
      selectBasePreservationEnvironment({
        ...socketlessEnvironment,
        UNRELATED_AMBIENT_VALUE: 'must-not-be-forwarded',
      })
    ).toEqual(socketlessEnvironment);
  });

  it('uses the same fixed shallow entry in the launcher and nested CLI provenance', () => {
    expect(phase2BasePreservationRuntimeEntryPath).toBe(basePreservationRuntimeEntryPath);
  });

  it('creates, executes, and cleans up one verified entry sequentially', async () => {
    const calls: string[] = [];
    const manifest = Object.freeze({
      sha256: '1'.repeat(64),
      moduleCount: 1,
      entryUrl:
        'file:///repo/packages/integration-tests/lib/compatibility/phase-2/base-preservation-entry.js',
      libraryRootUrl: 'file:///repo/packages/integration-tests/lib/',
      modules: Object.freeze({
        'file:///repo/packages/integration-tests/lib/compatibility/phase-2/base-preservation-entry.js':
          '2'.repeat(64),
      }),
    });

    await expect(
      launchPhase2BasePreservation(['run'], environment, {
        inspect: async () => {
          calls.push('inspect');
          return Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) });
        },
        build: async () => {
          calls.push('build');
        },
        createEntry: async () => {
          calls.push('entry');
          return creationReceipt;
        },
        identity: async () => {
          calls.push('identity');
          return manifest;
        },
        recheckEntry: async () => {
          calls.push('recheck-entry');
          return basePreservationRuntimeEntryPath;
        },
        execute: async (_entry, args, childEnvironment, receivedManifest, capability) => {
          calls.push('execute');
          expect(args).toEqual(['run']);
          expect(receivedManifest).toBe(manifest);
          expect(capability).toMatch(/^[0-9a-f]{64}$/u);
          expect(Object.keys(childEnvironment).toSorted()).toEqual(
            [
              ...basePreservationEnvironmentKeys,
              'ASTER_PHASE2_HARNESS_HEAD',
              'ASTER_PHASE2_HARNESS_TREE',
              'ASTER_PHASE2_RUNTIME_BUNDLE_SHA256',
              'LC_ALL',
            ].toSorted()
          );
          for (const key of basePreservationBrowserEnvironmentKeys) {
            expect(childEnvironment[key]).toBe(environment[key]);
          }
          expect(childEnvironment.ASTER_PHASE1_ENGINE_SOCKET).toBe(
            environment.ASTER_PHASE1_ENGINE_SOCKET
          );
          return 0;
        },
        cleanupEntry: async () => {
          calls.push('cleanup');
        },
      })
    ).resolves.toBe(0);
    expect(calls).toEqual([
      'inspect',
      'build',
      'inspect',
      'entry',
      'identity',
      'recheck-entry',
      'execute',
      'cleanup',
    ]);
  });

  it('accepts a socketless topology and omits the optional socket from the child environment', async () => {
    await expect(
      launchPhase2BasePreservation(['run'], socketlessEnvironment, {
        inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
        build: async () => 0,
        createEntry: async () => creationReceipt,
        identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
        recheckEntry: async () => basePreservationRuntimeEntryPath,
        execute: async (
          _entry: string,
          _args: readonly string[],
          childEnvironment: Readonly<Record<string, string>>
        ) => {
          expect(Object.hasOwn(childEnvironment, 'ASTER_PHASE1_ENGINE_SOCKET')).toBe(false);
          expect(Object.keys(childEnvironment).toSorted()).toEqual(
            [
              ...Object.keys(socketlessEnvironment),
              'ASTER_PHASE2_HARNESS_HEAD',
              'ASTER_PHASE2_HARNESS_TREE',
              'ASTER_PHASE2_RUNTIME_BUNDLE_SHA256',
              'LC_ALL',
            ].toSorted()
          );
          return 0;
        },
        cleanupEntry: async () => 0,
      } as never)
    ).resolves.toBe(0);
  });

  it('rejects missing, extra, controlled, or oversized environment and arguments before build', async () => {
    const build = import.meta.jest.fn();
    const dependencies = {
      inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
      build,
      createEntry: async () => creationReceipt,
      identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
      recheckEntry: async () => basePreservationRuntimeEntryPath,
      execute: async () => 0,
      cleanupEntry: async () => 0,
    } as never;
    const invalidEnvironments = [
      Object.fromEntries(Object.entries(environment).slice(1)),
      { ...environment, EXTRA: 'value' },
      { ...environment, [basePreservationEnvironmentKeys[0]!]: 'line\nbreak' },
      { ...environment, [basePreservationEnvironmentKeys[0]!]: 'x'.repeat(4097) },
    ];

    for (const invalid of invalidEnvironments) {
      await expect(launchPhase2BasePreservation(['run'], invalid, dependencies)).rejects.toThrow(
        'Invalid Phase 2 base-preservation launcher'
      );
    }
    await expect(launchPhase2BasePreservation([], environment, dependencies)).rejects.toThrow(
      'Invalid Phase 2 base-preservation launcher'
    );
    expect(build).not.toHaveBeenCalled();
  });

  it.each(basePreservationBrowserEnvironmentKeys)(
    'fails closed for every invalid %s browser runtime value',
    async (key) => {
      const build = import.meta.jest.fn();
      const dependencies = {
        inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
        build,
        createEntry: async () => creationReceipt,
        identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
        recheckEntry: async () => basePreservationRuntimeEntryPath,
        execute: async () => 0,
        cleanupEntry: async () => 0,
      } as never;
      const invalidValues = [
        Object.fromEntries(Object.entries(environment).filter(([name]) => name !== key)),
        { ...environment, [key]: '' },
        { ...environment, [key]: 'line\nbreak' },
        { ...environment, [key]: 'x'.repeat(4097) },
      ];

      for (const invalid of invalidValues) {
        await expect(launchPhase2BasePreservation(['run'], invalid, dependencies)).rejects.toThrow(
          'Invalid Phase 2 base-preservation launcher'
        );
      }
      expect(build).not.toHaveBeenCalled();
    }
  );

  it.each(['', 'line\nbreak', 'x'.repeat(4097)])(
    'rejects a malformed optional engine socket value',
    async (socket) => {
      const build = import.meta.jest.fn();
      await expect(
        launchPhase2BasePreservation(
          ['run'],
          { ...environment, ASTER_PHASE1_ENGINE_SOCKET: socket },
          {
            inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
            build,
            createEntry: async () => creationReceipt,
            identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
            recheckEntry: async () => basePreservationRuntimeEntryPath,
            execute: async () => 0,
            cleanupEntry: async () => 0,
          } as never
        )
      ).rejects.toThrow('Invalid Phase 2 base-preservation launcher');
      expect(build).not.toHaveBeenCalled();
    }
  );

  it('creates the exact shallow read-only bridge and gives both shared identity helpers the same graph', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-identity');
    const nestedEntry = path.join(
      fixture.root,
      'lib/compatibility/phase-2/base-preservation/cli.js'
    );
    await expect(computeRuntimeBundleManifest(nestedEntry)).rejects.toThrow(
      'Invalid Phase 2 launcher'
    );
    await expect(computePhase2RuntimeBundleIdentity(nestedEntry)).rejects.toThrow(
      'Invalid Phase 2 provenance'
    );

    try {
      const creation = await createBasePreservationBridgeEntry(fixture.root);
      expect(creation.path).toBe(fixture.bridge);
      const [bytes, state, launcher, provenance] = await Promise.all([
        readFile(fixture.bridge, 'utf8'),
        stat(fixture.bridge),
        computeRuntimeBundleManifest(fixture.bridge),
        computePhase2RuntimeBundleIdentity(fixture.bridge),
      ]);

      expect(bytes).toBe(basePreservationBridgeSource);
      expect(state.mode % 0o1000).toBe(0o400);
      expect(state.nlink).toBe(1);
      expect(launcher.sha256).toBe(provenance.sha256);
      expect(launcher.moduleCount).toBe(provenance.moduleCount);
      expect(launcher.moduleCount).toBeGreaterThan(1);
    } finally {
      await removeBridgeFixture(fixture);
    }
  });

  it('never touches or removes a preexisting bridge outside its private fixture root', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-isolated');
    const unrelated = await createBridgeFixture('phase2-base-bridge-unrelated');
    const sentinel = 'unrelated-production-bridge-sentinel\n';
    await writeFile(unrelated.bridge, sentinel, { mode: 0o400 });
    const before = await lstat(unrelated.bridge);

    try {
      await createBasePreservationBridgeEntry(fixture.root);
      await removeBridgeFixture(fixture);
      const [bytes, after] = await Promise.all([
        readFile(unrelated.bridge, 'utf8'),
        lstat(unrelated.bridge),
      ]);
      expect(bytes).toBe(sentinel);
      expect(after.dev).toBe(before.dev);
      expect(after.ino).toBe(before.ino);
      expect(after.mode).toBe(before.mode);
      expect(after.size).toBe(before.size);
    } finally {
      if (
        await lstat(fixture.root)
          .then(() => true)
          .catch(() => false)
      ) {
        await removeBridgeFixture(fixture);
      }
      await removeBridgeFixture(unrelated);
    }
  });

  it('fails closed when bridge creation finds a preexisting or aliased path', async () => {
    const preexisting = await createBridgeFixture('phase2-base-bridge-existing');
    const aliased = await createBridgeFixture('phase2-base-bridge-alias');

    try {
      await writeFile(preexisting.bridge, basePreservationBridgeSource, { mode: 0o400 });
      await symlink(
        path.join(aliased.root, 'lib/compatibility/phase-2/base-preservation/cli.js'),
        aliased.bridge
      );
      await expect(createBasePreservationBridgeEntry(preexisting.root)).rejects.toThrow(
        'Invalid Phase 2 base-preservation launcher'
      );
      await expect(createBasePreservationBridgeEntry(aliased.root)).rejects.toThrow(
        'Invalid Phase 2 base-preservation launcher'
      );
    } finally {
      await removeBridgeFixture(preexisting);
      await removeBridgeFixture(aliased);
    }
  });

  it('removes its just-created bridge when a post-open creation step fails', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-create-failure');
    const injectedFailure = new Error('post-open');

    try {
      await expect(
        createBasePreservationBridgeEntry(fixture.root, {
          afterOpen: async () => {
            throw injectedFailure;
          },
        } as never)
      ).rejects.toBe(injectedFailure);
      await expect(lstat(fixture.bridge)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await removeBridgeFixture(fixture);
    }
  });

  it('retries a transient initial fstat, closes the descriptor, and removes its bridge', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-fstat-retry');
    const injectedFailure = new Error('initial fstat');
    const handles: FileHandle[] = [];
    const stat = import.meta.jest.fn(async (handle: FileHandle) => {
      handles.push(handle);
      if (stat.mock.calls.length === 1) {
        throw injectedFailure;
      }
      return handle.stat();
    });

    try {
      await expect(
        createBasePreservationBridgeEntry(fixture.root, {
          stat,
        } as never)
      ).rejects.toBe(injectedFailure);
      expect(stat).toHaveBeenCalledTimes(2);
      await expect(handles[0]!.stat()).rejects.toMatchObject({ code: 'EBADF' });
      await expect(lstat(fixture.bridge)).rejects.toMatchObject({ code: 'ENOENT' });
    } finally {
      await removeBridgeFixture(fixture);
    }
  });

  it('preserves a replacement installed before recovery from initial fstat failure', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-fstat-replaced');
    const injectedFailure = new Error('initial fstat replacement');
    const replacement = 'fstat-replacement-sentinel\n';
    const stat = import.meta.jest.fn(async (handle: FileHandle) => {
      if (stat.mock.calls.length === 1) {
        await unlink(fixture.bridge);
        await writeFile(fixture.bridge, replacement, { mode: 0o400 });
        throw injectedFailure;
      }
      return handle.stat();
    });

    try {
      await expect(
        createBasePreservationBridgeEntry(fixture.root, {
          stat,
        } as never)
      ).rejects.toBe(injectedFailure);
      expect(stat).toHaveBeenCalledTimes(2);
      await expect(readFile(fixture.bridge, 'utf8')).resolves.toBe(replacement);
    } finally {
      await removeBridgeFixture(fixture);
    }
  });

  it('closes the descriptor and preserves the path when created inode identity is unavailable', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-fstat-unavailable');
    const injectedFailure = new Error('fstat unavailable');
    const handles: FileHandle[] = [];
    const stat = import.meta.jest.fn(async (handle: FileHandle) => {
      handles.push(handle);
      throw injectedFailure;
    });

    try {
      await expect(
        createBasePreservationBridgeEntry(fixture.root, {
          stat,
        } as never)
      ).rejects.toBe(injectedFailure);
      expect(stat).toHaveBeenCalledTimes(2);
      await expect(handles[0]!.stat()).rejects.toMatchObject({ code: 'EBADF' });
      await expect(readFile(fixture.bridge, 'utf8')).resolves.toBe('');
    } finally {
      await removeBridgeFixture(fixture);
    }
  });

  it('preserves a replacement installed during failed bridge creation', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-create-replaced');
    const injectedFailure = new Error('post-open replacement');
    const replacement = 'creation-replacement-sentinel\n';

    try {
      await expect(
        createBasePreservationBridgeEntry(fixture.root, {
          afterOpen: async () => {
            await unlink(fixture.bridge);
            await writeFile(fixture.bridge, replacement, { mode: 0o400 });
            throw injectedFailure;
          },
        } as never)
      ).rejects.toBe(injectedFailure);
      await expect(readFile(fixture.bridge, 'utf8')).resolves.toBe(replacement);
    } finally {
      await removeBridgeFixture(fixture);
    }
  });

  it('cleans up after identity and execution failures once bridge creation succeeds', async () => {
    const cleanupEntry = import.meta.jest.fn(async () => 0);
    const creation = creationReceipt;
    const dependencies = {
      inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
      build: async () => 0,
      createEntry: async () => creation,
      identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
      recheckEntry: async () => basePreservationRuntimeEntryPath,
      execute: async () => 0,
      cleanupEntry,
    };

    await expect(
      launchPhase2BasePreservation(['run'], environment, {
        ...dependencies,
        identity: async () => {
          throw new Error('identity');
        },
      } as never)
    ).rejects.toThrow('identity');
    await expect(
      launchPhase2BasePreservation(['run'], environment, {
        ...dependencies,
        execute: async () => {
          throw new Error('execute');
        },
      } as never)
    ).rejects.toThrow('execute');
    expect(cleanupEntry).toHaveBeenNthCalledWith(1, creation);
    expect(cleanupEntry).toHaveBeenNthCalledWith(2, creation);
  });

  it('preserves a bridge path replaced after creation', async () => {
    const fixture = await createBridgeFixture('phase2-base-bridge-replaced');
    const replacement = 'replacement-sentinel\n';

    try {
      const creation = await createBasePreservationBridgeEntry(fixture.root);
      await unlink(fixture.bridge);
      await writeFile(fixture.bridge, replacement, { mode: 0o400 });

      await expect(cleanupBasePreservationBridgeEntry(creation)).rejects.toThrow(
        'Invalid Phase 2 base-preservation launcher'
      );
      await expect(readFile(fixture.bridge, 'utf8')).resolves.toBe(replacement);
    } finally {
      await removeBridgeFixture(fixture);
    }
  });

  it('propagates cleanup failure after successful execution', async () => {
    const cleanupFailure = new Error('cleanup');
    await expect(
      launchPhase2BasePreservation(['run'], environment, {
        inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
        build: async () => 0,
        createEntry: async () => creationReceipt,
        identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
        recheckEntry: async () => basePreservationRuntimeEntryPath,
        execute: async () => 0,
        cleanupEntry: async () => {
          throw cleanupFailure;
        },
      } as never)
    ).rejects.toBe(cleanupFailure);
  });

  it('does not create or accept an entry after build failure or from an unrelated path', async () => {
    const createEntry = import.meta.jest.fn(async () => creationReceipt);
    const identity = import.meta.jest.fn(async () => Object.freeze({ sha256: '1'.repeat(64) }));
    const baseDependencies = {
      inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
      createEntry,
      identity,
      recheckEntry: async () => basePreservationRuntimeEntryPath,
      execute: async () => 0,
      cleanupEntry: async () => 0,
    };

    await expect(
      launchPhase2BasePreservation(['run'], environment, {
        ...baseDependencies,
        build: async () => {
          throw new Error('build');
        },
      } as never)
    ).rejects.toThrow('build');
    expect(createEntry).not.toHaveBeenCalled();

    await expect(
      launchPhase2BasePreservation(['run'], environment, {
        ...baseDependencies,
        build: async () => 0,
        createEntry: async () =>
          Object.freeze({
            path: '/repo/packages/integration-tests/lib/compatibility/phase-2/base-preservation/cli.js',
          }),
      } as never)
    ).rejects.toThrow('Invalid Phase 2 base-preservation launcher');
    expect(identity).not.toHaveBeenCalled();
  });
});

/* eslint-enable max-lines, max-params, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-argument */
