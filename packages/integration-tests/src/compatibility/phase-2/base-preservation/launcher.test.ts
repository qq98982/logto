/* eslint-disable max-params, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-argument -- The launcher test records five-part dependency calls, verifies sorted environment keys, and iterates hostile environment cases. */
import { lstat, mkdtemp, mkdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { computeRuntimeBundleManifest } from '../launcher.mjs';
import { computePhase2RuntimeBundleIdentity } from '../provenance.js';

import { phase2BasePreservationRuntimeEntryPath } from './cli.js';
import {
  basePreservationBridgeSource,
  basePreservationRuntimeEntryPath,
  basePreservationEnvironmentKeys,
  createBasePreservationBridgeEntry,
  launchPhase2BasePreservation,
} from './launcher.mjs';

const environment = Object.freeze(
  Object.fromEntries(basePreservationEnvironmentKeys.map((key) => [key, `${key}-value`]))
);

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
  it('uses the same fixed shallow entry in the launcher and nested CLI provenance', () => {
    expect(phase2BasePreservationRuntimeEntryPath).toBe(basePreservationRuntimeEntryPath);
  });

  it('builds one clean verified entry and forwards only the closed topology environment', async () => {
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
          return basePreservationRuntimeEntryPath;
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
          return 0;
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
    ]);
  });

  it('rejects missing, extra, controlled, or oversized environment and arguments before build', async () => {
    const build = import.meta.jest.fn();
    const dependencies = {
      inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
      build,
      createEntry: async () => basePreservationRuntimeEntryPath,
      identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
      recheckEntry: async () => basePreservationRuntimeEntryPath,
      execute: async () => 0,
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
      await expect(createBasePreservationBridgeEntry(fixture.root)).resolves.toBe(fixture.bridge);
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

  it('does not create or accept an entry after build failure or from an unrelated path', async () => {
    const createEntry = import.meta.jest.fn(async () => basePreservationRuntimeEntryPath);
    const identity = import.meta.jest.fn(async () => Object.freeze({ sha256: '1'.repeat(64) }));
    const baseDependencies = {
      inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
      createEntry,
      identity,
      recheckEntry: async () => basePreservationRuntimeEntryPath,
      execute: async () => 0,
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
          '/repo/packages/integration-tests/lib/compatibility/phase-2/base-preservation/cli.js',
      } as never)
    ).rejects.toThrow('Invalid Phase 2 base-preservation launcher');
    expect(identity).not.toHaveBeenCalled();
  });
});

/* eslint-enable max-params, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-argument */
