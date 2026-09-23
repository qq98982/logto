/* eslint-disable max-params, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-argument -- The launcher test records five-part dependency calls, verifies sorted environment keys, and iterates hostile environment cases. */
import { basePreservationEnvironmentKeys, launchPhase2BasePreservation } from './launcher.mjs';

const environment = Object.freeze(
  Object.fromEntries(basePreservationEnvironmentKeys.map((key) => [key, `${key}-value`]))
);

describe('Phase 2 base-preservation launcher', () => {
  it('builds one clean verified entry and forwards only the closed topology environment', async () => {
    const calls: string[] = [];
    const manifest = Object.freeze({
      sha256: '1'.repeat(64),
      moduleCount: 1,
      entryUrl:
        'file:///repo/packages/integration-tests/lib/compatibility/phase-2/base-preservation/cli.js',
      libraryRootUrl: 'file:///repo/packages/integration-tests/lib/',
      modules: Object.freeze({
        'file:///repo/packages/integration-tests/lib/compatibility/phase-2/base-preservation/cli.js':
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
        identity: async () => {
          calls.push('identity');
          return manifest;
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
    expect(calls).toEqual(['inspect', 'build', 'inspect', 'identity', 'execute']);
  });

  it('rejects missing, extra, controlled, or oversized environment and arguments before build', async () => {
    const build = import.meta.jest.fn();
    const dependencies = {
      inspect: async () => Object.freeze({ head: '3'.repeat(40), tree: '4'.repeat(40) }),
      build,
      identity: async () => Object.freeze({ sha256: '1'.repeat(64) }),
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
});

/* eslint-enable max-params, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-argument */
