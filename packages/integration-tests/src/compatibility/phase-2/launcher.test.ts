/* eslint-disable max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The tracked JavaScript launcher is intentionally exercised through its native ESM exports, five-part execution dependency, and mutable call-order controls. */
import { execFile } from 'node:child_process';
import { lstat, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  computeRuntimeBundleIdentity,
  computeRuntimeBundleManifest,
  createRuntimeBootstrap,
  createRuntimeHookImport,
  executeVerifiedPhase2Entry,
  launchPhase2,
} from './launcher.mjs';
import { computePhase2RuntimeBundleIdentity } from './provenance.js';

const executeFile = promisify(execFile);

describe('Phase 2 tracked launcher', () => {
  it('matches the runtime closure algorithm used inside the built CLI', async () => {
    const entry = path.resolve('lib/compatibility/phase-2/cli.js');
    await expect(computeRuntimeBundleIdentity(entry)).resolves.toEqual(
      await computePhase2RuntimeBundleIdentity(entry)
    );
  });

  it('builds only between equal clean HEAD checks and passes a closed expected identity', async () => {
    const calls: string[] = [];
    const head = '1'.repeat(40);
    const tree = '2'.repeat(40);
    const digest = '3'.repeat(64);
    const manifest = {
      sha256: digest,
      moduleCount: 1,
      entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
      libraryRootUrl: 'file:///private/lib/',
      modules: { 'file:///private/lib/compatibility/phase-2/cli.js': digest },
    };
    await expect(
      launchPhase2(['oracle'], {
        inspect: async () => {
          calls.push('inspect');
          return { head, tree };
        },
        build: async () => {
          calls.push('build');
        },
        identity: async () => {
          calls.push('identity');
          return manifest;
        },
        execute: async (
          _entry: string,
          args: readonly string[],
          environment: Record<string, string>,
          receivedManifest: typeof manifest,
          capability: string
        ) => {
          calls.push('execute');
          expect(args).toEqual(['oracle']);
          expect(capability).toMatch(/^[0-9a-f]{64}$/u);
          expect(receivedManifest).toBe(manifest);
          expect(environment).toEqual({
            ASTER_PHASE2_HARNESS_HEAD: head,
            ASTER_PHASE2_HARNESS_TREE: tree,
            ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: digest,
            LC_ALL: 'C',
            PATH: '/usr/bin:/bin',
          });
          return 0;
        },
      })
    ).resolves.toBe(0);
    expect(calls).toEqual(['inspect', 'build', 'inspect', 'identity', 'execute']);
  });

  it('rejects a HEAD substitution across the clean rebuild boundary', async () => {
    let inspection = 0;
    let executions = 0;
    const execute = async () => {
      executions += 1;
      return 0 as const;
    };
    await expect(
      launchPhase2([], {
        inspect: async () => {
          inspection += 1;
          return {
            head: (inspection === 1 ? '1' : '2').repeat(40),
            tree: '3'.repeat(40),
          };
        },
        build: async () => {
          // The injected build boundary is intentionally successful.
        },
        identity: async () => ({
          sha256: '4'.repeat(64),
          moduleCount: 1,
          entryUrl: 'file:///private/lib/compatibility/phase-2/cli.js',
          libraryRootUrl: 'file:///private/lib/',
          modules: {
            'file:///private/lib/compatibility/phase-2/cli.js': '4'.repeat(64),
          },
        }),
        execute,
      })
    ).rejects.toThrow('Invalid Phase 2 launcher');
    expect(executions).toBe(0);
  });

  it('rejects a malicious loaded module before it can restore itself or execute side effects', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/phase2-load-hook-');
    const libraryRoot = path.join(root, 'lib');
    const entryDirectory = path.join(libraryRoot, 'compatibility/phase-2');
    const entry = path.join(entryDirectory, 'entry.js');
    const modulePath = path.join(libraryRoot, 'runtime-module.js');
    const sideEffect = path.join(root, 'malicious-side-effect');
    const originalModule = 'export const value = "safe";\n';
    const capability = '5'.repeat(64);
    try {
      await mkdir(entryDirectory, { recursive: true, mode: 0o700 });
      await writeFile(path.join(root, 'package.json'), '{"type":"module"}\n');
      await writeFile(modulePath, originalModule);
      await writeFile(
        entry,
        `import { value } from "../../runtime-module.js";\nexport const runPhase2CliMain = async (args, receivedCapability) => {\n  if (globalThis[Symbol.for('aster.phase2.runtime-capability')] !== receivedCapability) throw new Error('missing runtime capability');\n  process.stdout.write(JSON.stringify(args) + ':' + value);\n  return 0;\n};\n`
      );
      const manifest = await computeRuntimeBundleManifest(entry);
      const registerImport = createRuntimeHookImport(manifest, capability);
      const bootstrap = createRuntimeBootstrap(manifest.entryUrl, capability);
      await expect(
        executeFile(
          process.execPath,
          [
            '--import',
            registerImport,
            '--input-type=module',
            '--eval',
            `await import(${JSON.stringify(bootstrap)})`,
            '--',
            'oracle',
            '--profile',
            '/private/profile.json',
          ],
          {
            env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 5000,
          }
        )
      ).resolves.toMatchObject({
        stdout: '["oracle","--profile","/private/profile.json"]:safe',
      });

      const maliciousModule = `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(
        sideEffect
      )}, 'executed');\nwriteFileSync(${JSON.stringify(modulePath)}, ${JSON.stringify(
        originalModule
      )});\nexport const value = 'evil';\n`;
      await writeFile(modulePath, maliciousModule);
      await expect(
        executeFile(
          process.execPath,
          [
            '--import',
            registerImport,
            '--input-type=module',
            '--eval',
            `await import(${JSON.stringify(bootstrap)})`,
            '--',
            'oracle',
            '--profile',
            '/private/profile.json',
          ],
          {
            env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
            timeout: 5000,
          }
        )
      ).rejects.toBeDefined();
      await expect(lstat(sideEffect)).rejects.toMatchObject({ code: 'ENOENT' });
      await expect(readFile(modulePath, 'utf8')).resolves.toBe(maliciousModule);
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it('executes the compiled re-export entry through the trusted bootstrap and rejects direct node execution', async () => {
    const entry = path.resolve('lib/compatibility/phase-2/cli.js');
    const manifest = await computeRuntimeBundleManifest(entry);
    const result: unknown = await executeVerifiedPhase2Entry(
      entry,
      [],
      { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      manifest,
      '6'.repeat(64)
    );
    expect(result).toMatchObject({
      code: 1,
      signal: null,
      stderr: 'Invalid Phase 2 arguments.\n',
      stdout: '',
      timedOut: false,
    });

    const direct = await executeFile(process.execPath, [entry], {
      env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      timeout: 5000,
    }).catch((error: unknown) => error as { stderr?: string });
    expect(direct).toMatchObject({ stderr: 'Invalid Phase 2 arguments.\n' });
  });
});

/* eslint-enable max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
