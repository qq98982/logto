/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The test owns an isolated Git repository and installs one global capability to prove clean-source and hook fencing. */
import { execFile } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  computePhase2RuntimeBundleIdentity,
  inspectCleanPhase2HarnessSource,
  inspectLaunchedPhase2HarnessSource,
  recheckCleanPhase2HarnessSource,
} from './provenance.js';

const run = promisify(execFile);
const capabilitySymbol = Symbol.for('aster.phase2.runtime-capability');
let root = '';
let runtimeEntry = '';
const installCapability = (capability: string): void => {
  Object.defineProperty(globalThis, capabilitySymbol, {
    configurable: true,
    enumerable: false,
    value: capability,
    writable: false,
  });
};
beforeEach(async () => {
  root = await mkdtemp('/var/tmp/henry-build/phase2-provenance-');
  await chmod(root, 0o700);
  await run('git', ['init'], { cwd: root });
  await run('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root });
  await run('git', ['config', 'user.name', 'test'], { cwd: root });
  await run('git', ['remote', 'add', 'origin', 'git@github.com:qq98982/logto.git'], { cwd: root });
  await writeFile(path.join(root, 'sentinel'), 'ok');
  await writeFile(path.join(root, '.gitignore'), 'packages/integration-tests/lib/\n');
  await run('git', ['add', 'sentinel', '.gitignore'], { cwd: root });
  await run('git', ['commit', '-m', 'fixture'], { cwd: root });
  const runtimeRoot = path.join(root, 'packages/integration-tests/lib/compatibility/phase-2');
  await mkdir(runtimeRoot, { recursive: true, mode: 0o700 });
  runtimeEntry = path.join(runtimeRoot, 'cli.js');
  await writeFile(runtimeEntry, 'import "../../chunk-runtime.js";\nexport const ok = true;\n');
  await writeFile(
    path.join(root, 'packages/integration-tests/lib/chunk-runtime.js'),
    'export const runtime = true;\n'
  );
});
afterEach(async () => rm(root, { force: true, recursive: true }));
it('mints and rechecks only canonical clean H source', async () => {
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  const capability = await inspectCleanPhase2HarnessSource(root, runtimeEntry, runtime.sha256);
  expect(capability.public.repositoryUrl).toBe('https://github.com/qq98982/logto.git');
  await expect(recheckCleanPhase2HarnessSource(capability)).resolves.toBeUndefined();
  await writeFile(path.join(root, 'dirty'), 'x');
  await expect(recheckCleanPhase2HarnessSource(capability)).rejects.toThrow(
    'Invalid Phase 2 provenance'
  );
});
it('rejects a substituted origin', async () => {
  await run('git', ['remote', 'set-url', 'origin', 'https://example.invalid/fake.git'], {
    cwd: root,
  });
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  await expect(inspectCleanPhase2HarnessSource(root, runtimeEntry, runtime.sha256)).rejects.toThrow(
    'Invalid Phase 2 provenance'
  );
});

it('rejects stale or replaced runtime closure bytes and launcher head substitution', async () => {
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  const { stdout: headOutput } = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
  const { stdout: treeOutput } = await run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root });
  const capability = 'a'.repeat(64);
  const environment = {
    ASTER_PHASE2_HARNESS_HEAD: headOutput.trim(),
    ASTER_PHASE2_HARNESS_TREE: treeOutput.trim(),
    ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: runtime.sha256,
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
  };
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).resolves.toMatchObject({ public: { runtimeBundleSha256: runtime.sha256 } });
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).rejects.toThrow('Invalid Phase 2 provenance');

  await writeFile(
    path.join(root, 'packages/integration-tests/lib/chunk-runtime.js'),
    'export const runtime = false;\n'
  );
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).rejects.toThrow('Invalid Phase 2 provenance');
  await writeFile(
    path.join(root, 'packages/integration-tests/lib/chunk-runtime.js'),
    'export const runtime = true;\n'
  );
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, {
      ...environment,
      ASTER_PHASE2_HARNESS_HEAD: 'f'.repeat(40),
    })
  ).rejects.toThrow('Invalid Phase 2 provenance');
});

it('rejects a launched environment when the verified entry capability is absent', async () => {
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  const { stdout: headOutput } = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
  const { stdout: treeOutput } = await run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root });
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, 'b'.repeat(64), {
      ASTER_PHASE2_HARNESS_HEAD: headOutput.trim(),
      ASTER_PHASE2_HARNESS_TREE: treeOutput.trim(),
      ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: runtime.sha256,
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    })
  ).rejects.toThrow('Invalid Phase 2 provenance');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
