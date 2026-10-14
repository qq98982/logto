/* eslint-disable max-lines, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The test owns an isolated Git repository and installs one global capability to prove clean-source and hook fencing. */
import { execFile } from 'node:child_process';
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import { projectPhase2BasePreservationHarnessEnvironment } from './base-preservation/cli.js';
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
let browserBuildRoot = '';
let browserCache = '';
let browserRunDirectory = '';
let browserHome = '';
let browserTemporary = '';
let xdgRuntime = '';
const installCapability = (capability: string): void => {
  Object.defineProperty(globalThis, capabilitySymbol, {
    configurable: true,
    enumerable: false,
    value: capability,
    writable: false,
  });
};
const launcherEnvironment = (
  head: string,
  tree: string,
  runtimeBundleSha256: string
): Readonly<Record<string, string | undefined>> =>
  projectPhase2BasePreservationHarnessEnvironment({
    ASTER_PHASE2_HARNESS_HEAD: head,
    ASTER_PHASE2_HARNESS_TREE: tree,
    ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: runtimeBundleSha256,
    ASTER_PHASE2_UNEXPECTED: 'dropped-by-base-projection',
    HOME: browserHome,
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
    PLAYWRIGHT_BROWSERS_PATH: browserCache,
    TMPDIR: browserTemporary,
    XDG_RUNTIME_DIR: xdgRuntime,
  });
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
  browserBuildRoot = path.join(root, 'packages/integration-tests/lib/browser-build');
  browserCache = path.join(browserBuildRoot, 'aster-playwright-browsers');
  browserRunDirectory = path.join(browserBuildRoot, 'runtime/run.test');
  browserHome = path.join(browserRunDirectory, 'home');
  browserTemporary = path.join(browserRunDirectory, 'browser-tmp');
  xdgRuntime = path.join(browserRunDirectory, 'xdg-runtime');
  await Promise.all(
    [browserCache, browserHome, browserTemporary, xdgRuntime].map(async (directory) => {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      await chmod(directory, 0o700);
    })
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
  const environment = launcherEnvironment(headOutput.trim(), treeOutput.trim(), runtime.sha256);
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
    inspectLaunchedPhase2HarnessSource(
      root,
      runtimeEntry,
      'b'.repeat(64),
      launcherEnvironment(headOutput.trim(), treeOutput.trim(), runtime.sha256)
    )
  ).rejects.toThrow('Invalid Phase 2 provenance');
});

it('admits the exact base-preservation browser environment projected to the launched child', async () => {
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  const { stdout: headOutput } = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
  const { stdout: treeOutput } = await run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root });
  const capability = 'd'.repeat(64);
  const environment = launcherEnvironment(headOutput.trim(), treeOutput.trim(), runtime.sha256);
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).resolves.toMatchObject({ public: { runtimeBundleSha256: runtime.sha256 } });

  await chmod(browserHome, 0o755);
  try {
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
    ).rejects.toThrow('Invalid Phase 2 provenance');
  } finally {
    await chmod(browserHome, 0o700);
  }

  const missingBrowserKeys = ['HOME', 'PLAYWRIGHT_BROWSERS_PATH', 'TMPDIR', 'XDG_RUNTIME_DIR'].map(
    (missing) => Object.fromEntries(Object.entries(environment).filter(([key]) => key !== missing))
  );
  const linkedRunDirectory = path.join(browserBuildRoot, 'runtime/linked-run');
  const linkedHome = path.join(linkedRunDirectory, 'home');
  const linkedTemporary = path.join(linkedRunDirectory, 'browser-tmp');
  const linkedXdg = path.join(linkedRunDirectory, 'xdg-runtime');
  await mkdir(linkedRunDirectory, { recursive: true, mode: 0o700 });
  await Promise.all(
    [linkedTemporary, linkedXdg].map(async (directory) => {
      await mkdir(directory, { mode: 0o700 });
      await chmod(directory, 0o700);
    })
  );
  await symlink(browserHome, linkedHome, 'dir');
  const wrongBuildRoot = path.join(root, 'packages/integration-tests/lib/wrong-browser-build');
  const wrongRunDirectory = path.join(wrongBuildRoot, 'runtime/run.test');
  const wrongHome = path.join(wrongRunDirectory, 'home');
  const wrongTemporary = path.join(wrongRunDirectory, 'browser-tmp');
  const wrongXdg = path.join(wrongRunDirectory, 'xdg-runtime');
  await Promise.all(
    [wrongHome, wrongTemporary, wrongXdg].map(async (directory) => {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      await chmod(directory, 0o700);
    })
  );
  const invalidEnvironments = [
    ...missingBrowserKeys,
    { ...environment, ASTER_PHASE2_UNEXPECTED: 'present' },
    { ...environment, HOME: 'home' },
    {
      ...environment,
      HOME: linkedHome,
      TMPDIR: linkedTemporary,
      XDG_RUNTIME_DIR: linkedXdg,
    },
    {
      ...environment,
      HOME: wrongHome,
      TMPDIR: wrongTemporary,
      XDG_RUNTIME_DIR: wrongXdg,
    },
  ];
  await invalidEnvironments.reduce(async (previous, invalidEnvironment) => {
    await previous;
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, invalidEnvironment)
    ).rejects.toThrow('Invalid Phase 2 provenance');
  }, Promise.resolve());
});

it('accepts only the canonical optional oracle SMTP socket launcher environment', async () => {
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  const { stdout: headOutput } = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
  const { stdout: treeOutput } = await run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root });
  const capability = 'c'.repeat(64);
  const environment = {
    ...launcherEnvironment(headOutput.trim(), treeOutput.trim(), runtime.sha256),
    ASTER_PHASE2_ORACLE_SMTP_SOCKET: '/var/tmp/henry-build/phase2-fixture/oracle-smtp.sock',
  };
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).resolves.toMatchObject({ public: { runtimeBundleSha256: runtime.sha256 } });

  const invalidEnvironments = [
    { ...environment, ASTER_PHASE2_ORACLE_SMTP_SOCKET: 'oracle-smtp.sock' },
    {
      ...environment,
      ASTER_PHASE2_ORACLE_SMTP_SOCKET: '/var/tmp/henry-build/phase2-fixture/../oracle-smtp.sock',
    },
    {
      ...environment,
      ASTER_PHASE2_ORACLE_SMTP_SOCKET:
        '/var/tmp/henry-build/phase2-fixture/candidate-verification-smtp.sock',
    },
    { ...environment, ASTER_PHASE2_UNEXPECTED: 'present' },
  ];
  await invalidEnvironments.reduce(async (previous, invalidEnvironment) => {
    await previous;
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, invalidEnvironment)
    ).rejects.toThrow('Invalid Phase 2 provenance');
  }, Promise.resolve());
});
it.each(['google', 'wechat', 'sms'] as const)(
  'admits only paired owned %s provider paths alongside the exact launcher environment',
  async (provider) => {
    const oracleKey = `ASTER_PHASE2_ORACLE_${provider.toUpperCase()}_PROVIDER_INPUT`;
    const candidateKey = `ASTER_PHASE2_CANDIDATE_${provider.toUpperCase()}_PROVIDER_INPUT`;
    const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
    const { stdout: headOutput } = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
    const { stdout: treeOutput } = await run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root });
    const capability = 'd'.repeat(64);
    const oraclePath = path.join(
      browserRunDirectory,
      provider === 'sms' ? 's/o/input.json' : `${provider}-provider/oracle/provider-input.json`
    );
    const candidatePath = path.join(
      browserRunDirectory,
      provider === 'sms' ? 's/c/input.json' : `${provider}-provider/candidate/provider-input.json`
    );
    await Promise.all(
      [oraclePath, candidatePath].map(async (filePath) => {
        await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
        await writeFile(filePath, '{}', { mode: 0o600 });
      })
    );
    const environment = {
      ...launcherEnvironment(headOutput.trim(), treeOutput.trim(), runtime.sha256),
      [oracleKey]: oraclePath,
      [candidateKey]: candidatePath,
    };
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
    ).resolves.toMatchObject({ public: { runtimeBundleSha256: runtime.sha256 } });
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, {
        ...environment,
        ASTER_PHASE2_ORACLE_SMTP_SOCKET: '/var/tmp/henry-build/phase2-fixture/oracle-smtp.sock',
      })
    ).resolves.toMatchObject({ public: { runtimeBundleSha256: runtime.sha256 } });
    const invalidEnvironments = [
      { ...environment, [oracleKey]: undefined },
      { ...environment, [candidateKey]: undefined },
      { ...environment, [oracleKey]: candidatePath },
      { ...environment, [candidateKey]: 'provider-input.json' },
      {
        ...environment,
        [oracleKey]: `${oraclePath}/../provider-input.json`,
      },
      { ...environment, ASTER_PHASE2_UNEXPECTED: 'present' },
    ];
    await invalidEnvironments.reduce(async (previous, invalidEnvironment) => {
      await previous;
      installCapability(capability);
      await expect(
        inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, invalidEnvironment)
      ).rejects.toThrow('Invalid Phase 2 provenance');
    }, Promise.resolve());
    await chmod(candidatePath, 0o644);
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
    ).rejects.toThrow('Invalid Phase 2 provenance');
    await chmod(candidatePath, 0o600);
    await rm(candidatePath);
    await symlink(oraclePath, candidatePath);
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
    ).rejects.toThrow('Invalid Phase 2 provenance');
  }
);

it('admits only paired private Common completion inputs without reading their payloads', async () => {
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  const { stdout: headOutput } = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
  const { stdout: treeOutput } = await run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root });
  const capability = 'e'.repeat(64);
  const oraclePath = path.join(browserRunDirectory, 'completion', 'oracle.json');
  const candidatePath = path.join(browserRunDirectory, 'completion', 'candidate.json');
  await mkdir(path.dirname(oraclePath), { recursive: true, mode: 0o700 });
  await Promise.all([
    writeFile(oraclePath, '{not-json', { mode: 0o600 }),
    writeFile(candidatePath, 'opaque', { mode: 0o600 }),
  ]);
  const environment = {
    ...launcherEnvironment(headOutput.trim(), treeOutput.trim(), runtime.sha256),
    ASTER_PHASE2_ORACLE_COMPLETION_INPUT: oraclePath,
    ASTER_PHASE2_CANDIDATE_COMPLETION_INPUT: candidatePath,
  };
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).resolves.toMatchObject({ public: { runtimeBundleSha256: runtime.sha256 } });

  const invalidEnvironments = [
    { ...environment, ASTER_PHASE2_ORACLE_COMPLETION_INPUT: undefined },
    { ...environment, ASTER_PHASE2_CANDIDATE_COMPLETION_INPUT: undefined },
    { ...environment, ASTER_PHASE2_ORACLE_COMPLETION_INPUT: 'oracle.json' },
    {
      ...environment,
      ASTER_PHASE2_ORACLE_COMPLETION_INPUT: `${path.dirname(oraclePath)}/../completion/oracle.json`,
    },
    { ...environment, ASTER_PHASE2_UNEXPECTED: 'present' },
  ];
  await invalidEnvironments.reduce(async (previous, invalidEnvironment) => {
    await previous;
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, invalidEnvironment)
    ).rejects.toThrow('Invalid Phase 2 provenance');
  }, Promise.resolve());

  await chmod(candidatePath, 0o640);
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).rejects.toThrow('Invalid Phase 2 provenance');
  await chmod(candidatePath, 0o600);

  const hardLink = path.join(browserRunDirectory, 'completion', 'candidate-linked.json');
  await link(candidatePath, hardLink);
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).rejects.toThrow('Invalid Phase 2 provenance');
  await rm(hardLink);

  await rm(candidatePath);
  await symlink(oraclePath, candidatePath);
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).rejects.toThrow('Invalid Phase 2 provenance');
});

it('admits only the canonical owned H5 CA file in the launched environment', async () => {
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntry);
  const { stdout: headOutput } = await run('git', ['rev-parse', 'HEAD'], { cwd: root });
  const { stdout: treeOutput } = await run('git', ['rev-parse', 'HEAD^{tree}'], { cwd: root });
  const capability = 'f'.repeat(64);
  const caFile = path.join(browserRunDirectory, 'common-completion/runtime-h5/h5-loopback-ca.pem');
  await mkdir(path.dirname(caFile), { recursive: true, mode: 0o700 });
  await writeFile(caFile, 'fixture-ca', { mode: 0o400 });
  const environment = {
    ...launcherEnvironment(headOutput.trim(), treeOutput.trim(), runtime.sha256),
    NODE_EXTRA_CA_CERTS: caFile,
  };
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).resolves.toMatchObject({ public: { runtimeBundleSha256: runtime.sha256 } });

  for (const invalidEnvironment of [
    { ...environment, NODE_EXTRA_CA_CERTS: path.join(browserRunDirectory, 'other-ca.pem') },
    { ...environment, NODE_EXTRA_CA_CERTS: `${path.dirname(caFile)}/../h5-loopback-ca.pem` },
  ]) {
    installCapability(capability);
    await expect(
      inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, invalidEnvironment)
    ).rejects.toThrow('Invalid Phase 2 provenance');
  }
  await chmod(caFile, 0o600);
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).rejects.toThrow('Invalid Phase 2 provenance');
  await chmod(caFile, 0o400);
  const linked = path.join(path.dirname(caFile), 'linked-ca.pem');
  await link(caFile, linked);
  installCapability(capability);
  await expect(
    inspectLaunchedPhase2HarnessSource(root, runtimeEntry, capability, environment)
  ).rejects.toThrow('Invalid Phase 2 provenance');
});
/* eslint-enable max-lines, no-await-in-loop */
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
