#!/usr/bin/env node
/* eslint-disable max-lines, complexity, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The launcher verifies filesystem mode bits and owns one source-bound runtime and bridge lifecycle. */
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath, unlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  computeRuntimeBundleManifest,
  executeVerifiedPhase2Entry,
  inspectCleanHead,
} from '../launcher.mjs';

const diagnostic = 'Phase 2 base-preservation launcher failed.\n';
const childFailurePattern =
  /^Phase 2 base-preservation failed \((arguments|paths|profile|harness|closure|phase1|runtime|harness-recheck|publish)\)\.\n$/u;
class BasePreservationChildFailure extends Error {}
export const diagnosticForBasePreservationChild = (result) =>
  result.timedOut === false &&
  result.code === 1 &&
  result.signal === null &&
  result.stdout === '' &&
  childFailurePattern.test(result.stderr)
    ? result.stderr
    : diagnostic;
const failure = 'Invalid Phase 2 base-preservation launcher';
export const basePreservationBridgeSource =
  "export { runPhase2CliMain } from './base-preservation/cli.js';\n";
const bridgeBytes = Buffer.from(basePreservationBridgeSource, 'utf8');
const defaultBridgeCreationHooks = Object.freeze({
  async afterOpen() {},
  stat: async (handle) => handle.stat(),
});

export const basePreservationBrowserEnvironmentKeys = Object.freeze([
  'HOME',
  'PLAYWRIGHT_BROWSERS_PATH',
  'TMPDIR',
  'XDG_RUNTIME_DIR',
]);

export const basePreservationOptionalEnvironmentKeys = Object.freeze([
  'ASTER_PHASE1_ENGINE_SOCKET',
]);

export const basePreservationEnvironmentKeys = Object.freeze([
  'PATH',
  ...basePreservationBrowserEnvironmentKeys,
  'ASTER_FIXTURE_SOCKET',
  'ASTER_PHASE1_BUILD_ROOT',
  'ASTER_PHASE1_CANDIDATE_ADMIN_COOKIE_KEY_SET_SHA256',
  'ASTER_PHASE1_CANDIDATE_ADMIN_SIGNING_KEY_SET_SHA256',
  'ASTER_PHASE1_CANDIDATE_ADMIN_URL',
  'ASTER_PHASE1_CANDIDATE_DATA_COOKIE_KEY_SET_SHA256',
  'ASTER_PHASE1_CANDIDATE_DATA_SIGNING_KEY_SET_SHA256',
  'ASTER_PHASE1_CANDIDATE_FOREIGN_COOKIE_KEY_SET_SHA256',
  'ASTER_PHASE1_CANDIDATE_FOREIGN_POSTGRES_CONTAINER_ID',
  'ASTER_PHASE1_CANDIDATE_FOREIGN_SIGNING_KEY_SET_SHA256',
  'ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL',
  'ASTER_PHASE1_CANDIDATE_FOREIGN_URL',
  'ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST',
  'ASTER_PHASE1_CANDIDATE_PRIMARY_POSTGRES_CONTAINER_ID',
  'ASTER_PHASE1_CANDIDATE_URL',
  'ASTER_PHASE1_CONFORMANCE_ROOT',
  'ASTER_PHASE1_ENGINE_SOCKET',
  'ASTER_PHASE1_EVIDENCE_DIR',
  'ASTER_PHASE1_MODE',
  'ASTER_PHASE1_ORACLE_ADMIN_COOKIE_KEY_SET_SHA256',
  'ASTER_PHASE1_ORACLE_ADMIN_SIGNING_KEY_SET_SHA256',
  'ASTER_PHASE1_ORACLE_ADMIN_URL',
  'ASTER_PHASE1_ORACLE_DATA_COOKIE_KEY_SET_SHA256',
  'ASTER_PHASE1_ORACLE_DATA_SIGNING_KEY_SET_SHA256',
  'ASTER_PHASE1_ORACLE_FOREIGN_COOKIE_KEY_SET_SHA256',
  'ASTER_PHASE1_ORACLE_FOREIGN_POSTGRES_CONTAINER_ID',
  'ASTER_PHASE1_ORACLE_FOREIGN_SIGNING_KEY_SET_SHA256',
  'ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL',
  'ASTER_PHASE1_ORACLE_FOREIGN_URL',
  'ASTER_PHASE1_ORACLE_IMAGE_DIGEST',
  'ASTER_PHASE1_ORACLE_PRIMARY_POSTGRES_CONTAINER_ID',
  'ASTER_PHASE1_ORACLE_SNAPSHOT_PATH',
  'ASTER_PHASE1_ORACLE_URL',
  'ASTER_PHASE1_PHASE0_CANDIDATE_IMAGE_DIGEST',
  'ASTER_PHASE1_PROCESS_TOKEN',
  'ASTER_PHASE1_TOPOLOGY_ID',
  'ASTER_PHASE2_CANDIDATE_SOURCE_COMMIT',
]);

export const basePreservationRequiredEnvironmentKeys = Object.freeze(
  basePreservationEnvironmentKeys.filter(
    (key) => !basePreservationOptionalEnvironmentKeys.includes(key)
  )
);

const fail = () => {
  throw new TypeError(failure);
};

const run = (command, args, options) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: options.stdio,
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 250).unref();
    }, options.timeoutMs);
    timer.unref();
    child.once('error', reject);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (timedOut || signal !== null || !Number.isSafeInteger(code)) {
        reject(new TypeError(failure));
        return;
      }
      resolve(code);
    });
  });

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../..');
const repositoryRoot = path.resolve(packageRoot, '../..');
export const basePreservationRuntimeEntryPath = path.join(
  packageRoot,
  'lib/compatibility/phase-2/base-preservation-entry.js'
);

const bridgePathFor = (root) =>
  path.join(root, 'lib/compatibility/phase-2/base-preservation-entry.js');
const nestedEntryPathFor = (root) =>
  path.join(root, 'lib/compatibility/phase-2/base-preservation/cli.js');

const currentUid = () => {
  const uid = process.getuid?.();
  return Number.isSafeInteger(uid) ? uid : fail();
};

const assertOwnedDirectory = async (directory) => {
  const state = await lstat(directory).catch(fail);
  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.uid !== currentUid() ||
    (state.mode & 0o002) !== 0 ||
    ((state.mode & 0o020) !== 0 && state.gid !== process.getgid?.()) ||
    (await realpath(directory).catch(fail)) !== directory
  ) {
    return fail();
  }
  return state;
};

const assertBuiltNestedEntry = async (root) => {
  const entry = nestedEntryPathFor(root);
  const state = await lstat(entry).catch(fail);
  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.uid !== currentUid() ||
    state.size <= 0 ||
    (await realpath(entry).catch(fail)) !== entry
  ) {
    return fail();
  }
};

const inspectBasePreservationBridgeEntry = async (root) => {
  if (!path.isAbsolute(root) || path.normalize(root) !== root) {
    return fail();
  }
  const bridge = bridgePathFor(root);
  const parent = path.dirname(bridge);
  const parentBefore = await assertOwnedDirectory(parent);
  await assertBuiltNestedEntry(root);
  const before = await lstat(bridge).catch(fail);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.uid !== currentUid() ||
    before.nlink !== 1 ||
    (before.mode & 0o777) !== 0o400 ||
    before.size !== bridgeBytes.byteLength ||
    (await realpath(bridge).catch(fail)) !== bridge
  ) {
    return fail();
  }
  const handle = await open(bridge, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const opened = await handle.stat();
    const bytes = await handle.readFile();
    const [after, pathAfter, parentAfter] = await Promise.all([
      handle.stat(),
      lstat(bridge),
      lstat(parent),
    ]);
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      opened.uid !== before.uid ||
      opened.nlink !== before.nlink ||
      (opened.mode & 0o777) !== (before.mode & 0o777) ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs ||
      after.ctimeMs !== opened.ctimeMs ||
      after.uid !== opened.uid ||
      after.nlink !== opened.nlink ||
      (after.mode & 0o777) !== (opened.mode & 0o777) ||
      pathAfter.isSymbolicLink() ||
      pathAfter.dev !== opened.dev ||
      pathAfter.ino !== opened.ino ||
      pathAfter.size !== opened.size ||
      pathAfter.mtimeMs !== opened.mtimeMs ||
      pathAfter.ctimeMs !== opened.ctimeMs ||
      pathAfter.uid !== opened.uid ||
      pathAfter.nlink !== opened.nlink ||
      (pathAfter.mode & 0o777) !== (opened.mode & 0o777) ||
      parentAfter.isSymbolicLink() ||
      parentAfter.dev !== parentBefore.dev ||
      parentAfter.ino !== parentBefore.ino ||
      !bytes.equals(bridgeBytes)
    ) {
      return fail();
    }
  } finally {
    await handle.close();
  }
  return bridge;
};

const cleanupFailedBridgeCreation = async (bridge, parent, parentBefore, created) => {
  try {
    const parentState = await assertOwnedDirectory(parent);
    const state = await lstat(bridge);
    if (
      parentState.dev !== parentBefore.dev ||
      parentState.ino !== parentBefore.ino ||
      state.isSymbolicLink() ||
      !state.isFile() ||
      state.dev !== created.dev ||
      state.ino !== created.ino ||
      state.uid !== created.uid ||
      state.nlink !== 1 ||
      (state.mode & 0o777) !== 0o400 ||
      state.size > bridgeBytes.byteLength
    ) {
      return;
    }
    const handle = await open(bridge, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    try {
      const bytes = await handle.readFile();
      const [pathAfter, parentAfter] = await Promise.all([lstat(bridge), lstat(parent)]);
      if (
        pathAfter.isSymbolicLink() ||
        pathAfter.dev !== state.dev ||
        pathAfter.ino !== state.ino ||
        pathAfter.uid !== state.uid ||
        pathAfter.nlink !== state.nlink ||
        (pathAfter.mode & 0o777) !== (state.mode & 0o777) ||
        pathAfter.size !== state.size ||
        pathAfter.mtimeMs !== state.mtimeMs ||
        pathAfter.ctimeMs !== state.ctimeMs ||
        parentAfter.isSymbolicLink() ||
        parentAfter.dev !== parentState.dev ||
        parentAfter.ino !== parentState.ino ||
        !bytes.equals(bridgeBytes.subarray(0, bytes.byteLength))
      ) {
        return;
      }
    } finally {
      await handle.close();
    }
    await unlink(bridge);
  } catch {
    // Preserve any path that cannot be proven to be the bridge created by this call.
  }
};

export const createBasePreservationBridgeEntry = async (
  root = packageRoot,
  hooks = defaultBridgeCreationHooks
) => {
  if (!path.isAbsolute(root) || path.normalize(root) !== root) {
    return fail();
  }
  const bridge = bridgePathFor(root);
  const parent = path.dirname(bridge);
  const creationHooks = Object.freeze({ ...defaultBridgeCreationHooks, ...hooks });
  const parentBefore = await assertOwnedDirectory(parent);
  await assertBuiltNestedEntry(root);
  const handle = await open(
    bridge,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o400
  ).catch(fail);
  let created;
  try {
    try {
      try {
        created = await creationHooks.stat(handle);
      } catch (error) {
        created = await creationHooks.stat(handle).catch(() => {});
        throw error;
      }
      await creationHooks.afterOpen(bridge, handle);
      await handle.writeFile(bridgeBytes);
      await handle.chmod(0o400);
      await handle.sync();
    } finally {
      await handle.close();
    }
    const parentAfter = await lstat(parent).catch(fail);
    if (
      parentAfter.isSymbolicLink() ||
      parentAfter.dev !== parentBefore.dev ||
      parentAfter.ino !== parentBefore.ino
    ) {
      return fail();
    }
    await inspectBasePreservationBridgeEntry(root);
    const state = await lstat(bridge).catch(fail);
    return Object.freeze({
      root,
      path: bridge,
      parent,
      parentDev: parentAfter.dev,
      parentIno: parentAfter.ino,
      dev: state.dev,
      ino: state.ino,
      uid: state.uid,
      mode: state.mode & 0o777,
      size: state.size,
      nlink: state.nlink,
      content: basePreservationBridgeSource,
    });
  } catch (error) {
    if (created !== undefined) {
      await cleanupFailedBridgeCreation(bridge, parent, parentBefore, created);
    }
    throw error;
  }
};

export const recheckBasePreservationBridgeEntry = async (root = packageRoot) =>
  inspectBasePreservationBridgeEntry(root);

export const cleanupBasePreservationBridgeEntry = async (creation) => {
  if (
    typeof creation !== 'object' ||
    creation === null ||
    Array.isArray(creation) ||
    !path.isAbsolute(creation.root) ||
    path.normalize(creation.root) !== creation.root ||
    !path.isAbsolute(creation.path) ||
    path.normalize(creation.path) !== creation.path
  ) {
    return fail();
  }
  const { root } = creation;
  const bridge = bridgePathFor(root);
  const parent = path.dirname(bridge);
  if (
    creation.path !== bridge ||
    creation.parent !== parent ||
    creation.content !== basePreservationBridgeSource
  ) {
    return fail();
  }
  const parentState = await assertOwnedDirectory(parent);
  await inspectBasePreservationBridgeEntry(root);
  const state = await lstat(bridge).catch(fail);
  if (
    parentState.dev !== creation.parentDev ||
    parentState.ino !== creation.parentIno ||
    state.isSymbolicLink() ||
    state.dev !== creation.dev ||
    state.ino !== creation.ino ||
    state.uid !== creation.uid ||
    (state.mode & 0o777) !== creation.mode ||
    state.size !== creation.size ||
    state.nlink !== creation.nlink
  ) {
    return fail();
  }
  await unlink(bridge).catch(fail);
};

const defaultDependencies = Object.freeze({
  inspect: inspectCleanHead,
  async build(root) {
    const code = await run('pnpm', ['--filter', '@logto/integration-tests', 'build'], {
      cwd: root,
      env: {
        HOME: process.env.HOME ?? fail(),
        LC_ALL: 'C',
        PATH: process.env.PATH ?? fail(),
      },
      stdio: 'ignore',
      timeoutMs: 5 * 60_000,
    });
    if (code !== 0) {
      fail();
    }
  },
  createEntry: createBasePreservationBridgeEntry,
  identity: computeRuntimeBundleManifest,
  recheckEntry: recheckBasePreservationBridgeEntry,
  cleanupEntry: cleanupBasePreservationBridgeEntry,
  async execute(entry, args, environment, manifest, capability) {
    const result = await executeVerifiedPhase2Entry(entry, args, environment, manifest, capability);
    const childDiagnostic = diagnosticForBasePreservationChild(result);
    if (childDiagnostic !== diagnostic) {
      throw new BasePreservationChildFailure(childDiagnostic);
    }
    if (result.timedOut || result.code !== 0 || result.signal !== null || result.stderr !== '') {
      return 1;
    }
    process.stdout.write(result.stdout);
    return 0;
  },
});

const validateEnvironmentValue = (value) => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value) > 4096 ||
    /\p{Cc}/u.test(value)
  ) {
    return fail();
  }
  return value;
};

export const selectBasePreservationEnvironment = (source = process.env) => {
  if (typeof source !== 'object' || source === null || Array.isArray(source)) {
    return fail();
  }
  const entries = basePreservationRequiredEnvironmentKeys.map((key) => [
    key,
    validateEnvironmentValue(source[key]),
  ]);
  for (const key of basePreservationOptionalEnvironmentKeys) {
    if (Object.hasOwn(source, key)) {
      entries.push([key, validateEnvironmentValue(source[key])]);
    }
  }
  return Object.freeze(Object.fromEntries(entries));
};

const validateEnvironment = (environment) => {
  if (
    typeof environment !== 'object' ||
    environment === null ||
    Array.isArray(environment) ||
    !basePreservationRequiredEnvironmentKeys.every((key) => Object.hasOwn(environment, key)) ||
    Object.keys(environment).some((key) => !basePreservationEnvironmentKeys.includes(key))
  ) {
    return fail();
  }
  for (const value of Object.values(environment)) {
    validateEnvironmentValue(value);
  }
  return Object.freeze({ ...environment });
};

const validateArguments = (args) => {
  if (
    !Array.isArray(args) ||
    args.length === 0 ||
    args.some(
      (value) =>
        typeof value !== 'string' || /\p{Cc}/u.test(value) || Buffer.byteLength(value) > 4096
    )
  ) {
    return fail();
  }
  return Object.freeze([...args]);
};

export const launchPhase2BasePreservation = async (
  arguments_,
  sourceEnvironment,
  dependencies = defaultDependencies
) => {
  const args = validateArguments(arguments_);
  const topologyEnvironment = validateEnvironment(sourceEnvironment);
  const before = await dependencies.inspect(repositoryRoot);
  await dependencies.build(repositoryRoot);
  const after = await dependencies.inspect(repositoryRoot);
  if (before.head !== after.head || before.tree !== after.tree) {
    fail();
  }
  const creation = await dependencies.createEntry(packageRoot);
  try {
    if (creation.path !== basePreservationRuntimeEntryPath) {
      fail();
    }
    const manifest = await dependencies.identity(creation.path);
    if ((await dependencies.recheckEntry(packageRoot)) !== creation.path) {
      fail();
    }
    const environment = Object.freeze({
      ...topologyEnvironment,
      ASTER_PHASE2_HARNESS_HEAD: before.head,
      ASTER_PHASE2_HARNESS_TREE: before.tree,
      ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: manifest.sha256,
      LC_ALL: 'C',
    });
    const capability = randomBytes(32).toString('hex');
    const code = await dependencies.execute(creation.path, args, environment, manifest, capability);
    if (code !== 0) {
      fail();
    }
    return 0;
  } finally {
    await dependencies.cleanupEntry(creation);
  }
};

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) {
  try {
    await launchPhase2BasePreservation(
      process.argv.slice(2),
      selectBasePreservationEnvironment(process.env)
    );
  } catch (error) {
    process.exitCode = 1;
    process.stderr.write(
      error instanceof BasePreservationChildFailure ? error.message : diagnostic
    );
  }
}

/* eslint-enable max-lines, complexity, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
