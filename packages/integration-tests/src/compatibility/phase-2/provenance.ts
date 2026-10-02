/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, unicorn/prevent-abbreviations -- Stable O_NOFOLLOW module reads, recursive ESM closure traversal, canonical hashing, and clean-Git fencing intentionally remain in one provenance authority. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

export const phase2OracleSourceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
export const phase2OracleImageDigest =
  'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd';

export type Phase2PublicHarnessProvenance = Readonly<{
  repositoryUrl: 'https://github.com/qq98982/logto.git';
  headCommit: string;
  headTree: string;
  runtimeBundleSha256: string;
}>;
export type Phase2SourceIdentity = Readonly<{
  repositoryRoot: string;
  repositoryDev: string;
  repositoryIno: string;
  clean: true;
  public: Phase2PublicHarnessProvenance;
  runtimeEntryPath: string;
}>;

export type Phase2RuntimeBundleIdentity = Readonly<{
  sha256: string;
  moduleCount: number;
}>;

export type Phase2ArtifactIdentity = Readonly<{
  path: string;
  sha256: string;
  dev: string;
  ino: string;
  uid: number;
  mode: number;
  nlink: number;
}>;

export type Phase2SocketIdentity = Readonly<{
  path: string;
  dev: string;
  ino: string;
  uid: number;
  mode: number;
  nlink: number;
  type: 'unix-socket';
}>;

export type Phase2TopologyIdentity = Readonly<{
  projectName: string;
  primary: Readonly<{
    containerId: string;
    service: string;
    imageDigest: string;
  }>;
  foreign: Readonly<{
    containerId: string;
    service: string;
    imageDigest: string;
  }>;
}>;

const executeFile = promisify(execFile);
const commitPattern = /^[0-9a-f]{40}$/u;
const treePattern = /^[0-9a-f]{40}$/u;
const shaPattern = /^[0-9a-f]{64}$/u;
const runtimeCapabilityPattern = /^[0-9a-f]{64}$/u;
const runtimeCapabilitySymbol = Symbol.for('aster.phase2.runtime-capability');
const diagnostic = 'Invalid Phase 2 provenance';
const maximumRuntimeModuleBytes = 16 * 1024 * 1024;
const maximumRuntimeModules = 512;
const launcherEnvironmentKeys = Object.freeze([
  'ASTER_PHASE2_HARNESS_HEAD',
  'ASTER_PHASE2_HARNESS_TREE',
  'ASTER_PHASE2_RUNTIME_BUNDLE_SHA256',
  'LC_ALL',
  'PATH',
]);
const launcherEnvironmentKeysWithOracleSmtp = Object.freeze(
  [...launcherEnvironmentKeys, 'ASTER_PHASE2_ORACLE_SMTP_SOCKET'].toSorted()
);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const consumeRuntimeCapability = (expected: string): void => {
  if (
    !runtimeCapabilityPattern.test(expected) ||
    Reflect.get(globalThis, runtimeCapabilitySymbol) !== expected ||
    !Reflect.deleteProperty(globalThis, runtimeCapabilitySymbol) ||
    Reflect.has(globalThis, runtimeCapabilitySymbol)
  ) {
    fail();
  }
};

const git = async (root: string, args: readonly string[]): Promise<string> => {
  try {
    const { stdout, stderr } = await executeFile('git', [...args], {
      cwd: root,
      encoding: 'utf8',
      env: {
        PATH: '/usr/bin:/bin',
        GIT_CONFIG_COUNT: '1',
        GIT_CONFIG_KEY_0: 'credential.helper',
        GIT_CONFIG_VALUE_0: '',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_TERMINAL_PROMPT: '0',
        LC_ALL: 'C',
      },
      maxBuffer: 1024 * 1024,
      timeout: 10_000,
    });
    if (stderr !== '') {
      return fail();
    }
    return stdout.trim();
  } catch {
    return fail();
  }
};

const runtimeImports = (source: string): readonly string[] => {
  const values: string[] = [];
  const staticPattern = /^(?:import|export)\s+(?:(?:[\s\S]*?)\s+from\s+)?["']([^"']+)["'];/gmu;
  const dynamicPattern = /\bimport\(\s*["']([^"']+)["']\s*\)/gu;
  for (const pattern of [staticPattern, dynamicPattern]) {
    for (const match of source.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier?.startsWith('.')) {
        values.push(specifier);
      }
    }
  }
  return Object.freeze([...new Set(values)]);
};

const readStableRuntimeModule = async (filePath: string): Promise<Uint8Array> => {
  const before = await lstat(filePath).catch(fail);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.size <= 0 ||
    before.size > maximumRuntimeModuleBytes ||
    (await realpath(filePath).catch(fail)) !== filePath
  ) {
    return fail();
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const opened = await handle.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      return fail();
    }
    const bytes = await handle.readFile();
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(filePath)]);
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs ||
      pathAfter.isSymbolicLink() ||
      pathAfter.dev !== opened.dev ||
      pathAfter.ino !== opened.ino ||
      pathAfter.size !== opened.size ||
      pathAfter.mtimeMs !== opened.mtimeMs
    ) {
      return fail();
    }
    return bytes;
  } finally {
    await handle.close();
  }
};

export const computePhase2RuntimeBundleIdentity = async (
  entryPath: string
): Promise<Phase2RuntimeBundleIdentity> => {
  if (!path.isAbsolute(entryPath) || path.normalize(entryPath) !== entryPath) {
    return fail();
  }
  const libRoot = path.resolve(path.dirname(entryPath), '../..');
  if (path.basename(libRoot) !== 'lib') {
    return fail();
  }
  const pending = [entryPath];
  const modules = new Map<string, Uint8Array>();
  while (pending.length > 0) {
    const current = pending.pop() ?? fail();
    if (modules.has(current)) {
      continue;
    }
    if (current !== libRoot && !current.startsWith(`${libRoot}${path.sep}`)) {
      return fail();
    }
    const bytes = await readStableRuntimeModule(current);
    modules.set(current, bytes);
    if (modules.size > maximumRuntimeModules) {
      return fail();
    }
    const source = new TextDecoder('utf8', { fatal: true }).decode(bytes);
    for (const specifier of runtimeImports(source)) {
      const resolved = path.resolve(path.dirname(current), specifier);
      if (path.extname(resolved) !== '.js') {
        return fail();
      }
      pending.push(resolved);
    }
  }
  const hash = createHash('sha256');
  for (const [filePath, bytes] of [...modules.entries()].toSorted(([left], [right]) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right))
  )) {
    const relative = path.relative(libRoot, filePath).split(path.sep).join('/');
    hash.update(`${Buffer.byteLength(relative)}:`);
    hash.update(relative);
    hash.update(`:${bytes.byteLength}:`);
    hash.update(bytes);
  }
  return Object.freeze({ sha256: hash.digest('hex'), moduleCount: modules.size });
};

export const inspectCleanPhase2HarnessSource = async (
  requestedRoot: string,
  runtimeEntryPath: string,
  runtimeBundleSha256: string
): Promise<Phase2SourceIdentity> => {
  if (
    !path.isAbsolute(requestedRoot) ||
    path.normalize(requestedRoot) !== requestedRoot ||
    !shaPattern.test(runtimeBundleSha256)
  ) {
    return fail();
  }
  const repositoryRoot = await git(requestedRoot, ['rev-parse', '--show-toplevel']);
  if (repositoryRoot !== requestedRoot) {
    return fail();
  }
  const [headCommit, headTree, status, origin] = await Promise.all([
    git(repositoryRoot, ['rev-parse', 'HEAD']),
    git(repositoryRoot, ['rev-parse', 'HEAD^{tree}']),
    git(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']),
    git(repositoryRoot, ['remote', 'get-url', 'origin']),
  ]);
  const state = await lstat(repositoryRoot).catch(fail);
  if (
    !commitPattern.test(headCommit) ||
    !treePattern.test(headTree) ||
    status !== '' ||
    !['git@github.com:qq98982/logto.git', 'https://github.com/qq98982/logto.git'].includes(
      origin
    ) ||
    state.isSymbolicLink() ||
    !state.isDirectory()
  ) {
    return fail();
  }
  return Object.freeze({
    repositoryRoot,
    repositoryDev: String(state.dev),
    repositoryIno: String(state.ino),
    clean: true,
    public: Object.freeze({
      repositoryUrl: 'https://github.com/qq98982/logto.git',
      headCommit,
      headTree,
      runtimeBundleSha256,
    }),
    runtimeEntryPath,
  });
};

export const inspectLaunchedPhase2HarnessSource = async (
  requestedRoot: string,
  runtimeEntryPath: string,
  runtimeCapability: string | undefined,
  environment: Readonly<Record<string, string | undefined>> = process.env
): Promise<Phase2SourceIdentity> => {
  const keys = Object.keys(environment).toSorted();
  const oracleSmtpSocket = environment.ASTER_PHASE2_ORACLE_SMTP_SOCKET;
  const expectedKeys =
    oracleSmtpSocket === undefined
      ? launcherEnvironmentKeys
      : launcherEnvironmentKeysWithOracleSmtp;
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index]) ||
    environment.LC_ALL !== 'C' ||
    typeof environment.PATH !== 'string' ||
    environment.PATH.length === 0 ||
    (oracleSmtpSocket !== undefined &&
      (typeof oracleSmtpSocket !== 'string' ||
        !path.isAbsolute(oracleSmtpSocket) ||
        path.normalize(oracleSmtpSocket) !== oracleSmtpSocket ||
        !oracleSmtpSocket.endsWith('/oracle-verification-smtp.sock')))
  ) {
    return fail();
  }
  const expectedHead = environment.ASTER_PHASE2_HARNESS_HEAD;
  const expectedTree = environment.ASTER_PHASE2_HARNESS_TREE;
  const expectedBundle = environment.ASTER_PHASE2_RUNTIME_BUNDLE_SHA256;
  if (
    typeof expectedHead !== 'string' ||
    !commitPattern.test(expectedHead) ||
    typeof expectedTree !== 'string' ||
    !treePattern.test(expectedTree) ||
    typeof expectedBundle !== 'string' ||
    !shaPattern.test(expectedBundle) ||
    typeof runtimeCapability !== 'string' ||
    !runtimeCapabilityPattern.test(runtimeCapability)
  ) {
    return fail();
  }
  consumeRuntimeCapability(runtimeCapability);
  const runtime = await computePhase2RuntimeBundleIdentity(runtimeEntryPath);
  if (runtime.sha256 !== expectedBundle) {
    return fail();
  }
  const source = await inspectCleanPhase2HarnessSource(
    requestedRoot,
    runtimeEntryPath,
    expectedBundle
  );
  if (source.public.headCommit !== expectedHead || source.public.headTree !== expectedTree) {
    return fail();
  }
  return source;
};

export const recheckCleanPhase2HarnessSource = async (
  capability: Phase2SourceIdentity
): Promise<void> => {
  const runtime = await computePhase2RuntimeBundleIdentity(capability.runtimeEntryPath);
  const current = await inspectCleanPhase2HarnessSource(
    capability.repositoryRoot,
    capability.runtimeEntryPath,
    runtime.sha256
  );
  if (
    current.repositoryDev !== capability.repositoryDev ||
    current.repositoryIno !== capability.repositoryIno ||
    JSON.stringify(current.public) !== JSON.stringify(capability.public) ||
    runtime.sha256 !== capability.public.runtimeBundleSha256
  ) {
    fail();
  }
};

/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-mutating-methods, unicorn/prevent-abbreviations */
