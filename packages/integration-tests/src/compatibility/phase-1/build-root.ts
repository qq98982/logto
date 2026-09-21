import { constants } from 'node:fs';
import { lstat, open, realpath, type FileHandle } from 'node:fs/promises';
import path from 'node:path';

export type AsterPhase1BuildRootEnvironment = Readonly<Record<string, string | undefined>>;

export const asterPhase1BuildRootEnvironmentVariable = 'ASTER_PHASE1_BUILD_ROOT';
export const defaultAsterPhase1BuildRoot = '/var/tmp/henry-build';

const diagnostic = 'Invalid Aster Phase 1 build root';
const unsafeExactRoots = new Set([
  '/',
  '/bin',
  '/boot',
  '/dev',
  '/etc',
  '/home',
  '/lib',
  '/lib64',
  '/proc',
  '/root',
  '/run',
  '/sbin',
  '/sys',
  '/tmp',
  '/usr',
  '/var',
  '/var/tmp',
]);
const unsafeTrees = ['/dev', '/proc', '/sys'];
// eslint-disable-next-line no-bitwise -- open(2) flags form a descriptor-pinning capability.
const trustedDirectoryOpenFlags = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;

export type AsterPhase1BuildTrustDependencies = Readonly<{
  getCurrentUserId: () => number | undefined;
}>;

type TrustedDirectoryIdentity = Readonly<{
  dev: bigint;
  ino: bigint;
  uid: bigint;
  mode: number;
  realPath: string;
}>;

const defaultTrustDependencies: AsterPhase1BuildTrustDependencies = Object.freeze({
  getCurrentUserId: () => process.getuid?.(),
});

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const hasControlCharacter = (value: string): boolean =>
  [...value].some((character) => {
    const point = character.codePointAt(0) ?? 0;

    return point < 32 || point === 127;
  });

const requireNormalizedAbsolutePath = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 4096 ||
    hasControlCharacter(value) ||
    !path.isAbsolute(value) ||
    path.resolve(value) !== value
  ) {
    return fail();
  }

  return value;
};

export const resolveAsterPhase1BuildRoot = (
  environment: AsterPhase1BuildRootEnvironment = process.env
): string => {
  const configured = environment[asterPhase1BuildRootEnvironmentVariable];
  const root = requireNormalizedAbsolutePath(configured ?? defaultAsterPhase1BuildRoot);

  if (
    unsafeExactRoots.has(root) ||
    unsafeTrees.some((unsafeRoot) => root.startsWith(`${unsafeRoot}${path.sep}`))
  ) {
    return fail();
  }

  return root;
};

export const requireAsterPhase1BuildPath = (
  value: unknown,
  environment: AsterPhase1BuildRootEnvironment = process.env
): string => {
  const root = resolveAsterPhase1BuildRoot(environment);
  const candidate = requireNormalizedAbsolutePath(value);
  const relative = path.relative(root, candidate);

  if (
    relative.length === 0 ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    return fail();
  }

  return candidate;
};

const modeBits = (mode: bigint): number => Number(mode % 0o1000n);

const readTrustedDirectoryIdentity = async (
  directory: string,
  expectedUserId: number
): Promise<TrustedDirectoryIdentity> => {
  const state = await lstat(directory, { bigint: true });
  const resolved = await realpath(directory);

  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.uid !== BigInt(expectedUserId) ||
    modeBits(state.mode) !== 0o700 ||
    resolved !== directory
  ) {
    return fail();
  }

  return Object.freeze({
    dev: state.dev,
    ino: state.ino,
    uid: state.uid,
    mode: modeBits(state.mode),
    realPath: resolved,
  });
};

const assertOpenedDirectoryIdentity = async (
  handle: FileHandle,
  expected: TrustedDirectoryIdentity
): Promise<void> => {
  const state = await handle.stat({ bigint: true });

  if (
    !state.isDirectory() ||
    state.dev !== expected.dev ||
    state.ino !== expected.ino ||
    state.uid !== expected.uid ||
    modeBits(state.mode) !== expected.mode
  ) {
    return fail();
  }
};

const sameDirectoryIdentity = (
  left: TrustedDirectoryIdentity,
  right: TrustedDirectoryIdentity
): boolean =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.uid === right.uid &&
  left.mode === right.mode &&
  left.realPath === right.realPath;

const withTrustedDirectory = async <Result>(
  directory: string,
  expected: TrustedDirectoryIdentity,
  use: (handle: FileHandle) => Promise<Result>
): Promise<Result> => {
  const handle = await open(directory, trustedDirectoryOpenFlags);

  try {
    await assertOpenedDirectoryIdentity(handle, expected);
    return await use(handle);
  } finally {
    await handle.close().catch(() => false);
  }
};

const withTrustedBuildDirectory = async <Result>(
  directory: unknown,
  environment: AsterPhase1BuildRootEnvironment,
  use: (descriptorPath: string) => Promise<Result>,
  dependencies: AsterPhase1BuildTrustDependencies
): Promise<Result> => {
  try {
    const root = resolveAsterPhase1BuildRoot(environment);
    const candidate = requireAsterPhase1BuildPath(directory, environment);
    const relative = path.relative(root, candidate);
    const userId = dependencies.getCurrentUserId();

    if (userId === undefined || !Number.isSafeInteger(userId) || userId < 0) {
      return fail();
    }
    const rootIdentity = await readTrustedDirectoryIdentity(root, userId);

    return await withTrustedDirectory(root, rootIdentity, async (rootHandle) => {
      const candidateIdentity = await readTrustedDirectoryIdentity(candidate, userId);
      const candidateViaRoot = path.join(`/proc/self/fd/${rootHandle.fd}`, relative);

      return withTrustedDirectory(candidateViaRoot, candidateIdentity, async (candidateHandle) => {
        const result = await use(`/proc/self/fd/${candidateHandle.fd}`);
        await assertOpenedDirectoryIdentity(rootHandle, rootIdentity);
        await assertOpenedDirectoryIdentity(candidateHandle, candidateIdentity);
        const [finalRoot, finalCandidate] = await Promise.all([
          readTrustedDirectoryIdentity(root, userId),
          readTrustedDirectoryIdentity(candidate, userId),
        ]);

        if (
          !sameDirectoryIdentity(rootIdentity, finalRoot) ||
          !sameDirectoryIdentity(candidateIdentity, finalCandidate)
        ) {
          return fail();
        }

        return result;
      });
    });
  } catch {
    return fail();
  }
};

export const withTrustedAsterPhase1BuildDirectory = async <Result>(
  directory: unknown,
  environment: AsterPhase1BuildRootEnvironment,
  use: (descriptorPath: string) => Promise<Result>
): Promise<Result> =>
  withTrustedBuildDirectory(directory, environment, use, defaultTrustDependencies);

export const withTrustedAsterPhase1BuildDirectoryForTesting = async <Result>(
  directory: unknown,
  environment: AsterPhase1BuildRootEnvironment,
  use: (descriptorPath: string) => Promise<Result>,
  dependencies: AsterPhase1BuildTrustDependencies
): Promise<Result> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return withTrustedBuildDirectory(directory, environment, use, dependencies);
};
