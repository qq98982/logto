/* eslint-disable max-lines, max-params, complexity, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, no-bitwise, no-await-in-loop, @typescript-eslint/no-empty-function -- Linux open flags, fd lifecycle state, transactional rollback, fixed guards, and sequential identity checks are intrinsic to this atomic sink. */
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, open, readdir, realpath, rm, unlink } from 'node:fs/promises';
import path from 'node:path';

import { jsonValueGuard } from '../model.js';
import type { JsonValue } from '../normalize.js';

import { canonicalPhase1ArtifactBytes } from './artifact-contract.js';
import {
  assertPhase1EvidenceIsSanitized,
  assertSerializedPhase1EvidenceIsSanitized,
  assertSerializedPhase1ArtifactEvidenceIsSanitized,
  snapshotPhase1EvidencePreservingVerifiedTokens,
} from './evidence.js';
import { snapshotClosedDataGraph } from './model.js';

type DirectoryIdentity = Readonly<{
  dev: bigint | number;
  ino: bigint | number;
  uid: number;
  realPath: string;
}>;
type FileIdentity = Readonly<{
  dev: bigint | number;
  ino: bigint | number;
}>;
type FileState = FileIdentity &
  Readonly<{
    uid: bigint | number;
    mode: bigint | number;
    nlink: bigint | number;
    isFile(): boolean;
  }>;

export type SecureEvidenceSinkTestHooks = Readonly<{
  beforeLink?: () => Promise<void>;
  afterLink?: () => Promise<void>;
}>;

export type SecureEvidenceSink = Readonly<{
  write(name: string, value: unknown): Promise<string>;
  rollback(name: string): Promise<void>;
  scan(): Promise<readonly string[]>;
}>;

export type SecureEvidenceInputAuthority = Readonly<{
  consume(input: SecureEvidenceAuthorizedInput): void;
}>;

export type SecureEvidenceAuthorizedInput = Readonly<{
  name: string;
  source: unknown;
  snapshot: Readonly<JsonValue>;
  serialized: string;
}>;

export type SecureJsonPublication = Readonly<{ path: string }>;

type ArtifactPolicy = Readonly<{
  failureRule: string;
  prepareInput(name: string, value: unknown): Readonly<{ serialized: string }>;
  assertSerialized(name: string, value: unknown): void;
}>;

const safeArtifactName = /^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/u;
const safeDiagnosticArtifact = /^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u;
const maximumArtifactBytes = 8 * 1024 * 1024;
const jsonPublications = new WeakMap<SecureJsonPublication, Readonly<{ identity: FileIdentity }>>();

class SecureEvidenceSinkError extends Error {
  constructor(artifact: string, rule: string) {
    const safeArtifact = safeDiagnosticArtifact.test(artifact) ? artifact : '.';
    super(`${safeArtifact}: ${rule}`);
    this.stack = this.message;
  }
}

const fail = (artifact: string, rule: string): never => {
  throw new SecureEvidenceSinkError(artifact, rule);
};

const guardFailure = async <Result>(
  artifact: string,
  rule: string,
  run: () => Promise<Result>
): Promise<Result> => {
  try {
    return await run();
  } catch (error: unknown) {
    if (error instanceof SecureEvidenceSinkError) {
      throw error;
    }

    return fail(artifact, rule);
  }
};

const guardSynchronousFailure = <Result>(
  artifact: string,
  rule: string,
  run: () => Result
): Result => {
  try {
    return run();
  } catch (error: unknown) {
    if (error instanceof SecureEvidenceSinkError) {
      throw error;
    }

    return fail(artifact, rule);
  }
};

const serializeClosedJson = (value: unknown): string =>
  Buffer.from(canonicalPhase1ArtifactBytes(value)).toString('utf8');
const serializedTokenEvidenceName = 'phase-1-differential.json';

const evidencePolicy = (authority?: SecureEvidenceInputAuthority): ArtifactPolicy => ({
  prepareInput: (name, value) => {
    assertPhase1EvidenceIsSanitized(value);
    const snapshot = snapshotPhase1EvidencePreservingVerifiedTokens<JsonValue>(value);
    assertPhase1EvidenceIsSanitized(snapshot);
    if (!authority) {
      const authorityFreeSnapshot = snapshotClosedDataGraph<JsonValue>(snapshot);

      if (authorityFreeSnapshot === undefined) {
        throw new TypeError('Invalid evidence publication');
      }
      assertSerializedPhase1EvidenceIsSanitized(authorityFreeSnapshot);
    }
    const serialized = serializeClosedJson(snapshot);
    authority?.consume(Object.freeze({ name, source: value, snapshot, serialized }));

    return Object.freeze({ serialized });
  },
  assertSerialized: (name, value) => {
    if (name === serializedTokenEvidenceName) {
      assertSerializedPhase1ArtifactEvidenceIsSanitized(value);
      return;
    }
    assertSerializedPhase1EvidenceIsSanitized(value);
  },
  failureRule: 'sanitizer',
});

const jsonPolicy: ArtifactPolicy = {
  prepareInput: (_name, value) => {
    if (!jsonValueGuard.safeParse(value).success) {
      throw new TypeError('Invalid JSON publication');
    }
    const snapshot = snapshotClosedDataGraph<JsonValue>(value);

    if (snapshot === undefined || !jsonValueGuard.safeParse(snapshot).success) {
      throw new TypeError('Invalid JSON publication');
    }

    return Object.freeze({ serialized: serializeClosedJson(snapshot) });
  },
  assertSerialized: (_name, value) => {
    if (!jsonValueGuard.safeParse(value).success) {
      throw new TypeError('Invalid JSON publication');
    }
  },
  failureRule: 'json',
};

const modeBits = (mode: number) => mode & 0o777;

const currentUid = (): number => {
  const uid = process.getuid?.();

  return typeof uid === 'number' ? uid : fail('.', 'owner-unavailable');
};

const readDirectoryIdentity = async (root: string): Promise<DirectoryIdentity> => {
  let state;
  let resolved;

  try {
    state = await lstat(root, { bigint: true });
    resolved = await realpath(root);
  } catch {
    return fail('.', 'directory-unavailable');
  }
  if (state.isSymbolicLink() || !state.isDirectory()) {
    return fail('.', 'directory-not-real');
  }
  if (resolved !== root) {
    return fail('.', 'directory-not-real');
  }
  if (Number(state.uid) !== currentUid()) {
    return fail('.', 'directory-owner');
  }
  if (modeBits(Number(state.mode)) !== 0o700) {
    return fail('.', 'directory-mode');
  }

  return Object.freeze({
    dev: state.dev,
    ino: state.ino,
    uid: Number(state.uid),
    realPath: resolved,
  });
};

const sameIdentity = (left: DirectoryIdentity, right: DirectoryIdentity): boolean =>
  left.dev === right.dev &&
  left.ino === right.ino &&
  left.uid === right.uid &&
  left.realPath === right.realPath;

const isSecureFileState = (state: FileState, expected?: FileIdentity): boolean =>
  state.isFile() &&
  Number(state.uid) === currentUid() &&
  modeBits(Number(state.mode)) === 0o600 &&
  Number(state.nlink) === 1 &&
  (expected === undefined || (state.dev === expected.dev && state.ino === expected.ino));

const requireDirectoryIdentity = async (
  root: string,
  expected: DirectoryIdentity
): Promise<void> => {
  const actual = await readDirectoryIdentity(root);

  if (!sameIdentity(actual, expected)) {
    fail('.', 'directory-identity');
  }
};

const fileExists = async (filePath: string, artifact: string): Promise<boolean> => {
  try {
    await lstat(filePath);
    return true;
  } catch (error: unknown) {
    if (
      typeof error === 'object' &&
      error !== null &&
      Object.getOwnPropertyDescriptor(error, 'code')?.value === 'ENOENT'
    ) {
      return false;
    }
    return fail(artifact, 'final-path-state');
  }
};

const validateFinal = async (
  filePath: string,
  artifact: string,
  expected?: FileIdentity
): Promise<FileIdentity> => {
  let state;

  try {
    state = await lstat(filePath, { bigint: true });
  } catch {
    return fail(artifact, 'final-unavailable');
  }
  if (state.isSymbolicLink() || !state.isFile()) {
    fail(artifact, 'non-regular-entry');
  }
  if (Number(state.uid) !== currentUid()) {
    fail(artifact, 'owner');
  }
  if (modeBits(Number(state.mode)) !== 0o600) {
    fail(artifact, 'mode');
  }
  if (Number(state.nlink) !== 1) {
    fail(artifact, 'link-count');
  }
  if (expected && (state.dev !== expected.dev || state.ino !== expected.ino)) {
    fail(artifact, 'final-identity');
  }

  return Object.freeze({ dev: state.dev, ino: state.ino });
};

const readAndSanitizeArtifact = async (
  filePath: string,
  artifact: string,
  policy: ArtifactPolicy,
  expected?: FileIdentity,
  expectedSerialized?: string
): Promise<void> => {
  let file;

  try {
    file = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    return fail(artifact, 'content-open');
  }
  try {
    const openedState = await guardFailure(artifact, 'content-stat', async () =>
      file.stat({ bigint: true })
    );

    if (!isSecureFileState(openedState, expected)) {
      return fail(artifact, 'final-identity');
    }
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    let position = 0;

    while (totalBytes <= maximumArtifactBytes) {
      const buffer = new Uint8Array(Math.min(64 * 1024, maximumArtifactBytes + 1 - totalBytes));
      // The position argument is evaluated before the read promise can yield.
      // eslint-disable-next-line @typescript-eslint/no-loop-func
      const { bytesRead } = await guardFailure(artifact, 'content-read', async () =>
        file.read(buffer, 0, buffer.byteLength, position)
      );

      if (bytesRead === 0) {
        break;
      }
      totalBytes += bytesRead;
      position += bytesRead;
      chunks.push(buffer.subarray(0, bytesRead));
    }
    if (totalBytes > maximumArtifactBytes) {
      return fail(artifact, 'content-size');
    }
    const bytes = Buffer.concat(chunks);

    if (
      expectedSerialized !== undefined &&
      !bytes.equals(Buffer.from(expectedSerialized, 'utf8'))
    ) {
      return fail(artifact, 'content-mismatch');
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
    } catch {
      return fail(artifact, 'content-json');
    }
    try {
      policy.assertSerialized(artifact, parsed);
    } catch {
      return fail(artifact, policy.failureRule);
    }
  } finally {
    await guardFailure(artifact, 'content-close', async () => file.close());
  }
  await validateFinal(filePath, artifact, expected);
};

const validateAllowlist = (names: readonly string[]): readonly string[] => {
  if (
    names.length === 0 ||
    new Set(names).size !== names.length ||
    names.some(
      (name) =>
        !safeArtifactName.test(name) ||
        path.basename(name) !== name ||
        name === '.' ||
        name === '..'
    )
  ) {
    throw new TypeError('Invalid phase 1 evidence allowlist');
  }

  return Object.freeze(names.toSorted());
};

const createSecureArtifactSink = async (
  root: string,
  allowlist: readonly string[],
  hooks: SecureEvidenceSinkTestHooks,
  policy: ArtifactPolicy,
  closedDirectory: boolean
): Promise<SecureEvidenceSink> => {
  if (!path.isAbsolute(root) || path.resolve(root) !== root) {
    throw new TypeError('Invalid phase 1 evidence directory');
  }
  const names = validateAllowlist(allowlist);
  const allowed = new Set(names);
  const publishedIdentities = new Map<string, FileIdentity>();
  const publishedSerialized = new Map<string, string>();
  const initialIdentity = await readDirectoryIdentity(root);

  const withDirectory = async <Result>(
    use: (directoryPath: string, identity: DirectoryIdentity) => Promise<Result>
  ): Promise<Result> => {
    await requireDirectoryIdentity(root, initialIdentity);
    const directory = await guardFailure('.', 'directory-open', async () =>
      open(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW)
    );

    try {
      const state = await guardFailure('.', 'directory-stat', async () =>
        directory.stat({ bigint: true })
      );
      const identity = Object.freeze({
        dev: state.dev,
        ino: state.ino,
        uid: Number(state.uid),
        realPath: initialIdentity.realPath,
      });

      if (!sameIdentity(identity, initialIdentity)) {
        return fail('.', 'directory-identity');
      }

      return await use(`/proc/self/fd/${directory.fd}`, identity);
    } finally {
      await guardFailure('.', 'directory-close', async () => directory.close());
    }
  };

  const scan = async (): Promise<readonly string[]> =>
    withDirectory(async (directoryPath, identity) => {
      const entries = await guardFailure('.', 'directory-read', async () =>
        readdir(directoryPath, { withFileTypes: true })
      );

      for (const name of names) {
        const entry = entries.find((candidate) => candidate.name === name);

        if (entry) {
          if (!entry.isFile() || entry.isSymbolicLink()) {
            return fail(name, 'non-regular-entry');
          }
          const filePath = path.join(directoryPath, name);
          const publishedIdentity = publishedIdentities.get(name);
          const expected = await validateFinal(filePath, name, publishedIdentity);
          await readAndSanitizeArtifact(
            filePath,
            name,
            policy,
            expected,
            publishedSerialized.get(name)
          );
        }
      }
      const unexpected = entries
        .map(({ name }) => name)
        .filter((name) => !allowed.has(name))
        .toSorted()[0];

      if (closedDirectory && unexpected) {
        return fail(unexpected, 'unexpected-entry');
      }
      await requireDirectoryIdentity(root, identity);

      return Object.freeze(entries.map(({ name }) => path.join(root, name)).toSorted());
    });

  return Object.freeze({
    write: async (name: string, value: unknown): Promise<string> => {
      if (!allowed.has(name)) {
        return fail(name, 'not-allowlisted');
      }
      const prepared = guardSynchronousFailure(name, policy.failureRule, () =>
        policy.prepareInput(name, value)
      );
      const { serialized } = prepared;

      if (Buffer.byteLength(serialized) > maximumArtifactBytes) {
        return fail(name, 'content-size');
      }

      const finalPath = await withDirectory(async (directoryPath, identity) => {
        const finalViaDirectory = path.join(directoryPath, name);
        const publishedPath = path.join(root, name);

        if (await fileExists(finalViaDirectory, name)) {
          return fail(name, 'final-path-exists');
        }
        const temporaryName = guardSynchronousFailure(
          name,
          'temporary-name',
          () => `.${name}.${randomBytes(12).toString('hex')}.tmp`
        );
        const temporaryPath = path.join(directoryPath, temporaryName);
        let temporaryPresent = false;
        let finalPublished = false;
        let completed = false;

        try {
          const temporary = await guardFailure(name, 'temporary-open', async () =>
            open(
              temporaryPath,
              constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY,
              0o600
            )
          );
          temporaryPresent = true;

          const temporaryIdentity = await (async (): Promise<FileIdentity> => {
            try {
              await guardFailure(name, 'temporary-write', async () =>
                temporary.writeFile(serialized, 'utf8')
              );
              await guardFailure(name, 'temporary-sync', async () => temporary.sync());
              const state = await guardFailure(name, 'temporary-stat', async () =>
                temporary.stat({ bigint: true })
              );

              if (
                !state.isFile() ||
                Number(state.uid) !== currentUid() ||
                modeBits(Number(state.mode)) !== 0o600
              ) {
                return fail(name, 'temporary-state');
              }
              return Object.freeze({ dev: state.dev, ino: state.ino });
            } finally {
              await guardFailure(name, 'temporary-close', async () => temporary.close());
            }
          })();
          await guardFailure(name, 'before-link', async () => hooks.beforeLink?.());
          await requireDirectoryIdentity(root, identity);
          try {
            await link(temporaryPath, finalViaDirectory);
          } catch (error: unknown) {
            if (
              typeof error === 'object' &&
              error !== null &&
              Object.getOwnPropertyDescriptor(error, 'code')?.value === 'EEXIST'
            ) {
              return fail(name, 'final-path-exists');
            }
            return fail(name, 'publish');
          }
          finalPublished = true;
          await guardFailure(name, 'after-link', async () => hooks.afterLink?.());
          await guardFailure(name, 'temporary-unlink', async () => unlink(temporaryPath));
          temporaryPresent = false;
          const directory = await guardFailure(name, 'directory-sync-open', async () =>
            open(directoryPath, constants.O_RDONLY | constants.O_DIRECTORY)
          );
          try {
            await guardFailure(name, 'directory-sync', async () => directory.sync());
          } finally {
            await guardFailure(name, 'directory-sync-close', async () => directory.close());
          }
          await validateFinal(finalViaDirectory, name, temporaryIdentity);
          await readAndSanitizeArtifact(
            finalViaDirectory,
            name,
            policy,
            temporaryIdentity,
            serialized
          );
          publishedIdentities.set(name, temporaryIdentity);
          publishedSerialized.set(name, serialized);
          await requireDirectoryIdentity(root, identity);
          completed = true;

          return publishedPath;
        } finally {
          if (temporaryPresent) {
            await unlink(temporaryPath).catch(() => {});
          }
          if (finalPublished && !completed) {
            publishedIdentities.delete(name);
            publishedSerialized.delete(name);
            await rm(finalViaDirectory, { force: true, recursive: true }).catch(() => {});
          }
        }
      });
      try {
        await scan();
      } catch (error: unknown) {
        publishedIdentities.delete(name);
        publishedSerialized.delete(name);
        await withDirectory(async (directoryPath) => {
          await rm(path.join(directoryPath, name), { force: true, recursive: true }).catch(
            () => {}
          );
        }).catch(() => {});
        throw error;
      }

      return finalPath;
    },

    rollback: async (name: string): Promise<void> => {
      if (!allowed.has(name)) {
        return fail(name, 'not-allowlisted');
      }
      const expected = publishedIdentities.get(name);

      if (!expected) {
        return fail(name, 'publication-identity');
      }
      await withDirectory(async (directoryPath) => {
        const publishedPath = path.join(directoryPath, name);
        const state = await lstat(publishedPath, { bigint: true }).catch(() => {});

        if (state) {
          if (
            !state.isFile() ||
            state.isSymbolicLink() ||
            state.dev !== expected.dev ||
            state.ino !== expected.ino
          ) {
            return fail(name, 'publication-identity');
          }
          await unlink(publishedPath);
        }
        if (await fileExists(publishedPath, name)) {
          return fail(name, 'rollback-presence');
        }
        const directory = await open(directoryPath, constants.O_RDONLY | constants.O_DIRECTORY);
        try {
          await directory.sync();
        } finally {
          await directory.close();
        }
      });
      publishedIdentities.delete(name);
      publishedSerialized.delete(name);
    },

    scan,
  });
};

export const createSecureEvidenceSink = async (
  root: string,
  allowlist: readonly string[],
  hooks: SecureEvidenceSinkTestHooks = {},
  authority?: SecureEvidenceInputAuthority
): Promise<SecureEvidenceSink> =>
  createSecureArtifactSink(root, allowlist, hooks, evidencePolicy(authority), true);

export const writeSecureJsonArtifact = async (
  outputPath: string,
  value: JsonValue,
  hooks: SecureEvidenceSinkTestHooks = {}
): Promise<SecureJsonPublication> => {
  const root = path.dirname(outputPath);
  const name = path.basename(outputPath);

  if (!path.isAbsolute(outputPath) || path.resolve(outputPath) !== outputPath) {
    throw new TypeError('Invalid secure JSON output');
  }
  const sink = await createSecureArtifactSink(root, [name], hooks, jsonPolicy, false);
  const publishedPath = await sink.write(name, value);
  const identity = await validateFinal(publishedPath, name);
  const publication = Object.freeze({ path: publishedPath });
  jsonPublications.set(publication, Object.freeze({ identity }));

  return publication;
};

export const rollbackSecureJsonArtifact = async (
  publication: SecureJsonPublication
): Promise<void> => {
  const authority = jsonPublications.get(publication);

  if (!authority) {
    throw new TypeError('Invalid secure JSON publication');
  }
  const state = await lstat(publication.path, { bigint: true }).catch(() => {});

  if (!state) {
    jsonPublications.delete(publication);
    return;
  }
  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.dev !== authority.identity.dev ||
    state.ino !== authority.identity.ino
  ) {
    throw new TypeError('Invalid secure JSON publication');
  }
  await unlink(publication.path);
  if (await lstat(publication.path).catch(() => {})) {
    throw new TypeError('Invalid secure JSON publication');
  }
  jsonPublications.delete(publication);
};

export const setSecureJsonArtifactMode = async (
  publication: SecureJsonPublication,
  mode: 0o400 | 0o600
): Promise<void> => {
  const authority = jsonPublications.get(publication);

  if (!authority) {
    throw new TypeError('Invalid secure JSON publication');
  }
  const handle = await open(publication.path, constants.O_RDONLY | constants.O_NOFOLLOW);

  try {
    const before = await handle.stat({ bigint: true });

    if (
      !before.isFile() ||
      before.dev !== authority.identity.dev ||
      before.ino !== authority.identity.ino
    ) {
      throw new TypeError('Invalid secure JSON publication');
    }
    await handle.chmod(mode);
    await handle.sync();
    const after = await handle.stat({ bigint: true });
    const pathState = await lstat(publication.path, { bigint: true });

    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      modeBits(Number(after.mode)) !== mode ||
      pathState.dev !== after.dev ||
      pathState.ino !== after.ino ||
      pathState.ctimeNs !== after.ctimeNs ||
      pathState.size !== after.size
    ) {
      throw new TypeError('Invalid secure JSON publication');
    }
  } finally {
    await handle.close();
  }
};

/* eslint-enable max-lines, max-params, complexity, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, no-bitwise, no-await-in-loop, @typescript-eslint/no-empty-function */
