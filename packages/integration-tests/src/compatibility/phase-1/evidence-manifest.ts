/* eslint-disable max-lines, complexity, no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-bitwise, @typescript-eslint/no-empty-function -- Descriptor-pinned evidence reads and atomic publication require explicit bounded mutable lifecycle state. */
import { randomBytes } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import {
  link,
  lstat,
  open,
  readdir,
  realpath,
  rm,
  unlink,
  type FileHandle,
} from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import type { JsonValue } from '../normalize.js';

import {
  assertPhase1PublicArtifactValue,
  canonicalPhase1ArtifactBytes,
  exactArtifactKeys,
  hashPhase1ArtifactBytes,
  isArtifactRecord,
  parseStrictPhase1ArtifactJson,
  phase1ArtifactMaximumBytes,
  phase1ArtifactModes,
  phase1EvidenceFileNames,
  phase1EvidenceManifestName,
  phase1HarnessResultName,
  type Phase1ArtifactMode,
  type Phase1EvidenceFileName,
} from './artifact-contract.js';
import { cloneAndDeepFreeze } from './model.js';

export type Phase1EvidenceManifestEntry = Readonly<{
  path: Phase1EvidenceFileName;
  sha256: string;
  size: number;
}>;

export type Phase1EvidenceManifest = Readonly<{
  schemaVersion: 1;
  mode: Phase1ArtifactMode;
  files: readonly Phase1EvidenceManifestEntry[];
}>;

export type Phase1EvidenceManifestArtifact = Readonly<{
  outputPath: string;
  mode: Phase1ArtifactMode;
  sha256: string;
  uploadable: boolean;
}>;

export type Phase1EvidenceManifestTestHooks = Readonly<{
  afterEvidenceRead?: () => Promise<void>;
  afterPublication?: () => Promise<void>;
}>;

export type LoadPhase1EvidenceManifestInput = Readonly<{
  mode: Phase1ArtifactMode;
  directory: string;
  manifestPath: string;
}>;

type FileIdentity = Readonly<{ dev: bigint; ino: bigint }>;
type DirectoryIdentity = FileIdentity & Readonly<{ uid: bigint; realPath: string }>;
type EvidenceFileSnapshot = Readonly<{
  identity: FileIdentity;
  bytes: Uint8Array;
  entry: Phase1EvidenceManifestEntry;
}>;
type ManifestAuthority = Readonly<{
  root: string;
  manifest: Phase1EvidenceManifest;
  manifestBytes: Uint8Array;
  evidence: ReadonlyMap<Phase1EvidenceFileName, EvidenceFileSnapshot>;
}>;
const diagnostic = 'Invalid phase 1 evidence manifest';
const sha256Pattern = /^[0-9a-f]{64}$/u;
const manifestAuthorities = new WeakMap<Phase1EvidenceManifestArtifact, ManifestAuthority>();

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const currentUid = (): number => {
  const uid = process.getuid?.();

  return typeof uid === 'number' ? uid : fail();
};

const modeBits = (mode: bigint | number): number => Number(mode) & 0o777;

const sameIdentity = (left: FileIdentity, right: FileIdentity): boolean =>
  left.dev === right.dev && left.ino === right.ino;

const secureFileState = (state: BigIntStats): boolean =>
  state.isFile() &&
  Number(state.uid) === currentUid() &&
  modeBits(state.mode) === 0o600 &&
  Number(state.nlink) === 1 &&
  state.size > 0 &&
  state.size <= BigInt(phase1ArtifactMaximumBytes);

const readDirectoryIdentity = async (root: string): Promise<DirectoryIdentity> => {
  const state = await lstat(root, { bigint: true });
  const resolved = await realpath(root);

  if (
    !path.isAbsolute(root) ||
    path.resolve(root) !== root ||
    resolved !== root ||
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    Number(state.uid) !== currentUid() ||
    modeBits(state.mode) !== 0o700
  ) {
    return fail();
  }

  return Object.freeze({ dev: state.dev, ino: state.ino, uid: state.uid, realPath: resolved });
};

const withDirectory = async <Result>(
  root: string,
  use: (
    descriptorPath: string,
    identity: DirectoryIdentity,
    directory: FileHandle
  ) => Promise<Result>
): Promise<Result> => {
  try {
    const initial = await readDirectoryIdentity(root);
    const directory = await open(
      root,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW
    );

    try {
      const opened = await directory.stat({ bigint: true });

      if (
        !opened.isDirectory() ||
        opened.dev !== initial.dev ||
        opened.ino !== initial.ino ||
        opened.uid !== initial.uid
      ) {
        return fail();
      }
      const result = await use(`/proc/self/fd/${directory.fd}`, initial, directory);
      const final = await readDirectoryIdentity(root);

      if (!sameIdentity(initial, final) || initial.uid !== final.uid) {
        return fail();
      }

      return result;
    } finally {
      await directory.close();
    }
  } catch {
    return fail();
  }
};

const requireExactTree = async (
  descriptorPath: string,
  expectedNames: readonly string[]
): Promise<void> => {
  const entries = await readdir(descriptorPath, { withFileTypes: true });
  const names = entries.map(({ name }) => name).toSorted();

  if (
    entries.some((entry) => !entry.isFile() || entry.isSymbolicLink()) ||
    names.length !== expectedNames.length ||
    names.some((name, index) => name !== expectedNames.toSorted()[index])
  ) {
    return fail();
  }
};

const readBounded = async (file: FileHandle): Promise<Uint8Array> => {
  const chunks: Uint8Array[] = [];
  let total = 0;
  let position = 0;

  while (total <= phase1ArtifactMaximumBytes) {
    const remaining = phase1ArtifactMaximumBytes + 1 - total;
    const buffer = new Uint8Array(Math.min(64 * 1024, remaining));
    const { bytesRead } = await file.read(buffer, 0, buffer.byteLength, position);

    if (bytesRead === 0) {
      break;
    }
    total += bytesRead;
    position += bytesRead;
    chunks.push(buffer.subarray(0, bytesRead));
  }
  if (total < 1 || total > phase1ArtifactMaximumBytes) {
    return fail();
  }

  return Buffer.concat(chunks);
};

const readEvidenceFile = async (
  descriptorPath: string,
  name: Phase1EvidenceFileName,
  mode: Phase1ArtifactMode
): Promise<EvidenceFileSnapshot> => {
  const filePath = path.join(descriptorPath, name);
  const file = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);

  try {
    const before = await file.stat({ bigint: true });

    if (!secureFileState(before)) {
      return fail();
    }
    const bytes = await readBounded(file);
    const value = parseStrictPhase1ArtifactJson(bytes);

    assertPhase1PublicArtifactValue(value);
    if (
      !isArtifactRecord(value) ||
      value.schemaVersion !== 1 ||
      value.mode !== mode ||
      value.sanitizerSuccess !== true
    ) {
      return fail();
    }
    const after = await file.stat({ bigint: true });
    const pathState = await lstat(filePath, { bigint: true });

    if (
      !secureFileState(after) ||
      !secureFileState(pathState) ||
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      after.dev !== pathState.dev ||
      after.ino !== pathState.ino ||
      BigInt(bytes.byteLength) !== after.size
    ) {
      return fail();
    }
    const sha256 = hashPhase1ArtifactBytes(bytes);

    return Object.freeze({
      identity: Object.freeze({ dev: after.dev, ino: after.ino }),
      bytes: Buffer.from(bytes),
      entry: Object.freeze({ path: name, sha256, size: bytes.byteLength }),
    });
  } finally {
    await file.close();
  }
};

const validatePublishedFile = async (
  descriptorPath: string,
  name: string,
  expectedBytes: Uint8Array,
  expectedIdentity?: FileIdentity
): Promise<FileIdentity> => {
  const filePath = path.join(descriptorPath, name);
  const file = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);

  try {
    const state = await file.stat({ bigint: true });

    if (
      !secureFileState(state) ||
      (expectedIdentity !== undefined && !sameIdentity(state, expectedIdentity))
    ) {
      return fail();
    }
    const bytes = await readBounded(file);

    if (!Buffer.from(bytes).equals(Buffer.from(expectedBytes))) {
      return fail();
    }

    return Object.freeze({ dev: state.dev, ino: state.ino });
  } finally {
    await file.close();
  }
};

const publishJson = async (
  descriptorPath: string,
  directory: FileHandle,
  name: typeof phase1EvidenceManifestName | typeof phase1HarnessResultName,
  value: JsonValue
): Promise<Readonly<{ bytes: Uint8Array; identity: FileIdentity }>> => {
  const bytes = canonicalPhase1ArtifactBytes(value);
  const temporaryName = `.${name}.${randomBytes(12).toString('hex')}.tmp`;
  const temporaryPath = path.join(descriptorPath, temporaryName);
  const finalPath = path.join(descriptorPath, name);
  let temporaryPresent = false;
  let finalPresent = false;
  let completed = false;

  try {
    const temporary = await open(
      temporaryPath,
      constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY,
      0o600
    );
    temporaryPresent = true;
    let identity: FileIdentity;

    try {
      await temporary.writeFile(bytes);
      await temporary.sync();
      const state = await temporary.stat({ bigint: true });

      if (!secureFileState(state) || BigInt(bytes.byteLength) !== state.size) {
        return fail();
      }
      identity = Object.freeze({ dev: state.dev, ino: state.ino });
    } finally {
      await temporary.close();
    }
    await link(temporaryPath, finalPath);
    finalPresent = true;
    await unlink(temporaryPath);
    temporaryPresent = false;
    await directory.sync();
    await validatePublishedFile(descriptorPath, name, bytes, identity);
    completed = true;

    return Object.freeze({ bytes: Buffer.from(bytes), identity });
  } finally {
    if (temporaryPresent) {
      await unlink(temporaryPath).catch(() => {});
    }
    if (finalPresent && !completed) {
      await rm(finalPath, { force: true }).catch(() => {});
    }
  }
};

export const parsePhase1EvidenceManifestBytes = (bytes: Uint8Array): Phase1EvidenceManifest => {
  try {
    const value = parseStrictPhase1ArtifactJson(bytes);

    assertPhase1PublicArtifactValue(value);
    if (
      !isArtifactRecord(value) ||
      !exactArtifactKeys(value, ['schemaVersion', 'mode', 'files']) ||
      value.schemaVersion !== 1 ||
      !phase1ArtifactModes.includes(value.mode as Phase1ArtifactMode) ||
      !Array.isArray(value.files) ||
      value.files.length !== phase1EvidenceFileNames.length
    ) {
      return fail();
    }
    const files = value.files.map((entry, index): Phase1EvidenceManifestEntry => {
      const expectedPath = phase1EvidenceFileNames[index];

      if (
        !expectedPath ||
        !isArtifactRecord(entry) ||
        !exactArtifactKeys(entry, ['path', 'sha256', 'size']) ||
        entry.path !== expectedPath ||
        typeof entry.sha256 !== 'string' ||
        !sha256Pattern.test(entry.sha256) ||
        !Number.isSafeInteger(entry.size) ||
        Number(entry.size) < 1 ||
        Number(entry.size) > phase1ArtifactMaximumBytes
      ) {
        return fail();
      }

      return Object.freeze({ path: expectedPath, sha256: entry.sha256, size: Number(entry.size) });
    });

    return cloneAndDeepFreeze({
      schemaVersion: 1 as const,
      mode: value.mode as Phase1ArtifactMode,
      files,
    });
  } catch {
    return fail();
  }
};

const rereadAuthority = async (
  authority: ManifestAuthority,
  includeHarnessResult = false
): Promise<ManifestAuthority> =>
  withDirectory(authority.root, async (descriptorPath) => {
    await requireExactTree(descriptorPath, [
      ...phase1EvidenceFileNames,
      phase1EvidenceManifestName,
      ...(includeHarnessResult ? [phase1HarnessResultName] : []),
    ]);
    const evidence = new Map<Phase1EvidenceFileName, EvidenceFileSnapshot>();

    for (const entry of authority.manifest.files) {
      const snapshot = await readEvidenceFile(descriptorPath, entry.path, authority.manifest.mode);
      const expected = authority.evidence.get(entry.path);

      if (
        !expected ||
        !sameIdentity(snapshot.identity, expected.identity) ||
        snapshot.entry.sha256 !== entry.sha256 ||
        snapshot.entry.size !== entry.size ||
        !Buffer.from(snapshot.bytes).equals(Buffer.from(expected.bytes))
      ) {
        return fail();
      }
      evidence.set(entry.path, snapshot);
    }
    await validatePublishedFile(
      descriptorPath,
      phase1EvidenceManifestName,
      authority.manifestBytes
    );

    return Object.freeze({ ...authority, evidence });
  });

export const writePhase1EvidenceManifest = async (
  evidenceDirectory: string,
  mode: Phase1ArtifactMode,
  hooks: Phase1EvidenceManifestTestHooks = {}
): Promise<Phase1EvidenceManifestArtifact> => {
  try {
    if (!phase1ArtifactModes.includes(mode)) {
      return fail();
    }
    const authority = await withDirectory(
      evidenceDirectory,
      async (descriptorPath, _identity, directory) => {
        await requireExactTree(descriptorPath, phase1EvidenceFileNames);
        const evidence = new Map<Phase1EvidenceFileName, EvidenceFileSnapshot>();

        for (const name of phase1EvidenceFileNames) {
          evidence.set(name, await readEvidenceFile(descriptorPath, name, mode));
        }
        await hooks.afterEvidenceRead?.();
        const manifest = cloneAndDeepFreeze({
          schemaVersion: 1 as const,
          mode,
          files: phase1EvidenceFileNames.map((name) => evidence.get(name)?.entry ?? fail()),
        });
        const publication = await publishJson(
          descriptorPath,
          directory,
          phase1EvidenceManifestName,
          manifest
        );
        await hooks.afterPublication?.();
        await requireExactTree(descriptorPath, [
          ...phase1EvidenceFileNames,
          phase1EvidenceManifestName,
        ]);
        const parsed = parsePhase1EvidenceManifestBytes(publication.bytes);

        if (!isDeepStrictEqual(parsed, manifest)) {
          return fail();
        }

        return Object.freeze({
          root: evidenceDirectory,
          manifest,
          manifestBytes: publication.bytes,
          evidence,
        });
      }
    );
    const verified = await rereadAuthority(authority);
    const artifact = Object.freeze({
      outputPath: path.join(evidenceDirectory, phase1EvidenceManifestName),
      mode,
      sha256: hashPhase1ArtifactBytes(verified.manifestBytes),
      uploadable: mode !== 'review-candidate',
    });

    manifestAuthorities.set(artifact, verified);

    return artifact;
  } catch {
    await rm(path.join(evidenceDirectory, phase1EvidenceManifestName), { force: true }).catch(
      () => {}
    );
    return fail();
  }
};

export const loadPhase1EvidenceManifestFromDisk = async (
  input: LoadPhase1EvidenceManifestInput
): Promise<Phase1EvidenceManifestArtifact> => {
  try {
    if (
      !phase1ArtifactModes.includes(input.mode) ||
      input.manifestPath !== path.join(input.directory, phase1EvidenceManifestName)
    ) {
      return fail();
    }
    const authority = await withDirectory(input.directory, async (descriptorPath) => {
      await requireExactTree(descriptorPath, [
        ...phase1EvidenceFileNames,
        phase1EvidenceManifestName,
      ]);
      const manifestFile = await open(
        path.join(descriptorPath, phase1EvidenceManifestName),
        constants.O_RDONLY | constants.O_NOFOLLOW
      );
      let manifestBytes: Uint8Array;

      try {
        const state = await manifestFile.stat({ bigint: true });

        if (!secureFileState(state)) {
          return fail();
        }
        manifestBytes = await readBounded(manifestFile);
      } finally {
        await manifestFile.close();
      }
      const manifest = parsePhase1EvidenceManifestBytes(manifestBytes);

      if (manifest.mode !== input.mode) {
        return fail();
      }
      const evidence = new Map<Phase1EvidenceFileName, EvidenceFileSnapshot>();

      for (const entry of manifest.files) {
        const snapshot = await readEvidenceFile(descriptorPath, entry.path, input.mode);

        if (snapshot.entry.sha256 !== entry.sha256 || snapshot.entry.size !== entry.size) {
          return fail();
        }
        evidence.set(entry.path, snapshot);
      }

      return Object.freeze({
        root: input.directory,
        manifest,
        manifestBytes: Buffer.from(manifestBytes),
        evidence,
      });
    });
    const verified = await rereadAuthority(authority);
    const artifact = Object.freeze({
      outputPath: input.manifestPath,
      mode: input.mode,
      sha256: hashPhase1ArtifactBytes(verified.manifestBytes),
      uploadable: input.mode !== 'review-candidate',
    });

    manifestAuthorities.set(artifact, verified);

    return artifact;
  } catch {
    return fail();
  }
};

export const assertPhase1EvidenceManifestUploadable = (
  artifact: Phase1EvidenceManifestArtifact
): void => {
  if (!manifestAuthorities.has(artifact) || !artifact.uploadable) {
    return fail();
  }
};

export const readPhase1EvidenceManifestArtifactForHarnessResult = async (
  artifact: Phase1EvidenceManifestArtifact,
  includeHarnessResult = false
): Promise<
  Readonly<{
    root: string;
    manifest: Phase1EvidenceManifest;
    manifestBytes: Uint8Array;
    evidenceBytes: Readonly<Record<Phase1EvidenceFileName, Uint8Array>>;
  }>
> => {
  try {
    const authority = manifestAuthorities.get(artifact);

    if (!authority) {
      return fail();
    }
    const verified = await rereadAuthority(authority, includeHarnessResult);
    const evidenceBytes: Record<Phase1EvidenceFileName, Uint8Array> = {
      'phase-1-browser.json': Buffer.from(
        verified.evidence.get('phase-1-browser.json')?.bytes ?? fail()
      ),
      'phase-1-candidate-invariants.json': Buffer.from(
        verified.evidence.get('phase-1-candidate-invariants.json')?.bytes ?? fail()
      ),
      'phase-1-conformance.json': Buffer.from(
        verified.evidence.get('phase-1-conformance.json')?.bytes ?? fail()
      ),
      'phase-1-differential.json': Buffer.from(
        verified.evidence.get('phase-1-differential.json')?.bytes ?? fail()
      ),
    };

    return Object.freeze({
      root: verified.root,
      manifest: verified.manifest,
      manifestBytes: Buffer.from(verified.manifestBytes),
      evidenceBytes: Object.freeze(evidenceBytes),
    });
  } catch {
    return fail();
  }
};

const parseManifestCliArguments = (
  arguments_: readonly string[]
): LoadPhase1EvidenceManifestInput => {
  const values = new Map<string, string>();

  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];

    if (
      !flag ||
      !['--mode', '--directory', '--output'].includes(flag) ||
      flag.includes('=') ||
      !value ||
      value.startsWith('--') ||
      values.has(flag)
    ) {
      return fail();
    }
    values.set(flag, value);
  }
  const mode = values.get('--mode');
  const directory = values.get('--directory');
  const output = values.get('--output');

  if (
    values.size !== 3 ||
    !phase1ArtifactModes.includes(mode as Phase1ArtifactMode) ||
    !directory ||
    !path.isAbsolute(directory) ||
    path.resolve(directory) !== directory ||
    output !== path.join(directory, phase1EvidenceManifestName)
  ) {
    return fail();
  }

  return Object.freeze({ mode: mode as Phase1ArtifactMode, directory, manifestPath: output });
};

export const runPhase1EvidenceManifestCli = async (
  arguments_: readonly string[] = process.argv.slice(2)
): Promise<number> => {
  try {
    const command = parseManifestCliArguments(arguments_);
    const artifact = await writePhase1EvidenceManifest(command.directory, command.mode);
    const reloaded = await loadPhase1EvidenceManifestFromDisk(command);

    if (artifact.sha256 !== reloaded.sha256) {
      return fail();
    }

    return 0;
  } catch {
    return 1;
  }
};

const isMainModule =
  process.argv[1]?.replaceAll('\\', '/').endsWith('/compatibility/phase-1/evidence-manifest.js') ===
  true;

if (isMainModule) {
  const exitCode = await runPhase1EvidenceManifestCli();

  if (exitCode !== 0) {
    console.error(diagnostic);
    process.exitCode = exitCode;
  }
}

/* eslint-enable max-lines, complexity, no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-bitwise, @typescript-eslint/no-empty-function */
