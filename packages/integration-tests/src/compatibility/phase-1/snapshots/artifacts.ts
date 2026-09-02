/* eslint-disable complexity, no-bitwise, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition, unicorn/no-await-expression-member, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This closed filesystem boundary performs descriptor flags, exact stage narrowing, rollback state, and readonly conversion. */
import { constants } from 'node:fs';
import { lstat, open, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';

import {
  phase1EvidenceFileNames,
  phase1EvidenceManifestName,
  phase1HarnessResultName,
  parseStrictPhase1ArtifactJson,
} from '../artifact-contract.js';
import { oracleCommit } from '../model.js';
import {
  createSecureEvidenceSink,
  rollbackSecureJsonArtifact,
  writeSecureJsonArtifact,
  type SecureJsonPublication,
} from '../secure-evidence-sink.js';

export const phase1EvidenceArtifactNames = phase1EvidenceFileNames;
export const phase1ManifestArtifactNames = Object.freeze([
  ...phase1EvidenceArtifactNames,
  phase1EvidenceManifestName,
] as const);
export const phase1FinalArtifactNames = Object.freeze([
  ...phase1ManifestArtifactNames,
  phase1HarnessResultName,
] as const);

export type Phase1ArtifactStage = 'evidence' | 'manifest' | 'final';

const diagnostic = 'Invalid phase 1 lifecycle artifact tree';
const digestPattern = /^sha256:[0-9a-f]{64}$/u;

export type PreparedMirrorRecord = Readonly<{
  sourceCommit: typeof oracleCommit;
  imageDigest: string;
}>;

const expectedForStage = (stage: Phase1ArtifactStage): readonly string[] => {
  if (stage === 'evidence') {
    return phase1EvidenceArtifactNames;
  }
  if (stage === 'manifest') {
    return phase1ManifestArtifactNames;
  }
  if (stage === 'final') {
    return phase1FinalArtifactNames;
  }
  throw new TypeError(diagnostic);
};

export const assertExactPhase1ArtifactTree = async (
  directory: string,
  stage: Phase1ArtifactStage
): Promise<readonly string[]> => {
  try {
    if (!path.isAbsolute(directory) || path.resolve(directory) !== directory) {
      throw new TypeError(diagnostic);
    }
    const state = await lstat(directory);

    if (
      state.isSymbolicLink() ||
      !state.isDirectory() ||
      state.mode % 0o1000 !== 0o700 ||
      (typeof process.getuid === 'function' && state.uid !== process.getuid()) ||
      (await realpath(directory)) !== directory
    ) {
      throw new TypeError(diagnostic);
    }
    const expected = expectedForStage(stage);
    const names = (await readdir(directory)).toSorted();

    if (JSON.stringify(names) !== JSON.stringify(expected)) {
      throw new TypeError(diagnostic);
    }
    const sink = await createSecureEvidenceSink(directory, expected);
    const paths = await sink.scan();

    return Object.freeze(paths);
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const writePreparedMirrorRecord = async (
  outputPath: string,
  sourceCommit: string,
  imageDigest: string
): Promise<SecureJsonPublication> => {
  let publication: SecureJsonPublication | undefined;

  try {
    if (sourceCommit !== oracleCommit || !digestPattern.test(imageDigest)) {
      throw new TypeError(diagnostic);
    }
    publication = await writeSecureJsonArtifact(outputPath, {
      sourceCommit: oracleCommit,
      imageDigest,
    });
    const parsed = JSON.parse(await readFile(publication.path, 'utf8')) as unknown;

    if (
      !parsed ||
      typeof parsed !== 'object' ||
      Array.isArray(parsed) ||
      Reflect.ownKeys(parsed).length !== 2 ||
      Reflect.get(parsed, 'sourceCommit') !== oracleCommit ||
      Reflect.get(parsed, 'imageDigest') !== imageDigest
    ) {
      throw new TypeError(diagnostic);
    }

    return publication;
  } catch {
    if (publication) {
      await rollbackSecureJsonArtifact(publication).catch(() => false);
    }
    throw new TypeError(diagnostic);
  }
};

export const readPreparedMirrorRecord = async (
  inputPath: string
): Promise<PreparedMirrorRecord> => {
  try {
    if (!path.isAbsolute(inputPath) || path.resolve(inputPath) !== inputPath) {
      throw new TypeError(diagnostic);
    }
    const handle = await open(inputPath, constants.O_RDONLY | constants.O_NOFOLLOW);

    try {
      const before = await handle.stat({ bigint: true });

      if (
        !before.isFile() ||
        Number(before.nlink) !== 1 ||
        Number(before.mode) % 0o1000 !== 0o600 ||
        Number(before.size) < 1 ||
        Number(before.size) > 1024 * 1024 ||
        (typeof process.getuid === 'function' && Number(before.uid) !== process.getuid()) ||
        (await realpath(inputPath)) !== inputPath
      ) {
        throw new TypeError(diagnostic);
      }
      const bytes = await handle.readFile();
      const after = await handle.stat({ bigint: true });

      if (
        before.dev !== after.dev ||
        before.ino !== after.ino ||
        before.size !== after.size ||
        before.ctimeNs !== after.ctimeNs ||
        bytes.byteLength !== Number(before.size)
      ) {
        throw new TypeError(diagnostic);
      }
      const value = parseStrictPhase1ArtifactJson(bytes);

      if (
        !value ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Reflect.ownKeys(value).length !== 2 ||
        Reflect.get(value, 'sourceCommit') !== oracleCommit ||
        typeof Reflect.get(value, 'imageDigest') !== 'string' ||
        !digestPattern.test(Reflect.get(value, 'imageDigest') as string)
      ) {
        throw new TypeError(diagnostic);
      }

      return Object.freeze({
        sourceCommit: oracleCommit,
        imageDigest: Reflect.get(value, 'imageDigest') as string,
      });
    } finally {
      await handle.close();
    }
  } catch {
    throw new TypeError(diagnostic);
  }
};

/* eslint-enable complexity, no-bitwise, no-restricted-syntax, @typescript-eslint/no-unnecessary-condition, unicorn/no-await-expression-member, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
