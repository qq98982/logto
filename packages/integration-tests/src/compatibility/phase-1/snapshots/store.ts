/* eslint-disable complexity, no-bitwise, no-restricted-syntax, @typescript-eslint/no-empty-function, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The immutable store owns descriptor flags, nanosecond identity checks, and rollback state across publication steps. */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import { parseStrictPhase1ArtifactJson, phase1ArtifactMaximumBytes } from '../artifact-contract.js';
import {
  requireAsterPhase1BuildPath,
  type AsterPhase1BuildRootEnvironment,
} from '../build-root.js';
import {
  rollbackSecureJsonArtifact,
  setSecureJsonArtifactMode,
  writeSecureJsonArtifact,
  type SecureJsonPublication,
} from '../secure-evidence-sink.js';

import { assertOracleSnapshotSet, type OracleSnapshotSet } from './oracle.js';

const diagnostic = 'Invalid phase 1 oracle snapshot store';

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const requireAbsoluteSnapshotPath = (
  value: string,
  environment: AsterPhase1BuildRootEnvironment
): string => {
  try {
    const resolved = requireAsterPhase1BuildPath(value, environment);

    return resolved.endsWith('.json') ? resolved : fail();
  } catch {
    return fail();
  }
};

const assertPrivateParent = async (snapshotPath: string): Promise<void> => {
  const parent = path.dirname(snapshotPath);
  const state = await lstat(parent);

  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.mode % 0o1000 !== 0o700 ||
    (typeof process.getuid === 'function' && state.uid !== process.getuid()) ||
    (await realpath(parent)) !== parent
  ) {
    return fail();
  }
};

export const loadImmutableOracleSnapshotSet = async (
  snapshotPath: string,
  environment: AsterPhase1BuildRootEnvironment = process.env
): Promise<OracleSnapshotSet> => {
  const resolved = requireAbsoluteSnapshotPath(snapshotPath, environment);
  await assertPrivateParent(resolved);
  const handle = await open(resolved, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() =>
    fail()
  );

  try {
    const before = await handle.stat({ bigint: true });

    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      Number(before.nlink) !== 1 ||
      Number(before.mode) % 0o1000 !== 0o400 ||
      before.size === 0n ||
      before.size > BigInt(phase1ArtifactMaximumBytes) ||
      (typeof process.getuid === 'function' && Number(before.uid) !== process.getuid()) ||
      (await realpath(resolved)) !== resolved
    ) {
      return fail();
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathState = await lstat(resolved, { bigint: true });

    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs ||
      pathState.dev !== after.dev ||
      pathState.ino !== after.ino ||
      pathState.size !== after.size ||
      pathState.ctimeNs !== after.ctimeNs ||
      bytes.byteLength !== Number(before.size) ||
      bytes.at(-1) !== 0x0a
    ) {
      return fail();
    }

    return assertOracleSnapshotSet(parseStrictPhase1ArtifactJson(bytes));
  } catch {
    return fail();
  } finally {
    await handle.close().catch(() => {});
  }
};

export const writeImmutableOracleSnapshotSet = async (
  snapshotPath: string,
  snapshotSet: OracleSnapshotSet,
  environment: AsterPhase1BuildRootEnvironment = process.env
): Promise<SecureJsonPublication> => {
  let publication: SecureJsonPublication | undefined;

  try {
    const resolved = requireAbsoluteSnapshotPath(snapshotPath, environment);
    await assertPrivateParent(resolved);
    const validated = assertOracleSnapshotSet(snapshotSet);
    publication = await writeSecureJsonArtifact(resolved, validated as never);
    await setSecureJsonArtifactMode(publication, 0o400);
    const reloaded = await loadImmutableOracleSnapshotSet(publication.path, environment);

    if (!isDeepStrictEqual(reloaded, validated)) {
      return fail();
    }

    return publication;
  } catch {
    if (publication) {
      await rollbackSecureJsonArtifact(publication).catch(() => {});
    }
    return fail();
  }
};

export const rollbackImmutableOracleSnapshotSet = async (
  publication: SecureJsonPublication
): Promise<void> => rollbackSecureJsonArtifact(publication);

/* eslint-enable complexity, no-bitwise, no-restricted-syntax, @typescript-eslint/no-empty-function, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
