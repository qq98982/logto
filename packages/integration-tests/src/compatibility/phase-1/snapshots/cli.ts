/* eslint-disable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The closed CLI parser and process exit assignment form one boundary. */
import {
  assertExactPhase1ArtifactTree,
  readPreparedMirrorRecord,
  writePreparedMirrorRecord,
  type Phase1ArtifactStage,
} from './artifacts.js';

const diagnostic = 'Phase 1 snapshot command failed.';

const flagMap = (arguments_: readonly string[]): ReadonlyMap<string, string> => {
  const result = new Map<string, string>();

  for (let index = 0; index < arguments_.length; index += 2) {
    const key = arguments_[index];
    const value = arguments_[index + 1];

    if (!key?.startsWith('--') || !value || value.startsWith('--') || result.has(key)) {
      throw new TypeError(diagnostic);
    }
    result.set(key, value);
  }

  return result;
};

export const runSnapshotCli = async (
  arguments_: readonly string[] = process.argv.slice(2)
): Promise<number> => {
  try {
    const [command, ...rest] = arguments_;
    const flags = flagMap(rest);

    if (command === 'write-prepared-mirror' && flags.size === 3) {
      await writePreparedMirrorRecord(
        flags.get('--output') ?? '',
        flags.get('--source-commit') ?? '',
        flags.get('--image-digest') ?? ''
      );
      return 0;
    }
    if (command === 'verify-artifacts' && flags.size === 2) {
      const stage = flags.get('--stage');

      if (stage !== 'evidence' && stage !== 'manifest' && stage !== 'final') {
        throw new TypeError(diagnostic);
      }
      await assertExactPhase1ArtifactTree(
        flags.get('--directory') ?? '',
        stage as Phase1ArtifactStage
      );
      return 0;
    }
    if (command === 'verify-prepared-mirror' && flags.size === 3) {
      const record = await readPreparedMirrorRecord(flags.get('--input') ?? '');

      if (
        record.sourceCommit !== flags.get('--source-commit') ||
        record.imageDigest !== flags.get('--image-digest')
      ) {
        throw new TypeError(diagnostic);
      }
      return 0;
    }
    throw new TypeError(diagnostic);
  } catch {
    console.error(diagnostic);
    return 1;
  }
};

if (process.argv[1]?.replaceAll('\\', '/').endsWith('/phase-1/snapshots/cli.js') === true) {
  process.exitCode = await runSnapshotCli();
}

/* eslint-enable complexity, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
