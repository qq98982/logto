/* eslint-disable unicorn/no-await-expression-member, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutation -- Filesystem assertions and one isolated corrupted JSON clone model immutable-store failures. */
import { chmod, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { oracleCommit } from '../model.js';

import { createOracleSnapshotSet, oracleSnapshotIds } from './oracle.js';
import {
  loadImmutableOracleSnapshotSet,
  rollbackImmutableOracleSnapshotSet,
  writeImmutableOracleSnapshotSet,
} from './store.js';

const roots = new Set<string>();
const createRoot = async () => {
  const root = path.join(
    '/var/tmp/henry-build',
    `phase1-snapshot-store-${process.pid}-${Date.now()}-${roots.size}`
  );
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  roots.add(root);
  return root;
};

const createCustomBuildRoot = async () => {
  const buildRoot = path.join(
    '/var/tmp',
    `aster-portable-snapshot-${process.pid}-${Date.now()}-${roots.size}`
  );
  const root = path.join(buildRoot, 'private');
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(buildRoot, 0o700);
  await chmod(root, 0o700);
  roots.add(buildRoot);
  return { buildRoot, root };
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const digest = `sha256:${'1'.repeat(64)}`;
const snapshotSet = () =>
  createOracleSnapshotSet({
    recordOracle: true,
    referenceCommit: oracleCommit,
    imageDigest: digest,
    harnessClean: true,
    sanitizerSuccess: true,
    projections: oracleSnapshotIds.map((id) => ({ id, value: { accepted: true, id } })),
  });

describe('immutable Phase 1 oracle snapshot store', () => {
  it('publishes once as owner-only read-only JSON and reloads the exact set', async () => {
    const root = await createRoot();
    const output = path.join(root, 'oracle-snapshots.json');
    const publication = await writeImmutableOracleSnapshotSet(output, snapshotSet());

    await expect(stat(publication.path)).resolves.toMatchObject({
      mode: expect.any(Number),
      nlink: 1,
    });
    expect((await stat(publication.path)).mode % 0o1000).toBe(0o400);
    await expect(loadImmutableOracleSnapshotSet(publication.path)).resolves.toEqual(snapshotSet());
    await expect(writeImmutableOracleSnapshotSet(output, snapshotSet())).rejects.toThrow(
      /^Invalid phase 1 oracle snapshot store$/u
    );
  });

  it('rejects writable, malformed, and integrity-changed snapshots', async () => {
    const root = await createRoot();
    const writable = path.join(root, 'writable.json');
    await writeFile(writable, `${JSON.stringify(snapshotSet())}\n`, { mode: 0o600 });
    await expect(loadImmutableOracleSnapshotSet(writable)).rejects.toThrow(
      /^Invalid phase 1 oracle snapshot store$/u
    );

    const malformed = path.join(root, 'malformed.json');
    await writeFile(malformed, '{"schemaVersion":1}\n', { mode: 0o400 });
    await expect(loadImmutableOracleSnapshotSet(malformed)).rejects.toThrow(
      /^Invalid phase 1 oracle snapshot store$/u
    );

    const validRoot = path.join(root, 'valid-root');
    await mkdir(validRoot, { mode: 0o700 });
    const valid = path.join(validRoot, 'valid.json');
    await writeImmutableOracleSnapshotSet(valid, snapshotSet());
    const changed = JSON.parse(await readFile(valid, 'utf8')) as {
      snapshots: Array<{ projectionSha256: string }>;
    };
    changed.snapshots[0]!.projectionSha256 = '0'.repeat(64);
    await chmod(valid, 0o600);
    await writeFile(valid, `${JSON.stringify(changed)}\n`);
    await chmod(valid, 0o400);
    await expect(loadImmutableOracleSnapshotSet(valid)).rejects.toThrow(
      /^Invalid phase 1 oracle snapshot store$/u
    );
  });

  it('rolls back only the exact publication identity', async () => {
    const root = await createRoot();
    const output = path.join(root, 'oracle-snapshots.json');
    const publication = await writeImmutableOracleSnapshotSet(output, snapshotSet());

    await rollbackImmutableOracleSnapshotSet(publication);
    await expect(stat(output)).rejects.toThrow();
    await expect(rollbackImmutableOracleSnapshotSet(publication)).rejects.toThrow();
  });

  it('publishes and reloads beneath an explicit custom safe build root', async () => {
    const { buildRoot, root } = await createCustomBuildRoot();
    const environment = { ASTER_PHASE1_BUILD_ROOT: buildRoot };
    const output = path.join(root, 'oracle-snapshots.json');
    const publication = await writeImmutableOracleSnapshotSet(output, snapshotSet(), environment);

    await expect(loadImmutableOracleSnapshotSet(publication.path, environment)).resolves.toEqual(
      snapshotSet()
    );
    await expect(
      loadImmutableOracleSnapshotSet(publication.path, {
        ASTER_PHASE1_BUILD_ROOT: '/var/tmp/other-build-root',
      })
    ).rejects.toThrow(/^Invalid phase 1 oracle snapshot store$/u);
  });
});

/* eslint-enable unicorn/no-await-expression-member, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutation */
