/* eslint-disable no-await-in-loop, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Hostile manifest cases mutate isolated JSON fixtures and exercise sequential CLI rejection. */
import { execFile } from 'node:child_process';
import {
  chmod,
  link,
  lstat,
  mkdir,
  readFile,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import { phase1EvidenceFileNames, type Phase1ArtifactMode } from './artifact-contract.js';
import {
  parsePhase1EvidenceManifestBytes,
  readPhase1EvidenceManifestArtifactForHarnessResult,
  runPhase1EvidenceManifestCli,
  writePhase1EvidenceManifest,
} from './evidence-manifest.js';

const roots = new Set<string>();
const executeFile = promisify(execFile);

const createRoot = async () => {
  const root = path.join('/var/tmp/henry-build', `phase1-manifest-${process.pid}-${Date.now()}`);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  roots.add(root);
  return root;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

const evidenceValue = (mode: Phase1ArtifactMode, name: string) => ({
  schemaVersion: 1,
  mode,
  provenance: {
    harnessCommit: 'a'.repeat(40),
    profileSha256: 'b'.repeat(64),
    schemaSha256: 'c'.repeat(64),
    imageDigest: `sha256:${'d'.repeat(64)}`,
  },
  sanitizerSuccess: true,
  value: { name, accepted: true },
});

const writeEvidenceTree = async (root: string, mode: Phase1ArtifactMode = 'mirror-control') => {
  await Promise.all(
    phase1EvidenceFileNames.map(async (name) =>
      writeFile(path.join(root, name), `${JSON.stringify(evidenceValue(mode, name))}\n`, {
        mode: 0o600,
      })
    )
  );
};

describe('Phase 1 evidence manifest', () => {
  it('publishes the exact sorted four-file manifest from descriptor-pinned bytes', async () => {
    const root = await createRoot();
    await writeEvidenceTree(root);
    const artifact = await writePhase1EvidenceManifest(root, 'mirror-control');
    const parsed = parsePhase1EvidenceManifestBytes(await readFile(artifact.outputPath));

    expect(parsed.files.map(({ path: filePath }) => filePath)).toEqual(phase1EvidenceFileNames);
    expect(parsed.files.every(({ size }) => size > 0 && size <= 1024 * 1024)).toBe(true);
    expect(parsed.files.every(({ sha256 }) => /^[0-9a-f]{64}$/u.test(sha256))).toBe(true);
    expect(artifact.uploadable).toBe(true);
    const state = await lstat(artifact.outputPath);
    expect(state.mode % 0o1000).toBe(0o600);
    expect(state.nlink).toBe(1);
  });

  it.each([
    [
      'missing',
      (value: Record<string, unknown>) => {
        (value.files as unknown[]).pop();
        return value;
      },
    ],
    [
      'extra',
      (value: Record<string, unknown>) => {
        (value.files as unknown[]).push({
          path: 'extra.json',
          sha256: 'e'.repeat(64),
          size: 1,
        });
        return value;
      },
    ],
    [
      'reordered',
      (value: Record<string, unknown>) => {
        (value.files as unknown[]).reverse();
        return value;
      },
    ],
    [
      'duplicate',
      (value: Record<string, unknown>) => {
        (value.files as unknown[])[1] = structuredClone((value.files as unknown[])[0]);
        return value;
      },
    ],
    [
      'traversal',
      (value: Record<string, unknown>) => {
        (value.files as Array<Record<string, unknown>>)[0]!.path = '../private.json';
        return value;
      },
    ],
    [
      'absolute',
      (value: Record<string, unknown>) => {
        (value.files as Array<Record<string, unknown>>)[0]!.path = '/private.json';
        return value;
      },
    ],
  ] as const)('rejects a %s manifest with one fixed diagnostic', async (_name, mutate) => {
    const root = await createRoot();
    await writeEvidenceTree(root);
    const artifact = await writePhase1EvidenceManifest(root, 'mirror-control');
    const value = JSON.parse(await readFile(artifact.outputPath, 'utf8')) as Record<
      string,
      unknown
    >;
    const bytes = Buffer.from(`${JSON.stringify(mutate(value))}\n`);

    expect(() => parsePhase1EvidenceManifestBytes(bytes)).toThrow(
      /^Invalid phase 1 evidence manifest$/u
    );
  });

  it('rejects missing extra symlink and hard-linked evidence trees', async () => {
    const missing = await createRoot();
    await writeEvidenceTree(missing);
    await unlink(path.join(missing, phase1EvidenceFileNames[0]));
    await expect(writePhase1EvidenceManifest(missing, 'mirror-control')).rejects.toThrow(
      /^Invalid phase 1 evidence manifest$/u
    );

    const extra = await createRoot();
    await writeEvidenceTree(extra);
    await writeFile(path.join(extra, 'extra.json'), '{}\n', { mode: 0o600 });
    await expect(writePhase1EvidenceManifest(extra, 'mirror-control')).rejects.toThrow(
      /^Invalid phase 1 evidence manifest$/u
    );

    const symbolic = await createRoot();
    await writeEvidenceTree(symbolic);
    const symbolicPath = path.join(symbolic, phase1EvidenceFileNames[0]);
    await unlink(symbolicPath);
    await symlink(path.join(symbolic, phase1EvidenceFileNames[1]), symbolicPath);
    await expect(writePhase1EvidenceManifest(symbolic, 'mirror-control')).rejects.toThrow(
      /^Invalid phase 1 evidence manifest$/u
    );

    const hard = await createRoot();
    await writeEvidenceTree(hard);
    await link(path.join(hard, phase1EvidenceFileNames[0]), path.join(hard, 'private-hard-link'));
    await expect(writePhase1EvidenceManifest(hard, 'mirror-control')).rejects.toThrow(
      /^Invalid phase 1 evidence manifest$/u
    );
  });

  it('rejects sensitive values hash-size mutation and an after-hash race', async () => {
    const sensitive = await createRoot();
    await writeEvidenceTree(sensitive);
    await writeFile(
      path.join(sensitive, phase1EvidenceFileNames[0]),
      `${JSON.stringify({
        ...evidenceValue('mirror-control', 'sensitive'),
        value: 'Bearer private-material',
      })}\n`,
      { mode: 0o600 }
    );
    await expect(writePhase1EvidenceManifest(sensitive, 'mirror-control')).rejects.toThrow(
      /^Invalid phase 1 evidence manifest$/u
    );

    const mutated = await createRoot();
    await writeEvidenceTree(mutated);
    const artifact = await writePhase1EvidenceManifest(mutated, 'mirror-control');
    await writeFile(
      path.join(mutated, phase1EvidenceFileNames[0]),
      `${JSON.stringify(evidenceValue('mirror-control', 'changed-after-manifest'))}\n`,
      { mode: 0o600 }
    );
    await expect(readPhase1EvidenceManifestArtifactForHarnessResult(artifact)).rejects.toThrow(
      /^Invalid phase 1 evidence manifest$/u
    );

    const raced = await createRoot();
    await writeEvidenceTree(raced);
    await expect(
      writePhase1EvidenceManifest(raced, 'mirror-control', {
        afterEvidenceRead: async () =>
          writeFile(
            path.join(raced, phase1EvidenceFileNames[0]),
            `${JSON.stringify(evidenceValue('mirror-control', 'raced'))}\n`,
            { mode: 0o600 }
          ),
      })
    ).rejects.toThrow(/^Invalid phase 1 evidence manifest$/u);
  });

  it('marks review-candidate output nonuploadable', async () => {
    const root = await createRoot();
    await writeEvidenceTree(root, 'review-candidate');
    const artifact = await writePhase1EvidenceManifest(root, 'review-candidate');

    expect(artifact.uploadable).toBe(false);
  });

  it('enforces the exact manifest CLI grammar and output directory', async () => {
    const root = await createRoot();
    await writeEvidenceTree(root);
    const output = path.join(root, 'evidence-manifest.json');
    const valid = ['--mode', 'mirror-control', '--directory', root, '--output', output];

    for (const invalid of [
      valid.slice(0, -2),
      [...valid, '--extra', 'value'],
      [...valid, '--mode', 'mirror-control'],
      ['--mode=mirror-control', '--directory', root, '--output', output],
      [
        '--mode',
        'mirror-control',
        '--directory',
        root,
        '--output',
        path.join(path.dirname(root), 'evidence-manifest.json'),
      ],
    ]) {
      await expect(runPhase1EvidenceManifestCli(invalid)).resolves.toBe(1);
    }
  });

  it('publishes and verifies the manifest in a separate process', async () => {
    const root = await createRoot();
    await writeEvidenceTree(root);
    const output = path.join(root, 'evidence-manifest.json');
    const cliPath = path.resolve(process.cwd(), 'lib/compatibility/phase-1/evidence-manifest.js');

    await expect(
      executeFile(
        process.execPath,
        [cliPath, '--mode', 'mirror-control', '--directory', root, '--output', output],
        { env: { NODE_ENV: 'production', PATH: '/usr/bin:/bin' } }
      )
    ).resolves.toMatchObject({ stdout: '', stderr: '' });
    expect(parsePhase1EvidenceManifestBytes(await readFile(output)).files).toHaveLength(4);
  });
});

/* eslint-enable no-await-in-loop, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
