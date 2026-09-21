/* eslint-disable no-await-in-loop -- Secure publication is intentionally sequential. */
import { execFile } from 'node:child_process';
import { chmod, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import { SymbolTable } from '../../symbol-table.js';
import { canonicalPhase1ArtifactBytes } from '../artifact-contract.js';
import { createVerifiedTokenObservations } from '../evidence.js';
import { oracleCommit } from '../model.js';
import { createSecureEvidenceSink } from '../secure-evidence-sink.js';

import {
  assertExactPhase1ArtifactTree,
  phase1EvidenceArtifactNames,
  phase1FinalArtifactNames,
  phase1ManifestArtifactNames,
  readPreparedMirrorRecord,
  writePreparedMirrorRecord,
} from './artifacts.js';

const roots = new Set<string>();
const executeFile = promisify(execFile);
const expectedEvidenceNames = [
  'phase-1-browser.json',
  'phase-1-candidate-invariants.json',
  'phase-1-conformance.json',
  'phase-1-differential.json',
] as const;
const expectedManifestNames = ['evidence-manifest.json', ...expectedEvidenceNames] as const;
const expectedFinalNames = [
  'evidence-manifest.json',
  'harness-result.json',
  ...expectedEvidenceNames,
] as const;

const createRoot = async (label: string): Promise<string> => {
  const root = path.join(
    '/var/tmp/henry-build',
    `task15-${label}-${process.pid}-${Date.now()}-${roots.size}`
  );
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  roots.add(root);
  return root;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

describe('Phase 1 lifecycle artifact boundary', () => {
  it('exports frozen canonical allowlists for every lifecycle stage', () => {
    expect(phase1EvidenceArtifactNames).toEqual(expectedEvidenceNames);
    expect(phase1ManifestArtifactNames).toEqual(expectedManifestNames);
    expect(phase1FinalArtifactNames).toEqual(expectedFinalNames);
    expect(
      [phase1EvidenceArtifactNames, phase1ManifestArtifactNames, phase1FinalArtifactNames].every(
        (names) => Object.isFrozen(names)
      )
    ).toBe(true);
  });

  it('accepts exactly the four sanitized evidence files and rejects missing or extra entries', async () => {
    const root = await createRoot('artifacts');
    const sink = await createSecureEvidenceSink(root, phase1EvidenceArtifactNames);
    for (const name of phase1EvidenceArtifactNames) {
      await sink.write(name, { schemaVersion: 1, passed: true });
    }

    await expect(assertExactPhase1ArtifactTree(root, 'evidence')).resolves.toHaveLength(4);
    await writeFile(path.join(root, 'raw.log'), 'private-log', { mode: 0o600 });
    await expect(assertExactPhase1ArtifactTree(root, 'evidence')).rejects.toThrow(
      /^Invalid phase 1 lifecycle artifact tree$/u
    );
  });

  it('accepts serialized tokens only in the differential file from a fresh process', async () => {
    const verified = createVerifiedTokenObservations(
      { refresh_token: 'runtime-refresh-value' },
      {
        target: {
          label: 'oracle',
          coreUrl: 'https://oracle.example/',
          adminUrl: 'https://oracle-admin.example/',
        },
        symbols: new SymbolTable(),
      },
      { boundedClaimTimestampPaths: [], proofs: [] }
    );
    const tokenArtifact = canonicalPhase1ArtifactBytes({
      schemaVersion: 1,
      tokens: verified.tokens,
    });
    const safeArtifact = canonicalPhase1ArtifactBytes({ schemaVersion: 1, passed: true });
    const snapshotCli = path.resolve(process.cwd(), 'lib/compatibility/phase-1/snapshots/cli.js');
    const verifyFreshProcess = async (directory: string) =>
      executeFile(process.execPath, [
        snapshotCli,
        'verify-artifacts',
        '--directory',
        directory,
        '--stage',
        'evidence',
      ]);
    const acceptedRoot = await createRoot('serialized-token-accepted');

    for (const name of phase1EvidenceArtifactNames) {
      await writeFile(
        path.join(acceptedRoot, name),
        name === 'phase-1-differential.json' ? tokenArtifact : safeArtifact,
        { mode: 0o600 }
      );
    }
    await expect(verifyFreshProcess(acceptedRoot)).resolves.toMatchObject({ stderr: '' });

    const rejectedRoot = await createRoot('serialized-token-rejected');
    for (const name of phase1EvidenceArtifactNames) {
      await writeFile(
        path.join(rejectedRoot, name),
        name === 'phase-1-browser.json' ? tokenArtifact : safeArtifact,
        { mode: 0o600 }
      );
    }
    await expect(verifyFreshProcess(rejectedRoot)).rejects.toMatchObject({ code: 1 });
  });

  it('accepts manifest and final artifact stages in canonical filename order', async () => {
    const serialized = canonicalPhase1ArtifactBytes({ schemaVersion: 1, passed: true });

    for (const [stage, names] of [
      ['manifest', phase1ManifestArtifactNames],
      ['final', phase1FinalArtifactNames],
    ] as const) {
      const root = await createRoot(stage);
      for (const name of names) {
        await writeFile(path.join(root, name), serialized, { mode: 0o600 });
      }

      await expect(assertExactPhase1ArtifactTree(root, stage)).resolves.toHaveLength(names.length);

      const extraRoot = await createRoot(`${stage}-extra`);
      for (const name of names) {
        await writeFile(path.join(extraRoot, name), serialized, { mode: 0o600 });
      }
      await writeFile(path.join(extraRoot, 'unexpected.json'), serialized, { mode: 0o600 });
      await expect(assertExactPhase1ArtifactTree(extraRoot, stage)).rejects.toThrow(
        /^Invalid phase 1 lifecycle artifact tree$/u
      );

      const missingRoot = await createRoot(`${stage}-missing`);
      for (const name of names.slice(1)) {
        await writeFile(path.join(missingRoot, name), serialized, { mode: 0o600 });
      }
      await expect(assertExactPhase1ArtifactTree(missingRoot, stage)).rejects.toThrow(
        /^Invalid phase 1 lifecycle artifact tree$/u
      );
    }
  });

  it('writes only the exact pinned mirror source and canonical image ID', async () => {
    const root = await createRoot('prepared');
    const output = path.join(root, 'prepared-mirror.json');
    const digest = `sha256:${'a'.repeat(64)}`;
    const publication = await writePreparedMirrorRecord(output, oracleCommit, digest);

    expect(JSON.parse(await readFile(publication.path, 'utf8'))).toEqual({
      sourceCommit: oracleCommit,
      imageDigest: digest,
    });
    await expect(readPreparedMirrorRecord(publication.path)).resolves.toEqual({
      sourceCommit: oracleCommit,
      imageDigest: digest,
    });
    await expect(
      writePreparedMirrorRecord(path.join(root, 'bad.json'), 'b'.repeat(40), digest)
    ).rejects.toThrow(/^Invalid phase 1 lifecycle artifact tree$/u);
  });
});

/* eslint-enable no-await-in-loop */
