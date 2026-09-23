/* eslint-disable no-await-in-loop, unicorn/consistent-function-scoping, @silverhand/fp/no-mutating-methods -- The closure mutation matrix iterates independent rejected graphs and compares deterministic sorted fixture keys. */
import { createHash } from 'node:crypto';

import {
  acceptedPhase1ExecutionRoots,
  buildAcceptedPhase1SourceClosureManifest,
  createAcceptedPhase1SourceClosureManifest,
  runtimeValueImportSpecifiers,
  type Phase1SourceClosureReader,
} from './source-closure.js';

const blob = (source: string) =>
  createHash('sha1')
    .update(`blob ${Buffer.byteLength(source)}\0${source}`)
    .digest('hex');

const reader =
  (files: Readonly<Record<string, string>>): Phase1SourceClosureReader =>
  async (file) => {
    const source = files[file];

    if (source === undefined) {
      throw new Error('missing');
    }

    return Object.freeze({ path: file, source, blobId: blob(source) });
  };

describe('Phase 2 accepted Phase 1 source closure', () => {
  it('includes only runtime value import edges', () => {
    expect(
      runtimeValueImportSpecifiers(`
import type { A } from './type-only.js';
import { type B, C } from './mixed.js';
import { type D } from './mixed-type-only.js';
import DefaultValue, { type E } from './default-value.js';
import * as Namespace from './namespace.js';
import './side-effect.js';
export type { F } from './export-type.js';
export { type G, H } from './export-mixed.js';
export * from './export-all.js';
await import('./literal-dynamic.js');
await import(variable);
import 'node:fs';
import 'external-package';
`)
    ).toEqual([
      './mixed.js',
      './default-value.js',
      './namespace.js',
      './side-effect.js',
      './export-mixed.js',
      './export-all.js',
      './literal-dynamic.js',
    ]);
  });

  it('maps relative JavaScript specifiers to tracked TypeScript files and visits cycles once', async () => {
    const files: Readonly<Record<string, string>> = {
      'packages/integration-tests/src/compatibility/phase-1/root.ts':
        "import './child.js';\nexport { value } from './value.js';\n",
      'packages/integration-tests/src/compatibility/phase-1/child.ts':
        "import './root.js';\nexport const child = true;\n",
      'packages/integration-tests/src/compatibility/phase-1/value.ts':
        'export const value = true;\n',
    };
    const manifest = await buildAcceptedPhase1SourceClosureManifest({
      acceptedCommit: '8'.repeat(40),
      roots: ['packages/integration-tests/src/compatibility/phase-1/root.ts'],
      current: reader(files),
      accepted: reader(files),
    });

    expect(manifest.files.map(({ path }) => path)).toEqual(Object.keys(files).sort());
    expect(
      manifest.files.every(
        ({ blobId }, index) => blobId === blob(files[manifest.files[index]!.path]!)
      )
    ).toBe(true);
  });

  it.each([
    ['missing import', "import './missing.js';\n"],
    ['escaping import', "import '../../../../../../outside.js';\n"],
    ['unsupported extension', "import './child.json';\n"],
    ['extensionless relative import', "import './child';\n"],
  ])('fails closed on %s', async (_name, source) => {
    const files = {
      'packages/integration-tests/src/compatibility/phase-1/root.ts': source,
    };

    await expect(
      buildAcceptedPhase1SourceClosureManifest({
        acceptedCommit: '8'.repeat(40),
        roots: ['packages/integration-tests/src/compatibility/phase-1/root.ts'],
        current: reader(files),
        accepted: reader(files),
      })
    ).rejects.toThrow('Invalid Phase 2 accepted Phase 1 source closure');
  });

  it('rejects changed blobs and changed closure path sets', async () => {
    const accepted = {
      'packages/integration-tests/src/compatibility/phase-1/root.ts': "import './child.js';\n",
      'packages/integration-tests/src/compatibility/phase-1/child.ts':
        'export const child = true;\n',
    };
    const changedBytes = {
      ...accepted,
      'packages/integration-tests/src/compatibility/phase-1/child.ts':
        'export const child = false;\n',
    };
    const changedPaths = {
      ...accepted,
      'packages/integration-tests/src/compatibility/phase-1/root.ts':
        "import './child.js';\nimport './extra.js';\n",
      'packages/integration-tests/src/compatibility/phase-1/extra.ts':
        'export const extra = true;\n',
    };
    const input = {
      acceptedCommit: '8'.repeat(40),
      roots: ['packages/integration-tests/src/compatibility/phase-1/root.ts'],
    } as const;

    await expect(
      buildAcceptedPhase1SourceClosureManifest({
        ...input,
        current: reader(changedBytes),
        accepted: reader(accepted),
      })
    ).rejects.toThrow('Invalid Phase 2 accepted Phase 1 source closure');
    await expect(
      buildAcceptedPhase1SourceClosureManifest({
        ...input,
        current: reader(changedPaths),
        accepted: reader(accepted),
      })
    ).rejects.toThrow('Invalid Phase 2 accepted Phase 1 source closure');
  });

  it('rejects dirty, wrong-origin, wrong-head, symlinked, and Phase 1-modifying implementations', async () => {
    const validInspection = {
      head: '9'.repeat(40),
      origin: 'https://github.com/qq98982/logto.git',
      clean: true as const,
      phase1ModifiedPaths: [] as readonly string[],
    };
    const read: Phase1SourceClosureReader = async (file) =>
      Object.freeze({ path: file, source: 'export const value = true;\n', blobId: 'a'.repeat(40) });

    for (const inspection of [
      { ...validInspection, clean: false as const },
      { ...validInspection, origin: 'https://example.invalid/logto.git' },
      { ...validInspection, head: 'invalid' },
      {
        ...validInspection,
        phase1ModifiedPaths: ['packages/integration-tests/src/compatibility/phase-1/model.ts'],
      },
    ]) {
      await expect(
        createAcceptedPhase1SourceClosureManifest('/repo', {
          inspect: async () => inspection,
          readAccepted: read,
          readCurrent: read,
        })
      ).rejects.toThrow('Invalid Phase 2 accepted Phase 1 source closure');
    }
    await expect(
      createAcceptedPhase1SourceClosureManifest('/repo', {
        inspect: async () => validInspection,
        readAccepted: read,
        readCurrent: async (file) => ({ ...(await read(file)), symbolicLink: true }),
      })
    ).rejects.toThrow('Invalid Phase 2 accepted Phase 1 source closure');
  });

  it('declares the complete accepted execution roots without test files', () => {
    expect(acceptedPhase1ExecutionRoots).toEqual([...acceptedPhase1ExecutionRoots].sort());
    expect(acceptedPhase1ExecutionRoots).toContain(
      'packages/integration-tests/src/compatibility/phase-1/scenarios/index.ts'
    );
    expect(acceptedPhase1ExecutionRoots).toContain(
      'packages/integration-tests/src/compatibility/phase-1/differential/session.ts'
    );
    expect(acceptedPhase1ExecutionRoots).toContain(
      'packages/integration-tests/src/compatibility/phase-1/differential/runtime.ts'
    );
    expect(acceptedPhase1ExecutionRoots.some((file) => file.endsWith('.test.ts'))).toBe(false);
  });
});

/* eslint-enable no-await-in-loop, unicorn/consistent-function-scoping, @silverhand/fp/no-mutating-methods */
