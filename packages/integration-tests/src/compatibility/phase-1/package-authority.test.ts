/* eslint-disable @silverhand/fp/no-delete, @silverhand/fp/no-mutation -- Each regression mutates one isolated manifest clone to exercise the public authority boundary. */
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import {
  assertPhase1IntegrationManifestDelta,
  assertPhase1IntegrationLockAuthority,
  Phase1PackageAuthorityError,
} from './package-authority.js';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const manifestPath = path.join(repositoryRoot, 'packages/integration-tests/package.json');
const phase0Commit = '40135e37201f36ac05ece1eff82e37bb6d9649f1';
const packagePath = 'packages/integration-tests/package.json';
const lockfilePath = path.join(repositoryRoot, 'pnpm-lock.yaml');
const encoder = new TextEncoder();

type MutableManifest = Record<string, unknown> & {
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};

const additions = Object.freeze({
  scripts: Object.freeze({
    'compatibility:phase1': 'node ./lib/compatibility/phase-1/cli.js',
    'test:compatibility:phase1':
      'pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/phase-1/',
  }),
  devDependencies: Object.freeze({
    '@playwright/test': '1.62.1',
    ajv: '8.20.0',
    'ajv-formats': '3.0.1',
    'jsonc-parser': '3.3.1',
    parse5: '7.2.1',
    'tough-cookie': '5.1.2',
    yaml: '2.9.0',
  }),
});

const authorities = async () => {
  const [{ stdout }, harnessBytes] = await Promise.all([
    executeFile('git', ['show', `${phase0Commit}:${packagePath}`], {
      cwd: repositoryRoot,
      encoding: 'buffer',
    }),
    readFile(manifestPath),
  ]);

  return Object.freeze({ baseBytes: Buffer.from(stdout), harnessBytes });
};

const mutableManifest = (bytes: Uint8Array): MutableManifest =>
  JSON.parse(Buffer.from(bytes).toString('utf8')) as MutableManifest;

const serialize = (manifest: MutableManifest): Uint8Array =>
  encoder.encode(`${JSON.stringify(manifest, undefined, 2)}\n`);

const expectRejected = (baseBytes: Uint8Array, harnessBytes: Uint8Array): void => {
  expect(() => {
    assertPhase1IntegrationManifestDelta(baseBytes, harnessBytes);
  }).toThrow(/^Invalid Phase 1 package authority$/u);
};

describe('Phase 1 integration package authority', () => {
  it('accepts the exact Phase 0 to current manifest delta', async () => {
    const { baseBytes, harnessBytes } = await authorities();

    expect(() => {
      assertPhase1IntegrationManifestDelta(baseBytes, harnessBytes);
    }).not.toThrow();
  });

  it('requires every exact script and direct dependency addition', async () => {
    const { baseBytes, harnessBytes } = await authorities();

    for (const [section, entries] of Object.entries(additions)) {
      for (const [name, version] of Object.entries(entries)) {
        const missing = mutableManifest(harnessBytes);
        missing[section] = Object.fromEntries(
          Object.entries(missing[section] as Record<string, string>).filter(
            ([candidate]) => candidate !== name
          )
        );
        expectRejected(baseBytes, serialize(missing));

        const wrong = mutableManifest(harnessBytes);
        (wrong[section] as Record<string, string>)[name] = `${version}-changed`;
        expectRejected(baseBytes, serialize(wrong));
      }
    }
  });

  it('rejects moved and extra additions', async () => {
    const { baseBytes, harnessBytes } = await authorities();
    const moved = mutableManifest(harnessBytes);
    delete moved.devDependencies.parse5;
    moved.dependencies.parse5 = '7.2.1';
    expectRejected(baseBytes, serialize(moved));

    const extraScript = mutableManifest(harnessBytes);
    extraScript.scripts['compatibility:extra'] = 'node ./extra.js';
    expectRejected(baseBytes, serialize(extraScript));

    const extraDependency = mutableManifest(harnessBytes);
    extraDependency.devDependencies['private-extra-package'] = '1.0.0';
    expectRejected(baseBytes, serialize(extraDependency));
  });

  it('rejects mutation of every pre-existing top-level section', async () => {
    const { baseBytes, harnessBytes } = await authorities();
    const base = mutableManifest(baseBytes);

    for (const key of Object.keys(base)) {
      const mutated = mutableManifest(harnessBytes);
      const value = mutated[key];

      mutated[key] =
        typeof value === 'string'
          ? `${value}-changed`
          : typeof value === 'boolean'
            ? !value
            : Array.isArray(value)
              ? [...(value as unknown[]), 'changed']
              : value && typeof value === 'object'
                ? { ...(value as Record<string, unknown>), authorityMutation: true }
                : 'changed';
      expectRejected(baseBytes, serialize(mutated));
    }
  });

  it.each([
    ['empty', new Uint8Array()],
    ['invalid UTF-8', Uint8Array.from([0xff])],
    ['malformed JSON', encoder.encode('{"scripts":')],
    ['comment', encoder.encode('{"scripts":{},/* unsafe */"devDependencies":{}}')],
    ['trailing comma', encoder.encode('{"scripts":{},"devDependencies":{},}')],
    ['duplicate root key', encoder.encode('{"scripts":{},"scripts":{},"devDependencies":{}}')],
    [
      'duplicate nested key',
      encoder.encode('{"scripts":{"build":"one","build":"two"},"devDependencies":{}}'),
    ],
    ['array root', encoder.encode('[]')],
    ['scalar root', encoder.encode('true')],
    ['oversized input', new Uint8Array(1024 * 1024 + 1)],
  ] as const)('rejects %s bytes', async (_name, invalid) => {
    const { baseBytes, harnessBytes } = await authorities();

    expectRejected(baseBytes, invalid);
    expectRejected(invalid, harnessBytes);
  });

  it('rejects byte-order marks and dangerous keys at every object depth', async () => {
    const { baseBytes, harnessBytes } = await authorities();
    const bom = Uint8Array.from([0xef, 0xbb, 0xbf, ...harnessBytes]);
    expectRejected(baseBytes, bom);
    expectRejected(bom, harnessBytes);

    for (const key of ['__proto__', 'constructor', 'prototype']) {
      expectRejected(
        baseBytes,
        encoder.encode(`{"scripts":{},"devDependencies":{},${JSON.stringify(key)}:{"nested":true}}`)
      );
      expectRejected(
        baseBytes,
        encoder.encode(
          `{"scripts":{"safe":{"nested":true,${JSON.stringify(key)}:{}}},"devDependencies":{}}`
        )
      );
    }
  });

  it('returns fixed non-echoing diagnostics with stable authority fields', async () => {
    const { baseBytes, harnessBytes } = await authorities();
    const marker = 'private-package-authority-marker';
    const mutated = mutableManifest(harnessBytes);
    mutated[marker] = true;

    try {
      assertPhase1IntegrationManifestDelta(baseBytes, serialize(mutated));
      throw new Error('Expected package authority rejection');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Phase1PackageAuthorityError);
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 package authority',
        pointer: '/harness',
        rule: 'manifest-delta',
      });
      expect(String(error)).not.toContain(marker);
      expect((error as Error).stack).not.toContain(marker);
    }
  });
});

describe('Phase 1 integration lockfile authority', () => {
  it('accepts the exact current pnpm lockfile bytes', async () => {
    const bytes = await readFile(lockfilePath);

    expect(() => {
      assertPhase1IntegrationLockAuthority(bytes);
    }).not.toThrow();
  });

  it('rejects one-byte mutation and truncation', async () => {
    const bytes = await readFile(lockfilePath);
    const mutated = Uint8Array.from(bytes);
    const index = Math.floor(mutated.length / 2);
    mutated[index] = ((mutated[index] ?? 0) + 1) % 256;

    for (const invalid of [mutated, bytes.subarray(0, -1)]) {
      expect(() => {
        assertPhase1IntegrationLockAuthority(invalid);
      }).toThrow(/^Invalid Phase 1 package authority$/u);
    }
  });

  it('rejects oversized and non-Uint8Array inputs', () => {
    for (const invalid of [new Uint8Array(1024 * 1024 + 1), 'not-lockfile-bytes']) {
      expect(() => {
        assertPhase1IntegrationLockAuthority(invalid as Uint8Array);
      }).toThrow(/^Invalid Phase 1 package authority$/u);
    }
  });

  it('keeps lockfile diagnostics fixed and non-echoing', () => {
    const marker = 'private-lockfile-authority-marker';

    try {
      assertPhase1IntegrationLockAuthority(encoder.encode(marker));
      throw new Error('Expected lockfile authority rejection');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Phase1PackageAuthorityError);
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 package authority',
        pointer: '/lockfile',
        rule: 'lockfile-sha256',
      });
      expect(String(error)).not.toContain(marker);
      expect((error as Error).stack).not.toContain(marker);
    }
  });
});

/* eslint-enable @silverhand/fp/no-delete, @silverhand/fp/no-mutation */
