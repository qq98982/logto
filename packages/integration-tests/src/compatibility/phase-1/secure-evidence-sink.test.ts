/* eslint-disable max-lines, no-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Adversarial publication tests deliberately mutate prototypes, input graphs, and one-use observation state inside isolated test boundaries. */
import {
  chmod,
  link,
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import { SymbolTable } from '../symbol-table.js';

import { canonicalPhase1ArtifactBytes } from './artifact-contract.js';
import { createVerifiedTokenObservations } from './evidence.js';
import {
  createSecureEvidenceSink,
  rollbackSecureJsonArtifact,
  type SecureEvidenceInputAuthority,
  writeSecureJsonArtifact,
} from './secure-evidence-sink.js';

const roots = new Set<string>();
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const oneUseAuthority = (
  expected: Record<string, unknown>,
  expectedName = 'scenario.json'
): SecureEvidenceInputAuthority => {
  const values = new WeakSet([expected]);

  return Object.freeze({
    consume: ({ name, source, snapshot, serialized }) => {
      if (
        name !== expectedName ||
        !isRecord(source) ||
        !values.delete(source) ||
        !isDeepStrictEqual(snapshot, expected) ||
        serialized !== Buffer.from(canonicalPhase1ArtifactBytes(snapshot)).toString('utf8')
      ) {
        throw new TypeError('Invalid test evidence authority');
      }
    },
  });
};

const createRoot = async () => {
  const root = path.join('/var/tmp/henry-build', `task8-sink-${process.pid}-${Date.now()}`);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  roots.add(root);
  return root;
};

afterEach(async () => {
  await Promise.all([...roots].map(async (root) => rm(root, { recursive: true, force: true })));
  roots.clear();
});

describe('phase 1 secure evidence sink', () => {
  it('exposes generic JSON publication without importing profile-bundle authority', async () => {
    const source = await readFile(
      path.resolve(process.cwd(), 'src/compatibility/phase-1/secure-evidence-sink.ts'),
      'utf8'
    );

    expect(source).not.toContain('Phase1ProfileBundle');
    expect(source).not.toContain('writeSecureReviewProfile');
    expect(source).not.toContain('assertValidatedPhase1ProfileBundle');
  });

  it('publishes and rolls back generic faithful JSON without review-profile authority', async () => {
    const root = await createRoot();
    const output = path.join(root, 'generic.json');
    const value = { schemaVersion: 1, value: 'safe' };
    const publication = await writeSecureJsonArtifact(output, value);
    const written = JSON.parse(await readFile(output, 'utf8')) as unknown;
    const state = await lstat(output);

    expect(written).toEqual(value);
    expect(state.mode % 0o1000).toBe(0o600);
    expect(state.nlink).toBe(1);
    await rollbackSecureJsonArtifact(publication);
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects non-JSON input and forged rollback publications', async () => {
    const root = await createRoot();
    const output = path.join(root, 'generic.json');

    await expect(writeSecureJsonArtifact(output, { value: undefined } as never)).rejects.toThrow(
      'generic.json: json'
    );
    await expect(rollbackSecureJsonArtifact(Object.freeze({ path: output }))).rejects.toThrow(
      'Invalid secure JSON publication'
    );
  });

  it('writes an exclusive regular 0600 single-link JSON artifact and scans the allowlist', async () => {
    const root = await createRoot();
    const sink = await createSecureEvidenceSink(root, ['scenario.json']);
    const finalPath = await sink.write('scenario.json', { schemaVersion: 1, value: 'safe' });

    expect(JSON.parse(await readFile(finalPath, 'utf8'))).toEqual({
      schemaVersion: 1,
      value: 'safe',
    });
    const state = await lstat(finalPath);
    expect(state.mode % 0o1000).toBe(0o600);
    expect(state.nlink).toBe(1);
    await expect(sink.scan()).resolves.toEqual([finalPath]);
    await expect(sink.rollback('scenario.json')).resolves.toBeUndefined();
    await expect(lstat(finalPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('never deletes a replacement inode during evidence rollback', async () => {
    const root = await createRoot();
    const finalPath = path.join(root, 'scenario.json');
    const originalPath = path.join(root, 'original.json');
    const sink = await createSecureEvidenceSink(root, ['scenario.json']);
    await sink.write('scenario.json', { schemaVersion: 1, value: 'original' });
    await rename(finalPath, originalPath);
    await writeFile(finalPath, '{"schemaVersion":1,"value":"replacement"}\n', { mode: 0o600 });

    await expect(sink.rollback('scenario.json')).rejects.toThrow(
      'scenario.json: publication-identity'
    );
    await expect(readFile(finalPath, 'utf8')).resolves.toContain('replacement');
    await expect(readFile(originalPath, 'utf8')).resolves.toContain('original');
  });

  it('never deletes a replacement inode during generic JSON rollback', async () => {
    const root = await createRoot();
    const finalPath = path.join(root, 'generic.json');
    const originalPath = path.join(root, 'original.json');
    const publication = await writeSecureJsonArtifact(finalPath, { value: 'original' });
    await rename(finalPath, originalPath);
    await writeFile(finalPath, '{"value":"replacement"}\n', { mode: 0o600 });

    await expect(rollbackSecureJsonArtifact(publication)).rejects.toThrow(
      'Invalid secure JSON publication'
    );
    await expect(readFile(finalPath, 'utf8')).resolves.toContain('replacement');
    await expect(readFile(originalPath, 'utf8')).resolves.toContain('original');
  });

  it('refuses existing final paths without replacing bytes', async () => {
    const root = await createRoot();
    const finalPath = path.join(root, 'scenario.json');
    await writeFile(finalPath, 'original', { mode: 0o600 });
    const sink = await createSecureEvidenceSink(root, ['scenario.json']);

    await expect(sink.write('scenario.json', { value: 'replacement' })).rejects.toThrow(
      'scenario.json: final-path-exists'
    );
    expect(await readFile(finalPath, 'utf8')).toBe('original');
  });

  it('rejects symlinks nested entries extra extensions and multiple hard links', async () => {
    const root = await createRoot();
    const sink = await createSecureEvidenceSink(root, ['scenario.json']);
    await writeFile(path.join(root, 'target'), 'safe', { mode: 0o600 });
    await symlink(path.join(root, 'target'), path.join(root, 'scenario.json'));
    await expect(sink.scan()).rejects.toThrow('scenario.json: non-regular-entry');

    await rm(path.join(root, 'scenario.json'));
    await link(path.join(root, 'target'), path.join(root, 'scenario.json'));
    await expect(sink.scan()).rejects.toThrow('scenario.json: link-count');
  });

  it('loses a target-creation race without replacing the existing bytes', async () => {
    const root = await createRoot();
    const finalPath = path.join(root, 'scenario.json');
    const sink = await createSecureEvidenceSink(root, ['scenario.json'], {
      beforeLink: async () => writeFile(finalPath, 'winner', { mode: 0o600 }),
    });

    await expect(sink.write('scenario.json', { value: 'loser' })).rejects.toThrow(
      'scenario.json: final-path-exists'
    );
    expect(await readFile(finalPath, 'utf8')).toBe('winner');
  });

  it('converts raw filesystem and hook errors to fixed artifact/rule diagnostics', async () => {
    const root = await createRoot();
    const privateDiagnostic = '/proc/self/fd/42/private-evidence-path';
    const sink = await createSecureEvidenceSink(root, ['scenario.json'], {
      beforeLink: async () => {
        throw new Error(privateDiagnostic);
      },
    });

    const error = await sink
      .write('scenario.json', { value: 'safe' })
      .catch((error_: unknown) => error_);
    const rendered = `${String(error)} ${JSON.stringify(error)}`;

    expect(rendered).toContain('scenario.json: before-link');
    expect(rendered).not.toContain(privateDiagnostic);
    expect(rendered).not.toContain('/proc/self/fd');
  });

  it('rejects a symlink directory replacement race before publication', async () => {
    const root = await createRoot();
    const moved = `${root}.moved`;
    roots.add(moved);
    const sink = await createSecureEvidenceSink(root, ['scenario.json'], {
      beforeLink: async () => {
        await rename(root, moved);
        await symlink(moved, root);
      },
    });

    await expect(sink.write('scenario.json', { value: 'safe' })).rejects.toThrow(
      '.: directory-not-real'
    );
    await expect(lstat(path.join(moved, 'scenario.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('rejects a root reached through a symlinked parent component', async () => {
    const parent = await createRoot();
    const realParent = path.join(parent, 'real');
    const aliasParent = path.join(parent, 'alias');
    const realRoot = path.join(realParent, 'evidence');
    await mkdir(realRoot, { recursive: true, mode: 0o700 });
    await symlink(realParent, aliasParent, 'dir');

    await expect(
      createSecureEvidenceSink(path.join(aliasParent, 'evidence'), ['scenario.json'])
    ).rejects.toThrow('.: directory-not-real');
  });

  it('detects a hard-link race after exclusive publication', async () => {
    const root = await createRoot();
    const sink = await createSecureEvidenceSink(root, ['scenario.json'], {
      afterLink: async () =>
        link(path.join(root, 'scenario.json'), path.join(root, 'attacker-hard-link')),
    });

    await expect(sink.write('scenario.json', { value: 'safe' })).rejects.toThrow(
      'scenario.json: link-count'
    );
  });

  it('rejects replacement of the published inode with another valid artifact', async () => {
    const root = await createRoot();
    const finalPath = path.join(root, 'scenario.json');
    const sink = await createSecureEvidenceSink(root, ['scenario.json'], {
      afterLink: async () => {
        await rm(finalPath);
        await writeFile(finalPath, '{"value":"replacement"}\n', { mode: 0o600 });
      },
    });

    await expect(sink.write('scenario.json', { value: 'original' })).rejects.toThrow(
      'scenario.json: final-identity'
    );
    await expect(lstat(finalPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('removes a directory raced into the published artifact path', async () => {
    const root = await createRoot();
    const finalPath = path.join(root, 'scenario.json');
    const sink = await createSecureEvidenceSink(root, ['scenario.json'], {
      afterLink: async () => {
        await rm(finalPath);
        await mkdir(finalPath, { mode: 0o700 });
        await writeFile(path.join(finalPath, 'nested'), 'attacker-content', { mode: 0o600 });
      },
    });

    await expect(sink.write('scenario.json', { value: 'original' })).rejects.toThrow(
      'scenario.json: non-regular-entry'
    );
    await expect(lstat(finalPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects nested directories and non-allowlisted extensions during the automatic scan', async () => {
    const root = await createRoot();
    await mkdir(path.join(root, 'nested'), { mode: 0o700 });
    const sink = await createSecureEvidenceSink(root, ['scenario.json']);

    await expect(sink.write('scenario.json', { value: 'safe' })).rejects.toThrow(
      'nested: unexpected-entry'
    );
    await expect(lstat(path.join(root, 'scenario.json'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('parses and sanitizes every pre-existing allowlisted artifact during scan', async () => {
    const root = await createRoot();
    await writeFile(
      path.join(root, 'scenario.json'),
      JSON.stringify({ accessToken: 'Bearer private-token' }),
      { mode: 0o600 }
    );
    const sink = await createSecureEvidenceSink(root, ['scenario.json']);

    await expect(sink.scan()).rejects.toThrow('scenario.json: sanitizer');
  });

  it('publishes verified token artifacts only as an authority-bound differential file', async () => {
    const verified = createVerifiedTokenObservations(
      { refresh_token: 'runtime-refresh-value' },
      {
        target: {
          label: 'candidate',
          coreUrl: 'https://candidate.example/',
          adminUrl: 'https://candidate-admin.example/',
        },
        symbols: new SymbolTable(),
      },
      { boundedClaimTimestampPaths: [], proofs: [] }
    );
    const value = { schemaVersion: 1, tokens: verified.tokens };
    const unauthorizedRoot = await createRoot();
    const unauthorized = await createSecureEvidenceSink(unauthorizedRoot, [
      'phase-1-differential.json',
    ]);

    await expect(unauthorized.write('phase-1-differential.json', value)).rejects.toThrow(
      'phase-1-differential.json: sanitizer'
    );

    const authorizedRoot = await createRoot();
    const authorized = await createSecureEvidenceSink(
      authorizedRoot,
      ['phase-1-differential.json'],
      {},
      oneUseAuthority(value, 'phase-1-differential.json')
    );

    await expect(authorized.write('phase-1-differential.json', value)).resolves.toBe(
      path.join(authorizedRoot, 'phase-1-differential.json')
    );

    const wrongNameRoot = await createRoot();
    const wrongName = await createSecureEvidenceSink(
      wrongNameRoot,
      ['phase-1-browser.json'],
      {},
      oneUseAuthority(value, 'phase-1-differential.json')
    );
    await expect(wrongName.write('phase-1-browser.json', value)).rejects.toThrow(
      'phase-1-browser.json: sanitizer'
    );
    await expect(lstat(path.join(wrongNameRoot, 'phase-1-browser.json'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('serializes authority-approved evidence independently of inherited toJSON hooks', async () => {
    const root = await createRoot();
    const value = { schemaVersion: 1, items: [{ safe: true }] };
    const sink = await createSecureEvidenceSink(
      root,
      ['scenario.json'],
      {},
      oneUseAuthority(value)
    );
    const objectToJson = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    const arrayToJson = Object.getOwnPropertyDescriptor(Array.prototype, 'toJSON');

    try {
      Object.defineProperty(Object.prototype, 'toJSON', {
        configurable: true,
        enumerable: false,
        value: () => ({ forgedByObjectPrototype: true }),
      });
      Object.defineProperty(Array.prototype, 'toJSON', {
        configurable: true,
        enumerable: false,
        value: () => [{ forgedByArrayPrototype: true }],
      });

      const published = await sink.write('scenario.json', value);

      await expect(readFile(published, 'utf8')).resolves.toBe(
        '{"schemaVersion":1,"items":[{"safe":true}]}\n'
      );
    } finally {
      if (objectToJson) {
        Object.defineProperty(Object.prototype, 'toJSON', objectToJson);
      } else {
        Reflect.deleteProperty(Object.prototype, 'toJSON');
      }
      if (arrayToJson) {
        Object.defineProperty(Array.prototype, 'toJSON', arrayToJson);
      } else {
        Reflect.deleteProperty(Array.prototype, 'toJSON');
      }
    }
  });

  it('rejects a non-enumerable own toJSON before consuming authority', async () => {
    const root = await createRoot();
    const value = { schemaVersion: 1, safe: true };
    let consumed = false;
    Object.defineProperty(value, 'toJSON', {
      configurable: false,
      enumerable: false,
      value: () => ({ forged: true }),
    });
    const sink = await createSecureEvidenceSink(
      root,
      ['scenario.json'],
      {},
      {
        consume: () => {
          consumed = true;
        },
      }
    );

    await expect(sink.write('scenario.json', value)).rejects.toThrow('scenario.json: sanitizer');
    expect(consumed).toBe(false);
    await expect(lstat(path.join(root, 'scenario.json'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('publishes the strict snapshot captured before authority consumption', async () => {
    const root = await createRoot();
    const value = { schemaVersion: 1, value: 'approved' };
    const sink = await createSecureEvidenceSink(
      root,
      ['scenario.json'],
      {},
      {
        consume: ({ name, source, snapshot, serialized }) => {
          expect(name).toBe('scenario.json');
          expect(source).toBe(value);
          expect(snapshot).toEqual(value);
          expect(serialized).toBe('{"schemaVersion":1,"value":"approved"}\n');
          value.value = 'forged-after-authority';
        },
      }
    );

    const published = await sink.write('scenario.json', value);

    await expect(readFile(published, 'utf8')).resolves.toBe(
      '{"schemaVersion":1,"value":"approved"}\n'
    );
  });

  it('rejects in-place replacement with different valid bytes before publication completes', async () => {
    const root = await createRoot();
    const finalPath = path.join(root, 'scenario.json');
    const value = { schemaVersion: 1, value: 'approved' };
    const sink = await createSecureEvidenceSink(
      root,
      ['scenario.json'],
      {
        afterLink: async () =>
          writeFile(finalPath, '{"schemaVersion":1,"value":"forged"}\n', { mode: 0o600 }),
      },
      oneUseAuthority(value)
    );

    await expect(sink.write('scenario.json', value)).rejects.toThrow(
      'scenario.json: content-mismatch'
    );
    await expect(lstat(finalPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('does not use coordinator authority as a fallback for invalid token evidence', async () => {
    const root = await createRoot();
    const value = {
      schemaVersion: 1,
      tokens: [
        {
          kind: 'access',
          format: 'jwt',
          signatureVerified: true,
          header: { alg: 'RS256' },
          claims: { iss: 'https://issuer.example', aud: 'urn:api' },
        },
      ],
    };
    const sink = await createSecureEvidenceSink(
      root,
      ['scenario.json'],
      {},
      oneUseAuthority(value)
    );

    await expect(sink.write('scenario.json', value)).rejects.toThrow('scenario.json: sanitizer');
    await expect(lstat(path.join(root, 'scenario.json'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects ephemeral nonce and verification credentials before publication', async () => {
    const root = await createRoot();
    const sink = await createSecureEvidenceSink(root, ['scenario.json']);

    await expect(
      sink.write('scenario.json', {
        nested: {
          nonce: 'private-nonce',
          code_verifier: 'private-verifier',
          code: 'private-code',
          state: 'private-state',
          verificationId: 42,
          verificationCode: 123_456,
        },
      })
    ).rejects.toThrow('scenario.json: sanitizer');
    await expect(lstat(path.join(root, 'scenario.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(
      sink.write('scenario.json', {
        nested: { jwk: { kty: 'oct', k: 'private-key-material' } },
      })
    ).rejects.toThrow('scenario.json: sanitizer');
    await expect(
      sink.write('scenario.json', {
        tokens: [
          {
            kind: 'access',
            format: 'jwt',
            header: null,
            claims: [],
            signatureVerified: true,
          },
        ],
      })
    ).rejects.toThrow('scenario.json: sanitizer');
    await expect(
      sink.write('scenario.json', {
        tokens: [
          {
            kind: 'access',
            format: 'jwt',
            signatureVerified: true,
            header: { alg: 'RS256', kid: '<signing-key.kid.1>' },
            claims: { iss: 'https://issuer.example', aud: 'urn:api' },
          },
        ],
      })
    ).rejects.toThrow('scenario.json: sanitizer');
    await expect(
      sink.write('scenario.json', {
        tokens: [
          {
            kind: 'access',
            format: 'jwt',
            signatureVerified: true,
            header: { alg: 'RS256' },
            claims: { cnf: { jwk: { kty: 'oct', k: 'private-key-material' } } },
          },
        ],
      })
    ).rejects.toThrow('scenario.json: sanitizer');
    await expect(
      sink.write('scenario.json', {
        tokens: [{ kind: 'refresh', format: 'opaque', characterCount: 0, present: true }],
      })
    ).rejects.toThrow('scenario.json: sanitizer');
    await expect(sink.write('scenario.json', { policy: { verificationCode: true } })).resolves.toBe(
      path.join(root, 'scenario.json')
    );
  });
});

/* eslint-enable max-lines, no-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
