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

import {
  createSecureEvidenceSink,
  rollbackSecureJsonArtifact,
  writeSecureJsonArtifact,
} from './secure-evidence-sink.js';

const roots = new Set<string>();

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
