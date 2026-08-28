/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Security coverage stays cohesive; filesystem failure tests require controlled mutable instrumentation. */
import { lstatSync } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

import {
  assertEvidenceIsSanitized,
  writeRunEvidence,
  writeScenarioEvidence,
  type EvidenceWriterOptions,
} from './evidence.js';

const buildRoot = '/var/tmp/henry-build';
const defaultCompatibilityDirectory = path.join(buildRoot, 'aster-compatibility');
const defaultEvidenceDirectory = '/var/tmp/henry-build/aster-compatibility/direct';
const referenceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const compactTokenFixture = [
  'eyJhbGciOiJIUzI1NiJ9',
  'eyJzdWIiOiJ1c2VyIn0',
  'c2lnbmF0dXJlLW1hdGVyaWFs',
].join('.');
const pemPrivateKeyFixture = [
  '-----BEGIN PRIVATE',
  ' KEY-----\nfixture\n-----END PRIVATE',
  ' KEY-----',
].join('');
const createdRoots = new Set<string>();
const securePathFileSystem: NonNullable<EvidenceWriterOptions['fileSystem']> = {
  chmodPath: chmod,
  getCurrentUserId: () => lstatSync(buildRoot).uid,
  getPathState: lstat,
  getRealPath: realpath,
  makeDirectory: mkdir,
  openFile: open,
  renameFile: rename,
  unlinkFile: unlink,
};

const createRealWriterOptions = (
  evidenceDirectory: string,
  fileSystem: NonNullable<EvidenceWriterOptions['fileSystem']> = {}
): EvidenceWriterOptions => ({
  env: { ASTER_EVIDENCE_DIR: evidenceDirectory },
  fileSystem: { ...securePathFileSystem, ...fileSystem },
});

const createPrivateRoot = async () => {
  const root = await mkdtemp(path.join(buildRoot, 'aster-evidence-test-'));
  createdRoots.add(root);
  await chmod(root, 0o700);
  return root;
};

const scenarioEvidence = (scenarioId = 'management-api.users.create') => ({
  schemaVersion: 1 as const,
  scenarioId,
  oracle: {
    target: 'oracle' as const,
    observations: [{ stepId: 'create-user', kind: 'http' as const, value: { status: 200 } }],
  },
  candidate: {
    target: 'candidate' as const,
    observations: [{ stepId: 'create-user', kind: 'http' as const, value: { status: 401 } }],
  },
  differences: [{ path: '/observations/0/value/status', oracle: 200, candidate: 401 }],
});

const runEvidence = () => ({
  schemaVersion: 1 as const,
  referenceCommit,
  oracleImageDigest: `sha256:${'a'.repeat(64)}`,
  candidateImageDigest: `sha256:${'b'.repeat(64)}`,
  scenarios: [{ scenarioId: 'management-api.users.create', differenceCount: 1 }],
  negativeControl: { differencePath: '/observations/0/value/status' },
});

const getRejectionMessage = async (operation: () => Promise<unknown>) => {
  try {
    await operation();
  } catch (error: unknown) {
    return error instanceof Error ? error.message : String(error);
  }

  throw new Error('Expected operation to reject');
};

type VirtualSecurePathOptions = {
  currentUserId?: number | undefined;
  existingDirectories?: string[];
  modeByPath?: Readonly<Record<string, number>>;
  ownerByPath?: Readonly<Record<string, number>>;
  postChmodModeByPath?: Readonly<Record<string, number>>;
  postChmodOwnerByPath?: Readonly<Record<string, number>>;
  symlinkPaths?: string[];
};

class MissingVirtualPathError extends Error {
  get code() {
    return 'ENOENT';
  }
}

const createVirtualDefaultFileSystem = (options: VirtualSecurePathOptions = {}) => {
  const currentUserId = Object.hasOwn(options, 'currentUserId') ? options.currentUserId : 1000;
  const directories = new Set(options.existingDirectories ?? []);
  const finalFiles = new Set<string>();
  const chmodCalls: Array<[string, number]> = [];
  const makeDirectoryCalls: Array<[string, { recursive: boolean; mode: number }]> = [];
  const modes = new Map(Object.entries(options.modeByPath ?? {}));
  const owners = new Map(Object.entries(options.ownerByPath ?? {}));
  const symlinkPaths = new Set(options.symlinkPaths ?? []);
  const fileSystem: NonNullable<EvidenceWriterOptions['fileSystem']> = {
    getCurrentUserId: () => currentUserId,
    getPathState: async (filePath) => {
      const isFinalFile = finalFiles.has(filePath);

      if (!isFinalFile && !directories.has(filePath)) {
        throw new MissingVirtualPathError('Virtual path missing');
      }

      return {
        uid: owners.get(filePath) ?? currentUserId ?? 1000,
        mode: isFinalFile ? 0o600 : (modes.get(filePath) ?? 0o700),
        isDirectory: () => !isFinalFile,
        isFile: () => isFinalFile,
        isSymbolicLink: () => symlinkPaths.has(filePath),
      };
    },
    getRealPath: async (filePath) => filePath,
    makeDirectory: async (directoryPath, directoryOptions) => {
      makeDirectoryCalls.push([directoryPath, directoryOptions]);
      directories.add(directoryPath);
      modes.set(directoryPath, directoryOptions.mode);
      owners.set(directoryPath, currentUserId ?? 1000);
      return directoryPath;
    },
    chmodPath: async (filePath, mode) => {
      chmodCalls.push([filePath, mode]);
      modes.set(filePath, options.postChmodModeByPath?.[filePath] ?? mode);
      owners.set(
        filePath,
        options.postChmodOwnerByPath?.[filePath] ?? owners.get(filePath) ?? currentUserId ?? 1000
      );
    },
    openFile: async () => ({
      writeFile: async () => {
        await Promise.resolve();
      },
      close: async () => {
        await Promise.resolve();
      },
    }),
    renameFile: async (_oldPath, newPath) => {
      finalFiles.add(newPath);
    },
    unlinkFile: async () => {
      await Promise.resolve();
    },
  };

  return { fileSystem, chmodCalls, makeDirectoryCalls };
};

afterEach(async () => {
  await Promise.all(
    [...createdRoots].map(async (root) => {
      await rm(root, { recursive: true, force: true });
      createdRoots.delete(root);
    })
  );
});

describe('assertEvidenceIsSanitized', () => {
  it.each([
    'password',
    'password_value',
    'authorizationCode',
    'authorization_code',
    'accessToken',
    'access_token',
    'refreshToken',
    'refresh_token',
    'idToken',
    'id_token',
    'cookie',
    'cookieValue',
    'set-cookie',
    'set_cookie',
    'privateKey',
    'clientSecret',
    'client_secret',
    'connectorSecret',
    'connector_secret',
    'authorization',
    'x-functions-key',
    'token',
    'tokens',
    'refresh_tokens',
    'id_tokens',
    'id_token_hint',
    'token_hash',
    'tokenValue',
    'idTokenValue',
    'rawTokenData',
    'tokenSet',
    'tokenInfo',
    'tokenDetails',
    'authTokenDetails',
    'tokenId',
    'tokenRaw',
    'setupScript',
    'scriptStart',
    'scriptPayload',
    'environmentVariables',
    'apiKey',
    'credential',
  ])('rejects forbidden evidence key %s without echoing its value', (key) => {
    const forbiddenValue = 'fixture-value-that-must-not-be-echoed';

    expect(() => {
      assertEvidenceIsSanitized({ [key]: forbiddenValue });
    }).toThrow(key);

    try {
      assertEvidenceIsSanitized({ [key]: forbiddenValue });
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).not.toContain(forbiddenValue);
    }
  });

  it.each([' Pass Word ', 'ACCESS TOKEN', 'Client\tSecret', 'SET COOKIE'])(
    'normalizes whitespace and case in forbidden key %s',
    (key) => {
      expect(() => {
        assertEvidenceIsSanitized({ [key]: 'redacted-fixture' });
      }).toThrow(key);
    }
  );

  it('checks keys and values recursively through arrays and objects', () => {
    expect(() => {
      assertEvidenceIsSanitized({ observations: [{ nested: [{ client_secret: 'fixture' }] }] });
    }).toThrow('client_secret');
  });

  it.each([
    'Bearer eyJhbGciOiJIUzI1NiJ9.fixture-signature-material',
    compactTokenFixture,
    pemPrivateKeyFixture,
    'Cookie: session=fixture; Path=/',
    'Set-Cookie: session=fixture; HttpOnly; Secure',
    'session=fixture; Path=/; HttpOnly; Secure; SameSite=Lax',
    `https://example.com/callback?access_token=${compactTokenFixture}&state=opaque`,
    `https://example.com/callback#/${compactTokenFixture}/done`,
    `https://example.com/tokens/${compactTokenFixture}/claims`,
  ])('rejects credential-bearing string category without echoing it', (value) => {
    try {
      assertEvidenceIsSanitized({ observation: value });
      throw new Error('Expected sanitizer rejection');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Evidence contains forbidden credential material');
      expect((error as Error).message).not.toContain(value);
    }
  });

  it.each([
    `Bearer ${compactTokenFixture}`,
    compactTokenFixture,
    pemPrivateKeyFixture,
    'Cookie: session=fixture; Path=/',
  ])('rejects credential material used as an object key without echoing it', (key) => {
    try {
      assertEvidenceIsSanitized({ [key]: 'ordinary-value' });
      throw new Error('Expected sanitizer rejection');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).toBe('Evidence contains forbidden credential material');
      expect((error as Error).message).not.toContain(key);
    }
  });

  it('allows reviewed metadata and ordinary normalized semantic values', () => {
    expect(() => {
      assertEvidenceIsSanitized({
        passwordAlgorithm: 'Argon2id',
        hasPassword: true,
        tokenLifetimeSeconds: 3600,
        tokenType: 'Bearer',
        subject: '<user.primary>',
        url: 'https://example.com/callback?error=password_reset_token_expired',
        error: 'invalid token or password',
        authorizationError: 'expected a Bearer token or password',
        token_endpoint: 'https://example.com/oidc/token',
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        description: 'Public token metadata and script documentation',
        version: 'v1.2.3',
      });
    }).not.toThrow();
  });

  it('rejects non-JSON values with a fixed non-echoing error', () => {
    expect(() => {
      assertEvidenceIsSanitized({ value: Number.POSITIVE_INFINITY });
    }).toThrow('Evidence must be faithful JSON');
    expect(() => {
      assertEvidenceIsSanitized(new Date());
    }).toThrow('Evidence must be faithful JSON');
  });
});

describe('atomic evidence writers', () => {
  it('rejects credential material before schema errors can expose invalid fields', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const options = createRealWriterOptions(evidenceDirectory);
    const invalidKind = {
      ...scenarioEvidence(),
      oracle: {
        ...scenarioEvidence().oracle,
        observations: [
          {
            ...scenarioEvidence().oracle.observations[0],
            kind: compactTokenFixture,
          },
        ],
      },
    };
    const invalidTarget = {
      ...scenarioEvidence(),
      candidate: {
        ...scenarioEvidence().candidate,
        target: `Bearer ${compactTokenFixture}`,
      },
    };
    const invalidRunLiteral = { ...runEvidence(), referenceCommit: compactTokenFixture };

    const messages = await Promise.all(
      [
        async () => writeScenarioEvidence(invalidKind, options),
        async () => writeScenarioEvidence(invalidTarget, options),
        async () => writeRunEvidence(invalidRunLiteral, options),
      ].map(async (operation) => getRejectionMessage(operation))
    );

    for (const message of messages) {
      expect(message).toBe('Evidence contains forbidden credential material');
      expect(message).not.toContain(compactTokenFixture);
    }

    await expect(lstat(evidenceDirectory)).rejects.toBeDefined();
  });

  it('replaces Zod details with fixed schema errors and does not touch the filesystem', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const options = createRealWriterOptions(evidenceDirectory);
    const invalidKindMarker = 'opaque-invalid-kind-marker';
    const invalidRunMarker = 'opaque-invalid-reference-marker';
    const scenarioMessage = await getRejectionMessage(async () =>
      writeScenarioEvidence(
        {
          ...scenarioEvidence(),
          oracle: {
            ...scenarioEvidence().oracle,
            observations: [
              {
                ...scenarioEvidence().oracle.observations[0],
                kind: invalidKindMarker,
              },
            ],
          },
        },
        options
      )
    );
    const runMessage = await getRejectionMessage(async () =>
      writeRunEvidence({ ...runEvidence(), referenceCommit: invalidRunMarker }, options)
    );

    expect(scenarioMessage).toBe('Invalid scenario evidence');
    expect(scenarioMessage).not.toContain(invalidKindMarker);
    expect(runMessage).toBe('Invalid run evidence');
    expect(runMessage).not.toContain(invalidRunMarker);
    await expect(lstat(evidenceDirectory)).rejects.toBeDefined();
  });

  it('writes parsed scenario and run evidence with stable formatting and restrictive modes', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const options = createRealWriterOptions(evidenceDirectory);

    const scenarioPath = await writeScenarioEvidence(scenarioEvidence(), options);
    const runPath = await writeRunEvidence(runEvidence(), options);

    expect(scenarioPath).toBe(path.join(evidenceDirectory, 'management-api.users.create.json'));
    expect(runPath).toBe(path.join(evidenceDirectory, 'run.json'));
    expect(await readFile(scenarioPath, 'utf8')).toBe(
      `${JSON.stringify(scenarioEvidence(), undefined, 2)}\n`
    );
    expect(await readFile(runPath, 'utf8')).toBe(
      `${JSON.stringify(runEvidence(), undefined, 2)}\n`
    );
    const directoryState = await lstat(evidenceDirectory);
    const scenarioState = await lstat(scenarioPath);
    const runState = await lstat(runPath);
    expect(directoryState.mode % 0o1000).toBe(0o700);
    expect(scenarioState.mode % 0o1000).toBe(0o600);
    expect(runState.mode % 0o1000).toBe(0o600);
  });

  it('uses ASTER_EVIDENCE_DIR for direct calls without a writer options object', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const previousDirectory = process.env.ASTER_EVIDENCE_DIR;
    process.env.ASTER_EVIDENCE_DIR = evidenceDirectory;

    try {
      expect(
        path.dirname(await writeRunEvidence(runEvidence(), { fileSystem: securePathFileSystem }))
      ).toBe(evidenceDirectory);
    } finally {
      if (previousDirectory === undefined) {
        Reflect.deleteProperty(process.env, 'ASTER_EVIDENCE_DIR');
      } else {
        process.env.ASTER_EVIDENCE_DIR = previousDirectory;
      }
    }
  });

  it('resolves and hardens the unset approved default path segment by segment', async () => {
    const { fileSystem, chmodCalls, makeDirectoryCalls } = createVirtualDefaultFileSystem();

    expect(await writeRunEvidence(runEvidence(), { env: {}, fileSystem })).toBe(
      path.join(defaultEvidenceDirectory, 'run.json')
    );
    expect(chmodCalls).toContainEqual([buildRoot, 0o700]);
    expect(chmodCalls).toContainEqual([defaultCompatibilityDirectory, 0o700]);
    expect(chmodCalls).toContainEqual([defaultEvidenceDirectory, 0o700]);
    expect(makeDirectoryCalls).toEqual([
      [buildRoot, { recursive: false, mode: 0o700 }],
      [defaultCompatibilityDirectory, { recursive: false, mode: 0o700 }],
      [defaultEvidenceDirectory, { recursive: false, mode: 0o700 }],
    ]);
  });

  it.each([
    { label: 'explicit exact default', evidenceDirectory: defaultEvidenceDirectory },
    {
      label: 'explicit nested default',
      evidenceDirectory: path.join(defaultEvidenceDirectory, 'nested'),
    },
  ])('hardens $label destinations under the default build root', async ({ evidenceDirectory }) => {
    const { fileSystem, makeDirectoryCalls } = createVirtualDefaultFileSystem();

    expect(
      await writeRunEvidence(runEvidence(), {
        env: { ASTER_EVIDENCE_DIR: evidenceDirectory },
        fileSystem,
      })
    ).toBe(path.join(evidenceDirectory, 'run.json'));
    expect(makeDirectoryCalls.every(([, options]) => !options.recursive)).toBe(true);
  });

  it.each([
    { label: 'foreign intermediate', foreignPath: defaultCompatibilityDirectory },
    { label: 'foreign leaf', foreignPath: defaultEvidenceDirectory },
  ])('rejects a $label under the default build root', async ({ foreignPath }) => {
    const { fileSystem } = createVirtualDefaultFileSystem({
      existingDirectories: [buildRoot, defaultCompatibilityDirectory, defaultEvidenceDirectory],
      ownerByPath: { [foreignPath]: 2000 },
    });

    await expect(writeRunEvidence(runEvidence(), { env: {}, fileSystem })).rejects.toThrow(
      'Default evidence path must contain private owned directories'
    );
  });

  it('hardens a permissive current-owned intermediate directory', async () => {
    const { fileSystem, chmodCalls } = createVirtualDefaultFileSystem({
      existingDirectories: [buildRoot, defaultCompatibilityDirectory, defaultEvidenceDirectory],
      modeByPath: { [defaultCompatibilityDirectory]: 0o777 },
    });

    await expect(writeRunEvidence(runEvidence(), { env: {}, fileSystem })).resolves.toBe(
      path.join(defaultEvidenceDirectory, 'run.json')
    );
    expect(chmodCalls).toContainEqual([defaultCompatibilityDirectory, 0o700]);
  });

  it.each([
    { label: 'missing getuid', options: { currentUserId: undefined } },
    {
      label: 'intermediate symlink',
      options: {
        existingDirectories: [buildRoot, defaultCompatibilityDirectory],
        symlinkPaths: [defaultCompatibilityDirectory],
      },
    },
    {
      label: 'post-chmod mode mismatch',
      options: { postChmodModeByPath: { [defaultEvidenceDirectory]: 0o777 } },
    },
    {
      label: 'post-chmod owner mismatch',
      options: { postChmodOwnerByPath: { [defaultEvidenceDirectory]: 2000 } },
    },
  ])('rejects secure-path failure: $label', async ({ options }) => {
    const { fileSystem } = createVirtualDefaultFileSystem(options);

    await expect(writeRunEvidence(runEvidence(), { env: {}, fileSystem })).rejects.toThrow(
      'Default evidence path must contain private owned directories'
    );
  });

  it('overwrites a final file atomically without preserving permissive mode', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const options = createRealWriterOptions(evidenceDirectory);
    const original = scenarioEvidence();
    const replacement = {
      ...original,
      differences: [],
    };
    const finalPath = await writeScenarioEvidence(original, options);
    await chmod(finalPath, 0o666);

    await writeScenarioEvidence(replacement, options);

    expect(JSON.parse(await readFile(finalPath, 'utf8'))).toEqual(replacement);
    const finalState = await lstat(finalPath);
    expect(finalState.mode % 0o1000).toBe(0o600);
  });

  it.each(['.', '..', '../escape', 'nested/name', 'nested\\name', '/absolute', 'line\nbreak'])(
    'rejects unsafe scenario ID %s without creating a final file',
    async (scenarioId) => {
      const root = await createPrivateRoot();
      const evidenceDirectory = path.join(root, 'evidence');

      await expect(
        writeScenarioEvidence(scenarioEvidence(scenarioId), {
          env: { ASTER_EVIDENCE_DIR: evidenceDirectory },
        })
      ).rejects.toThrow('Scenario ID is not a safe evidence filename');
      await expect(lstat(path.join(evidenceDirectory, `${scenarioId}.json`))).rejects.toBeDefined();
    }
  );

  it('reserves run.json for run evidence and preserves its existing content', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const options = createRealWriterOptions(evidenceDirectory);
    const runPath = await writeRunEvidence(runEvidence(), options);
    const originalRun = await readFile(runPath, 'utf8');

    await Promise.all(
      ['run', 'Run', 'RUN'].map(async (scenarioId) =>
        expect(writeScenarioEvidence(scenarioEvidence(scenarioId), options)).rejects.toThrow(
          'Scenario ID is not a safe evidence filename'
        )
      )
    );
    expect(await readFile(runPath, 'utf8')).toBe(originalRun);
  });

  it.each(['relative/evidence', '/dev/shm', '/dev/shm/aster-evidence'])(
    'rejects unsafe evidence directory %s',
    async (evidenceDirectory) => {
      await expect(
        writeRunEvidence(runEvidence(), { env: { ASTER_EVIDENCE_DIR: evidenceDirectory } })
      ).rejects.toThrow('Evidence directory must be an absolute private disk path');
    }
  );

  it('rejects a symlink evidence directory', async () => {
    const root = await createPrivateRoot();
    const realDirectory = path.join(root, 'real');
    const linkDirectory = path.join(root, 'link');
    await mkdir(realDirectory);
    await symlink(realDirectory, linkDirectory);

    await expect(
      writeRunEvidence(runEvidence(), createRealWriterOptions(linkDirectory))
    ).rejects.toThrow('Default evidence path must contain private owned directories');
  });

  it('rejects an evidence directory reached through a symlinked parent', async () => {
    const root = await createPrivateRoot();
    const realParent = path.join(root, 'real-parent');
    const linkedParent = path.join(root, 'linked-parent');
    await mkdir(realParent);
    await symlink(realParent, linkedParent);

    await expect(
      writeRunEvidence(runEvidence(), createRealWriterOptions(path.join(linkedParent, 'evidence')))
    ).rejects.toThrow('Default evidence path must contain private owned directories');
  });

  it('rejects forbidden unknown keys before Zod can strip them and preserves existing evidence', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const options = createRealWriterOptions(evidenceDirectory);
    const finalPath = await writeScenarioEvidence(scenarioEvidence(), options);
    const originalBody = await readFile(finalPath, 'utf8');
    const unsafeInput = { ...scenarioEvidence(), client_secret: 'fixture-secret' };

    await expect(writeScenarioEvidence(unsafeInput, options)).rejects.toThrow('client_secret');
    expect(await readFile(finalPath, 'utf8')).toBe(originalBody);
  });

  it('rejects invalid image digests without creating run.json', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const invalid = { ...runEvidence(), oracleImageDigest: `sha256:${'A'.repeat(64)}` };

    await expect(
      writeRunEvidence(invalid, { env: { ASTER_EVIDENCE_DIR: evidenceDirectory } })
    ).rejects.toThrow();
    await expect(lstat(path.join(evidenceDirectory, 'run.json'))).rejects.toBeDefined();
  });

  it('does not write evidence bodies to console streams', async () => {
    const root = await createPrivateRoot();
    const options = createRealWriterOptions(path.join(root, 'evidence'));
    const originalMethods = {
      log: console.log,
      error: console.error,
      warn: console.warn,
    };
    const calls: unknown[][] = [];
    const capture = (...arguments_: unknown[]) => {
      calls.push(arguments_);
    };
    console.log = capture;
    console.error = capture;
    console.warn = capture;

    try {
      await writeScenarioEvidence(scenarioEvidence(), options);
      await writeRunEvidence(runEvidence(), options);
    } finally {
      console.log = originalMethods.log;
      console.error = originalMethods.error;
      console.warn = originalMethods.warn;
    }

    expect(calls).toEqual([]);
  });

  it('cleans only its exact temporary file when rename fails and preserves the prior final', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const baseOptions = createRealWriterOptions(evidenceDirectory);
    const finalPath = await writeRunEvidence(runEvidence(), baseOptions);
    const originalBody = await readFile(finalPath, 'utf8');
    let temporaryPath = '';
    const options = createRealWriterOptions(evidenceDirectory, {
      renameFile: async (from) => {
        temporaryPath = from;
        throw new Error('injected rename failure');
      },
    });

    await expect(writeRunEvidence(runEvidence(), options)).rejects.toThrow(
      'injected rename failure'
    );
    expect(await readFile(finalPath, 'utf8')).toBe(originalBody);
    await expect(lstat(temporaryPath)).rejects.toBeDefined();
  });

  it('cleans its temporary file when writing fails', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    let temporaryPath = '';
    const options = createRealWriterOptions(evidenceDirectory, {
      openFile: async (filePath, flags, mode) => {
        temporaryPath = filePath;
        const handle = await open(filePath, flags, mode);

        return {
          writeFile: async () => {
            throw new Error('injected write failure');
          },
          close: async () => handle.close(),
        };
      },
    });

    await expect(writeRunEvidence(runEvidence(), options)).rejects.toThrow(
      'injected write failure'
    );
    await expect(lstat(temporaryPath)).rejects.toBeDefined();
    await expect(lstat(path.join(evidenceDirectory, 'run.json'))).rejects.toBeDefined();
  });

  it('does not follow a pre-existing temporary symlink', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const symlinkTarget = path.join(root, 'symlink-target');
    await writeFile(symlinkTarget, 'unchanged\n', { mode: 0o600 });
    const options = createRealWriterOptions(evidenceDirectory, {
      openFile: async (filePath, flags, mode) => {
        await symlink(symlinkTarget, filePath);
        return open(filePath, flags, mode);
      },
    });

    await expect(writeRunEvidence(runEvidence(), options)).rejects.toMatchObject({
      code: 'EEXIST',
    });
    expect(await readFile(symlinkTarget, 'utf8')).toBe('unchanged\n');
    await expect(lstat(path.join(evidenceDirectory, 'run.json'))).rejects.toBeDefined();
  });

  it('preserves the original rename error when temporary cleanup also fails', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    const options = createRealWriterOptions(evidenceDirectory, {
      renameFile: async () => {
        throw new Error('primary rename failure');
      },
      unlinkFile: async () => {
        throw new Error('secondary cleanup failure');
      },
    });

    await expect(writeRunEvidence(runEvidence(), options)).rejects.toThrow(
      'primary rename failure'
    );
  });
});
/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
