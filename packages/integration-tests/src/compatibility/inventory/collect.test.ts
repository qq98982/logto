/* eslint-disable max-lines */
import {
  appendFile,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import {
  createServer,
  type IncomingHttpHeaders,
  type Server,
  type ServerResponse,
} from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { z } from 'zod';

import {
  parseInventoryArguments,
  resolveTargetConfig,
  runInventoryCli,
  type InventoryCliDependencies,
} from './cli.js';
import {
  collectCapabilityManifest,
  collectIntegrationTestCapabilities,
  extractConnectorCapabilities,
  extractOidcCapabilities,
  extractOpenApiCapabilities,
  mergeCapabilities,
} from './collect.js';
import { resolveCompatibilityPaths } from './paths.js';

const referenceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const fakeReadFiles = async () => ['console\\users\\index.test.ts', 'src/tests/api/users.test.ts'];
const validOidcDiscovery = {
  grant_types_supported: ['authorization_code'],
  response_types_supported: ['code'],
  response_modes_supported: ['query'],
  token_endpoint_auth_methods_supported: ['client_secret_basic'],
};
const validRuntimeResponses: Readonly<Record<string, unknown>> = {
  '/api/.well-known/experience.openapi.json': {
    paths: { '/api/experience': { post: {} } },
  },
  '/api/.well-known/management.openapi.json': {
    paths: { '/api/users': { get: {} } },
  },
  '/api/.well-known/user.openapi.json': {
    paths: { '/api/account': { patch: {} } },
  },
  '/oidc/.well-known/openid-configuration': validOidcDiscovery,
  '/api/connector-factories': [{ id: 'email' }],
};

const listenOnLoopback = async (server: Server) => {
  await new Promise<void>((resolve, reject) => {
    const handleError = (error: Error) => {
      reject(error);
    };

    server.once('error', handleError);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', handleError);
      resolve();
    });
  });
  const address = server.address();

  if (address === null || typeof address === 'string') {
    throw new Error('Expected an ephemeral TCP server address');
  }

  return `http://127.0.0.1:${address.port}`;
};

const closeServer = async (server: Server) => {
  if (!server.listening) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
    server.closeAllConnections();
  });
};

const sendJson = (response: ServerResponse, statusCode: number, value: unknown) => {
  response.writeHead(statusCode, { 'content-type': 'application/json' });
  response.end(JSON.stringify(value));
};

const fetchJsonFromTestServer = async (
  url: URL,
  options?: { headers?: Readonly<Record<string, string>> }
) => {
  const response = await fetch(url, { headers: options?.headers });
  const source = await response.text();

  return z.unknown().parse(JSON.parse(source));
};

const objectRecordGuard = z.custom<Record<string, unknown>>(
  (value) => typeof value === 'object' && value !== null && !Array.isArray(value)
);
const nullPrototypePathItem = objectRecordGuard.parse(
  Object.assign(Object.create(null), { get: {} })
);
const extraPrototypeLayerPathItem = objectRecordGuard.parse(
  // eslint-disable-next-line @silverhand/fp/no-mutating-assign, @typescript-eslint/no-unsafe-argument -- Deliberately construct the rejected two-layer prototype fixture.
  Object.assign(Object.create(Object.create(null)), { get: {} })
);

class CustomPrototypePathItem {
  isCustomPrototype() {
    return true;
  }
}

const createCoreRuntimeServer = (requests: Map<string, IncomingHttpHeaders>) =>
  createServer((request, response) => {
    const requestPath = request.url ?? '';
    const document = validRuntimeResponses[requestPath];

    requests.set(requestPath, request.headers);

    if (document === undefined) {
      sendJson(response, 404, { error: 'not-found' });
      return;
    }

    sendJson(response, 200, document);
  });

const collectFromRuntimeResponses = async (responseByPath: Readonly<Record<string, unknown>>) =>
  collectCapabilityManifest(
    {
      label: 'oracle',
      coreUrl: 'https://core.example.com',
      adminUrl: 'https://admin.example.com',
    },
    {
      testRoot: '/repo/packages/integration-tests/src/tests',
      manualCapabilitiesPath: '/repo/compatibility/manual-capabilities.json',
      fetchJson: async (url) => responseByPath[url.pathname],
      readFiles: async () => [],
      readManualCapabilities: async () => [],
    }
  );

const sampleCapability = {
  id: 'manual.sample',
  surface: 'manual' as const,
  source: 'compatibility/manual-capabilities.json',
  existingEvidence: [],
};
const sampleManifest = {
  schemaVersion: 1 as const,
  referenceCommit: referenceCommit as typeof referenceCommit,
  capabilities: [sampleCapability],
};
const cliEnvironment = {
  ASTER_ORACLE_URL: 'https://oracle.example.com',
  ASTER_ORACLE_ADMIN_URL: 'https://oracle-admin.example.com',
  ASTER_CANDIDATE_URL: 'https://candidate.example.com',
  ASTER_CANDIDATE_ADMIN_URL: 'https://candidate-admin.example.com',
};

const createCliDependencies = (
  temporaryRoot: string,
  overrides: Partial<InventoryCliDependencies> = {}
): InventoryCliDependencies => ({
  resolvePaths: async () => ({
    repoRoot: temporaryRoot,
    manifestPath: path.join(temporaryRoot, 'baseline-manifest.json'),
    manualCapabilitiesPath: path.join(temporaryRoot, 'manual-capabilities.json'),
    integrationTestRoot: path.join(temporaryRoot, 'tests'),
  }),
  collectManifest: async () => sampleManifest,
  readManifestFile: async (filePath) => readFile(filePath, 'utf8'),
  writeManifestFile: async (filePath, contents, options) => writeFile(filePath, contents, options),
  renameFile: async (oldPath, newPath) => rename(oldPath, newPath),
  unlinkFile: async (filePath) => rm(filePath),
  writeOutput: async (message) => {
    expect(typeof message).toBe('string');
  },
  writeError: async (message) => {
    expect(typeof message).toBe('string');
  },
  randomId: () => 'fixed-id',
  ...overrides,
});

describe('capability inventory collectors', () => {
  it.each([
    ['management-api', 'http.management-api'] as const,
    ['experience-api', 'http.experience-api'] as const,
    ['user-api', 'http.user-api'] as const,
  ])('sorts supported %s OpenAPI operations by stable ID', (surface, idPrefix) => {
    const capabilities = extractOpenApiCapabilities(surface, `/${surface}.openapi.json`, {
      paths: {
        '/api/not-supported': { options: {} },
        '/api/users': { post: {}, get: {}, head: {} },
      },
    });

    expect(capabilities.map(({ id }) => id)).toEqual([
      `${idPrefix}.get./api/users`,
      `${idPrefix}.post./api/users`,
    ]);
    expect(capabilities[0]).toEqual({
      id: `${idPrefix}.get./api/users`,
      surface,
      source: `/${surface}.openapi.json`,
      existingEvidence: [],
    });
  });

  it('uses parsed OpenAPI paths rather than source-like text elsewhere in the document', () => {
    expect(
      extractOpenApiCapabilities('management-api', '/management.openapi.json', {
        description: 'GET /api/not-a-real-operation',
      })
    ).toEqual([]);
  });

  it('expands only advertised OIDC arrays into deterministically sorted capabilities', () => {
    expect(
      extractOidcCapabilities({
        grant_types_supported: ['refresh_token', 'authorization_code'],
        response_types_supported: ['code'],
        response_modes_supported: ['query'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
      })
    ).toEqual([
      {
        id: 'oidc.grant.authorization_code',
        surface: 'oidc',
        source: '/oidc/.well-known/openid-configuration',
        existingEvidence: [],
      },
      expect.objectContaining({ id: 'oidc.grant.refresh_token' }),
      expect.objectContaining({ id: 'oidc.response_mode.query' }),
      expect.objectContaining({ id: 'oidc.response_type.code' }),
      expect.objectContaining({
        id: 'oidc.token_endpoint_auth_method.client_secret_basic',
      }),
    ]);
    expect(extractOidcCapabilities({ grant_types_supported: ['authorization_code'] })).toHaveLength(
      1
    );
  });

  it('encodes valid compound OIDC response types and rejects duplicate generated IDs', () => {
    expect(
      extractOidcCapabilities({ response_types_supported: ['code id_token'] }).map(({ id }) => id)
    ).toEqual(['oidc.response_type.code+id_token']);
    expect(() =>
      extractOidcCapabilities({
        response_types_supported: ['code id_token', 'code id_token'],
      })
    ).toThrow('Duplicate capability ID: oidc.response_type.code+id_token');
  });

  it.each([
    ' code',
    'code ',
    'code  id_token',
    'code\tid_token',
    'code\vid_token',
    'code\nid_token',
  ])('rejects invalid OIDC response type whitespace: %p', (responseType) => {
    expect(() => extractOidcCapabilities({ response_types_supported: [responseType] })).toThrow(
      /response_types_supported/
    );
  });

  it('continues to reject whitespace in non-response OIDC identifiers', () => {
    expect(() =>
      extractOidcCapabilities({ grant_types_supported: ['authorization code'] })
    ).toThrow(/grant_types_supported/);
  });

  it('sorts connector factory IDs', () => {
    expect(
      extractConnectorCapabilities([{ id: 'wechat-web' }, { id: 'google-universal' }]).map(
        ({ id }) => id
      )
    ).toEqual(['connector.google-universal', 'connector.wechat-web']);
  });

  it.each([[{}], [{ id: '' }], [{ id: 42 }]])(
    'rejects a connector factory with a missing or invalid ID: %p',
    (connector) => {
      expect(() => extractConnectorCapabilities([connector])).toThrow(/connector factory.*id/i);
    }
  );

  it('maps normalized test file paths without parsing test names or reading a fake filesystem', async () => {
    await expect(
      collectIntegrationTestCapabilities('/repo/packages/integration-tests/src/tests', {
        readFiles: fakeReadFiles,
      })
    ).resolves.toEqual([
      {
        id: 'test.api/users.test.ts',
        surface: 'integration-test',
        source: 'packages/integration-tests/src/tests/api/users.test.ts',
        existingEvidence: ['packages/integration-tests/src/tests/api/users.test.ts'],
      },
      {
        id: 'test.console/users/index.test.ts',
        surface: 'integration-test',
        source: 'packages/integration-tests/src/tests/console/users/index.test.ts',
        existingEvidence: ['packages/integration-tests/src/tests/console/users/index.test.ts'],
      },
    ]);
  });

  it('rejects duplicate capability IDs after merging all sources', () => {
    const capability = {
      id: 'manual.duplicate',
      surface: 'manual' as const,
      source: 'compatibility/manual-capabilities.json',
      existingEvidence: [],
    };

    expect(() => mergeCapabilities([capability], [capability])).toThrow(
      'Duplicate capability ID: manual.duplicate'
    );
  });

  it('fetches each runtime surface and sends the development user header only to connectors', async () => {
    const manifest = await collectCapabilityManifest(
      {
        label: 'oracle',
        coreUrl: 'https://core.example.com',
        adminUrl: 'https://admin.example.com',
      },
      {
        testRoot: '/repo/packages/integration-tests/src/tests',
        manualCapabilitiesPath: '/repo/compatibility/manual-capabilities.json',
        fetchJson: async (url, options) => {
          if (url.pathname === '/api/connector-factories') {
            expect(options?.headers).toEqual({
              'development-user-id': 'integration-test-admin-user',
            });
          } else {
            expect(options).toBeUndefined();
          }

          return validRuntimeResponses[url.pathname];
        },
        readFiles: async () => ['api/users.test.ts'],
        readManualCapabilities: async () => [],
      }
    );

    expect(manifest.schemaVersion).toBe(1);
    expect(manifest.referenceCommit).toBe(referenceCommit);
    expect(manifest.capabilities.map(({ id }) => id)).toEqual([
      'connector.email',
      'http.experience-api.post./api/experience',
      'http.management-api.get./api/users',
      'http.user-api.patch./api/account',
      'oidc.grant.authorization_code',
      'oidc.response_mode.query',
      'oidc.response_type.code',
      'oidc.token_endpoint_auth_method.client_secret_basic',
      'test.api/users.test.ts',
    ]);
  });

  it('fetches every live inventory document from core and never sends auth to admin', async () => {
    const coreRequests = new Map<string, IncomingHttpHeaders>();
    const adminRequests = new Map<string, IncomingHttpHeaders>();
    const coreServer = createCoreRuntimeServer(coreRequests);
    const adminServer = createServer((request, response) => {
      adminRequests.set(request.url ?? '', request.headers);
      sendJson(response, 500, { error: 'admin-origin-must-not-be-used' });
    });

    try {
      const [coreUrl, adminUrl] = await Promise.all([
        listenOnLoopback(coreServer),
        listenOnLoopback(adminServer),
      ]);

      await collectCapabilityManifest(
        { label: 'oracle', coreUrl, adminUrl },
        {
          testRoot: '/repo/packages/integration-tests/src/tests',
          manualCapabilitiesPath: '/repo/compatibility/manual-capabilities.json',
          fetchJson: fetchJsonFromTestServer,
          readFiles: async () => [],
          readManualCapabilities: async () => [],
        }
      );

      expect(Array.from(coreRequests.keys()).toSorted()).toEqual(
        Object.keys(validRuntimeResponses).toSorted()
      );
      expect(adminRequests.size).toBe(0);

      for (const [requestPath, headers] of coreRequests) {
        const unexpectedHeaders = Object.keys(headers).filter(
          (header) =>
            ![
              'accept',
              'accept-encoding',
              'accept-language',
              'connection',
              'development-user-id',
              'host',
              'sec-fetch-mode',
              'user-agent',
            ].includes(header)
        );

        expect(unexpectedHeaders).toEqual([]);
        expect(headers.authorization).toBeUndefined();
        expect(headers['proxy-authorization']).toBeUndefined();
        expect(headers.cookie).toBeUndefined();
        expect(headers['x-api-key']).toBeUndefined();
        expect(headers['x-auth-token']).toBeUndefined();
        expect(headers['development-user-id']).toBe(
          requestPath === '/api/connector-factories' ? 'integration-test-admin-user' : undefined
        );
      }
    } finally {
      await Promise.all([closeServer(coreServer), closeServer(adminServer)]);
    }
  });

  it('collects from core when the distinct admin origin is unreachable', async () => {
    const coreRequests = new Map<string, IncomingHttpHeaders>();
    const coreServer = createCoreRuntimeServer(coreRequests);
    const closedAdminServer = createServer();

    try {
      const [coreUrl, adminUrl] = await Promise.all([
        listenOnLoopback(coreServer),
        listenOnLoopback(closedAdminServer),
      ]);
      await closeServer(closedAdminServer);

      const manifest = await collectCapabilityManifest(
        { label: 'candidate', coreUrl, adminUrl },
        {
          testRoot: '/repo/packages/integration-tests/src/tests',
          manualCapabilitiesPath: '/repo/compatibility/manual-capabilities.json',
          fetchJson: fetchJsonFromTestServer,
          readFiles: async () => [],
          readManualCapabilities: async () => [],
        }
      );
      const capabilityIds = manifest.capabilities.map(({ id }) => id);

      expect(capabilityIds).toContain('connector.email');
      expect(capabilityIds).toContain('http.management-api.get./api/users');
      expect(capabilityIds).toContain('http.user-api.patch./api/account');
      expect(Array.from(coreRequests.keys()).toSorted()).toEqual(
        Object.keys(validRuntimeResponses).toSorted()
      );
    } finally {
      await Promise.all([closeServer(coreServer), closeServer(closedAdminServer)]);
    }
  });

  it.each([
    { name: 'a non-object document', document: [] },
    { name: 'a missing paths record', document: {} },
    { name: 'an empty paths record', document: { paths: {} } },
    {
      name: 'a path item with a custom prototype layer',
      document: { paths: { '/api/users': new CustomPrototypePathItem() } },
    },
    {
      name: 'a path item whose prototype has a null prototype',
      document: { paths: { '/api/users': extraPrototypeLayerPathItem } },
    },
    { name: 'a null path item', document: { paths: { '/api/users': null } } },
    { name: 'an array path item', document: { paths: { '/api/users': [] } } },
    { name: 'a null operation', document: { paths: { '/api/users': { get: null } } } },
    { name: 'a string operation', document: { paths: { '/api/users': { get: 'invalid' } } } },
    { name: 'an array operation', document: { paths: { '/api/users': { get: [] } } } },
  ])('rejects runtime OpenAPI documents with $name', async ({ document }) => {
    await expect(
      collectFromRuntimeResponses({
        ...validRuntimeResponses,
        '/api/.well-known/experience.openapi.json': document,
      })
    ).rejects.toThrow(/plain object|paths|operation/i);
  });

  it('accepts ordinary and null-prototype OpenAPI records', async () => {
    const manifest = await collectFromRuntimeResponses({
      ...validRuntimeResponses,
      '/api/.well-known/experience.openapi.json': {
        paths: {
          '/api/ordinary': { get: {} },
          '/api/null-prototype': nullPrototypePathItem,
        },
      },
    });
    const capabilityIds = manifest.capabilities.map(({ id }) => id);

    expect(capabilityIds).toContain('http.experience-api.get./api/ordinary');
    expect(capabilityIds).toContain('http.experience-api.get./api/null-prototype');
  });

  it.each([
    { name: 'a non-object document', discovery: [] },
    {
      name: 'a missing required field',
      discovery: { ...validOidcDiscovery, response_modes_supported: undefined },
    },
    {
      name: 'an empty required array',
      discovery: { ...validOidcDiscovery, grant_types_supported: [] },
    },
    {
      name: 'an empty array entry',
      discovery: { ...validOidcDiscovery, grant_types_supported: [''] },
    },
    {
      name: 'an invalid compound response type',
      discovery: { ...validOidcDiscovery, response_types_supported: ['code  id_token'] },
    },
  ])('rejects runtime OIDC discovery with $name', async ({ discovery }) => {
    await expect(
      collectFromRuntimeResponses({
        ...validRuntimeResponses,
        '/oidc/.well-known/openid-configuration': discovery,
      })
    ).rejects.toThrow(
      /plain object|grant_types_supported|response_types_supported|response_modes_supported/
    );
  });
});

describe('compatibility inventory paths', () => {
  it.each(['', 'relative/repo'])('rejects a non-absolute ASTER_REPO_ROOT: %p', async (repoRoot) => {
    await expect(resolveCompatibilityPaths({ env: { ASTER_REPO_ROOT: repoRoot } })).rejects.toThrow(
      'ASTER_REPO_ROOT must be an absolute path'
    );
  });

  it('rejects an ASTER_REPO_ROOT without the workspace marker', async () => {
    const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'aster-inventory-missing-marker-'));

    try {
      await expect(
        resolveCompatibilityPaths({ env: { ASTER_REPO_ROOT: temporaryRoot } })
      ).rejects.toThrow(/ASTER_REPO_ROOT.*pnpm-workspace\.yaml/);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it('resolves repository paths independently of the current working directory', async () => {
    const originalWorkingDirectory = process.cwd();
    const unrelatedDirectory = await mkdtemp(path.join(tmpdir(), 'aster-inventory-cwd-'));

    try {
      process.chdir(unrelatedDirectory);
      const paths = await resolveCompatibilityPaths({ env: {} });
      const expectedRoot = await realpath(
        fileURLToPath(new URL('../../../../../', import.meta.url))
      );

      expect(paths).toEqual({
        repoRoot: expectedRoot,
        manifestPath: path.join(expectedRoot, 'compatibility/baseline-manifest.json'),
        manualCapabilitiesPath: path.join(expectedRoot, 'compatibility/manual-capabilities.json'),
        integrationTestRoot: path.join(expectedRoot, 'packages/integration-tests/src/tests'),
      });
    } finally {
      process.chdir(originalWorkingDirectory);
      await rm(unrelatedDirectory, { recursive: true, force: true });
    }
  });
});

describe('compatibility inventory CLI contracts', () => {
  it('accepts exactly one target and mode', () => {
    expect(parseInventoryArguments(['--target', 'oracle', '--check'])).toEqual({
      target: 'oracle',
      mode: 'check',
    });
  });

  it.each([
    { arguments_: [] },
    { arguments_: ['--target', 'oracle'] },
    { arguments_: ['--target', 'oracle', '--check', '--write'] },
    { arguments_: ['--target', 'oracle', '--check', '--unknown'] },
    { arguments_: ['--target', 'other', '--check'] },
  ])('rejects missing, ambiguous, or unknown arguments: $arguments_', ({ arguments_ }) => {
    expect(() => parseInventoryArguments(arguments_)).toThrow(/usage/i);
  });

  it('reports the exact invalid Aster URL variable', () => {
    expect(() =>
      resolveTargetConfig('candidate', {
        ASTER_CANDIDATE_URL: 'file:///tmp/service',
        ASTER_CANDIDATE_ADMIN_URL: 'https://admin.example.com',
      })
    ).toThrow('ASTER_CANDIDATE_URL must be an HTTP(S) URL');
  });

  it.each([
    {
      variableName: 'ASTER_CANDIDATE_URL',
      value: 'https://candidate.example.com/tenant',
    },
    {
      variableName: 'ASTER_CANDIDATE_ADMIN_URL',
      value: 'https://candidate-admin.example.com?tenant=one',
    },
    {
      variableName: 'ASTER_CANDIDATE_URL',
      value: 'https://candidate.example.com/#fragment',
    },
  ])('rejects non-origin URL in $variableName', ({ variableName, value }) => {
    expect(() =>
      resolveTargetConfig('candidate', {
        ...cliEnvironment,
        [variableName]: value,
      })
    ).toThrow(`${variableName} must not contain a path, query, or fragment`);
  });

  it('rejects candidate writes even when the manifest write gate is enabled', async () => {
    await expect(
      runInventoryCli(
        ['--target', 'candidate', '--write'],
        { ...cliEnvironment, ASTER_ALLOW_MANIFEST_WRITE: '1' },
        createCliDependencies('/unused')
      )
    ).rejects.toThrow('--write requires --target oracle');
  });

  it.each([{ gate: undefined }, { gate: '0' }, { gate: 'true' }])(
    'rejects oracle writes without the exact gate: $gate',
    async ({ gate }) => {
      await expect(
        runInventoryCli(
          ['--target', 'oracle', '--write'],
          { ...cliEnvironment, ASTER_ALLOW_MANIFEST_WRITE: gate },
          createCliDependencies('/unused')
        )
      ).rejects.toThrow('ASTER_ALLOW_MANIFEST_WRITE=1');
    }
  );

  it('writes two-space JSON through an exclusive sibling temp file and rename', async () => {
    const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'aster-inventory-write-'));
    const manifestPath = path.join(temporaryRoot, 'baseline-manifest.json');
    const temporaryPath = `${manifestPath}.${process.pid}.fixed-id.tmp`;

    try {
      const exitCode = await runInventoryCli(
        ['--target', 'oracle', '--write'],
        { ...cliEnvironment, ASTER_ALLOW_MANIFEST_WRITE: '1' },
        createCliDependencies(temporaryRoot, {
          writeManifestFile: async (filePath, contents, options) => {
            expect(filePath).toBe(temporaryPath);
            expect(options).toEqual({ encoding: 'utf8', flag: 'wx' });
            await writeFile(filePath, contents, options);
          },
          renameFile: async (oldPath, newPath) => {
            expect(oldPath).toBe(temporaryPath);
            expect(newPath).toBe(manifestPath);
            await rename(oldPath, newPath);
          },
        })
      );

      expect(exitCode).toBe(0);
      expect(await readFile(manifestPath, 'utf8')).toBe(
        `${JSON.stringify(sampleManifest, undefined, 2)}\n`
      );
      expect(await readdir(temporaryRoot)).toEqual(['baseline-manifest.json']);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it('preserves the write error when no temp file was created', async () => {
    const temporaryRoot = await mkdtemp(
      path.join(tmpdir(), 'aster-inventory-write-empty-failure-')
    );

    try {
      await expect(
        runInventoryCli(
          ['--target', 'oracle', '--write'],
          { ...cliEnvironment, ASTER_ALLOW_MANIFEST_WRITE: '1' },
          createCliDependencies(temporaryRoot, {
            writeManifestFile: async () => {
              throw new Error('write failed before create');
            },
          })
        )
      ).rejects.toThrow('write failed before create');
      expect(await readdir(temporaryRoot)).toEqual([]);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it.each([{ failure: 'write' }, { failure: 'rename' }])(
    'removes its temp file after a $failure failure',
    async ({ failure }) => {
      const temporaryRoot = await mkdtemp(
        path.join(tmpdir(), `aster-inventory-${failure}-failure-`)
      );

      try {
        const dependencies = createCliDependencies(
          temporaryRoot,
          failure === 'write'
            ? {
                writeManifestFile: async (filePath, contents, options) => {
                  await writeFile(filePath, contents, options);
                  throw new Error('write failed');
                },
              }
            : {
                renameFile: async () => {
                  throw new Error('rename failed');
                },
              }
        );

        await expect(
          runInventoryCli(
            ['--target', 'oracle', '--write'],
            { ...cliEnvironment, ASTER_ALLOW_MANIFEST_WRITE: '1' },
            dependencies
          )
        ).rejects.toThrow(`${failure} failed`);
        expect(await readdir(temporaryRoot)).toEqual([]);
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }
  );

  it('accepts a semantically matching manifest with different formatting and key order', async () => {
    const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'aster-inventory-check-match-'));
    const outputPath = path.join(temporaryRoot, 'output.txt');

    try {
      await writeFile(
        path.join(temporaryRoot, 'baseline-manifest.json'),
        `{"capabilities":[{"existingEvidence":[],"source":"compatibility/manual-capabilities.json","surface":"manual","id":"manual.sample"}],"referenceCommit":"${referenceCommit}","schemaVersion":1}`
      );
      const exitCode = await runInventoryCli(
        ['--target', 'oracle', '--check'],
        cliEnvironment,
        createCliDependencies(temporaryRoot, {
          writeOutput: async (message) => appendFile(outputPath, `${message}\n`),
        })
      );

      expect(exitCode).toBe(0);
      expect(await readFile(outputPath, 'utf8')).toBe(
        'Capability inventory matches (1 capabilities).\n'
      );
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it('returns drift exit 1 with deterministic added and removed diagnostics', async () => {
    const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'aster-inventory-check-drift-'));
    const diagnosticsPath = path.join(temporaryRoot, 'diagnostics.txt');
    const removedCapability = { ...sampleCapability, id: 'manual.z-removed' };
    const addedCapability = { ...sampleCapability, id: 'manual.a-added' };

    try {
      await writeFile(
        path.join(temporaryRoot, 'baseline-manifest.json'),
        JSON.stringify({ ...sampleManifest, capabilities: [removedCapability] })
      );
      const exitCode = await runInventoryCli(
        ['--target', 'oracle', '--check'],
        cliEnvironment,
        createCliDependencies(temporaryRoot, {
          collectManifest: async () => ({ ...sampleManifest, capabilities: [addedCapability] }),
          writeError: async (message) => appendFile(diagnosticsPath, `${message}\n`),
        })
      );

      expect(exitCode).toBe(1);
      expect(await readFile(diagnosticsPath, 'utf8')).toBe(
        'Added capability IDs: manual.a-added\nRemoved capability IDs: manual.z-removed\n'
      );
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it('returns drift exit 1 when capability metadata changes without changing IDs', async () => {
    const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'aster-inventory-metadata-drift-'));
    const diagnosticsPath = path.join(temporaryRoot, 'diagnostics.txt');
    const changedCapability = {
      ...sampleCapability,
      source: 'compatibility/reviewed-manual-capabilities.json',
    };

    try {
      await writeFile(
        path.join(temporaryRoot, 'baseline-manifest.json'),
        JSON.stringify(sampleManifest)
      );
      const exitCode = await runInventoryCli(
        ['--target', 'oracle', '--check'],
        cliEnvironment,
        createCliDependencies(temporaryRoot, {
          collectManifest: async () => ({
            ...sampleManifest,
            capabilities: [changedCapability],
          }),
          writeError: async (message) => appendFile(diagnosticsPath, `${message}\n`),
        })
      );

      expect(exitCode).toBe(1);
      expect(await readFile(diagnosticsPath, 'utf8')).toBe(
        'Added capability IDs: (none)\nRemoved capability IDs: (none)\n'
      );
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it.each([
    { name: 'missing', contents: undefined, error: /Unable to read committed capability manifest/ },
    { name: 'invalid JSON', contents: '{', error: /Invalid committed capability manifest JSON/ },
    { name: 'invalid schema', contents: '{}', error: /Invalid committed capability manifest/ },
  ])('fails clearly for a $name committed manifest', async ({ contents, error }) => {
    const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'aster-inventory-invalid-manifest-'));

    try {
      if (contents !== undefined) {
        await writeFile(path.join(temporaryRoot, 'baseline-manifest.json'), contents);
      }

      await expect(
        runInventoryCli(
          ['--target', 'oracle', '--check'],
          cliEnvironment,
          createCliDependencies(temporaryRoot)
        )
      ).rejects.toThrow(error);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });
});
/* eslint-enable max-lines */
