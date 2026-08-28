import { mkdtemp, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseInventoryArguments, resolveTargetConfig } from './cli.js';
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

  it('canonicalizes compound OIDC response types and rejects duplicate generated IDs', () => {
    expect(
      extractOidcCapabilities({ response_types_supported: ['code\vid_token'] }).map(({ id }) => id)
    ).toEqual(['oidc.response_type.code+id_token']);
    expect(() =>
      extractOidcCapabilities({
        response_types_supported: ['code id_token', 'code  id_token'],
      })
    ).toThrow('Duplicate capability ID: oidc.response_type.code+id_token');
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
    const responseByPath: Record<string, unknown> = {
      '/api/.well-known/experience.openapi.json': {
        paths: { '/api/experience': { post: {} } },
      },
      '/api/.well-known/management.openapi.json': {
        paths: { '/api/users': { get: {} } },
      },
      '/api/.well-known/user.openapi.json': {
        paths: { '/api/account': { patch: {} } },
      },
      '/oidc/.well-known/openid-configuration': {
        grant_types_supported: ['authorization_code'],
      },
      '/api/connector-factories': [{ id: 'email' }],
    };

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

          return responseByPath[url.pathname];
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
      'test.api/users.test.ts',
    ]);
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
});
