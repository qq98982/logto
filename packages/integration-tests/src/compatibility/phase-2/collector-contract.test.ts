/* eslint-disable complexity, max-lines, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/consistent-function-scoping -- The in-process HTTP fixture needs mutable counters, entity state, and an ordered request ledger to verify the complete collector CLI boundary without starting the reference lifecycle. */
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import {
  createServer,
  type IncomingMessage,
  type RequestListener,
  type ServerResponse,
} from 'node:http';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { exportJWK, generateKeyPair, SignJWT } from 'jose';

const execFileAsync = promisify(execFile);
const collectorModuleUrl = new URL(
  '../../../../../.scripts/compatibility/phase2-client-credentials-oracle.mjs',
  import.meta.url
);
const collectorPath = fileURLToPath(collectorModuleUrl);
const referenceSource = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const referenceImage = 'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd';
const caseNames = [
  'basic-explicit-resource',
  'post-explicit-resource',
  'default-resource',
  'resource-no-scope',
  'resource-partial-scope',
  'organization-empty-scope',
  'organization-scope',
  'organization-resource-scope',
  'unknown-client-basic',
  'unknown-client-post',
  'wrong-secret-basic',
  'wrong-secret-post',
  'mixed-authentication',
  'missing-target',
  'unknown-resource',
  'unassociated-organization',
  'duplicate-resource',
  'duplicate-scope-name',
  'malformed-scope-whitespace',
  'unsupported-parameter',
] as const;
const cleanupPaths = [
  '/api/organizations/organization-1/applications/app-1/roles/organization-role-2',
  '/api/organizations/organization-1/applications/app-1',
  '/api/organization-roles/organization-role-2',
  '/api/organization-scopes/organization-scope-1',
  '/api/organizations/organization-1',
  '/api/applications/app-2/roles/role-1',
  '/api/applications/app-1/roles/role-1',
  '/api/roles/role-1',
  '/api/resources/resource-1/scopes/scope-3',
  '/api/resources/resource-1/scopes/scope-2',
  '/api/resources/resource-1/scopes/scope-1',
  '/api/resources/resource-2',
  '/api/resources/resource-1',
  '/api/applications/app-2',
  '/api/applications/app-1',
] as const;
const testRoot = `/var/tmp/henry-build/phase2-oracle-contract-${process.pid}-${randomBytes(6).toString('hex')}`;

type Fixture = Readonly<{
  endpoint: string;
  deletes: string[];
  tokenRequests: Array<
    Readonly<{
      authorization: string | undefined;
      entries: Array<readonly [string, string]>;
    }>
  >;
  failTokens: (value: boolean) => void;
  corruptNextResourceResponse: () => void;
  ownedEntityCount: () => number;
  close: () => Promise<void>;
  plantedCompactToken: string;
  plantedSecrets: readonly string[];
}>;

const readRequestBody = async (request: IncomingMessage): Promise<string> => {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) {
    const value: unknown = chunk;
    if (typeof value === 'string') {
      chunks.push(Buffer.from(value));
    } else if (value instanceof Uint8Array) {
      chunks.push(value);
    } else {
      throw new TypeError('fixture received an unsupported request chunk');
    }
  }
  return Buffer.concat(chunks).toString('utf8');
};

const json = (response: ServerResponse, status: number, body: unknown) => {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json',
    'x-fixture': 'retained',
  });
  response.end(JSON.stringify(body));
};

const jwkSet = (response: ServerResponse, body: unknown) => {
  response.writeHead(200, {
    'cache-control': 'no-cache, max-age=0, must-revalidate',
    'content-type': 'application/jwk-set+json',
  });
  response.end(JSON.stringify(body));
};

const created = (response: ServerResponse) => {
  response.writeHead(201, { 'content-type': 'text/plain; charset=utf-8' });
  response.end('Created');
};

const listen = async (handler: RequestListener) => {
  const server = createServer(handler);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, 'localhost', resolve);
  });
  const address = server.address();
  if (typeof address !== 'object' || address === null) {
    throw new TypeError('fixture did not bind a TCP port');
  }
  return {
    endpoint: `http://localhost:${address.port}`,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });
    },
  };
};

const createFixture = async (): Promise<Fixture> => {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = await exportJWK(publicKey);
  const plantedCompactToken = await new SignJWT({ client_id: 'fixture-client', scope: 'read' })
    .setProtectedHeader({ alg: 'ES256', kid: 'fixture-key', typ: 'at+jwt' })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
  const jwks = { keys: [{ ...publicJwk, alg: 'ES256', kid: 'fixture-key', use: 'sig' }] };
  const plantedSecrets = [
    'BasicCollectorSecret000000000001',
    'PostCollectorSecret0000000000002',
  ] as const;
  const deletes: string[] = [];
  const tokenRequests: Fixture['tokenRequests'] = [];
  let failTokens = false;
  let corruptResourceResponse = false;
  let applicationCount = 0;
  let resourceCount = 0;
  let scopeCount = 0;
  let roleCount = 0;
  let organizationCount = 0;
  let organizationScopeCount = 0;
  const entities = {
    applications: new Map<string, Record<string, unknown>>(),
    resources: new Map<string, Record<string, unknown>>(),
    roles: new Map<string, Record<string, unknown>>(),
    organizations: new Map<string, Record<string, unknown>>(),
    'organization-scopes': new Map<string, Record<string, unknown>>(),
    'organization-roles': new Map<string, Record<string, unknown>>(),
  } as const;

  const server = await listen(async (request, response) => {
    const method = request.method ?? '';
    const path = new URL(request.url ?? '/', 'http://fixture.invalid').pathname;
    if (method === 'GET' && path === '/oidc/jwks') {
      jwkSet(response, jwks);
      return;
    }
    if (method === 'POST' && path === '/oidc/token') {
      const bodyText = await readRequestBody(request);
      const { authorization } = request.headers;
      tokenRequests.push({
        authorization: typeof authorization === 'string' ? authorization : undefined,
        entries: [...new URLSearchParams(bodyText).entries()],
      });
      if (failTokens) {
        json(response, 200, { access_token: 'not-a-compact-token' });
        return;
      }
      json(response, 200, {
        access_token: plantedCompactToken,
        expires_in: 3600,
        token_type: 'Bearer',
        echoedSecret: plantedSecrets[1],
        plantedAuthorization: 'Authorization: Basic planted-value',
        plantedCompactToken,
        adjacentCompactToken: `x${plantedCompactToken}suffix`,
      });
      return;
    }
    const bodyText = await readRequestBody(request);
    const body = bodyText.length > 0 ? (JSON.parse(bodyText) as Record<string, unknown>) : {};
    if (request.headers['development-user-id'] !== 'integration-test-admin-user') {
      json(response, 401, { error: 'missing development user' });
      return;
    }
    const collectionMatch =
      /^\/api\/(applications|resources|roles|organizations|organization-scopes|organization-roles)$/u.exec(
        path
      );
    if (method === 'GET' && collectionMatch) {
      const [, collectionName] = collectionMatch;
      const collection = collectionName as keyof typeof entities;
      json(response, 200, [...entities[collection].values()]);
      return;
    }
    if (method === 'DELETE') {
      deletes.push(path);
      const entityMatch =
        /^\/api\/(applications|resources|roles|organizations|organization-scopes|organization-roles)\/([^/]+)$/u.exec(
          path
        );
      if (entityMatch) {
        const collection = entityMatch[1] as keyof typeof entities;
        if (!entities[collection].delete(entityMatch[2]!)) {
          json(response, 404, { error: 'not found' });
          return;
        }
      }
      response.writeHead(204);
      response.end();
      return;
    }
    if (method === 'POST' && path === '/api/applications') {
      applicationCount += 1;
      const application = { id: `app-${applicationCount}`, name: body.name };
      entities.applications.set(application.id, application);
      json(response, 200, application);
      return;
    }
    const secretMatch = /^\/api\/applications\/(app-[12])\/secrets$/u.exec(path);
    if (method === 'GET' && secretMatch) {
      const index = secretMatch[1] === 'app-1' ? 0 : 1;
      json(response, 200, [{ name: 'Default secret', value: plantedSecrets[index] }]);
      return;
    }
    if (method === 'POST' && path === '/api/resources') {
      resourceCount += 1;
      const resource = {
        id: `resource-${resourceCount}`,
        indicator: body.indicator,
        name: body.name,
      };
      entities.resources.set(resource.id, resource);
      if (corruptResourceResponse) {
        corruptResourceResponse = false;
        response.writeHead(201, { 'content-type': 'application/json' });
        response.end('{"id":');
        return;
      }
      json(response, 201, resource);
      return;
    }
    if (method === 'POST' && /^\/api\/resources\/resource-[12]\/scopes$/u.test(path)) {
      scopeCount += 1;
      json(response, 201, { id: `scope-${scopeCount}`, name: body.name });
      return;
    }
    if (method === 'PATCH' && /^\/api\/resources\/resource-[12]\/is-default$/u.test(path)) {
      json(response, 200, { id: path.split('/')[3], isDefault: body.isDefault });
      return;
    }
    if (method === 'POST' && path === '/api/roles') {
      roleCount += 1;
      const role = { id: `role-${roleCount}`, name: body.name };
      entities.roles.set(role.id, role);
      json(response, 200, role);
      return;
    }
    if (method === 'POST' && path === '/api/organizations') {
      organizationCount += 1;
      const organization = { id: `organization-${organizationCount}`, name: body.name };
      entities.organizations.set(organization.id, organization);
      json(response, 201, organization);
      return;
    }
    if (method === 'POST' && path === '/api/organization-scopes') {
      organizationScopeCount += 1;
      const organizationScope = {
        id: `organization-scope-${organizationScopeCount}`,
        name: body.name,
        description: body.description,
      };
      entities['organization-scopes'].set(organizationScope.id, organizationScope);
      json(response, 201, organizationScope);
      return;
    }
    if (method === 'POST' && path === '/api/organization-roles') {
      roleCount += 1;
      const organizationRole = { id: `organization-role-${roleCount}`, name: body.name };
      entities['organization-roles'].set(organizationRole.id, organizationRole);
      json(response, 201, organizationRole);
      return;
    }
    if (
      method === 'POST' &&
      (path === '/api/organizations/organization-1/applications' ||
        path === '/api/organizations/organization-1/applications/app-1/roles')
    ) {
      created(response);
      return;
    }
    if (method === 'POST') {
      json(response, 201, {});
      return;
    }
    json(response, 404, { error: 'unhandled fixture route' });
  });

  return {
    endpoint: server.endpoint,
    deletes,
    tokenRequests,
    failTokens: (value) => {
      failTokens = value;
    },
    corruptNextResourceResponse: () => {
      corruptResourceResponse = true;
    },
    ownedEntityCount: () =>
      Object.values(entities).reduce((total, collection) => total + collection.size, 0),
    close: async () => {
      await server.close();
    },
    plantedCompactToken,
    plantedSecrets,
  };
};

const collectorArguments = (fixture: Fixture, output: string) => [
  collectorPath,
  '--endpoint',
  fixture.endpoint,
  '--output',
  output,
  '--reference-source',
  referenceSource,
  '--reference-image',
  referenceImage,
];

const runCollector = async (fixture: Fixture, output: string) =>
  execFileAsync(process.execPath, collectorArguments(fixture, output), {
    cwd: fileURLToPath(new URL('../../../../../', import.meta.url)),
    timeout: 30_000,
  });

const expectedTokenRequests = (secrets: readonly string[]): Fixture['tokenRequests'] => {
  const basicSecret = secrets[0];
  const postSecret = secrets[1];
  if (basicSecret === undefined || postSecret === undefined) {
    throw new TypeError('fixture secrets missing');
  }
  const basic = (clientId: string, secret: string) =>
    `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}`;
  const request = (
    authorization: string | undefined,
    entries: Array<readonly [string, string]>
  ) => ({ authorization, entries });
  const primary = 'https://phase2.example.invalid/api-primary';
  const defaultResource = 'https://phase2.example.invalid/api-default';
  const unknownSecret = 'UnknownCollectorSecret0000000000';
  const wrongSecret = 'WrongCollectorSecret000000000000';

  return [
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
    ]),
    request(undefined, [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['client_id', 'app-2'],
      ['client_secret', postSecret],
    ]),
    request(basic('app-1', basicSecret), [['grant_type', 'client_credentials']]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['scope', 'read unavailable'],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['organization_id', 'organization-1'],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['organization_id', 'organization-1'],
      ['scope', 'organization:read unavailable'],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['organization_id', 'organization-1'],
      ['scope', 'read write unassigned'],
    ]),
    request(basic('phase2-unknown-client-basic', unknownSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
    ]),
    request(undefined, [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['client_id', 'phase2-unknown-client-post'],
      ['client_secret', unknownSecret],
    ]),
    request(basic('app-1', wrongSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
    ]),
    request(undefined, [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['client_id', 'app-2'],
      ['client_secret', wrongSecret],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['client_id', 'app-2'],
      ['client_secret', postSecret],
    ]),
    request(basic('app-1', basicSecret), [['grant_type', 'client_credentials']]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', 'https://phase2.example.invalid/unknown'],
    ]),
    request(undefined, [
      ['grant_type', 'client_credentials'],
      ['organization_id', 'organization-1'],
      ['client_id', 'app-2'],
      ['client_secret', postSecret],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['resource', defaultResource],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['scope', 'read read write'],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['scope', ' read  write '],
    ]),
    request(basic('app-1', basicSecret), [
      ['grant_type', 'client_credentials'],
      ['resource', primary],
      ['unsupported_parameter', 'rejected'],
    ]),
  ];
};

beforeAll(async () => {
  await mkdir(testRoot, { mode: 0o700, recursive: true });
  await chmod(testRoot, 0o700);
});

afterAll(async () => {
  await rm(testRoot, { force: true, recursive: true });
});

describe('Phase 2 client credentials collector contract', () => {
  it('publishes the exact ordered sanitized packet with mode 0600 after reverse cleanup', async () => {
    const fixture = await createFixture();
    const output = `${testRoot}/phase2-client-credentials-oracle-success.json`;
    try {
      const result = await runCollector(fixture, output);
      const packetText = await readFile(output, 'utf8');
      const packet = JSON.parse(packetText) as {
        cases: Array<{ name: string }>;
        cleanup: {
          operations: Array<{ name: string; status: string }>;
          reconciliation: Array<{ name: string; status: string }>;
        };
      };

      expect(result.stdout).toBe('Phase 2 client credentials oracle collected.\n');
      expect(result.stderr).toBe('');
      expect(packet.cases.map(({ name }) => name)).toEqual(caseNames);
      expect(packet.cleanup.operations.every(({ status }) => status === 'deleted')).toBe(true);
      expect(packet.cleanup.reconciliation).toEqual([]);
      const outputMetadata = await stat(output);
      expect(outputMetadata.mode & 0o777).toBe(0o600);
      expect(fixture.deletes).toEqual(cleanupPaths);
      expect(fixture.ownedEntityCount()).toBe(0);
      expect(fixture.tokenRequests).toEqual(expectedTokenRequests(fixture.plantedSecrets));
      for (const secret of fixture.plantedSecrets) {
        expect(packetText).not.toContain(secret);
      }
      expect(packetText).not.toContain(fixture.plantedCompactToken);
      expect(packetText.toLowerCase()).not.toContain('authorization');

      const sentinel = '{"sentinel":true}\n';
      await writeFile(output, sentinel, { mode: 0o600 });
      await expect(runCollector(fixture, output)).rejects.toMatchObject({
        stderr: 'Phase 2 client credentials oracle collection failed.\n',
      });
      await expect(readFile(output, 'utf8')).resolves.toBe(sentinel);
    } finally {
      await fixture.close();
    }
  });

  it('cleans provisioned entities but does not publish when collection fails', async () => {
    const fixture = await createFixture();
    const output = `${testRoot}/phase2-client-credentials-oracle-failure.json`;
    fixture.failTokens(true);
    try {
      await expect(runCollector(fixture, output)).rejects.toMatchObject({
        stdout: '',
        stderr: 'Phase 2 client credentials oracle collection failed.\n',
      });
      await expect(stat(output)).rejects.toMatchObject({ code: 'ENOENT' });
      expect(fixture.deletes).toEqual(cleanupPaths);
      expect(fixture.ownedEntityCount()).toBe(0);
    } finally {
      await fixture.close();
    }
  });

  it('reconciles a created entity when its successful mutation response is malformed', async () => {
    const fixture = await createFixture();
    const output = `${testRoot}/phase2-client-credentials-oracle-reconciliation.json`;
    fixture.corruptNextResourceResponse();
    try {
      await expect(runCollector(fixture, output)).rejects.toMatchObject({
        stdout: '',
        stderr: 'Phase 2 client credentials oracle collection failed.\n',
      });
      await expect(stat(output)).rejects.toMatchObject({ code: 'ENOENT' });
      expect(fixture.tokenRequests).toEqual([]);
      expect(fixture.deletes).toEqual([
        '/api/applications/app-2',
        '/api/applications/app-1',
        '/api/resources/resource-1',
      ]);
      expect(fixture.ownedEntityCount()).toBe(0);
    } finally {
      await fixture.close();
    }
  });

  it('accepts localhost fixtures while rejecting open arguments, unsafe paths, and non-loopback origins', async () => {
    await expect(
      execFileAsync(process.execPath, [collectorPath, '--unknown', 'value'], { timeout: 5000 })
    ).rejects.toMatchObject({
      stdout: '',
      stderr: 'Phase 2 client credentials oracle collection failed.\n',
    });
    await expect(
      execFileAsync(
        process.execPath,
        [
          collectorPath,
          '--endpoint',
          'http://127.0.0.1:3101',
          '--output',
          '/tmp/phase2-client-credentials-oracle-invalid.json',
          '--reference-source',
          referenceSource,
          '--reference-image',
          referenceImage,
        ],
        { timeout: 5000 }
      )
    ).rejects.toMatchObject({
      stderr: 'Phase 2 client credentials oracle collection failed.\n',
    });
    await Promise.all(
      ['http://192.0.2.1:3101', 'http://localhost:443'].map(async (endpoint) =>
        expect(
          execFileAsync(
            process.execPath,
            [
              collectorPath,
              '--endpoint',
              endpoint,
              '--output',
              `${testRoot}/phase2-client-credentials-oracle-rejected-origin.json`,
              '--reference-source',
              referenceSource,
              '--reference-image',
              referenceImage,
            ],
            { timeout: 5000 }
          )
        ).rejects.toMatchObject({
          stdout: '',
          stderr: 'Phase 2 client credentials oracle collection failed.\n',
        })
      )
    );
  });

  it('bounds best-effort cancellation even when the cancel promise never settles', async () => {
    const source = `
      const { cancelSafely } = await import(${JSON.stringify(collectorModuleUrl.href)});
      const started = Date.now();
      await cancelSafely({ cancel: () => new Promise(() => undefined) });
      const elapsed = Date.now() - started;
      if (elapsed < 75 || elapsed > 1000) process.exit(2);
      process.stdout.write('bounded\\n');
    `;
    const result = await execFileAsync(
      process.execPath,
      ['--input-type=module', '--eval', source],
      { timeout: 2000 }
    );
    const collectorSource = await readFile(collectorPath, 'utf8');

    expect(result).toEqual(expect.objectContaining({ stdout: 'bounded\n', stderr: '' }));
    expect(collectorSource).not.toMatch(/(?:response\.body|reader)\??\.cancel\(/u);
  });
});
/* eslint-enable complexity, max-lines, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/consistent-function-scoping */
