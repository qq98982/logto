/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Cohesive HTTP lifecycle coverage requires controlled mutable server instrumentation. */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';

import { loadCompatibilityConfig, validateTargetConfig } from './config.js';
import type { TargetConfig } from './model.js';
import {
  runScenarioForTarget,
  type CompatibilityScenario,
  type ScenarioRunnerOptions,
} from './scenario.js';
import { TargetClient, TargetClientError } from './target-client.js';

type RecordedRequest = {
  method: string;
  path: string;
  headers: IncomingMessage['headers'];
  body: unknown;
};

type TestServer = {
  baseUrl: string;
  requests: RecordedRequest[];
  close: () => Promise<void>;
};

const readRequestBody = async (request: IncomingMessage): Promise<unknown> => {
  const chunks: Uint8Array[] = [];

  for await (const chunk of request) {
    const value: unknown = chunk;

    if (typeof value === 'string') {
      chunks.push(Buffer.from(value));
    } else if (value instanceof Uint8Array) {
      chunks.push(value);
    } else {
      throw new TypeError('Unexpected request body chunk');
    }
  }

  if (chunks.length === 0) {
    return undefined;
  }

  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
};

const sendJson = (response: ServerResponse, status: number, body: unknown) => {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
};

const sendMalformedJson = (response: ServerResponse, status: number, body: string) => {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(body);
};

const startServer = async (
  handler: (
    request: RecordedRequest,
    response: ServerResponse,
    baseUrl: string
  ) => void | Promise<void>
): Promise<TestServer> => {
  const requests: RecordedRequest[] = [];
  let baseUrl = '';
  const server = createServer(async (request, response) => {
    try {
      const recordedRequest = {
        method: request.method ?? '',
        path: request.url ?? '',
        headers: request.headers,
        body: await readRequestBody(request),
      };
      requests.push(recordedRequest);
      await handler(recordedRequest, response, baseUrl);
    } catch {
      sendJson(response, 500, { error: 'test-server-failure' });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}/`;

  return {
    baseUrl,
    requests,
    close: async () => {
      server.closeAllConnections();
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

const createTarget = (label: TargetConfig['label'], baseUrl: string): TargetConfig => ({
  label,
  coreUrl: baseUrl,
  adminUrl: baseUrl,
});

const completeWithoutResult = async (): Promise<void> => {
  await Promise.resolve();
};

const createCleanupClient = (cleanup: () => Promise<void>) =>
  ({ cleanup }) as unknown as TargetClient;

const renderError = (error: unknown): string => {
  const enumerableProperties =
    typeof error === 'object' && error !== null ? Object.fromEntries(Object.entries(error)) : error;
  const aggregateErrors = error instanceof AggregateError ? error.errors : [];

  return [
    String(error),
    inspect(error, { depth: null }),
    JSON.stringify(error),
    inspect(enumerableProperties, { depth: null }),
    inspect(aggregateErrors, { depth: null }),
  ].join('\n');
};

describe('loadCompatibilityConfig', () => {
  const validEnvironment = {
    ASTER_ORACLE_URL: 'http://localhost:3101',
    ASTER_ORACLE_ADMIN_URL: 'http://localhost:3201',
    ASTER_CANDIDATE_URL: 'http://localhost:3102',
    ASTER_CANDIDATE_ADMIN_URL: 'http://localhost:3202',
  };

  it.each(Object.keys(validEnvironment))('names missing %s without exposing values', (variable) => {
    const environment = { ...validEnvironment, [variable]: undefined };

    expect(() => loadCompatibilityConfig(environment)).toThrow(variable);
  });

  it.each(Object.keys(validEnvironment))('rejects empty %s', (variable) => {
    const environment = { ...validEnvironment, [variable]: '   ' };

    expect(() => loadCompatibilityConfig(environment)).toThrow(variable);
  });

  it.each([
    ['not-a-url', 'invalid'],
    ['ftp://example.com', 'non-http'],
    ['https://user:password@example.com', 'credentials'],
    ['https://example.com/api', 'path'],
    ['https://example.com/?mode=test', 'query'],
    ['https://example.com/#fragment', 'fragment'],
  ])('rejects %s target URLs', (value) => {
    expect(() =>
      loadCompatibilityConfig({ ...validEnvironment, ASTER_CANDIDATE_URL: value })
    ).toThrow('ASTER_CANDIDATE_URL');
  });

  it('does not echo a rejected URL that contains sensitive material', () => {
    const secret = 'synthetic-password-never-print';

    expect(() =>
      loadCompatibilityConfig({
        ...validEnvironment,
        ASTER_CANDIDATE_URL: `https://user:${secret}@example.com`,
      })
    ).toThrow(new Error('Invalid ASTER_CANDIDATE_URL'));
  });

  it('rejects either canonically shared oracle/candidate origin', () => {
    expect(() =>
      loadCompatibilityConfig({
        ASTER_ORACLE_URL: 'HTTPS://EXAMPLE.COM:443',
        ASTER_ORACLE_ADMIN_URL: 'https://oracle-admin.example.com',
        ASTER_CANDIDATE_URL: 'https://example.com/',
        ASTER_CANDIDATE_ADMIN_URL: 'https://candidate-admin.example.com/',
      })
    ).toThrow('Oracle and candidate core URLs must differ');

    expect(() =>
      loadCompatibilityConfig({
        ASTER_ORACLE_URL: 'https://oracle.example.com',
        ASTER_ORACLE_ADMIN_URL: 'HTTPS://ADMIN.EXAMPLE.COM:443',
        ASTER_CANDIDATE_URL: 'https://candidate.example.com',
        ASTER_CANDIDATE_ADMIN_URL: 'https://admin.example.com/',
      })
    ).toThrow('Oracle and candidate admin URLs must differ');
  });

  it('allows core/admin equality within each isolated target', () => {
    expect(
      loadCompatibilityConfig({
        ASTER_ORACLE_URL: 'https://oracle.example.com',
        ASTER_ORACLE_ADMIN_URL: 'https://oracle.example.com',
        ASTER_CANDIDATE_URL: 'https://candidate.example.com',
        ASTER_CANDIDATE_ADMIN_URL: 'https://candidate.example.com',
      })
    ).toEqual({
      oracle: {
        label: 'oracle',
        coreUrl: 'https://oracle.example.com/',
        adminUrl: 'https://oracle.example.com/',
      },
      candidate: {
        label: 'candidate',
        coreUrl: 'https://candidate.example.com/',
        adminUrl: 'https://candidate.example.com/',
      },
    });
  });

  it('allows a cross-role overlap while counterpart origins remain isolated', () => {
    expect(
      loadCompatibilityConfig({
        ASTER_ORACLE_URL: 'https://shared.example.com',
        ASTER_ORACLE_ADMIN_URL: 'https://oracle-admin.example.com',
        ASTER_CANDIDATE_URL: 'https://candidate.example.com',
        ASTER_CANDIDATE_ADMIN_URL: 'https://shared.example.com',
      })
    ).toMatchObject({
      oracle: { coreUrl: 'https://shared.example.com/' },
      candidate: { adminUrl: 'https://shared.example.com/' },
    });
  });

  it('returns canonical target URLs and fixed labels', () => {
    const config = loadCompatibilityConfig({
      ...validEnvironment,
      ASTER_ORACLE_URL: 'HTTP://LOCALHOST:3101',
      ASTER_ORACLE_ADMIN_URL: 'http://localhost:3201/',
      ASTER_CANDIDATE_URL: 'https://EXAMPLE.com:443',
      ASTER_CANDIDATE_ADMIN_URL: 'https://admin.example.com',
      ASTER_ORACLE_LABEL: 'candidate',
    });

    expect(config).toEqual({
      oracle: {
        label: 'oracle',
        coreUrl: 'http://localhost:3101/',
        adminUrl: 'http://localhost:3201/',
      },
      candidate: {
        label: 'candidate',
        coreUrl: 'https://example.com/',
        adminUrl: 'https://admin.example.com/',
      },
    });
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.oracle)).toBe(true);
    expect(Object.isFrozen(config.candidate)).toBe(true);
  });

  it.each([
    ['coreUrl', 'https://user:private-value@example.com'],
    ['adminUrl', 'https://example.com/console'],
  ])('strictly validates and freezes direct target field %s', (field, value) => {
    const target = {
      label: 'oracle' as const,
      coreUrl: 'https://core.example.com',
      adminUrl: 'https://admin.example.com',
      [field]: value,
    };

    const errors = [() => validateTargetConfig(target), () => new TargetClient(target)].map(
      (operation) => {
        try {
          operation();
          throw new Error('Expected strict target validation to fail');
        } catch (error: unknown) {
          return error;
        }
      }
    );

    expect(errors.map(String).join('\n')).toContain(`Invalid ${field}`);
    expect(errors.map(String).join('\n')).not.toContain(value);

    const validated = validateTargetConfig({
      label: 'oracle',
      coreUrl: 'HTTPS://CORE.EXAMPLE.COM:443',
      adminUrl: 'https://admin.example.com',
    });
    expect(Object.isFrozen(validated)).toBe(true);
    expect(validated.coreUrl).toBe('https://core.example.com/');
    expect(Object.isFrozen(new TargetClient(validated).target)).toBe(true);
  });

  it('fails before a client factory can observe an invalid environment', () => {
    let factoryCallCount = 0;
    const loadAndCreateClient = (environment: Readonly<Record<string, string | undefined>>) => {
      const { oracle } = loadCompatibilityConfig(environment);
      factoryCallCount += 1;
      return new TargetClient(oracle);
    };

    expect(() =>
      loadAndCreateClient({ ...validEnvironment, ASTER_CANDIDATE_URL: 'not-a-url' })
    ).toThrow('ASTER_CANDIDATE_URL');
    expect(factoryCallCount).toBe(0);
  });
});

describe('TargetClient', () => {
  it('isolates management and per-request userinfo authorization headers', async () => {
    const server = await startServer((request, response) => {
      sendJson(response, 200, { path: request.path });
    });

    try {
      const client = new TargetClient(createTarget('oracle', server.baseUrl));
      await client.core.get('core-probe');
      await client.management.get('management-probe');
      await client.experience.get('experience-probe');
      await client.getManagementOpenApi();
      await client.getExperienceOpenApi();
      await client.getUserOpenApi();
      await client.getUserInfo('synthetic-access-token');
      await client.core.get('core-after-userinfo');

      expect(server.requests).toHaveLength(8);
      expect(
        server.requests.map(({ path, headers }) => [path, headers['development-user-id']])
      ).toEqual([
        ['/core-probe', undefined],
        ['/api/management-probe', 'integration-test-admin-user'],
        ['/api/experience-probe', undefined],
        ['/api/.well-known/management.openapi.json', undefined],
        ['/api/.well-known/experience.openapi.json', undefined],
        ['/api/.well-known/user.openapi.json', undefined],
        ['/oidc/me', undefined],
        ['/core-after-userinfo', undefined],
      ]);
      expect(server.requests.map(({ headers }) => headers.authorization)).toEqual([
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        'Bearer synthetic-access-token',
        undefined,
      ]);
    } finally {
      await server.close();
    }
  });

  it('keeps every Management operation on coreUrl and never calls adminUrl', async () => {
    const coreServer = await startServer((request, response) => {
      if (request.method === 'POST' && request.path === '/api/users') {
        sendJson(response, 200, { id: 'core-user' });
        return;
      }

      sendJson(response, 200, { id: 'core-user' });
    });
    const adminServer = await startServer((_request, response) => {
      sendJson(response, 500, { error: 'admin-origin-must-not-receive-management' });
    });

    try {
      const client = new TargetClient({
        label: 'oracle',
        coreUrl: coreServer.baseUrl,
        adminUrl: adminServer.baseUrl,
      });
      await client.listConnectorFactories();
      await client.setUsernamePasswordExperience();
      const user = await client.createUser({ username: 'core-only-user' });
      await client.getUser(user.id);
      await client.deleteUser(user.id);

      expect(coreServer.requests.map(({ method, path }) => [method, path])).toEqual([
        ['GET', '/api/connector-factories'],
        ['PATCH', '/api/sign-in-exp'],
        ['POST', '/api/users'],
        ['GET', '/api/users/core-user'],
        ['DELETE', '/api/users/core-user'],
      ]);
      expect(adminServer.requests).toEqual([]);
    } finally {
      await Promise.all([coreServer.close(), adminServer.close()]);
    }
  });

  it('uses the exact phase-0 methods, paths, and request bodies', async () => {
    let nextUserId = 0;
    const server = await startServer((request, response) => {
      if (request.method === 'POST' && request.path === '/api/users') {
        nextUserId += 1;
        sendJson(response, 200, {
          id: `user-${nextUserId}`,
          ...(request.body as Record<string, unknown>),
        });
        return;
      }

      sendJson(response, 200, { id: 'user-1' });
    });

    try {
      const client = new TargetClient({
        label: 'oracle',
        coreUrl: server.baseUrl,
        adminUrl: 'https://console.example.com/',
      });
      await client.getDiscovery();
      await client.getManagementOpenApi();
      await client.getExperienceOpenApi();
      await client.getUserOpenApi();
      await client.listConnectorFactories();
      await client.setUsernamePasswordExperience();
      const user = await client.createUser({
        username: 'scenario-user',
        password: 'synthetic-password-never-print',
      });
      await client.getUser(user.id);
      await client.getUserInfo('synthetic-token-never-print');
      await client.deleteUser(user.id);

      expect(server.requests.map(({ method, path }) => [method, path])).toEqual([
        ['GET', '/oidc/.well-known/openid-configuration'],
        ['GET', '/api/.well-known/management.openapi.json'],
        ['GET', '/api/.well-known/experience.openapi.json'],
        ['GET', '/api/.well-known/user.openapi.json'],
        ['GET', '/api/connector-factories'],
        ['PATCH', '/api/sign-in-exp'],
        ['POST', '/api/users'],
        ['GET', '/api/users/user-1'],
        ['GET', '/oidc/me'],
        ['DELETE', '/api/users/user-1'],
      ]);
      expect(server.requests[5]?.body).toEqual({
        signInMode: 'SignInAndRegister',
        signUp: { identifiers: ['username'], password: true, verify: false },
        signIn: {
          methods: [
            {
              identifier: 'username',
              password: true,
              verificationCode: false,
              isPasswordPrimary: true,
            },
          ],
        },
        passwordPolicy: {},
      });
      expect(server.requests[6]?.body).toEqual({
        username: 'scenario-user',
        password: 'synthetic-password-never-print',
      });
    } finally {
      await server.close();
    }
  });

  it('sanitizes HTTP errors across string, inspect, JSON, and enumerable representations', async () => {
    const token = ['synthetic', 'token', 'never', 'print'].join('-');
    const password = ['synthetic', 'password', 'never', 'print'].join('-');
    const responseMarker = ['private', 'response', 'body', 'marker'].join('-');
    const server = await startServer((request, response) => {
      sendJson(response, 500, {
        reflected: request.path === '/oidc/me' ? request.headers.authorization : request.body,
        responseMarker,
      });
    });

    try {
      const client = new TargetClient(createTarget('oracle', server.baseUrl));
      await expect(client.getUserInfo('   ')).rejects.toThrow('Access token must be non-empty');

      const errors = await Promise.all(
        [
          async () => client.getUserInfo(token),
          async () => client.createUser({ username: 'failure', password }),
        ].map(async (operation) => {
          try {
            await operation();
            throw new Error('Expected request to fail');
          } catch (error: unknown) {
            return error;
          }
        })
      );
      const errorOutput = errors.map((error) => renderError(error)).join('\n');

      expect(errorOutput).not.toContain(token);
      expect(errorOutput).not.toContain(password);
      expect(errorOutput).not.toContain(responseMarker);
      expect(errors).toEqual([
        expect.objectContaining({ operation: 'getUserInfo', status: 500 }),
        expect.objectContaining({ operation: 'createUser', status: 500 }),
      ]);
      expect(errors.every((error) => error instanceof TargetClientError)).toBe(true);
      expect(
        errors.map((error) => Object.keys(error as Record<string, unknown>).toSorted())
      ).toEqual([
        ['operation', 'status'],
        ['operation', 'status'],
      ]);
    } finally {
      await server.close();
    }
  });

  it('sanitizes malformed JSON errors without retaining response data', async () => {
    const responseMarker = ['malformed', 'private', 'body'].join('-');
    const server = await startServer((_request, response) => {
      sendMalformedJson(response, 200, `{"marker":"${responseMarker}"`);
    });

    try {
      const client = new TargetClient(createTarget('oracle', server.baseUrl));

      try {
        await client.getDiscovery();
        throw new Error('Expected malformed JSON to fail');
      } catch (error: unknown) {
        expect(error).toBeInstanceOf(TargetClientError);
        expect(error).toMatchObject({ operation: 'getDiscovery', status: undefined });
        expect(renderError(error)).not.toContain(responseMarker);
      }
    } finally {
      await server.close();
    }
  });

  it('performs one physical request per logical GET and DELETE when responses are retryable', async () => {
    const server = await startServer((request, response) => {
      if (request.method === 'POST') {
        sendJson(response, 200, { id: 'retry-user' });
        return;
      }

      sendJson(response, 500, { error: 'retryable-but-not-retried' });
    });

    try {
      const client = new TargetClient(createTarget('oracle', server.baseUrl));
      await expect(client.getDiscovery()).rejects.toMatchObject({ status: 500 });
      await client.createUser({ username: 'retry-user' });
      await expect(client.deleteUser('retry-user')).rejects.toMatchObject({ status: 500 });

      expect(
        server.requests
          .filter(
            ({ method, path }) =>
              (method === 'GET' && path === '/oidc/.well-known/openid-configuration') ||
              (method === 'DELETE' && path === '/api/users/retry-user')
          )
          .map(({ method, path }) => [method, path])
      ).toEqual([
        ['GET', '/oidc/.well-known/openid-configuration'],
        ['DELETE', '/api/users/retry-user'],
      ]);
    } finally {
      await server.close();
    }
  });

  it('treats DELETE 404 as already deleted and untracks the user', async () => {
    const server = await startServer((request, response) => {
      if (request.method === 'POST') {
        sendJson(response, 200, { id: 'already-gone' });
        return;
      }

      sendJson(response, 404, { error: 'not-found' });
    });

    try {
      const client = new TargetClient(createTarget('oracle', server.baseUrl));
      await client.createUser({ username: 'already-gone' });
      await client.deleteUser('already-gone');
      await client.cleanup();

      expect(server.requests.filter(({ method }) => method === 'DELETE')).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it('cleans tracked users in exact reverse order, retries only later cleanup calls, and is idempotent', async () => {
    const deleteAttempts = new Map<string, number>();
    const server = await startServer((request, response) => {
      if (request.method === 'POST') {
        const { username } = request.body as { username: string };
        sendJson(response, 200, { id: username });
        return;
      }

      if (request.method === 'DELETE') {
        const userId = request.path.split('/').at(-1) ?? '';
        const attempt = (deleteAttempts.get(userId) ?? 0) + 1;
        deleteAttempts.set(userId, attempt);

        if (userId === 'second' && attempt === 1) {
          sendJson(response, 500, { hidden: 'response-body-must-not-be-recorded' });
          return;
        }
      }

      sendJson(response, 200, {});
    });

    try {
      const client = new TargetClient(createTarget('oracle', server.baseUrl));
      await client.createUser({ username: 'first' });
      await client.createUser({ username: 'second' });
      await client.createUser({ username: 'third' });

      try {
        await client.cleanup();
        throw new Error('Expected cleanup to fail');
      } catch (error: unknown) {
        expect(error).toBeInstanceOf(AggregateError);
        expect((error as AggregateError).errors).toHaveLength(1);
        expect((error as AggregateError).message).toBe('Failed to clean up 1 user(s)');
        expect((error as AggregateError).errors[0]).toMatchObject({
          operation: 'deleteUser',
          status: 500,
        });
        expect(renderError(error)).not.toContain('response-body-must-not-be-recorded');
      }

      const firstCleanupDeletes = server.requests
        .filter(({ method }) => method === 'DELETE')
        .map(({ path }) => path);
      expect(firstCleanupDeletes).toEqual([
        '/api/users/third',
        '/api/users/second',
        '/api/users/first',
      ]);

      await client.cleanup();
      await client.cleanup();

      const allDeletes = server.requests
        .filter(({ method }) => method === 'DELETE')
        .map(({ path }) => path);
      expect(allDeletes.slice(firstCleanupDeletes.length)).toEqual(['/api/users/second']);
    } finally {
      await server.close();
    }
  });
});

describe('runScenarioForTarget', () => {
  it('runs one shared scenario once per target and normalizes target URLs and symbols', async () => {
    const oracleServer = await startServer((_request, response, baseUrl) => {
      sendJson(response, 200, { issuer: baseUrl, userId: `user-at-${baseUrl}` });
    });
    const candidateServer = await startServer((_request, response, baseUrl) => {
      sendJson(response, 200, { issuer: baseUrl, userId: `user-at-${baseUrl}` });
    });
    const invocations: Array<TargetConfig['label']> = [];
    const scenario: CompatibilityScenario = {
      id: 'shared/discovery-scenario',
      run: async ({ target, client, symbols, observe }) => {
        invocations.push(target.label);
        const response = (await client.getDiscovery()) as unknown as {
          issuer: string;
          userId: string;
        };
        symbols.bind('created-user', response.userId);
        observe({ stepId: 'discovery', kind: 'http', value: response });
      },
    };

    try {
      const oracle = await runScenarioForTarget(
        scenario,
        createTarget('oracle', oracleServer.baseUrl)
      );
      const candidate = await runScenarioForTarget(
        scenario,
        createTarget('candidate', candidateServer.baseUrl)
      );

      expect(invocations).toEqual(['oracle', 'candidate']);
      expect(oracle.target).toBe('oracle');
      expect(candidate.target).toBe('candidate');
      expect(oracle.observations).toEqual(candidate.observations);
      expect(oracle.observations).toEqual([
        {
          stepId: 'discovery',
          kind: 'http',
          value: { issuer: '<target.core-url>/', userId: '<created-user>' },
        },
      ]);
    } finally {
      await Promise.all([oracleServer.close(), candidateServer.close()]);
    }
  });

  it('uses fresh symbols and observation collections while preserving order and metadata', async () => {
    const server = await startServer((_request, response) => {
      sendJson(response, 200, {});
    });
    let invocation = 0;
    const scenario: CompatibilityScenario = {
      id: 'fresh-state',
      run: async ({ symbols, observe }) => {
        invocation += 1;
        symbols.bind('run-value', `runtime-${invocation}`);
        observe({ stepId: 'first/step', kind: 'semantic-state', value: `runtime-${invocation}` });
        observe({ stepId: 'second step', kind: 'http', value: invocation });
      },
    };

    try {
      const first = await runScenarioForTarget(scenario, createTarget('oracle', server.baseUrl));
      const second = await runScenarioForTarget(
        scenario,
        createTarget('candidate', server.baseUrl)
      );

      expect(first.observations).toEqual([
        { stepId: 'first/step', kind: 'semantic-state', value: '<run-value>' },
        { stepId: 'second step', kind: 'http', value: 1 },
      ]);
      expect(second.observations).toEqual([
        { stepId: 'first/step', kind: 'semantic-state', value: '<run-value>' },
        { stepId: 'second step', kind: 'http', value: 2 },
      ]);
    } finally {
      await server.close();
    }
  });

  it('validates and clones observations immediately', async () => {
    const server = await startServer((_request, response) => {
      sendJson(response, 200, {});
    });
    const mutableValue = { nested: { value: 'before' } };

    try {
      const evidence = await runScenarioForTarget(
        {
          id: 'clone-observation',
          run: async ({ observe }) => {
            observe({ stepId: 'state', kind: 'semantic-state', value: mutableValue });
            mutableValue.nested.value = 'after';
          },
        },
        createTarget('oracle', server.baseUrl)
      );
      expect(evidence.observations[0]?.value).toEqual({ nested: { value: 'before' } });

      await expect(
        runScenarioForTarget(
          {
            id: 'invalid-observation',
            run: async ({ observe }) => {
              observe({
                stepId: '',
                kind: 'semantic-state',
                value: {},
              });
            },
          },
          createTarget('oracle', server.baseUrl)
        )
      ).rejects.toThrow();
    } finally {
      await server.close();
    }
  });

  it('validates target and scenario id before constructing a client', async () => {
    let factoryCallCount = 0;
    const clientFactory = () => {
      factoryCallCount += 1;
      throw new Error('factory-called');
    };
    const options: ScenarioRunnerOptions = { clientFactory };

    await expect(
      runScenarioForTarget(
        { id: 'valid', run: completeWithoutResult },
        { label: 'oracle', coreUrl: 'not-a-url', adminUrl: 'https://admin.example.com' },
        options
      )
    ).rejects.not.toThrow('factory-called');
    await expect(
      runScenarioForTarget(
        { id: '\u0000', run: completeWithoutResult },
        createTarget('oracle', 'https://core.example.com/'),
        options
      )
    ).rejects.not.toThrow('factory-called');
    expect(factoryCallCount).toBe(0);
  });

  it('aggregates a primary failure with sanitized real-client cleanup failure', async () => {
    const responseMarker = ['cleanup', 'private', 'response', 'marker'].join('-');
    const password = ['cleanup', 'request', 'password', 'marker'].join('-');
    const server = await startServer((request, response) => {
      if (request.method === 'POST') {
        sendJson(response, 200, { id: 'tracked-real-user' });
        return;
      }

      sendJson(response, 500, { responseMarker });
    });
    const primaryError = new Error('primary non-network scenario failure');
    const client = new TargetClient(createTarget('oracle', server.baseUrl));

    try {
      await runScenarioForTarget(
        {
          id: 'real-dual-failure',
          run: async ({ client: scenarioClient }) => {
            await scenarioClient.createUser({ username: 'tracked-real-user', password });
            throw primaryError;
          },
        },
        createTarget('oracle', server.baseUrl),
        { client }
      );
      throw new Error('Expected scenario and cleanup to fail');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(AggregateError);
      const [scenarioError, cleanupError] = Array.from<unknown>((error as AggregateError).errors);

      expect(scenarioError).toBe(primaryError);
      expect(cleanupError).toBeInstanceOf(AggregateError);
      expect((cleanupError as AggregateError).errors).toEqual([
        expect.objectContaining({ operation: 'deleteUser', status: 500 }),
      ]);
      expect(renderError(error)).not.toContain(responseMarker);
      expect(renderError(error)).not.toContain(password);
      expect(server.requests.filter(({ method }) => method === 'DELETE')).toHaveLength(1);
    } finally {
      await server.close();
    }
  });

  it('preserves exact scenario or cleanup errors and aggregates both in stable order', async () => {
    const target = createTarget('oracle', 'https://core.example.com/');
    const scenarioError = new Error('primary scenario failure');
    const cleanupError = new Error('cleanup failure');
    await expect(
      runScenarioForTarget(
        {
          id: 'scenario-only',
          run: async () => {
            throw scenarioError;
          },
        },
        target,
        { client: createCleanupClient(completeWithoutResult) }
      )
    ).rejects.toBe(scenarioError);

    await expect(
      runScenarioForTarget({ id: 'cleanup-only', run: completeWithoutResult }, target, {
        client: createCleanupClient(async () => {
          throw cleanupError;
        }),
      })
    ).rejects.toBe(cleanupError);

    try {
      await runScenarioForTarget(
        {
          id: 'both',
          run: async () => {
            throw scenarioError;
          },
        },
        target,
        {
          client: createCleanupClient(async () => {
            throw cleanupError;
          }),
        }
      );
      throw new Error('Expected aggregate failure');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(AggregateError);
      expect((error as AggregateError).errors).toEqual([scenarioError, cleanupError]);
    }
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
