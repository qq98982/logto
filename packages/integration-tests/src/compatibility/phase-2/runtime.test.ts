/* eslint-disable max-lines, no-await-in-loop, @typescript-eslint/no-loop-func, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/consistent-function-scoping -- Runtime protocol tests capture sequential command state, repeat replace/restore probes thirty times, and own temporary executable paths. */
import { createHash } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rename, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:net';
import path from 'node:path';

import type {
  CommandRunnerRequest,
  CommandRunnerResult,
} from '../phase-1/clients/command-provisioner.js';

import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from './fixtures.js';
import {
  createCommandPhase2ScenarioStateDriver,
  fetchPhase2Discovery,
  fetchPhase2PublicJwks,
  preparePhase2TargetForExecution,
  validatePhase2TargetDescriptor,
  verifyPhase2Target,
  type Phase2TargetDescriptor,
} from './runtime.js';

const rootPrefix = '/var/tmp/henry-build/phase2-runtime-';
let root = '';
let driverPath = '';
let driverSha = '';
let servers: Server[] = [];
const topology = () => ({
  projectName: 'aster-phase2-client-credentials-2222222222222222',
  primary: {
    containerId: '2'.repeat(64),
    service: 'candidate-primary-core',
    imageDigest: `sha256:${'b'.repeat(64)}`,
  },
  foreign: {
    containerId: '4'.repeat(64),
    service: 'candidate-foreign-core',
    imageDigest: `sha256:${'b'.repeat(64)}`,
  },
});

const descriptor = (): Phase2TargetDescriptor =>
  validatePhase2TargetDescriptor({
    schemaVersion: 1,
    kind: 'candidate',
    sourceCommit: 'a'.repeat(40),
    imageDigest: `sha256:${'b'.repeat(64)}`,
    projectName: topology().projectName,
    primaryContainerId: '2'.repeat(64),
    foreignContainerId: '4'.repeat(64),
    target: {
      label: 'candidate',
      coreUrl: 'http://localhost:3321/',
      adminUrl: 'http://localhost:3421/',
    },
    foreignTarget: {
      label: 'candidate',
      coreUrl: 'http://localhost:3322/',
      adminUrl: 'http://localhost:3422/',
    },
    stateDriver: {
      path: driverPath,
      sha256: driverSha,
      controlSocket: path.join(root, 'state.sock'),
    },
    fixtureExecutable: { path: driverPath, sha256: driverSha },
    fixtureSocket: path.join(root, 'fixture.sock'),
    invariantDriver: {
      path: driverPath,
      sha256: driverSha,
      controlSocket: path.join(root, 'invariant.sock'),
    },
  });

const fixture: ProvisionedPhase2Fixture = Object.freeze({
  public: Object.freeze({
    allocationId: 'runtime-fixture',
    clients: Object.freeze({
      basic: Object.freeze({ id: 'phase2-m2m-basic', method: 'client_secret_basic' }),
      post: Object.freeze({ id: 'phase2-m2m-post', method: 'client_secret_post' }),
    }),
    resources: Object.freeze({
      primary: Object.freeze({
        id: 'phase2-resource-primary',
        indicator: 'https://phase2.example.invalid/api-primary',
      }),
      default: Object.freeze({
        id: 'phase2-resource',
        indicator: 'https://phase2.example.invalid/api-default',
      }),
    }),
    organization: Object.freeze({ id: 'phase2-org', scopeName: 'organization:read' }),
    scopes: Object.freeze({
      read: Object.freeze({ id: 'read-scope', name: 'read' }),
      write: Object.freeze({ id: 'write-scope', name: 'write' }),
      unassigned: Object.freeze({ id: 'unassigned-scope', name: 'unassigned' }),
    }),
    boundary: Object.freeze({ primary: 'provisioned', foreign: 'unchanged' }),
  }),
  withSecretLease: async <Result>(
    use: (lease: Phase2FixtureSecretLease) => Promise<Result>
  ): Promise<Result> =>
    use({
      getClientSecret: () => 'A'.repeat(32),
      toJSON: (): never => {
        throw new Error('lease');
      },
    }),
});

const successfulTokenObservation = () => ({
  status: 200,
  headers: Object.freeze({}),
  body: Object.freeze({ expires_in: 3600, token_type: 'Bearer' }),
  jwt: Object.freeze({
    header: Object.freeze({ alg: 'ES384', kid: 'runtime-key', typ: 'at+jwt' }),
    claims: Object.freeze({}),
    signatureSha256: 'a'.repeat(64),
  }),
});

const result = (stdout: string): CommandRunnerResult => ({
  exitCode: 0,
  signal: null,
  stdout,
  stderr: '',
  timedOut: false,
  killed: false,
  reaped: true,
});

beforeAll(async () => {
  root = await mkdtemp(rootPrefix);
  driverPath = path.join(root, 'driver');
  await writeFile(driverPath, '#!/bin/sh\nexit 1\n', { mode: 0o700 });
  await chmod(driverPath, 0o700);
  driverSha = createHash('sha256')
    .update(await readFile(driverPath))
    .digest('hex');
  servers = await Promise.all(
    ['state.sock', 'fixture.sock', 'invariant.sock'].map(
      async (name) =>
        new Promise<Server>((resolve, reject) => {
          const server = createServer();
          server.once('error', reject);
          server.listen(path.join(root, name), () => {
            resolve(server);
          });
        })
    )
  );
  await Promise.all(
    ['state.sock', 'fixture.sock', 'invariant.sock'].map(async (name) =>
      chmod(path.join(root, name), 0o600)
    )
  );
});

afterAll(async () => {
  await Promise.all(
    servers.map(
      async (server) =>
        new Promise<void>((resolve) => {
          server.close(() => {
            resolve();
          });
        })
    )
  );
  await rm(root, { force: true, recursive: true });
});

describe('Phase 2 runtime adapters', () => {
  it('validates closed oracle/candidate target descriptors', () => {
    expect(descriptor()).toMatchObject({
      kind: 'candidate',
      fixtureSocket: path.join(root, 'fixture.sock'),
    });
    expect(() => validatePhase2TargetDescriptor({ ...descriptor(), extra: true })).toThrow(
      'Invalid Phase 2 runtime'
    );
    expect(() =>
      validatePhase2TargetDescriptor({ ...descriptor(), foreignTarget: descriptor().target })
    ).toThrow('Invalid Phase 2 runtime');
    expect(() =>
      validatePhase2TargetDescriptor({
        ...descriptor(),
        target: { ...descriptor().target, coreUrl: 'http://127.0.0.1:3321/' },
      })
    ).toThrow('Invalid Phase 2 runtime');
    expect(() => validatePhase2TargetDescriptor({ ...descriptor(), kind: 'oracle' })).toThrow(
      'Invalid Phase 2 runtime'
    );
    expect(() =>
      validatePhase2TargetDescriptor({ ...descriptor(), commandPath: 'bin:/usr/bin' })
    ).toThrow('Invalid Phase 2 runtime');
    expect(() =>
      validatePhase2TargetDescriptor({
        ...descriptor(),
        stateDriver: { ...descriptor().stateDriver, controlSocket: '/tmp/control\n.sock' },
      })
    ).toThrow('Invalid Phase 2 runtime');
  });

  it('bounds public JWKS/discovery reads and rejects private JWK material', async () => {
    const requestFetch: typeof fetch = async (input) => {
      const url = new URL(String(input));
      const body = url.pathname.endsWith('/jwks')
        ? { keys: [{ kty: 'EC', crv: 'P-384', x: 'x', y: 'y', kid: 'key-1', alg: 'ES384' }] }
        : { grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'] };
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    await expect(fetchPhase2PublicJwks(descriptor().target, requestFetch)).resolves.toEqual({
      keys: [{ kty: 'EC', crv: 'P-384', x: 'x', y: 'y', kid: 'key-1', alg: 'ES384' }],
    });
    await expect(fetchPhase2Discovery(descriptor().target, requestFetch)).resolves.toEqual({
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
    });
    await expect(
      fetchPhase2PublicJwks(
        descriptor().target,
        async () =>
          new Response(JSON.stringify({ keys: [{ kty: 'EC', kid: 'key', d: 'private' }] }), {
            status: 200,
          })
      )
    ).rejects.toThrow('Invalid Phase 2 runtime');
  });

  it('verifies executable/socket identity, mode, hash and symlink rejection', async () => {
    await expect(verifyPhase2Target(descriptor())).resolves.toMatchObject({ topology: topology() });
    await expect(
      verifyPhase2Target({
        ...descriptor(),
        stateDriver: { ...descriptor().stateDriver, sha256: '0'.repeat(64) },
      })
    ).rejects.toThrow();
    await chmod(driverPath, 0o755);
    await expect(verifyPhase2Target(descriptor())).rejects.toThrow();
    await chmod(driverPath, 0o700);
    const link = path.join(root, 'driver-link');
    await symlink(driverPath, link);
    await expect(
      verifyPhase2Target({
        ...descriptor(),
        stateDriver: { ...descriptor().stateDriver, path: link },
      })
    ).rejects.toThrow();
    await expect(
      verifyPhase2Target({
        ...descriptor(),
        stateDriver: { ...descriptor().stateDriver, path: '/usr/bin/true' },
      })
    ).rejects.toThrow();
    await chmod(path.join(root, 'state.sock'), 0o666);
    await expect(verifyPhase2Target(descriptor())).rejects.toThrow();
    await chmod(path.join(root, 'state.sock'), 0o600);
  });

  it('detects executable replacement after launch and does not hide abort verification failure', async () => {
    const original = await readFile(driverPath);
    const operations: string[] = [];
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      const input = JSON.parse(request.stdin) as Record<string, unknown>;
      operations.push(String(input.operation));
      await writeFile(driverPath, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-state',
          operation: input.operation,
          scenarioId: input.scenarioId,
          handle: 'a'.repeat(32),
          attestation: topology(),
        })
      );
    };
    try {
      const state = await createCommandPhase2ScenarioStateDriver({
        descriptor: descriptor(),
        runner,
      });
      await expect(
        state.observe('client-credentials.basic-explicit-resource', fixture, async () => ({
          status: 200,
          headers: {},
          body: {},
        }))
      ).rejects.toBeInstanceOf(AggregateError);
      expect(operations).toEqual(['begin', 'abort']);
    } finally {
      await writeFile(driverPath, original, { mode: 0o700 });
      await chmod(driverPath, 0o700);
    }
  });

  it('materializes private execution copies and detects target or ancestor replace-then-restore mutations', async () => {
    const sessionRoot = path.join(root, 'owned-session');
    await mkdir(sessionRoot, { mode: 0o700 });
    await chmod(sessionRoot, 0o700);
    const verified = await verifyPhase2Target(descriptor());
    const prepared = await preparePhase2TargetForExecution(verified, sessionRoot, 'candidate');
    expect(prepared.descriptor.stateDriver.path).toBe(
      path.join(sessionRoot, 'candidate-executables', 'state-driver')
    );
    expect(await readFile(prepared.descriptor.stateDriver.path)).toEqual(
      await readFile(driverPath)
    );

    for (let attempt = 0; attempt < 30; attempt += 1) {
      const artifactBackup = `${driverPath}.original-${attempt}`;
      await expect(
        prepared.fence.run(async () => {
          await rename(driverPath, artifactBackup);
          await writeFile(driverPath, '#!/bin/sh\nexit 0\n', { mode: 0o700 });
          await rm(driverPath);
          await rename(artifactBackup, driverPath);
        })
      ).rejects.toThrow('Invalid Phase 2 runtime');
    }

    const socketPath = path.join(root, 'state.sock');
    for (let attempt = 0; attempt < 30; attempt += 1) {
      const socketBackup = path.join(root, `state.sock.original-${attempt}`);
      await expect(
        prepared.fence.run(async () => {
          await rename(socketPath, socketBackup);
          await rename(socketBackup, socketPath);
        })
      ).rejects.toThrow('Invalid Phase 2 runtime');
    }

    for (let attempt = 0; attempt < 30; attempt += 1) {
      const ancestorBackup = `${root}.original-${attempt}`;
      await expect(
        prepared.fence.run(async () => {
          await rename(root, ancestorBackup);
          await rename(ancestorBackup, root);
        })
      ).rejects.toThrow('Invalid Phase 2 runtime');
    }
  });

  it('executes begin/request/finish, default mutation, and abort on request failure', async () => {
    const calls: Array<Record<string, unknown>> = [];
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      const input = JSON.parse(request.stdin) as Record<string, unknown>;
      calls.push(input);
      const { operation } = input;
      const { scenarioId } = input;
      if (operation === 'begin') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation,
            scenarioId,
            handle: 'a'.repeat(32),
            attestation: topology(),
          })
        );
      }
      if (operation === 'finish') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation,
            scenarioId,
            handle: 'a'.repeat(32),
            authority: {
              decision: 'authorized',
              targetKind: 'resource',
              target: fixture.public.resources.primary.indicator,
              availableScopes: ['read'],
              effectiveScopes: ['read'],
            },
            signingUse: { generalKeyUse: 'verified', oidcIdTokenKeyUse: 'unchanged' },
            sideEffects: {
              users: 0,
              sessions: 0,
              grants: 0,
              authorizationCodes: 0,
              interactions: 0,
              refreshTokens: 0,
              tokenFamilies: 0,
            },
            attestation: topology(),
          })
        );
      }
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-state',
          operation,
          scenarioId,
          ok: true,
          attestation: topology(),
        })
      );
    };
    const state = await createCommandPhase2ScenarioStateDriver({
      descriptor: descriptor(),
      runner,
    });
    const observation = await state.observe(
      'client-credentials.resource-partial-scope',
      fixture,
      async () => successfulTokenObservation()
    );
    expect(observation.authority.effectiveScopes).toEqual(['read']);
    expect(calls.map(({ operation }) => operation)).toEqual(['begin', 'finish']);
    expect(calls[1]).toMatchObject({
      responseStatus: 200,
      tokenIssued: true,
      responseError: null,
      signingKeyId: 'runtime-key',
    });
    expect(JSON.stringify(calls[1])).not.toContain('signatureSha256');
    expect(JSON.stringify(calls[1])).not.toContain('access_token');
    await state.setDefaultResource(fixture, false);
    expect(calls.at(-1)).toMatchObject({ operation: 'set-default-resource', enabled: false });

    await expect(
      state.observe('client-credentials.unknown-resource', fixture, async () => {
        throw new Error('request failed');
      })
    ).rejects.toThrow('request failed');
    expect(calls.at(-1)).toMatchObject({ operation: 'abort', handle: 'a'.repeat(32) });
  });

  it('forwards the actual closed OAuth error to finish without descriptions or credentials', async () => {
    const finishRequests: Array<Record<string, unknown>> = [];
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      const input = JSON.parse(request.stdin) as Record<string, unknown>;
      if (input.operation === 'begin') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation: 'begin',
            scenarioId: input.scenarioId,
            handle: 'a'.repeat(32),
            attestation: topology(),
          })
        );
      }
      if (input.operation === 'finish') {
        finishRequests.push(input);
        const { responseError } = input;
        const decision =
          responseError === 'invalid_client'
            ? 'unauthorized-client'
            : responseError === 'invalid_target'
              ? 'invalid-target'
              : responseError === 'access_denied'
                ? 'access-denied'
                : responseError === 'invalid_request'
                  ? 'invalid-request'
                  : 'authorized';
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation: 'finish',
            scenarioId: input.scenarioId,
            handle: input.handle,
            authority: {
              decision,
              targetKind: 'none',
              target: null,
              availableScopes: [],
              effectiveScopes: [],
            },
            signingUse: { generalKeyUse: 'unchanged', oidcIdTokenKeyUse: 'unchanged' },
            sideEffects: {
              users: 0,
              sessions: 0,
              grants: 0,
              authorizationCodes: 0,
              interactions: 0,
              refreshTokens: 0,
              tokenFamilies: 0,
            },
            attestation: topology(),
          })
        );
      }
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-state',
          operation: input.operation,
          scenarioId: input.scenarioId,
          ok: true,
          attestation: topology(),
        })
      );
    };
    const state = await createCommandPhase2ScenarioStateDriver({
      descriptor: descriptor(),
      runner,
    });
    const cases = [
      ['client-credentials.wrong-secret-basic', 401, 'invalid_client'],
      ['client-credentials.unknown-client-basic', 400, 'invalid_client'],
      ['client-credentials.mixed-authentication', 400, 'invalid_request'],
      ['client-credentials.duplicate-resource', 400, 'invalid_target'],
    ] as const;
    for (const [scenarioId, status, responseError] of cases) {
      await state.observe(scenarioId, fixture, async () => ({
        status,
        headers: {},
        body: {
          error: responseError,
          error_description: 'sanitized description must stay out of the driver request',
        },
      }));
    }
    expect(
      finishRequests.map(
        ({ scenarioId, responseError, responseStatus, tokenIssued, signingKeyId }) => ({
          scenarioId,
          responseError,
          responseStatus,
          tokenIssued,
          signingKeyId,
        })
      )
    ).toEqual(
      cases.map(([scenarioId, responseStatus, responseError]) => ({
        scenarioId,
        responseError,
        responseStatus,
        tokenIssued: false,
        signingKeyId: null,
      }))
    );
    for (const request of finishRequests) {
      expect(request).not.toHaveProperty('error_description');
      expect(JSON.stringify(request)).not.toContain('sanitized description');
    }
  });

  it.each([
    ['successful token', successfulTokenObservation(), 'unchanged'],
    [
      'failed token request',
      Object.freeze({
        status: 401,
        headers: Object.freeze({}),
        body: Object.freeze({ error: 'invalid_client' }),
      }),
      'verified',
    ],
  ] as const)('rejects signing use inconsistent with a %s', async (_label, response, use) => {
    const operations: unknown[] = [];
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      const input = JSON.parse(request.stdin) as Record<string, unknown>;
      operations.push(input.operation);
      if (input.operation === 'begin') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation: 'begin',
            scenarioId: input.scenarioId,
            handle: 'a'.repeat(32),
            attestation: topology(),
          })
        );
      }
      if (input.operation === 'finish') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation: 'finish',
            scenarioId: input.scenarioId,
            handle: 'a'.repeat(32),
            authority: {
              decision: 'unauthorized-client',
              targetKind: 'none',
              target: null,
              availableScopes: [],
              effectiveScopes: [],
            },
            signingUse: { generalKeyUse: use, oidcIdTokenKeyUse: 'unchanged' },
            sideEffects: {
              users: 0,
              sessions: 0,
              grants: 0,
              authorizationCodes: 0,
              interactions: 0,
              refreshTokens: 0,
              tokenFamilies: 0,
            },
            attestation: topology(),
          })
        );
      }
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-state',
          operation: 'abort',
          scenarioId: input.scenarioId,
          ok: true,
          attestation: topology(),
        })
      );
    };
    const state = await createCommandPhase2ScenarioStateDriver({
      descriptor: descriptor(),
      runner,
    });

    await expect(
      state.observe('client-credentials.wrong-secret-basic', fixture, async () => response)
    ).rejects.toThrow('Invalid Phase 2 runtime');
    expect(operations).toEqual(['begin', 'finish', 'abort']);
  });

  it.each([
    ['missing error', { status: 400, headers: {}, body: {} }],
    ['unknown error', { status: 400, headers: {}, body: { error: 'server_error' } }],
    ['JWT with non-200 status', { ...successfulTokenObservation(), status: 201 }],
    [
      'JWT with an unsafe signing kid',
      {
        ...successfulTokenObservation(),
        jwt: {
          ...successfulTokenObservation().jwt,
          header: { alg: 'ES384', kid: 'unsafe/key', typ: 'at+jwt' },
        },
      },
    ],
    [
      'JWT with an error field',
      { ...successfulTokenObservation(), body: { error: 'invalid_client' } },
    ],
  ] as const)('aborts before finish for %s', async (_label, response) => {
    const operations: string[] = [];
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      const input = JSON.parse(request.stdin) as Record<string, unknown>;
      operations.push(String(input.operation));
      if (input.operation === 'begin') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation: 'begin',
            scenarioId: input.scenarioId,
            handle: 'a'.repeat(32),
            attestation: topology(),
          })
        );
      }
      if (input.operation === 'finish') {
        throw new Error('finish must not be invoked');
      }
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-state',
          operation: 'abort',
          scenarioId: input.scenarioId,
          ok: true,
          attestation: topology(),
        })
      );
    };
    const state = await createCommandPhase2ScenarioStateDriver({
      descriptor: descriptor(),
      runner,
    });
    await expect(
      state.observe('client-credentials.mixed-authentication', fixture, async () => response)
    ).rejects.toThrow('Invalid Phase 2 runtime');
    expect(operations).toEqual(['begin', 'abort']);
  });

  it.each([
    'invalid-handle',
    'execute-failure',
    'finish-transport',
    'finish-json',
    'handle-mismatch',
    'abort-failure',
  ] as const)('aborts and preserves cleanup failure for %s', async (failureMode) => {
    const operations: string[] = [];
    const runner = async (request: CommandRunnerRequest): Promise<CommandRunnerResult> => {
      const input = JSON.parse(request.stdin) as Record<string, unknown>;
      const operation = String(input.operation);
      operations.push(operation);
      if (operation === 'begin') {
        return result(
          JSON.stringify({
            schemaVersion: 1,
            kind: 'phase2-client-credentials-state',
            operation,
            scenarioId: input.scenarioId,
            handle: failureMode === 'invalid-handle' ? 'bad' : 'a'.repeat(32),
            attestation: topology(),
          })
        );
      }
      if (operation === 'abort') {
        return failureMode === 'abort-failure'
          ? { ...result(''), exitCode: 1 }
          : result(
              JSON.stringify({
                schemaVersion: 1,
                kind: 'phase2-client-credentials-state',
                operation,
                scenarioId: input.scenarioId,
                ok: true,
                attestation: topology(),
              })
            );
      }
      if (failureMode === 'finish-transport') {
        return { ...result(''), exitCode: 1 };
      }
      if (failureMode === 'finish-json') {
        return result('{');
      }
      return result(
        JSON.stringify({
          schemaVersion: 1,
          kind: 'phase2-client-credentials-state',
          operation,
          scenarioId: input.scenarioId,
          handle: failureMode === 'handle-mismatch' ? 'b'.repeat(32) : 'a'.repeat(32),
          authority: {
            decision: 'authorized',
            targetKind: 'resource',
            target: fixture.public.resources.primary.indicator,
            availableScopes: [],
            effectiveScopes: [],
          },
          signingUse: { generalKeyUse: 'verified', oidcIdTokenKeyUse: 'unchanged' },
          sideEffects: {
            users: 0,
            sessions: 0,
            grants: 0,
            authorizationCodes: 0,
            interactions: 0,
            refreshTokens: 0,
            tokenFamilies: 0,
          },
          attestation: topology(),
        })
      );
    };
    const state = await createCommandPhase2ScenarioStateDriver({
      descriptor: descriptor(),
      runner,
    });
    const operation = state.observe(
      'client-credentials.basic-explicit-resource',
      fixture,
      async () => {
        if (failureMode === 'execute-failure' || failureMode === 'abort-failure') {
          throw new Error('primary');
        }
        return successfulTokenObservation();
      }
    );
    await (failureMode === 'abort-failure'
      ? expect(operation).rejects.toBeInstanceOf(AggregateError)
      : expect(operation).rejects.toThrow());
    expect(operations.at(-1)).toBe('abort');
  });
});

/* eslint-enable max-lines, no-await-in-loop, @typescript-eslint/no-loop-func, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/consistent-function-scoping */
