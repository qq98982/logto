/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- CLI integration coverage uses local servers and captured dependency state. */
import { chmod, mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer, type ServerResponse } from 'node:http';
import path from 'node:path';

import { runCompatibilityCli, type CompatibilityCliDependencies } from './cli.js';
import { compareJson } from './compare.js';
import {
  writeNegativeControlEvidence,
  writeRunEvidence,
  writeScenarioEvidence,
} from './evidence.js';
import type { Observation, ScenarioEvidence, TargetConfig, TargetEvidence } from './model.js';
import { runScenarioForTarget } from './scenario.js';
import discoveryScenario, { sanitizeJwks, sortDiscoveryDocument } from './scenarios/discovery.js';
import { defaultCompatibilityScenarios } from './scenarios/index.js';
import { SymbolTable } from './symbol-table.js';
import { TargetClient } from './target-client.js';

const buildRoot = '/var/tmp/henry-build';
const referenceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const oracleDigest = `sha256:${'a'.repeat(64)}`;
const candidateDigest = `sha256:${'b'.repeat(64)}`;
const createdRoots = new Set<string>();

type RouteResponse = { status?: number; contentType?: string; location?: string; body: unknown };

const sendResponse = (response: ServerResponse, routeResponse: RouteResponse) => {
  response.statusCode = routeResponse.status ?? 200;
  response.setHeader(
    'content-type',
    routeResponse.contentType ?? 'application/json; charset=utf-8'
  );

  if (routeResponse.location !== undefined) {
    response.setHeader('location', routeResponse.location);
  }

  response.end(JSON.stringify(routeResponse.body));
};

const startDiscoveryServer = async (
  resolveResponse: (route: string, baseUrl: string) => RouteResponse
) => {
  let baseUrl = '';
  const requests: string[] = [];
  const server = createServer((request, response) => {
    const route = new URL(request.url ?? '/', baseUrl).pathname;
    requests.push(route);
    sendResponse(response, resolveResponse(route, baseUrl));
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();

  if (!address || typeof address === 'string') {
    throw new Error('Test server did not expose a TCP address');
  }

  baseUrl = `http://127.0.0.1:${address.port}/`;

  return {
    baseUrl,
    requests,
    close: async () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      }),
  };
};

const discoveryDocument = (baseUrl: string) => ({
  issuer: `${baseUrl}oidc`,
  authorization_endpoint: `${baseUrl}oidc/auth`,
  jwks_uri: `${baseUrl}oidc/jwks`,
  scopes_supported: ['profile', 'openid'],
  claims_supported: ['sub', 'email'],
  observable_sequence: ['second', 'first'],
});

const startOrderedDiscoveryServer = async (reverse: boolean) => {
  const keys = reverse
    ? [
        { kid: 'z-candidate', kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
        { kid: 'a-candidate', kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
      ]
    : [
        { kid: 'a-oracle', kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
        { kid: 'z-oracle', kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
      ];
  const server = await startDiscoveryServer((route, baseUrl) => {
    if (route === '/oidc/jwks') {
      return { body: { keys } };
    }

    return { body: discoveryDocument(baseUrl) };
  });

  return { ...server, servedKidOrder: keys.map(({ kid }) => kid) };
};

const createTarget = (label: TargetConfig['label'], coreUrl: string): TargetConfig => ({
  label,
  coreUrl,
  adminUrl:
    label === 'oracle' ? 'https://oracle-admin.invalid/' : 'https://candidate-admin.invalid/',
});

const targetEvidence = (
  target: TargetConfig['label'],
  issuer = '<target.core-url>/oidc'
): TargetEvidence => ({
  target,
  observations: [
    {
      stepId: 'discovery.openid',
      kind: 'http',
      value: { issuer, status: 200, mediaType: 'application/json' },
    },
  ],
});

const scenarioEvidence = (
  differences: ScenarioEvidence['differences'] = [],
  scenarioId = 'discovery'
): ScenarioEvidence => ({
  schemaVersion: 1,
  scenarioId,
  oracle: { ...targetEvidence('oracle'), target: 'oracle' },
  candidate: { ...targetEvidence('candidate'), target: 'candidate' },
  differences,
});

const config = {
  oracle: createTarget('oracle', 'https://oracle.invalid/'),
  candidate: createTarget('candidate', 'https://candidate.invalid/'),
};

const createPrivateRoot = async () => {
  const root = await mkdtemp(path.join(buildRoot, 'aster-cli-test-'));
  createdRoots.add(root);
  await chmod(root, 0o700);
  return root;
};

const createCliHarness = (
  overrides: Partial<CompatibilityCliDependencies> = {}
): {
  dependencies: Partial<CompatibilityCliDependencies>;
  stdout: string[];
  stderr: string[];
  writtenScenarios: unknown[];
  writtenNegativeControls: unknown[];
} => {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const writtenScenarios: unknown[] = [];
  const writtenNegativeControls: unknown[] = [];
  const dependencies: Partial<CompatibilityCliDependencies> = {
    loadConfig: () => config,
    runScenario: async (_scenario, target) => targetEvidence(target.label),
    compare: compareJson,
    writeScenario: async (input) => {
      writtenScenarios.push(input);
      return '/var/tmp/henry-build/scenario.json';
    },
    writeNegativeControl: async (input) => {
      writtenNegativeControls.push(input);
      return '/var/tmp/henry-build/negative-control.json';
    },
    stdout: (message) => {
      stdout.push(message);
    },
    stderr: (message) => {
      stderr.push(message);
    },
    ...overrides,
  };

  return { dependencies, stdout, stderr, writtenScenarios, writtenNegativeControls };
};

afterEach(async () => {
  await Promise.all(
    [...createdRoots].map(async (root) => {
      await rm(root, { recursive: true, force: true });
      createdRoots.delete(root);
    })
  );
});

describe('discovery scenario', () => {
  it('emits raw sorted observations before the runner normalization boundary', async () => {
    const server = await startDiscoveryServer((route, baseUrl) =>
      route === '/oidc/jwks'
        ? { body: { keys: [{ kid: 'raw-runtime-kid', kty: 'EC', alg: 'ES384' }] } }
        : { body: discoveryDocument(baseUrl) }
    );
    const client = new TargetClient(createTarget('oracle', server.baseUrl));
    const symbols = new SymbolTable();
    const observations: Observation[] = [];

    try {
      await discoveryScenario.run({
        target: client.target,
        client,
        symbols,
        observe: (observation) => {
          observations.push(observation);
        },
      });

      expect(observations[0]?.value).toMatchObject({
        issuer: `${server.baseUrl}oidc`,
        scopes_supported: ['openid', 'profile'],
      });
      expect(observations[2]?.value).toMatchObject({
        keys: [{ kid: 'raw-runtime-kid', kty: 'EC', alg: 'ES384' }],
      });
      expect(symbols.getLogicalName('raw-runtime-kid')).toBe('signing-key.kid.1');
      expect(JSON.stringify(observations)).not.toContain('<target.core-url>');
      expect(JSON.stringify(observations)).not.toContain('<signing-key.kid.1>');
    } finally {
      await client.cleanup();
      await server.close();
    }
  });

  it('reads all public documents, normalizes URLs and sets, and emits sanitized key metadata', async () => {
    const server = await startDiscoveryServer((route, baseUrl) => {
      if (route === '/oidc/jwks') {
        return {
          contentType: 'application/jwk-set+json; charset=utf-8',
          body: {
            keys: [
              {
                kid: 'runtime-rsa',
                kty: 'RSA',
                use: 'sig',
                alg: 'RS256',
                n: 'never-record',
                e: 'never-record',
                x5u: 'never-record',
                jwk: { private: 'never-record' },
                certificates: ['never-record'],
                PEM: 'never-record',
              },
              {
                kid: 'runtime-ec',
                kty: 'EC',
                use: 'sig',
                alg: 'ES384',
                crv: 'P-384',
                x: 'never-record',
                y: 'never-record',
                x5c: ['never-record'],
              },
            ],
          },
        };
      }

      return { body: discoveryDocument(baseUrl) };
    });

    try {
      const evidence = await runScenarioForTarget(
        discoveryScenario,
        createTarget('oracle', server.baseUrl)
      );

      expect(server.requests).toEqual([
        '/oidc/.well-known/openid-configuration',
        '/oidc/.well-known/oauth-authorization-server',
        '/oidc/jwks',
      ]);
      expect(evidence.observations[0]).toEqual({
        stepId: 'discovery.openid',
        kind: 'http',
        value: {
          issuer: '<target.core-url>/oidc',
          authorization_endpoint: '<target.core-url>/oidc/auth',
          jwks_uri: '<target.core-url>/oidc/jwks',
          scopes_supported: ['openid', 'profile'],
          claims_supported: ['email', 'sub'],
          observable_sequence: ['second', 'first'],
          status: 200,
          mediaType: 'application/json',
        },
      });
      expect(evidence.observations[1]?.value).toEqual({ equal: true });
      expect(evidence.observations[2]?.value).toEqual({
        status: 200,
        mediaType: 'application/jwk-set+json',
        keys: [
          { kid: '<signing-key.kid.1>', kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
          { kid: '<signing-key.kid.2>', kty: 'RSA', use: 'sig', alg: 'RS256' },
        ],
      });
      expect(JSON.stringify(evidence)).not.toMatch(/never-record|"[xyne]"|x5c/u);
    } finally {
      await server.close();
    }
  });

  it('compares target-independent multi-key sets despite URL, kid, and response-order changes', async () => {
    const oracleServer = await startOrderedDiscoveryServer(false);
    const candidateServer = await startOrderedDiscoveryServer(true);

    try {
      expect(oracleServer.servedKidOrder).toEqual(['a-oracle', 'z-oracle']);
      expect(candidateServer.servedKidOrder).toEqual(['z-candidate', 'a-candidate']);
      expect(oracleServer.servedKidOrder.map((kid) => kid[0])).toEqual(['a', 'z']);
      expect(candidateServer.servedKidOrder.map((kid) => kid[0])).toEqual(['z', 'a']);

      const [oracle, candidate] = await Promise.all([
        runScenarioForTarget(discoveryScenario, createTarget('oracle', oracleServer.baseUrl)),
        runScenarioForTarget(discoveryScenario, createTarget('candidate', candidateServer.baseUrl)),
      ]);

      expect(
        compareJson({ observations: oracle.observations }, { observations: candidate.observations })
      ).toEqual([]);
    } finally {
      await Promise.all([oracleServer.close(), candidateServer.close()]);
    }
  });

  it('normalizes raw target and adversarial kid substrings exactly once', async () => {
    const server = await startDiscoveryServer((route, baseUrl) => {
      const hostKid = new URL(baseUrl).hostname;

      if (route === '/oidc/jwks') {
        return {
          body: {
            keys: [
              { kid: 'target', kty: 'EC', use: 'sig', alg: 'ES384' },
              { kid: '<target', kty: 'EC', use: 'sig', alg: 'ES384' },
              { kid: hostKid, kty: 'EC', use: 'sig', alg: 'ES384' },
            ],
          },
        };
      }

      return {
        body: {
          ...discoveryDocument(baseUrl),
          symbol_probe: ['target', '<target', hostKid, `${baseUrl}resource`],
        },
      };
    });

    try {
      const evidence = await runScenarioForTarget(
        discoveryScenario,
        createTarget('oracle', server.baseUrl)
      );
      const openidValue = evidence.observations[0]?.value;
      const jwksValue = evidence.observations[2]?.value;

      expect(openidValue).toMatchObject({
        issuer: '<target.core-url>/oidc',
        symbol_probe: [
          '<signing-key.kid.3>',
          '<signing-key.kid.2>',
          '<signing-key.kid.1>',
          '<target.core-url>/resource',
        ],
      });
      expect(jwksValue).toMatchObject({
        keys: [
          { kid: '<signing-key.kid.1>' },
          { kid: '<signing-key.kid.2>' },
          { kid: '<signing-key.kid.3>' },
        ],
      });
      expect(JSON.stringify(evidence)).not.toMatch(/<signing-key\.kid\.\d+>\.core-url/u);
    } finally {
      await server.close();
    }
  });

  it.each([
    { label: 'non-200 status', response: { status: 503, body: { marker: 'private-marker' } } },
    {
      label: 'non-JSON content type',
      response: { contentType: 'text/plain', body: { marker: 'private-marker' } },
    },
  ])('rejects $label with a fixed non-echoing error', async ({ response }) => {
    const server = await startDiscoveryServer(() => response);

    try {
      await expect(
        runScenarioForTarget(discoveryScenario, createTarget('oracle', server.baseUrl))
      ).rejects.toThrow('Discovery endpoint read failed');
      await expect(
        runScenarioForTarget(discoveryScenario, createTarget('oracle', server.baseUrl))
      ).rejects.not.toThrow('private-marker');
    } finally {
      await server.close();
    }
  });

  it('rejects unequal discovery documents without echoing document values', async () => {
    const secretMarker = 'synthetic-secret-marker';
    const server = await startDiscoveryServer((route, baseUrl) => ({
      body:
        route === '/oidc/.well-known/oauth-authorization-server'
          ? { ...discoveryDocument(baseUrl), issuer: secretMarker }
          : discoveryDocument(baseUrl),
    }));

    try {
      try {
        await runScenarioForTarget(discoveryScenario, createTarget('oracle', server.baseUrl));
        throw new Error('Expected discovery mismatch');
      } catch (error: unknown) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Discovery documents are not semantically equal');
        expect((error as Error).message).not.toContain(secretMarker);
      }
    } finally {
      await server.close();
    }
  });

  it.each([
    '/oidc/.well-known/openid-configuration',
    '/oidc/.well-known/oauth-authorization-server',
    '/oidc/jwks',
  ])('rejects a manual redirect from %s without following it', async (redirectRoute) => {
    const targetMarker = 'redirect-target-private-marker';
    const redirectTarget = await startDiscoveryServer((_route, baseUrl) => ({
      body: { ...discoveryDocument(baseUrl), marker: targetMarker },
    }));
    const source = await startDiscoveryServer((route, baseUrl) => {
      if (route === redirectRoute) {
        return {
          status: 302,
          location: `${redirectTarget.baseUrl}redirected-private-url`,
          body: { marker: 'redirect-private-body' },
        };
      }

      if (route === '/oidc/jwks') {
        return { body: { keys: [{ kid: 'source-key', kty: 'EC' }] } };
      }

      return { body: discoveryDocument(baseUrl) };
    });

    try {
      try {
        await runScenarioForTarget(discoveryScenario, createTarget('oracle', source.baseUrl));
        throw new Error('Expected redirect rejection');
      } catch (error: unknown) {
        expect(error).toBeInstanceOf(Error);
        expect((error as Error).message).toBe('Discovery endpoint read failed');
        expect((error as Error).message).not.toMatch(
          /redirect-target-private-marker|redirect-private-body|redirected-private-url/u
        );
      }

      expect(redirectTarget.requests).toEqual([]);
    } finally {
      await Promise.all([source.close(), redirectTarget.close()]);
    }
  });

  it('sorts only documented set-like arrays and validates JWKS structure', () => {
    const context = {
      target: createTarget('oracle', 'https://oracle.invalid/'),
      symbols: new SymbolTable(),
    };

    expect(
      sortDiscoveryDocument({
        issuer: 'https://oracle.invalid/oidc',
        scopes_supported: ['z', 'a'],
        nested: { claims_supported: ['z', 'a'], observable: ['z', 'a'] },
      })
    ).toEqual({
      issuer: 'https://oracle.invalid/oidc',
      scopes_supported: ['a', 'z'],
      nested: { claims_supported: ['a', 'z'], observable: ['z', 'a'] },
    });
    expect(() => sanitizeJwks({}, context)).toThrow('Invalid discovery JWKS');
    expect(() => sanitizeJwks({ keys: [] }, context)).toThrow('Invalid discovery JWKS');
    expect(() => sanitizeJwks({ keys: [null] }, context)).toThrow('Invalid discovery JWKS');
    expect(() => sanitizeJwks({ keys: [{ kid: 42 }] }, context)).toThrow('Invalid discovery JWKS');
    expect(() =>
      sanitizeJwks(
        {
          keys: [
            { kid: 'duplicate', kty: 'EC' },
            { kid: 'duplicate', kty: 'EC' },
          ],
        },
        context
      )
    ).toThrow('Invalid discovery JWKS');
  });
});

describe('compatibility CLI', () => {
  it('writes positive evidence and returns 0 only for zero differences', async () => {
    const harness = createCliHarness();

    expect(await runCompatibilityCli([], {}, harness.dependencies)).toBe(0);
    expect(harness.writtenScenarios).toEqual([
      scenarioEvidence(),
      scenarioEvidence([], 'password-code'),
    ]);
    expect(harness.stdout).toEqual([
      'Scenario discovery: 0 difference(s)',
      'Scenario password-code: 0 difference(s)',
    ]);
    expect(harness.stderr).toEqual([]);
  });

  it('uses the exact sole default registry in order', async () => {
    const seenScenarios: unknown[] = [];
    const harness = createCliHarness({
      runScenario: async (scenario, target) => {
        if (target.label === 'oracle') {
          seenScenarios.push(scenario);
        }

        return targetEvidence(target.label);
      },
    });

    await expect(runCompatibilityCli([], {}, harness.dependencies)).resolves.toBe(0);
    expect(seenScenarios).toEqual(defaultCompatibilityScenarios);
  });

  it('always writes positive evidence and returns 1 for material differences', async () => {
    const harness = createCliHarness({
      runScenario: async (_scenario, target) =>
        targetEvidence(
          target.label,
          target.label === 'oracle' ? '<target.core-url>/oidc' : '<target.core-url>/different'
        ),
    });

    expect(await runCompatibilityCli([], {}, harness.dependencies)).toBe(1);
    expect(harness.writtenScenarios).toHaveLength(2);
    expect(harness.writtenScenarios[0]).toMatchObject({
      differences: [{ path: '/observations/0/value/issuer' }],
    });
    expect(harness.writtenScenarios[1]).toMatchObject({
      scenarioId: 'password-code',
      differences: [{ path: '/observations/0/value/issuer' }],
    });
  });

  it('rejects unknown and malformed modes before config or network dependencies', async () => {
    const marker = 'synthetic-secret-marker';
    let touched = false;
    const harness = createCliHarness({
      loadConfig: () => {
        touched = true;
        throw new Error(marker);
      },
    });

    await Promise.all(
      [
        ['--fault-injection', marker],
        ['--fault-injection'],
        ['--finalize-run', '--negative-control-path', 'relative'],
        ['--finalize-run', '--negative-control-path', '/a', '--extra'],
      ].map(async (args) => {
        await expect(runCompatibilityCli(args, {}, harness.dependencies)).resolves.toBe(1);
      })
    );

    expect(touched).toBe(false);
    expect([...harness.stdout, ...harness.stderr].join('\n')).not.toContain(marker);
  });

  it('rejects empty, duplicate, unsafe, and reserved registries before every mode effect', async () => {
    const scenario = (id: string) => ({
      id,
      run: async () => {
        await Promise.resolve();
      },
    });
    const registries = [
      [],
      [scenario('duplicate'), scenario('duplicate')],
      ...['', '.', '..', '../escape', 'nested/name', 'nested\\name', 'run', 'negative-control'].map(
        (id) => [scenario(id)]
      ),
    ];
    const modes = [
      [] as string[],
      ['--fault-injection', 'discovery-issuer'],
      ['--finalize-run', '--negative-control-path', '/observations/0/value/issuer'],
    ];

    await Promise.all(
      registries.flatMap((scenarios) =>
        modes.map(async (args) => {
          let touched = false;
          const harness = createCliHarness({
            scenarios,
            loadConfig: () => {
              touched = true;
              throw new Error('Registry validation was too late');
            },
            runScenario: async () => {
              touched = true;
              throw new Error('Registry validation was too late');
            },
            readFile: async () => {
              touched = true;
              throw new Error('Registry validation was too late');
            },
            writeScenario: async () => {
              touched = true;
              throw new Error('Registry validation was too late');
            },
            writeNegativeControl: async () => {
              touched = true;
              throw new Error('Registry validation was too late');
            },
            writeRun: async () => {
              touched = true;
              throw new Error('Registry validation was too late');
            },
          });

          await expect(
            runCompatibilityCli(
              args,
              {
                ASTER_ORACLE_IMAGE_DIGEST: oracleDigest,
                ASTER_CANDIDATE_IMAGE_DIGEST: candidateDigest,
              },
              harness.dependencies
            )
          ).resolves.toBe(1);
          expect(touched).toBe(false);
          expect(harness.stderr).toEqual(['Compatibility operation failed.']);
        })
      )
    );
  });

  it('runs scenarios sequentially in registry order and writes each result once', async () => {
    const first = {
      id: 'first',
      run: async () => {
        await Promise.resolve();
      },
    };
    const second = {
      id: 'second',
      run: async () => {
        await Promise.resolve();
      },
    };
    const events: string[] = [];
    const harness = createCliHarness({
      scenarios: [first, second],
      runScenario: async (scenario, target) => {
        events.push(`${scenario.id}.${target.label}.start`);
        await Promise.resolve();
        events.push(`${scenario.id}.${target.label}.end`);
        return targetEvidence(target.label);
      },
      writeScenario: async (input) => {
        if (
          typeof input !== 'object' ||
          input === null ||
          !('scenarioId' in input) ||
          typeof input.scenarioId !== 'string'
        ) {
          throw new TypeError('Invalid test scenario evidence');
        }

        events.push(`${input.scenarioId}.write`);
        return `/var/tmp/henry-build/${input.scenarioId}.json`;
      },
    });

    await expect(runCompatibilityCli([], {}, harness.dependencies)).resolves.toBe(0);
    expect(events).toEqual([
      'first.oracle.start',
      'first.candidate.start',
      'first.oracle.end',
      'first.candidate.end',
      'first.write',
      'second.oracle.start',
      'second.candidate.start',
      'second.oracle.end',
      'second.candidate.end',
      'second.write',
    ]);
  });

  it('returns 2 and writes only exact negative-control evidence for the issuer fault', async () => {
    const harness = createCliHarness();

    expect(
      await runCompatibilityCli(['--fault-injection', 'discovery-issuer'], {}, harness.dependencies)
    ).toBe(2);
    expect(harness.writtenScenarios).toEqual([]);
    expect(harness.writtenNegativeControls).toEqual([
      {
        schemaVersion: 1,
        faultInjection: 'discovery-issuer',
        differencePaths: ['/observations/0/value/issuer'],
      },
    ]);
  });

  it('returns 3 and writes no negative evidence when injection is not detected exactly', async () => {
    let comparisonCount = 0;
    const harness = createCliHarness({
      compare: () => {
        comparisonCount += 1;
        return [];
      },
    });

    expect(
      await runCompatibilityCli(['--fault-injection', 'discovery-issuer'], {}, harness.dependencies)
    ).toBe(3);
    expect(comparisonCount).toBe(2);
    expect(harness.writtenNegativeControls).toEqual([]);
  });

  it('returns 1 on a dirty fault baseline without mutation or negative evidence', async () => {
    const candidate = targetEvidence('candidate', '<target.core-url>/already-different');
    const originalCandidate = structuredClone(candidate);
    const harness = createCliHarness({
      runScenario: async (_scenario, target) =>
        target.label === 'oracle' ? targetEvidence('oracle') : candidate,
    });

    await expect(
      runCompatibilityCli(['--fault-injection', 'discovery-issuer'], {}, harness.dependencies)
    ).resolves.toBe(1);
    expect(candidate).toEqual(originalCandidate);
    expect(harness.writtenNegativeControls).toEqual([]);
    expect(harness.stderr).toEqual(['Compatibility negative-control precondition failed.']);
  });

  it('preserves existing positive evidence bytes during a real fault-control write', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    await writeScenarioEvidence(scenarioEvidence(), {
      env: { ASTER_EVIDENCE_DIR: evidenceDirectory },
    });
    const positivePath = path.join(evidenceDirectory, 'discovery.json');
    const originalBytes = await readFile(positivePath);
    const harness = createCliHarness({
      writeScenario: async () => {
        throw new Error('Positive writer must not be called');
      },
      writeNegativeControl: writeNegativeControlEvidence,
    });

    expect(
      await runCompatibilityCli(
        ['--fault-injection', 'discovery-issuer'],
        { ASTER_EVIDENCE_DIR: evidenceDirectory },
        harness.dependencies
      )
    ).toBe(2);
    expect(await readFile(positivePath)).toEqual(originalBytes);
    expect(
      JSON.parse(await readFile(path.join(evidenceDirectory, 'negative-control.json'), 'utf8'))
    ).toEqual({
      schemaVersion: 1,
      faultInjection: 'discovery-issuer',
      differencePaths: ['/observations/0/value/issuer'],
    });
  });

  it('finalizes run evidence from positive files without config or scenario execution', async () => {
    const root = await createPrivateRoot();
    const evidenceDirectory = path.join(root, 'evidence');
    await writeScenarioEvidence(
      scenarioEvidence([
        {
          path: '/observations/0/value/status',
          oracle: 200,
          candidate: 201,
        },
      ]),
      { env: { ASTER_EVIDENCE_DIR: evidenceDirectory } }
    );
    await writeScenarioEvidence(scenarioEvidence([], 'password-code'), {
      env: { ASTER_EVIDENCE_DIR: evidenceDirectory },
    });
    await writeNegativeControlEvidence(
      {
        schemaVersion: 1,
        faultInjection: 'discovery-issuer',
        differencePaths: ['/observations/0/value/issuer'],
      },
      { env: { ASTER_EVIDENCE_DIR: evidenceDirectory } }
    );
    let touched = false;
    const harness = createCliHarness({
      loadConfig: () => {
        touched = true;
        throw new Error('Must not load config');
      },
      runScenario: async () => {
        touched = true;
        throw new Error('Must not run scenario');
      },
      writeRun: writeRunEvidence,
      readFile: async (filePath) => readFile(filePath, 'utf8'),
    });
    const env = {
      ASTER_EVIDENCE_DIR: evidenceDirectory,
      ASTER_ORACLE_IMAGE_DIGEST: oracleDigest,
      ASTER_CANDIDATE_IMAGE_DIGEST: candidateDigest,
    };

    expect(
      await runCompatibilityCli(
        ['--finalize-run', '--negative-control-path', '/observations/0/value/issuer'],
        env,
        harness.dependencies
      )
    ).toBe(0);
    expect(touched).toBe(false);
    expect(JSON.parse(await readFile(path.join(evidenceDirectory, 'run.json'), 'utf8'))).toEqual({
      schemaVersion: 1,
      referenceCommit,
      oracleImageDigest: oracleDigest,
      candidateImageDigest: candidateDigest,
      scenarios: [
        { scenarioId: 'discovery', differenceCount: 1 },
        { scenarioId: 'password-code', differenceCount: 0 },
      ],
      negativeControl: { differencePath: '/observations/0/value/issuer' },
    });
  });

  it.each([
    { label: 'missing file', negativeControl: null },
    {
      label: 'wrong path',
      negativeControl: {
        schemaVersion: 1,
        faultInjection: 'discovery-issuer',
        differencePaths: ['/wrong'],
      },
    },
    {
      label: 'additional path',
      negativeControl: {
        schemaVersion: 1,
        faultInjection: 'discovery-issuer',
        differencePaths: ['/observations/0/value/issuer', '/z'],
      },
    },
    {
      label: 'unknown injection',
      negativeControl: {
        schemaVersion: 1,
        faultInjection: 'unknown',
        differencePaths: ['/observations/0/value/issuer'],
      },
    },
    {
      label: 'secret extra key',
      negativeControl: {
        schemaVersion: 1,
        faultInjection: 'discovery-issuer',
        differencePaths: ['/observations/0/value/issuer'],
        client_secret: 'synthetic-secret-marker',
      },
    },
  ])(
    'rejects $label negative-control audit evidence without writing run.json',
    async ({ negativeControl }) => {
      let runWritten = false;
      const harness = createCliHarness({
        readFile: async (filePath) => {
          if (path.basename(filePath) === 'negative-control.json') {
            if (negativeControl === null) {
              throw new Error('missing negative-control marker');
            }

            return JSON.stringify(negativeControl);
          }

          return JSON.stringify(scenarioEvidence());
        },
        writeRun: async () => {
          runWritten = true;
          return '/var/tmp/henry-build/run.json';
        },
      });

      await expect(
        runCompatibilityCli(
          ['--finalize-run', '--negative-control-path', '/observations/0/value/issuer'],
          {
            ASTER_ORACLE_IMAGE_DIGEST: oracleDigest,
            ASTER_CANDIDATE_IMAGE_DIGEST: candidateDigest,
          },
          harness.dependencies
        )
      ).resolves.toBe(1);
      expect(runWritten).toBe(false);
      expect(harness.stderr).toEqual(['Compatibility operation failed.']);
      expect(harness.stderr.join('\n')).not.toContain('synthetic-secret-marker');
    }
  );

  it('reads finalize evidence sequentially in registry order and rejects valid substituted run data', async () => {
    const first = {
      id: 'first',
      run: async () => {
        await Promise.resolve();
      },
    };
    const second = {
      id: 'second',
      run: async () => {
        await Promise.resolve();
      },
    };
    const reads: string[] = [];
    let intendedRun: unknown;
    const harness = createCliHarness({
      scenarios: [first, second],
      loadConfig: () => {
        throw new Error('Finalize must not load config');
      },
      runScenario: async () => {
        throw new Error('Finalize must not run scenarios');
      },
      writeRun: async (input) => {
        intendedRun = input;
        return '/var/tmp/henry-build/evidence/run.json';
      },
      readFile: async (filePath) => {
        const filename = path.basename(filePath);
        reads.push(filename);

        if (filename === 'negative-control.json') {
          return JSON.stringify({
            schemaVersion: 1,
            faultInjection: 'discovery-issuer',
            differencePaths: ['/observations/0/value/issuer'],
          });
        }

        if (filename === 'first.json') {
          return JSON.stringify(scenarioEvidence([], 'first'));
        }

        if (filename === 'second.json') {
          return JSON.stringify(scenarioEvidence([], 'second'));
        }

        if (
          typeof intendedRun !== 'object' ||
          intendedRun === null ||
          !('scenarios' in intendedRun)
        ) {
          throw new Error('Run evidence was not written first');
        }

        return JSON.stringify({
          ...intendedRun,
          scenarios: [{ scenarioId: 'first', differenceCount: 9 }],
        });
      },
    });

    await expect(
      runCompatibilityCli(
        ['--finalize-run', '--negative-control-path', '/observations/0/value/issuer'],
        {
          ASTER_ORACLE_IMAGE_DIGEST: oracleDigest,
          ASTER_CANDIDATE_IMAGE_DIGEST: candidateDigest,
        },
        harness.dependencies
      )
    ).resolves.toBe(1);
    expect(reads).toEqual(['negative-control.json', 'first.json', 'second.json', 'run.json']);
    expect(harness.stderr).toEqual(['Compatibility operation failed.']);
  });

  it.each([
    { variable: 'ASTER_ORACLE_IMAGE_DIGEST', value: undefined },
    { variable: 'ASTER_CANDIDATE_IMAGE_DIGEST', value: 'sha256:secret-marker' },
  ])(
    'rejects missing or invalid $variable without reading evidence',
    async ({ variable, value }) => {
      let read = false;
      const harness = createCliHarness({
        readFile: async () => {
          read = true;
          throw new Error('Must not read');
        },
      });
      const env: Record<string, string | undefined> = {
        ASTER_ORACLE_IMAGE_DIGEST: oracleDigest,
        ASTER_CANDIDATE_IMAGE_DIGEST: candidateDigest,
        [variable]: value,
      };

      expect(
        await runCompatibilityCli(
          ['--finalize-run', '--negative-control-path', '/observations/0/value/issuer'],
          env,
          harness.dependencies
        )
      ).toBe(1);
      expect(read).toBe(false);
      expect(harness.stderr).toEqual([`Invalid ${variable}.`]);
      expect(harness.stderr.join('\n')).not.toContain(value ?? 'undefined');
    }
  );

  it('rejects invalid and tampered positive or written run evidence with fixed output', async () => {
    const marker = 'synthetic-secret-marker';
    const harness = createCliHarness({
      readFile: async (filePath) =>
        path.basename(filePath) === 'negative-control.json'
          ? JSON.stringify({
              schemaVersion: 1,
              faultInjection: 'discovery-issuer',
              differencePaths: ['/observations/0/value/issuer'],
            })
          : JSON.stringify({ ...scenarioEvidence(), scenarioId: marker }),
      writeRun: async () => '/var/tmp/henry-build/run.json',
    });

    expect(
      await runCompatibilityCli(
        ['--finalize-run', '--negative-control-path', '/observations/0/value/issuer'],
        {
          ASTER_ORACLE_IMAGE_DIGEST: oracleDigest,
          ASTER_CANDIDATE_IMAGE_DIGEST: candidateDigest,
        },
        harness.dependencies
      )
    ).toBe(1);
    expect(harness.stderr).toEqual(['Compatibility operation failed.']);
    expect(harness.stderr.join('\n')).not.toContain(marker);
  });

  it('returns 1 with status-only diagnostics for runtime failures', async () => {
    const marker = 'synthetic-secret-marker';
    const harness = createCliHarness({
      runScenario: async () => {
        throw new Error(marker);
      },
    });

    expect(await runCompatibilityCli([], {}, harness.dependencies)).toBe(1);
    expect(harness.stderr).toEqual(['Compatibility operation failed.']);
    expect([...harness.stdout, ...harness.stderr].join('\n')).not.toContain(marker);
  });
});
/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
