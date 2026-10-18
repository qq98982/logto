/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions -- These tests own temporary prepared-target capabilities, deferred execution state, and deliberate invalid capabilities. */
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer, type Server } from 'node:net';
import path from 'node:path';
import { setImmediate } from 'node:timers/promises';

import type { ProvisionedPhase2Fixture } from './fixtures.js';
import {
  preparePhase2TargetForExecution,
  validatePhase2TargetDescriptor,
  verifyPhase2Target,
  type Phase2TargetDescriptor,
} from './runtime.js';
import type { runTokenExchangeUserJwtForTarget } from './scenarios/token-exchange-target-driver.js';
import {
  assertTokenExchangeComparisonEvidence,
  createTokenExchangeComparisonTarget,
  runBoundTokenExchangeComparisonTargets,
  runTokenExchangeComparison,
} from './token-exchange-comparison.js';

type TargetDriverInput = Parameters<typeof runTokenExchangeUserJwtForTarget>[0];
const projection = Object.freeze({
  responseKeys: ['access_token', 'expires_in', 'scope', 'token_type'],
  tokenType: 'Bearer',
  outputKind: 'jwt',
  sourceReusable: true,
  subjectPreserved: true,
  clientPreserved: true,
  audienceIsResource: true,
  scopeMatchesFixtureAuthority: true,
  lifetimeSeconds: 3600,
  managedSubject: {
    creationKeys: ['expiresIn', 'subjectToken'],
    expiresIn: 600,
    badTarget: { status: 400, error: 'invalid_target', sourcePreserved: true },
    successAfterBadTarget: true,
    replay: { status: 400, error: 'invalid_grant' },
    badActor: { status: 400, error: 'invalid_grant', sourcePreserved: true },
    successAfterBadActor: true,
  },
  personalAccessToken: {
    publicKeys: ['createdAt', 'expiresAt', 'name', 'tenantId', 'userId', 'value'],
    expiresAtNull: true,
    listedWithValue: true,
    repeatedResourceExchange: true,
    deleteStatus: 204,
    rejectedAfterDelete: { status: 400, error: 'invalid_grant' },
  },
  opaque: {
    responseKeys: ['access_token', 'expires_in', 'scope', 'token_type'],
    lifetimeSeconds: 3600,
    compact: 'opaque',
    scope: 'openid profile',
    userinfoSubject: true,
    introspectionActive: true,
    subjectToResourceJwt: true,
    openidActorClaim: true,
    profileActorRejected: { status: 400, error: 'invalid_grant', sourcePreserved: true },
    profileSubjectAccepted: true,
    revokedSubjectRejected: { status: 400, error: 'invalid_grant' },
    revokedActorRejected: { status: 400, error: 'invalid_grant', sourcePreserved: true },
    priorOpaqueOutputRemainsActive: true,
  },
  admissionGrammar: {
    disabled: {
      status: 400,
      error: 'invalid_request',
      errorDescription: 'requested grant type is not allowed for this client',
    },
    unknownClientMasksMissingSubject: {
      status: 400,
      error: 'invalid_client',
      errorDescription: 'invalid client unknown-client',
    },
    publicMissingSubject: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "missing required parameter 'subject_token'",
    },
    publicMissingSubjectType: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "missing required parameter 'subject_token_type'",
    },
    confidentialMissingProof: {
      status: 400,
      error: 'invalid_request',
      errorDescription: 'no client authentication mechanism provided',
    },
    confidentialWrongProof: {
      status: 401,
      error: 'invalid_client',
      errorDescription: 'client authentication failed',
    },
    confidentialCorrectProofMasksMissingSubject: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "missing required parameters 'subject_token' and 'subject_token_type'",
    },
    duplicateSubject: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'subject_token' parameter must not be provided twice",
    },
    duplicateSubjectType: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'subject_token_type' parameter must not be provided twice",
    },
    duplicateActor: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'actor_token' parameter must not be provided twice",
    },
    duplicateActorType: {
      status: 400,
      error: 'invalid_request',
      errorDescription: "'actor_token_type' parameter must not be provided twice",
    },
    repeatedResourceSelectsOpaque: true,
    requestedTokenTypeIgnored: true,
    metadataRestored: true,
  },
  organization: {
    organizationOnly: {
      lifetimeSeconds: 3600,
      scope: '',
      audienceMapped: true,
      organizationIdClaimAbsent: true,
    },
    resourceAndOrganization: {
      lifetimeSeconds: 3600,
      scopePreserved: true,
      audienceIsResource: true,
      organizationIdClaim: true,
    },
  },
  customizer: {
    managedTokenShape: true,
    managedUserContext: true,
    managedApplicationContext: true,
    managedOrganizationContext: true,
    managedSubjectTokenContext: true,
    ordinaryJwtSubjectTokenContextAbsent: true,
    personalAccessTokenSubjectTokenContextAbsent: true,
    deny: { status: 400, error: 'access_denied', sourcePreserved: true },
    configurationRestored: true,
  },
  scopeCanonicalization: {
    opaque: {
      duplicateNamesCollapsed: true,
      unknownNamesFiltered: true,
      scope: 'openid profile',
    },
    resource: {
      duplicateNamesCollapsed: true,
      unknownNamesFiltered: true,
      scopeMatchesFixtureAuthority: true,
    },
    organization: {
      duplicateNamesCollapsed: true,
      unauthorizedNamesFiltered: true,
      scope: '',
      lifetimeSeconds: 3600,
    },
  },
} as const);
const evidence = Object.freeze({
  schemaVersion: 1,
  kind: 'aster-token-exchange-supplemental-comparison',
  scenarioId: 'token-exchange.user-jwt-reuse',
  oracle: {
    binding: {
      sourceCommit: 'a'.repeat(40),
      imageDigest: `sha256:${'b'.repeat(64)}`,
      stateDriverSha256: 'c'.repeat(64),
    },
    projection,
  },
  candidate: {
    binding: {
      sourceCommit: 'd'.repeat(40),
      imageDigest: `sha256:${'e'.repeat(64)}`,
      stateDriverSha256: 'f'.repeat(64),
    },
    projection,
  },
  differences: [],
});

it('validates serialized publication evidence and rejects a nested lifecycle mismatch', () => {
  expect(assertTokenExchangeComparisonEvidence(JSON.parse(JSON.stringify(evidence)))).toEqual(
    evidence
  );
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          managedSubject: { ...projection.managedSubject, successAfterBadActor: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          admissionGrammar: {
            ...projection.admissionGrammar,
            confidentialCorrectProofMasksMissingSubject: {
              ...projection.admissionGrammar.confidentialCorrectProofMasksMissingSubject,
              errorDescription:
                "missing required parameters 'subject_token_type' and 'subject_token'",
            },
          },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          opaque: { ...projection.opaque, priorOpaqueOutputRemainsActive: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          admissionGrammar: { ...projection.admissionGrammar, metadataRestored: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          customizer: { ...projection.customizer, managedSubjectTokenContext: false },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          scopeCanonicalization: {
            ...projection.scopeCanonicalization,
            resource: {
              ...projection.scopeCanonicalization.resource,
              duplicateNamesCollapsed: false,
            },
          },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
  expect(() =>
    assertTokenExchangeComparisonEvidence({
      ...evidence,
      candidate: {
        ...evidence.candidate,
        projection: {
          ...projection,
          organization: {
            ...projection.organization,
            resourceAndOrganization: {
              ...projection.organization.resourceAndOrganization,
              lifetimeSeconds: 300,
            },
          },
        },
      },
    })
  ).toThrow('Invalid token-exchange supplemental comparison');
});

const rootPrefix = '/var/tmp/henry-build/token-exchange-comparison-';
const unavailableRelease = (): never => {
  throw new TypeError('Deferred release unavailable');
};
let root = '';
let driverPath = '';
let receiptPath = '';
let servers: Server[] = [];
const fixture = Object.freeze({
  public: Object.freeze({}) as ProvisionedPhase2Fixture['public'],
  withSecretLease: async () => {
    throw new Error('unused');
  },
}) satisfies ProvisionedPhase2Fixture;

const listen = async (socketPath: string): Promise<Server> =>
  new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.removeListener('error', reject);
      servers = [...servers, server];
      resolve(server);
    });
  });

const closeServer = async (server: Server): Promise<void> =>
  new Promise((resolve) => {
    server.close(() => {
      resolve();
    });
  });

const descriptor = (
  kind: 'oracle' | 'candidate',
  socketPath: string,
  driverSha256: string
): Phase2TargetDescriptor =>
  validatePhase2TargetDescriptor({
    schemaVersion: 1,
    kind,
    sourceCommit: kind === 'oracle' ? '6'.repeat(40) : 'a'.repeat(40),
    imageDigest: `sha256:${kind === 'oracle' ? '7'.repeat(64) : 'b'.repeat(64)}`,
    projectName: 'aster-phase2-client-credentials-0123456789abcdef',
    primaryContainerId: kind === 'oracle' ? '1'.repeat(64) : '3'.repeat(64),
    foreignContainerId: kind === 'oracle' ? '2'.repeat(64) : '4'.repeat(64),
    target: {
      label: kind,
      coreUrl: kind === 'oracle' ? 'http://localhost:3311/' : 'http://localhost:3321/',
      adminUrl: kind === 'oracle' ? 'http://localhost:3411/' : 'http://localhost:3421/',
    },
    foreignTarget: {
      label: kind,
      coreUrl: kind === 'oracle' ? 'http://localhost:3312/' : 'http://localhost:3322/',
      adminUrl: kind === 'oracle' ? 'http://localhost:3412/' : 'http://localhost:3422/',
    },
    stateDriver: { path: driverPath, sha256: driverSha256, controlSocket: socketPath },
    fetchObserverReceiptFile: receiptPath,
    ...(kind === 'candidate'
      ? {
          fixtureExecutable: { path: driverPath, sha256: driverSha256 },
          fixtureSocket: path.join(root, 'candidate-fixture.sock'),
          invariantDriver: {
            path: driverPath,
            sha256: driverSha256,
            controlSocket: path.join(root, 'candidate-invariant.sock'),
          },
        }
      : {}),
  });

beforeAll(async () => {
  root = await mkdtemp(rootPrefix);
  await chmod(root, 0o700);
  driverPath = path.join(root, 'state-driver');
  receiptPath = path.join(root, 'receipts.ndjson');
  await Promise.all([
    writeFile(driverPath, '#!/bin/sh\nexit 0\n', { mode: 0o700 }),
    writeFile(receiptPath, '', { mode: 0o600 }),
  ]);
  await Promise.all([
    listen(path.join(root, 'oracle.sock')),
    listen(path.join(root, 'candidate.sock')),
    listen(path.join(root, 'candidate-fixture.sock')),
    listen(path.join(root, 'candidate-invariant.sock')),
  ]);
  await Promise.all([
    chmod(path.join(root, 'oracle.sock'), 0o600),
    chmod(path.join(root, 'candidate.sock'), 0o600),
    chmod(path.join(root, 'candidate-fixture.sock'), 0o600),
    chmod(path.join(root, 'candidate-invariant.sock'), 0o600),
  ]);
});

afterAll(async () => {
  await Promise.all(servers.map(async (server) => closeServer(server)));
  servers = [];
  await rm(root, { force: true, recursive: true });
});

const prepareTarget = async (kind: 'oracle' | 'candidate') => {
  const driverSha256 = createHash('sha256')
    .update(await readFile(driverPath))
    .digest('hex');
  const source = descriptor(kind, path.join(root, `${kind}.sock`), driverSha256);
  const verified = await verifyPhase2Target(source);
  const sessionRoot = await mkdtemp(path.join(root, `${kind}-session-`));
  await chmod(sessionRoot, 0o700);
  const prepared = await preparePhase2TargetForExecution(verified, sessionRoot, kind);
  return createTokenExchangeComparisonTarget(prepared, fixture);
};

it('waits for the sibling target before preserving one target failure', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const oracleError = new Error('oracle failed');
  let releaseCandidate: () => void = unavailableRelease;
  const candidateGate = new Promise<void>((resolve) => {
    releaseCandidate = resolve;
  });
  let candidateStarted = false;
  let candidateFinished = false;
  let comparisonSettled = false;
  const execute = async ({ target }: TargetDriverInput) => {
    if (target.label === 'oracle') {
      throw oracleError;
    }
    candidateStarted = true;
    await candidateGate;
    candidateFinished = true;
    return projection;
  };
  const comparison = runBoundTokenExchangeComparisonTargets(
    { oracle, candidate, signal: new AbortController().signal },
    execute
  );
  void (async () => {
    try {
      await comparison;
    } catch {
      comparisonSettled = true;
      return;
    }
    comparisonSettled = true;
  })();
  try {
    await setImmediate();
    expect(candidateStarted).toBe(true);
    expect(candidateFinished).toBe(false);
    expect(comparisonSettled).toBe(false);
  } finally {
    releaseCandidate();
  }
  await expect(comparison).rejects.toBe(oracleError);
  expect(candidateFinished).toBe(true);
});

it('preserves two target failures in oracle and candidate order', async () => {
  const oracle = await prepareTarget('oracle');
  const candidate = await prepareTarget('candidate');
  const oracleError = new Error('oracle failed');
  const candidateError = new Error('candidate failed');
  let caught: unknown;
  try {
    await runBoundTokenExchangeComparisonTargets(
      { oracle, candidate, signal: new AbortController().signal },
      async ({ target }) => {
        throw target.label === 'oracle' ? oracleError : candidateError;
      }
    );
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors).toEqual([oracleError, candidateError]);
});

it('rejects caller-forged prepared targets before executing evidence', async () => {
  const forged = Object.freeze({ descriptor: Object.freeze({}) }) as never;
  expect(() => createTokenExchangeComparisonTarget(forged, fixture)).toThrow(
    'Invalid Phase 2 runtime'
  );
});

it('rejects extra authoritative execution properties', async () => {
  await expect(
    runTokenExchangeComparison({
      oracle: {} as never,
      candidate: {} as never,
      signal: new AbortController().signal,
      fetch: () => {
        throw new Error('must not execute');
      },
    } as never)
  ).rejects.toThrow('Invalid token-exchange supplemental comparison');
});
/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions */
