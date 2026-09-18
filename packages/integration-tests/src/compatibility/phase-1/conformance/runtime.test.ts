/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- Runtime tests record bounded process requests and deliberately forge partial profile/context authorities. */
import {
  authorizePhase1RunForTesting,
  type Phase1RunAuthorization,
  type Phase1RunMode,
} from '../cli.js';
import type { Phase1Profile } from '../profile-types.js';

import { phase1ConformanceSuiteCommit, phase1ConformanceSuiteRepository } from './config.js';
import {
  createPhase1ConformanceGateRuntimeContext,
  createPhase1ConformanceRuntimeContextForTesting,
  type Phase1ConformanceRuntimeContext,
} from './context.js';
import {
  phase1ConformanceAdapterControlIds,
  type Phase1ConformanceProcessRequest,
  type Phase1ConformanceProcessResult,
} from './runner.js';
import {
  runPhase1ConformanceRuntimeForTesting,
  type Phase1ConformanceRuntimeEvidence,
} from './runtime.js';

const harnessCommit = '1'.repeat(40);
const oracleImageDigest = `sha256:${'2'.repeat(64)}`;
const candidateImageDigest = `sha256:${'5'.repeat(64)}`;
const callbackUri = 'https://suite.example/test/a/aster-phase1/callback';

const profile = (): Phase1Profile =>
  ({
    phase1Harness: { commit: harnessCommit },
    fixtures: {
      adminTenant: {
        application: { oidcClientMetadata: { redirectUris: ['https://admin.example/callback'] } },
      },
      dataTenant: {
        applications: [{ oidcClientMetadata: { redirectUris: ['https://data.example/callback'] } }],
      },
    },
    consoleAuthentication: { grants: ['authorization_code', 'refresh_token'] },
    oidc: {
      grants: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      responseModes: ['query'],
      tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
      idTokenSigningAlgorithmsSupported: ['ES384'],
      jwksKeyMetadata: { kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
    },
    conformance: {
      suiteRepository: phase1ConformanceSuiteRepository,
      suiteCommit: phase1ConformanceSuiteCommit,
      target: {
        namespace: 'aster-phase1-conformance',
        issuer: 'https://server.example/oidc',
        discoveryUrl: 'https://server.example/oidc/.well-known/openid-configuration',
        suiteBaseUrl: 'https://suite.example',
        alias: 'aster-phase1',
        callbackUri,
        tls: {
          trustDomain: 'private',
          issuer: 'private',
          asterMaterial: 'private',
          suiteMaterial: 'private',
          lifecycle: 'private',
        },
      },
      staticClients: [
        {
          id: 'oidf-basic-1',
          tokenEndpointAuthMethod: 'client_secret_basic',
          redirectUris: [callbackUri],
        },
        {
          id: 'oidf-basic-2',
          tokenEndpointAuthMethod: 'client_secret_basic',
          redirectUris: [callbackUri],
        },
        {
          id: 'oidf-post-1',
          tokenEndpointAuthMethod: 'client_secret_post',
          redirectUris: [callbackUri],
        },
      ],
      plans: [
        {
          testPlanName: 'oidcc-basic-certification-test-plan',
          displayName: 'Basic',
          variants: {
            serverMetadata: 'discovery',
            clientRegistration: 'static_client',
            responseType: 'code',
            responseMode: 'default',
            clientAuthTypes: ['client_secret_basic', 'client_secret_post'],
          },
        },
        {
          testPlanName: 'oidcc-config-certification-test-plan',
          displayName: 'Config',
          variants: { serverMetadata: 'discovery', clientRegistration: 'static_client' },
        },
      ],
    },
  }) as unknown as Phase1Profile;

const authorization = (mode: Phase1RunMode): Phase1RunAuthorization => {
  const provenance = Object.freeze(
    mode === 'review-candidate'
      ? { kind: 'review-candidate' as const, harnessCommit, publishable: false as const }
      : {
          kind: 'accepted-harness' as const,
          harnessCommit,
          protectedBranch: 'phase1-acceptance-lock',
          pullRequestNumber: 17,
          publishable: true as const,
        }
  );

  return authorizePhase1RunForTesting(
    Object.freeze({
      mode,
      profile: profile(),
      profileSha256: '3'.repeat(64),
      schemaSha256: '4'.repeat(64),
      provenance,
      protectedExecution:
        mode === 'review-candidate' ? undefined : Object.freeze({ mode, provenance }),
      controls: Object.freeze({
        recordOracle: false,
        observationControls: true,
        discoveryExtraControl: true,
        candidateInvariantControls: true,
      }),
    }) as unknown as Phase1RunAuthorization
  );
};

const context = (
  mode: 'review-candidate' | 'mirror-control' = 'mirror-control',
  conformanceRoot = '/var/tmp/henry-build/phase1/conformance'
): Phase1ConformanceRuntimeContext =>
  createPhase1ConformanceRuntimeContextForTesting({
    authorization: authorization(mode),
    oracleImageDigest,
    candidateImageDigest: mode === 'mirror-control' ? oracleImageDigest : candidateImageDigest,
    evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
    repositoryRoot: '/home/henry/repo/logto',
    conformanceRoot,
  });

const conformanceGateContext = (): Phase1ConformanceRuntimeContext =>
  createPhase1ConformanceGateRuntimeContext({
    authorization: authorizePhase1RunForTesting(
      Object.freeze({
        mode: 'runtime-candidate',
        profile: profile(),
        profileSha256: '3'.repeat(64),
        schemaSha256: '4'.repeat(64),
        provenance: Object.freeze({
          kind: 'review-candidate' as const,
          harnessCommit,
          publishable: false as const,
        }),
        protectedExecution: undefined,
        controls: Object.freeze({
          recordOracle: false,
          observationControls: true,
          discoveryExtraControl: true,
          candidateInvariantControls: true,
        }),
        conformanceGate: true as const,
      }) as Phase1RunAuthorization
    ),
    candidateImageDigest,
    evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
    repositoryRoot: '/home/henry/repo/logto',
    conformanceRoot: '/var/tmp/henry-build/phase1/conformance',
  });

const runtimeWithoutGateContext = (): Phase1ConformanceRuntimeContext =>
  ({
    authorization: authorization('runtime-candidate'),
    candidateImageDigest,
    evidenceDirectory: '/var/tmp/henry-build/phase1/evidence',
    repositoryRoot: '/home/henry/repo/logto',
    conformanceRoot: '/var/tmp/henry-build/phase1/conformance',
  }) as Phase1ConformanceRuntimeContext;

const processResult = (
  request: Phase1ConformanceProcessRequest,
  overrides: Partial<Phase1ConformanceProcessResult> = {}
): Phase1ConformanceProcessResult => {
  const input = JSON.parse(request.stdin) as {
    staticClient?: { id: string };
    planId?: string;
    variant?: unknown;
  };
  const output =
    request.args[0] === '--adapter-control-id'
      ? {
          schemaVersion: 1,
          kind: 'phase1-conformance-adapter-control-terminal',
          suiteCommit: phase1ConformanceSuiteCommit,
          adapterControlId: input.staticClient?.id,
          status: 'PASSED',
          result: { configured: true, redirectUriMatches: true },
        }
      : {
          schemaVersion: 1,
          kind: 'phase1-conformance-terminal',
          suiteCommit: phase1ConformanceSuiteCommit,
          adapterControlId: 'phase1-conformance.runner.strict-terminal',
          planId: input.planId,
          variant: input.variant,
          status: 'PASSED',
          resultId:
            input.planId === 'oidcc-basic-certification-test-plan'
              ? 'oidf-result-opaque-001'
              : 'oidf-result-opaque-002',
          result: { outcome: 'passed', checks: { completed: true } },
        };

  return {
    pid: 1234,
    processGroupId: 1234,
    exitCode: 0,
    signal: undefined,
    stdout: JSON.stringify(output),
    stderr: '',
    timedOut: false,
    killed: false,
    reaped: true,
    ...overrides,
  };
};

describe('Phase 1 conformance production runtime', () => {
  it.each(['review-candidate', 'mirror-control'] as const)(
    'runs only the exact adapter controls and emits closed %s evidence',
    async (mode) => {
      const requests: Phase1ConformanceProcessRequest[] = [];
      const result: Phase1ConformanceRuntimeEvidence = await runPhase1ConformanceRuntimeForTesting(
        context(mode),
        {
          runner: async (request) => {
            requests.push(request);
            return processResult(request);
          },
        }
      );

      expect(requests.map(({ args }) => args)).toEqual(
        phase1ConformanceAdapterControlIds.map((id) => ['--adapter-control-id', id])
      );
      expect(requests.every(({ command }) => command.endsWith('run-phase1-conformance.sh'))).toBe(
        true
      );
      expect(requests.every(({ cwd }) => cwd === '/home/henry/repo/logto')).toBe(true);
      expect(requests.every(({ env }) => Object.keys(env).length === 5)).toBe(true);
      expect(requests[0]?.env).toEqual({
        PATH: '/usr/bin:/bin',
        ASTER_PHASE1_BUILD_ROOT: '/var/tmp/henry-build',
        ASTER_PHASE1_HARNESS_COMMIT: harnessCommit,
        ASTER_PHASE1_CONFORMANCE_ROOT: '/var/tmp/henry-build/phase1/conformance',
        ASTER_PHASE1_CONFORMANCE_DRIVER:
          '/home/henry/repo/logto/.scripts/compatibility/phase1-conformance-driver.sh',
      });
      expect(result).toMatchObject({
        schemaVersion: 1,
        mode,
        provenance: {
          harnessCommit,
          profileSha256: '3'.repeat(64),
          schemaSha256: '4'.repeat(64),
          imageDigest: oracleImageDigest,
        },
        sanitizerSuccess: true,
        officialResultIds: [],
        planResults: [],
      });
      expect(result.adapterControls.map(({ id }) => id)).toEqual(
        phase1ConformanceAdapterControlIds
      );
      expect(Object.isFrozen(result)).toBe(true);
    }
  );

  it('runs three controls and both official plans for the runtime conformance gate', async () => {
    const requests: Phase1ConformanceProcessRequest[] = [];
    const result = await runPhase1ConformanceRuntimeForTesting(conformanceGateContext(), {
      runner: async (request) => {
        requests.push(request);
        return processResult(request);
      },
    });

    expect(requests.map(({ args }) => args)).toEqual([
      ['--adapter-control-id', 'oidf-basic-1'],
      ['--adapter-control-id', 'oidf-basic-2'],
      ['--adapter-control-id', 'oidf-post-1'],
      ['--plan-id', 'oidcc-basic-certification-test-plan'],
      ['--plan-id', 'oidcc-config-certification-test-plan'],
    ]);
    expect(result).toMatchObject({
      schemaVersion: 1,
      mode: 'runtime-candidate',
      provenance: {
        harnessCommit,
        profileSha256: '3'.repeat(64),
        schemaSha256: '4'.repeat(64),
        imageDigest: candidateImageDigest,
      },
      sanitizerSuccess: true,
      officialResultIds: ['oidf-result-opaque-001', 'oidf-result-opaque-002'],
    });
    expect(result.adapterControls).toHaveLength(3);
    expect(result.planResults.map(({ planId }) => planId)).toEqual([
      'oidcc-basic-certification-test-plan',
      'oidcc-config-certification-test-plan',
    ]);
  });

  it('runs beneath a custom safe build root and rejects an unsafe root', async () => {
    const buildRoot = '/var/tmp/aster-portable-runtime';
    const customRoot = `${buildRoot}/private`;
    const requests: Phase1ConformanceProcessRequest[] = [];

    await expect(
      runPhase1ConformanceRuntimeForTesting(context('mirror-control', customRoot), {
        environment: { ASTER_PHASE1_BUILD_ROOT: buildRoot },
        runner: async (request) => {
          requests.push(request);
          return processResult(request);
        },
      })
    ).resolves.toMatchObject({ mode: 'mirror-control' });
    expect(requests[0]?.env.ASTER_PHASE1_BUILD_ROOT).toBe(buildRoot);

    await expect(
      runPhase1ConformanceRuntimeForTesting(context(), {
        environment: { ASTER_PHASE1_BUILD_ROOT: '/var/tmp' },
        runner: async (request) => processResult(request),
      })
    ).rejects.toThrow(/^Invalid phase 1 conformance runtime$/u);
  });

  it('fails closed for runtime-candidate before invoking the suite adapter', async () => {
    let touched = false;

    await expect(
      runPhase1ConformanceRuntimeForTesting(runtimeWithoutGateContext(), {
        runner: async (request) => {
          touched = true;
          return processResult(request);
        },
      })
    ).rejects.toThrow(/^Phase 1 official conformance plan runtime is unavailable$/u);
    expect(touched).toBe(false);
  });

  it('rejects an unbranded conformance context before invoking the runner', async () => {
    let touched = false;

    await expect(
      runPhase1ConformanceRuntimeForTesting(
        { ...conformanceGateContext() },
        {
          runner: async (request) => {
            touched = true;
            return processResult(request);
          },
        }
      )
    ).rejects.toThrow(/^Invalid phase 1 conformance runtime$/u);
    expect(touched).toBe(false);
  });

  it('rejects an injected runner outside NODE_ENV=test', async () => {
    const originalNodeEnvironment = process.env.NODE_ENV;
    const runtime = conformanceGateContext();
    let touched = false;

    process.env.NODE_ENV = 'production';
    try {
      await expect(
        runPhase1ConformanceRuntimeForTesting(runtime, {
          runner: async (request) => {
            touched = true;
            return processResult(request);
          },
        })
      ).rejects.toThrow(/^Invalid phase 1 conformance runtime$/u);
    } finally {
      process.env.NODE_ENV = originalNodeEnvironment;
    }
    expect(touched).toBe(false);
  });

  it('converts process failures to one non-echoing runtime diagnostic', async () => {
    const privateValue = 'Bearer private-conformance-value';
    const error = await runPhase1ConformanceRuntimeForTesting(context(), {
      runner: async (request) => processResult(request, { stderr: privateValue }),
    }).catch((error_: unknown) => error_);

    expect(String(error)).toBe('TypeError: Invalid phase 1 conformance runtime');
    expect(`${String(error)} ${JSON.stringify(error)}`).not.toContain(privateValue);
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
