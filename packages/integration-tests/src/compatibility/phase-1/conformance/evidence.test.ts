import type { Phase1Profile } from '../profile-types.js';

import { phase1ConformanceSuiteCommit, phase1ConformanceSuiteRepository } from './config.js';
import { createPhase1ConformanceEvidence, hashCanonicalConformanceJson } from './evidence.js';
import {
  createBrandedPhase1ConformanceRunResultForTesting,
  phase1ConformanceAdapterControlIds,
  runPhase1Conformance,
  type Phase1ConformanceProcessRequest,
  type Phase1ConformanceRunResult,
} from './runner.js';

const provenance = {
  harnessCommit: '1'.repeat(40),
  profileSha256: '2'.repeat(64),
  schemaSha256: '3'.repeat(64),
  imageDigest: `sha256:${'4'.repeat(64)}`,
};

const runResult = (): Phase1ConformanceRunResult => ({
  schemaVersion: 1,
  mode: 'runtime-candidate',
  adapterControls: [
    { id: 'oidf-post-1', projection: { configured: true } },
    { id: 'oidf-basic-2', projection: { configured: true } },
    { id: 'oidf-basic-1', projection: { configured: true } },
  ],
  officialResults: [
    {
      planId: 'oidcc-config-certification-test-plan',
      resultId: 'oidf-result-opaque-002',
      status: 'PASSED',
      variant: { serverMetadata: 'discovery', clientRegistration: 'static_client' },
      result: { outcome: 'passed', checks: { discovery: true } },
    },
    {
      planId: 'oidcc-basic-certification-test-plan',
      resultId: 'oidf-result-opaque-001',
      status: 'PASSED',
      variant: { responseType: 'code', clientRegistration: 'static_client' },
      result: { outcome: 'passed', checks: { basicPlan: true } },
    },
  ],
});

const callbackUri = 'https://suite.example/test/a/aster-phase1/callback';
const conformanceProfile = () =>
  ({
    fixtures: {
      adminTenant: { application: { oidcClientMetadata: { redirectUris: ['https://admin/cb'] } } },
      dataTenant: { applications: [{ oidcClientMetadata: { redirectUris: ['https://data/cb'] } }] },
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
        namespace: 'private',
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

const brandedRunResult = async (
  mode: 'review-candidate' | 'mirror-control' | 'runtime-candidate'
) =>
  runPhase1Conformance(conformanceProfile(), mode, {
    checkedOutSuiteCommit: phase1ConformanceSuiteCommit,
    repositoryRoot: '/repo',
    scriptPath: '/repo/.scripts/compatibility/run-phase1-conformance.sh',
    workingDirectory: '/repo',
    environment: {
      PATH: '/usr/bin:/bin',
      ASTER_PHASE1_BUILD_ROOT: '/var/tmp/henry-build',
      ASTER_PHASE1_HARNESS_COMMIT: 'a'.repeat(40),
      ASTER_PHASE1_CONFORMANCE_ROOT: '/var/tmp/henry-build/evidence-test',
      ASTER_PHASE1_CONFORMANCE_DRIVER: '/repo/.scripts/compatibility/phase1-conformance-driver.sh',
    },
    runner: async (request: Phase1ConformanceProcessRequest) => {
      const input = JSON.parse(request.stdin) as {
        planId?: string;
        variant?: unknown;
        staticClient?: { id: string };
      };
      const control = request.args[0] === '--adapter-control-id';
      const resultId =
        input.planId === 'oidcc-config-certification-test-plan'
          ? 'oidf-result-opaque-002'
          : 'oidf-result-opaque-001';
      const terminal = control
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
            kind: 'phase1-conformance-official-terminal',
            suiteCommit: phase1ConformanceSuiteCommit,
            planId: input.planId,
            variant: input.variant,
            status: 'PASSED',
            resultId,
            result: { outcome: 'passed', checks: { completed: true } },
          };
      return {
        pid: 1234,
        processGroupId: 1234,
        exitCode: 0,
        signal: undefined,
        stdout: JSON.stringify(terminal),
        stderr: '',
        timedOut: false,
        killed: false,
        reaped: true,
      };
    },
  });

describe('Phase 1 conformance evidence', () => {
  it('emits the exact assembler root with sorted adapter and plan projections', async () => {
    const evidence = createPhase1ConformanceEvidence(
      await brandedRunResult('runtime-candidate'),
      provenance
    );

    expect(Object.keys(evidence)).toEqual([
      'schemaVersion',
      'mode',
      'provenance',
      'sanitizerSuccess',
      'adapterControls',
      'officialResultIds',
      'planResults',
    ]);
    expect(evidence.provenance).toEqual(provenance);
    expect(evidence.sanitizerSuccess).toBe(true);
    expect(evidence.adapterControls.map(({ id }) => id)).toEqual(
      phase1ConformanceAdapterControlIds
    );
    expect(evidence.officialResultIds).toEqual([
      'oidf-result-opaque-001',
      'oidf-result-opaque-002',
    ]);
    expect(evidence.planResults.map(({ planId }) => planId)).toEqual([
      'oidcc-basic-certification-test-plan',
      'oidcc-config-certification-test-plan',
    ]);
    for (const control of evidence.adapterControls) {
      expect(Object.keys(control)).toEqual(['id', 'detected', 'result']);
      expect(control.detected).toBe(true);
      expect(control.result.label).toBe('adapter-control');
      expect(control.result.projectionSha256).toBe(
        hashCanonicalConformanceJson(control.result.value)
      );
    }
    for (const plan of evidence.planResults) {
      expect(Object.keys(plan)).toEqual(['planId', 'resultId', 'resultSha256', 'result']);
      expect(plan.result.label).toBe('official-plan-result');
      expect(plan.resultSha256).toBe(plan.result.projectionSha256);
      expect(plan.resultSha256).toBe(hashCanonicalConformanceJson(plan.result.value));
    }
    expect(Object.isFrozen(evidence)).toBe(true);
    expect(JSON.stringify(evidence)).not.toMatch(/log|stderr|stdout|private/iu);
  });

  it.each(['review-candidate', 'mirror-control'] as const)(
    'keeps official IDs and plan results empty in %s mode',
    async (mode) => {
      const evidence = createPhase1ConformanceEvidence(await brandedRunResult(mode), provenance);

      expect(evidence.officialResultIds).toEqual([]);
      expect(evidence.planResults).toEqual([]);
    }
  );

  it('rejects a structurally valid unbranded result', () => {
    expect(() => createPhase1ConformanceEvidence(runResult(), provenance)).toThrow(
      /^Invalid phase 1 conformance evidence$/u
    );
  });

  it('reaches the evidence duplicate-result guard for a test-authorized hostile result', async () => {
    const valid = await brandedRunResult('runtime-candidate');
    const first = valid.officialResults[0]!;
    const second = valid.officialResults[1]!;
    const hostile = createBrandedPhase1ConformanceRunResultForTesting({
      ...valid,
      officialResults: [first, { ...second, resultId: first.resultId }],
    });

    expect(() => createPhase1ConformanceEvidence(hostile, provenance)).toThrow(
      /^Invalid phase 1 conformance evidence$/u
    );
  });

  it('produces the same hash for reordered object keys but preserves array order', () => {
    expect(hashCanonicalConformanceJson({ b: 2, a: { y: 2, x: 1 } })).toBe(
      hashCanonicalConformanceJson({ a: { x: 1, y: 2 }, b: 2 })
    );
    expect(hashCanonicalConformanceJson({ values: [1, 2] })).not.toBe(
      hashCanonicalConformanceJson({ values: [2, 1] })
    );
  });

  it('matches the Aster canonical JSON trailing-newline hash vector', () => {
    expect(hashCanonicalConformanceJson({ b: 2, a: { y: 2, x: 1 } })).toBe(
      '7d18070743e5a89438758e4f5d12b96e094b6dee334b2ef013cb082964d1b472'
    );
  });

  it.each([
    [
      'duplicate result ID',
      (value: Phase1ConformanceRunResult) => ({
        ...value,
        officialResults: [
          value.officialResults[0]!,
          { ...value.officialResults[1]!, resultId: value.officialResults[0]!.resultId },
        ],
      }),
    ],
    [
      'plan name as result ID',
      (value: Phase1ConformanceRunResult) => ({
        ...value,
        officialResults: [
          { ...value.officialResults[0]!, resultId: value.officialResults[0]!.planId },
          value.officialResults[1]!,
        ],
      }),
    ],
    ['raw log field', (value: Phase1ConformanceRunResult) => ({ ...value, stderr: 'private-log' })],
    [
      'wrong adapter ID',
      (value: Phase1ConformanceRunResult) => ({
        ...value,
        adapterControls: [
          { ...value.adapterControls[0]!, id: 'wrong' },
          ...value.adapterControls.slice(1),
        ],
      }),
    ],
    [
      'secret-bearing result',
      (value: Phase1ConformanceRunResult) => ({
        ...value,
        officialResults: [
          { ...value.officialResults[0]!, result: { refreshToken: 'secret-token-value' } },
          value.officialResults[1]!,
        ],
      }),
    ],
  ] as const)('rejects %s with one fixed diagnostic', (_name, mutate) => {
    expect(() => createPhase1ConformanceEvidence(mutate(runResult()) as never, provenance)).toThrow(
      /^Invalid phase 1 conformance evidence$/u
    );
  });

  it('rejects malformed provenance without echoing values', async () => {
    const result = await brandedRunResult('runtime-candidate');

    expect(() =>
      createPhase1ConformanceEvidence(result, {
        ...provenance,
        harnessCommit: 'not-a-commit',
      })
    ).toThrow(/^Invalid phase 1 conformance evidence$/u);
  });
});
