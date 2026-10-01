/* eslint-disable max-lines, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Negative controls deliberately forge forbidden public provenance fields. */
import { jsonValueGuard } from '../model.js';
import type { JsonValue } from '../normalize.js';

import {
  clientCredentialsCandidateInvariantExpectedProjection,
  clientCredentialsCandidateInvariantIds,
  runClientCredentialsCandidateInvariantControls,
} from './candidate-invariants/client-credentials.js';
import {
  customJwtFetchPolicyCandidateInvariantIds,
  customJwtFetchPolicyExpectedProjection,
  runCustomJwtFetchPolicyControls,
} from './candidate-invariants/custom-jwt-fetch-policy.js';
import {
  customJwtCandidateInvariantExpectedProjection,
  customJwtCandidateInvariantIds,
  runCustomJwtCandidateInvariantControls,
} from './candidate-invariants/custom-jwt.js';
import {
  deviceCandidateInvariantExpectedProjection,
  deviceCandidateInvariantIds,
  runDeviceCandidateInvariantControls,
} from './candidate-invariants/device-authorization.js';
import {
  assertPhase2TargetEvidenceIsSanitized,
  createPhase2EvidenceEnvelope,
  Phase2SanitizerFailure,
  validatePhase2OracleArtifact,
  type Phase2TargetProvenance,
} from './envelope.js';
import { phase2ExpectedProfileAuthority, type Phase2ProfileRegistries } from './profile.js';
import type { Phase2SourceIdentity } from './provenance.js';
import { assertDiscoveryEndpointFieldsContract } from './scenarios/client-credentials.js';

const profile: Phase2ProfileRegistries = {
  ...phase2ExpectedProfileAuthority,
  deviceOperations: Object.freeze([
    'device.authorize',
    'device.open-shortcut',
    'device.open-verification',
    'device.submit-verification',
    'device.submit-password',
    'device.read-consent',
    'device.submit-consent',
    'device.resume-consent',
    'device.open-success',
    'device.poll-token',
    'device.rotate-refresh',
    'device.introspect-token',
    'device.revoke-token',
    'device.request-userinfo',
    'device.open-logout',
    'device.confirm-logout',
    'device.discover-oidc',
    'device.discover-oauth',
  ] as const),
  differentialScenarios: [],
  candidateInvariantScenarios: [],
  discovery: {
    grantTypesSupportedAppend: Object.freeze([
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ] as const),
    endpointFieldsAppend: Object.freeze([
      'introspection_endpoint',
      'revocation_endpoint',
      'end_session_endpoint',
      'device_authorization_endpoint',
    ] as const),
    scopesSupportedAppend: ['urn:aster:scope:sessions'],
    stillAbsent: Object.freeze(['registration_endpoint'] as const),
  },
};
const harness: Phase2SourceIdentity = {
  repositoryRoot: '/private/repo',
  repositoryDev: '1',
  repositoryIno: '2',
  clean: true,
  public: {
    repositoryUrl: 'https://github.com/qq98982/logto.git',
    headCommit: '3'.repeat(40),
    headTree: '4'.repeat(40),
    runtimeBundleSha256: 'a'.repeat(64),
  },
  runtimeEntryPath: '/private/repo/packages/integration-tests/lib/compatibility/phase-2/cli.js',
};
const target = (kind: 'oracle' | 'candidate'): Phase2TargetProvenance => ({
  sourceCommit: kind === 'oracle' ? '6852a7b8c8984c5c12b2061e8c51faa310a36412' : '5'.repeat(40),
  imageDigest:
    kind === 'oracle'
      ? 'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd'
      : `sha256:${'6'.repeat(64)}`,
  topology: { primaryRole: `${kind}-primary-core`, foreignRole: `${kind}-foreign-core` },
  drivers: {
    state: { role: 'state-driver', sha256: '7'.repeat(64) },
    ...(kind === 'candidate'
      ? {
          fixture: { role: 'fixture-executable' as const, sha256: '8'.repeat(64) },
          invariant: { role: 'invariant-driver' as const, sha256: '9'.repeat(64) },
        }
      : {}),
  },
});

const deviceAuthorizationProjection = {
  status: 200,
  contentType: 'application/json',
  headers: {},
  keys: [],
  cookies: [{ name: 'interaction', options: ['HttpOnly'], clearing: false }],
  challenge: undefined,
  location: undefined,
  oauthError: { category: undefined, description: undefined },
  userCodeShape: undefined,
  deviceCodeShape: undefined,
  expiresIn: undefined,
  interval: undefined,
  tokenType: undefined,
  verificationUri: undefined,
  verificationUriComplete: undefined,
  experience: undefined,
};

const sanitizerStageOf = (value: unknown): string => {
  try {
    assertPhase2TargetEvidenceIsSanitized(value);
    return 'accepted';
  } catch (error: unknown) {
    return error instanceof Phase2SanitizerFailure ? error.stage : 'unclassified';
  }
};

describe('Phase 2 public provenance envelope', () => {
  it('sanitizes each target scenario with its owning scanner', () => {
    const safeEvidence = {
      target: 'oracle',
      discovery: {
        endpointFieldsAppend: ['device_authorization_endpoint'],
      },
      controls: [{ passed: true }],
      scenarios: [
        {
          id: 'client-credentials.basic-explicit-resource',
          projection: { http: { status: 200 } },
        },
        {
          id: 'device-authorization.urlencoded-success',
          projection: deviceAuthorizationProjection,
        },
      ],
    };

    expect(() => {
      assertPhase2TargetEvidenceIsSanitized(safeEvidence);
    }).not.toThrow();
    expect(() => {
      assertPhase2TargetEvidenceIsSanitized({
        ...safeEvidence,
        scenarios: [
          ...safeEvidence.scenarios,
          {
            id: 'device-authorization.json-object-success',
            projection: deviceAuthorizationProjection,
          },
        ],
      });
    }).not.toThrow();
    expect(() => {
      assertPhase2TargetEvidenceIsSanitized({
        ...safeEvidence,
        scenarios: Array.from({ length: 169 }, () => safeEvidence.scenarios[0]),
      });
    }).toThrow('Invalid Phase 2 evidence sanitizer');
    expect(() => {
      assertPhase2TargetEvidenceIsSanitized({
        ...safeEvidence,
        scenarios: new Proxy(safeEvidence.scenarios, {
          get: (source, key) =>
            key === Symbol.iterator ? () => [][Symbol.iterator]() : Reflect.get(source, key),
        }),
      });
    }).toThrow('Invalid Phase 2 evidence sanitizer');
    const getterCalls = { count: 0 };
    const accessorScenario = Object.defineProperties(
      {},
      {
        id: { enumerable: true, value: 'device-authorization.urlencoded-success' },
        projection: {
          enumerable: true,
          get: () => {
            getterCalls.count += 1;
            return getterCalls.count === 1
              ? deviceAuthorizationProjection
              : { privateKey: 'planted-value' };
          },
        },
      }
    );
    expect(() => {
      assertPhase2TargetEvidenceIsSanitized({ ...safeEvidence, scenarios: [accessorScenario] });
    }).toThrow('Invalid Phase 2 evidence sanitizer');
    expect(getterCalls.count).toBe(0);
    expect(() => {
      assertPhase2TargetEvidenceIsSanitized({
        ...safeEvidence,
        scenarios: [
          {
            id: 'client-credentials.basic-explicit-resource',
            projection: { cookies: { count: 1 } },
          },
          safeEvidence.scenarios[1],
        ],
      });
    }).toThrow('Invalid Phase 2 evidence sanitizer');
    expect(() => {
      assertPhase2TargetEvidenceIsSanitized({
        ...safeEvidence,
        scenarios: [
          safeEvidence.scenarios[0],
          {
            id: 'device-authorization.urlencoded-success',
            projection: { privateKey: 'planted-value' },
          },
        ],
      });
    }).toThrow('Invalid Phase 2 evidence sanitizer');
    expect(() => {
      assertPhase2TargetEvidenceIsSanitized({
        ...safeEvidence,
        scenarios: [
          {
            id: 'client-credentials.basic-explicit-resource',
            projection: { http: { status: 200, oversized: 'x'.repeat(16 * 1024 + 1) } },
          },
          safeEvidence.scenarios[1],
        ],
      });
    }).toThrow('Invalid Phase 2 evidence sanitizer');
    expect(
      sanitizerStageOf({
        ...safeEvidence,
        scenarios: Array.from({ length: 169 }, () => safeEvidence.scenarios[0]),
      })
    ).toBe('ids');
    expect(
      sanitizerStageOf({
        ...safeEvidence,
        scenarios: [
          { id: 'client-credentials.basic-explicit-resource', projection: { cookies: [] } },
        ],
      })
    ).toBe('client-0');
    expect(
      sanitizerStageOf({
        ...safeEvidence,
        scenarios: [
          safeEvidence.scenarios[0],
          { id: 'device-authorization.urlencoded-success', projection: { privateKey: 'planted' } },
        ],
      })
    ).toBe('device-1');
  });

  it('round-trips legitimate device evidence while rejecting planted secrets', () => {
    const artifactProfile = {
      ...profile,
      differentialScenarios: ['device-authorization.urlencoded-success'],
    } as Phase2ProfileRegistries;
    const payload = {
      schemaVersion: 1,
      mode: 'oracle',
      target: {
        target: 'oracle',
        scenarios: [
          {
            id: 'device-authorization.urlencoded-success',
            projection: deviceAuthorizationProjection,
          },
        ],
        discovery: {},
        controls: [],
      },
    } as unknown as JsonValue;
    const artifact = createPhase2EvidenceEnvelope({
      mode: 'oracle',
      profile: artifactProfile,
      harness,
      oracle: target('oracle'),
      payload,
    });

    expect(jsonValueGuard.safeParse(artifact).success).toBe(true);
    const parsed = JSON.parse(JSON.stringify(artifact)) as unknown;
    const restored = validatePhase2OracleArtifact(parsed, artifactProfile, harness);
    const wireProjection: Record<string, unknown> = (artifact.payload as any).target.scenarios[0]
      .projection;
    const restoredProjection: Record<string, unknown> = (restored.payload as any).target
      .scenarios[0].projection;
    expect(Object.hasOwn(wireProjection, 'challenge')).toBe(false);
    expect(Object.hasOwn(restoredProjection, 'challenge')).toBe(true);
    expect(restoredProjection.challenge).toBeUndefined();
    expect(Object.isFrozen(restoredProjection)).toBe(true);
    expect(Object.isFrozen(restoredProjection.oauthError as Record<string, unknown>)).toBe(true);
    expect(Object.isFrozen((restored.payload as any).target.scenarios as readonly unknown[])).toBe(
      true
    );
    for (const scenario of [
      {
        id: 'client-credentials.basic-explicit-resource',
        projection: { cookies: { value: 'planted-value' } },
      },
      {
        id: 'device-authorization.urlencoded-success',
        projection: { privateKey: 'planted-value' },
      },
    ]) {
      const plantedPayload = structuredClone(payload) as any;
      plantedPayload.target.scenarios[0] = scenario;
      expect(() =>
        createPhase2EvidenceEnvelope({
          mode: 'oracle',
          profile: artifactProfile,
          harness,
          oracle: target('oracle'),
          payload: plantedPayload,
        })
      ).toThrow();
    }
    for (const mutate of [
      (projection: any) => {
        projection.cookies[0].value = 'planted-value';
      },
      (projection: any) => {
        projection.tokenType = 'planted-value';
      },
      (projection: any) => {
        projection.authorization_endpoint = 'planted-value';
      },
    ]) {
      const plantedPayload = structuredClone(payload) as any;
      mutate(plantedPayload.target.scenarios[0].projection);
      expect(() =>
        createPhase2EvidenceEnvelope({
          mode: 'oracle',
          profile: artifactProfile,
          harness,
          oracle: target('oracle'),
          payload: plantedPayload,
        })
      ).toThrow();
    }
  });

  it('accepts only a canonical immutable oracle artifact with the exact scenario revision and order', () => {
    const artifactProfile = {
      ...profile,
      differentialScenarios: [
        'client-credentials.basic-explicit-resource',
        'client-credentials.post-explicit-resource',
      ],
    } as Phase2ProfileRegistries;
    const artifact = createPhase2EvidenceEnvelope({
      mode: 'oracle',
      profile: artifactProfile,
      harness,
      oracle: target('oracle'),
      payload: {
        schemaVersion: 1,
        mode: 'oracle',
        target: {
          target: 'oracle',
          scenarios: artifactProfile.differentialScenarios.map((id) => ({ id, projection: {} })),
          discovery: {},
          controls: [],
        },
      },
    });
    expect(validatePhase2OracleArtifact(artifact, artifactProfile, harness)).toEqual(artifact);
    const mutate = (change: (value: any) => void) => {
      const candidate = structuredClone(artifact) as any;
      change(candidate);
      expect(() => validatePhase2OracleArtifact(candidate, artifactProfile, harness)).toThrow(
        'Invalid Phase 2 evidence envelope'
      );
    };
    mutate((value) => {
      value.mode = 'differential';
    });
    mutate((value) => {
      value.provenance.profileSha256 = '0'.repeat(64);
    });
    mutate((value) => {
      value.payload.target.scenarios.reverse();
    });
    mutate((value) => {
      value.payload.target.scenarios[1].id = value.payload.target.scenarios[0].id;
    });
    mutate((value) => {
      value.payload.target.scenarios.push({
        id: 'client-credentials.default-resource',
        projection: {},
      });
    });
  });

  it('publishes both targets after projecting discovery from one closed profile', () => {
    const endpointFields = profile.discovery.endpointFieldsAppend;
    const projected = (issuer: string) =>
      assertDiscoveryEndpointFieldsContract(
        {
          introspection_endpoint: `${issuer}/token/introspection`,
          revocation_endpoint: `${issuer}/token/revocation`,
          end_session_endpoint: `${issuer}/session/end`,
          device_authorization_endpoint: `${issuer}/device/auth`,
        },
        endpointFields,
        issuer
      );
    const value = createPhase2EvidenceEnvelope({
      mode: 'differential',
      profile,
      harness,
      oracle: target('oracle'),
      candidate: target('candidate'),
      payload: {
        oracle: { discovery: { endpointFieldsAppend: projected('https://oracle.example/oidc') } },
        candidate: {
          discovery: { endpointFieldsAppend: projected('https://candidate.example/oidc') },
        },
      } as unknown as JsonValue,
    });
    expect(value.sanitizerSuccess).toBe(true);
  });

  it('publishes the full 168-comparison differential envelope contract', () => {
    const comparisons = Array.from({ length: 168 }, (_, index) => ({
      scenarioId: `comparison-${index}`,
      differenceCount: 0,
    }));
    const value = createPhase2EvidenceEnvelope({
      mode: 'differential',
      profile,
      harness,
      oracle: target('oracle'),
      candidate: target('candidate'),
      payload: {
        schemaVersion: 1,
        mode: 'differential',
        oracle: {},
        candidate: {},
        comparisons,
      },
    });

    expect(value.payload).toMatchObject({ comparisons });
    expect(value.sanitizerSuccess).toBe(true);
  });

  it('publishes only semantic provenance and enforces mode bindings', () => {
    const value = createPhase2EvidenceEnvelope({
      mode: 'differential',
      profile,
      harness,
      oracle: target('oracle'),
      candidate: target('candidate'),
      payload: { ok: true },
    });
    const text = JSON.stringify(value);
    expect(text).not.toContain('/private');
    expect(text).not.toMatch(/container|projectName|socket|repositoryRoot|"dev"|"ino"|"uid"/u);
    expect(value.provenance.harness.runtimeBundleSha256).toBe('a'.repeat(64));
    expect(value.sanitizerSuccess).toBe(true);
  });

  it('accepts only the exact ordered sixteen candidate invariant proofs', () => {
    const candidateProfile = {
      ...profile,
      candidateInvariantScenarios: [
        ...clientCredentialsCandidateInvariantIds,
        ...deviceCandidateInvariantIds,
        ...customJwtCandidateInvariantIds,
        ...customJwtFetchPolicyCandidateInvariantIds,
      ],
    } as Phase2ProfileRegistries;
    const invariants = [
      ...clientCredentialsCandidateInvariantIds.map((id) =>
        runClientCredentialsCandidateInvariantControls(
          id,
          clientCredentialsCandidateInvariantExpectedProjection(id)
        )
      ),
      ...deviceCandidateInvariantIds.map((id) =>
        runDeviceCandidateInvariantControls(id, deviceCandidateInvariantExpectedProjection(id))
      ),
      ...customJwtCandidateInvariantIds.map((id) =>
        runCustomJwtCandidateInvariantControls(
          id,
          customJwtCandidateInvariantExpectedProjection(id)
        )
      ),
      ...customJwtFetchPolicyCandidateInvariantIds.map((id) =>
        runCustomJwtFetchPolicyControls(id, customJwtFetchPolicyExpectedProjection(id))
      ),
    ];
    const create = (entries: unknown[]) =>
      createPhase2EvidenceEnvelope({
        mode: 'candidate-invariants',
        profile: candidateProfile,
        harness,
        candidate: target('candidate'),
        payload: {
          schemaVersion: 1,
          mode: 'candidate-invariants',
          invariants: entries,
        } as JsonValue,
      });
    expect(create(invariants).payload).toMatchObject({ mode: 'candidate-invariants' });
    const getterCalls = { count: 0 };
    const dynamicPayload = Object.defineProperties(
      {},
      {
        schemaVersion: { enumerable: true, value: 1 },
        mode: { enumerable: true, value: 'candidate-invariants' },
        invariants: {
          enumerable: true,
          get: () => {
            getterCalls.count += 1;
            return getterCalls.count < 3
              ? invariants
              : [{ id: 'private-secret', value: 'planted' }];
          },
        },
      }
    );
    expect(() =>
      createPhase2EvidenceEnvelope({
        mode: 'candidate-invariants',
        profile: candidateProfile,
        harness,
        candidate: target('candidate'),
        payload: dynamicPayload as JsonValue,
      })
    ).toThrow('Invalid Phase 2 evidence envelope');
    expect(getterCalls.count).toBe(0);
    for (const invalid of [
      invariants.slice(1),
      invariants.toSpliced(0, 2, invariants[1]!, invariants[0]!),
      [...invariants, invariants[0]],
      invariants.toSpliced(5, 1, {
        ...invariants[5],
        extra: true,
      } as unknown as (typeof invariants)[number]),
    ]) {
      expect(() => create(invalid)).toThrow('Invalid Phase 2 evidence envelope');
    }
  });
  it('rejects source/image substitution and local capability leakage', () => {
    expect(() =>
      createPhase2EvidenceEnvelope({
        mode: 'oracle',
        profile,
        harness,
        oracle: target('candidate'),
        payload: { ok: true },
      })
    ).toThrow();
    expect(() =>
      createPhase2EvidenceEnvelope({
        mode: 'differential',
        profile,
        harness,
        oracle: target('oracle'),
        candidate: { ...target('oracle') },
        payload: { ok: true },
      })
    ).toThrow();
    for (const planted of [
      { path: '/private/driver' },
      { socketPath: '/private/control.sock' },
      { containerId: 'a'.repeat(64) },
      { projectName: 'private-project' },
    ]) {
      expect(() =>
        createPhase2EvidenceEnvelope({
          mode: 'oracle',
          profile,
          harness,
          oracle: { ...target('oracle'), ...planted } as any,
          payload: { ok: true },
        })
      ).toThrow();
    }
    expect(() =>
      createPhase2EvidenceEnvelope({
        mode: 'oracle',
        profile,
        harness,
        oracle: target('oracle'),
        payload: { sha256: 'a'.repeat(64) },
      })
    ).toThrow();
    for (const payload of [{ device_code: 'planted' }, { xsrf: 'planted' }]) {
      expect(() =>
        createPhase2EvidenceEnvelope({
          mode: 'oracle',
          profile,
          harness,
          oracle: target('oracle'),
          payload: payload as unknown as JsonValue,
        })
      ).toThrow('Invalid Phase 2 device authorization projection');
    }
  });
});
/* eslint-enable max-lines, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
