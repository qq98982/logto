/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Negative controls deliberately forge forbidden public provenance fields. */
import type { JsonValue } from '../normalize.js';

import {
  createPhase2EvidenceEnvelope,
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

describe('Phase 2 public provenance envelope', () => {
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
    expect(validatePhase2OracleArtifact(artifact, artifactProfile, harness)).toBe(artifact);
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
/* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
