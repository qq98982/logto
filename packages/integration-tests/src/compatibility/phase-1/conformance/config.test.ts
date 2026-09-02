/* eslint-disable @silverhand/fp/no-mutation -- Each negative case mutates one synthetic profile field. */
import type { Phase1Profile } from '../profile-types.js';

import {
  createPhase1ConformanceConfig,
  phase1ConformanceSuiteCommit,
  phase1ConformanceSuiteRepository,
} from './config.js';

const callbackUri =
  'https://conformance.aster-phase1-conformance.svc.cluster.local:8443/test/a/aster-phase1/callback';

const profile = (): Phase1Profile =>
  ({
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
        issuer: 'https://aster-server.aster-phase1-conformance.svc.cluster.local:3443/oidc',
        discoveryUrl:
          'https://aster-server.aster-phase1-conformance.svc.cluster.local:3443/oidc/.well-known/openid-configuration',
        suiteBaseUrl: 'https://conformance.aster-phase1-conformance.svc.cluster.local:8443',
        alias: 'aster-phase1',
        callbackUri,
        tls: {
          trustDomain: 'private test trust domain',
          issuer: 'private issuer',
          asterMaterial: 'private Aster material path',
          suiteMaterial: 'private suite material path',
          lifecycle: 'private lifecycle',
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
          displayName: 'OpenID Connect Core: Basic Certification Profile Authorization server test',
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
          displayName:
            'OpenID Connect Core: Config Certification Profile Authorization server test',
          variants: { clientRegistration: 'static_client', serverMetadata: 'discovery' },
        },
      ],
    },
  }) as unknown as Phase1Profile;

describe('Phase 1 conformance public config', () => {
  it('derives only the exact public suite plans clients and target metadata', () => {
    const config = createPhase1ConformanceConfig(profile());

    expect(config).toEqual({
      schemaVersion: 1,
      suite: { repository: phase1ConformanceSuiteRepository, commit: phase1ConformanceSuiteCommit },
      target: {
        issuer: 'https://aster-server.aster-phase1-conformance.svc.cluster.local:3443/oidc',
        discoveryUrl:
          'https://aster-server.aster-phase1-conformance.svc.cluster.local:3443/oidc/.well-known/openid-configuration',
        suiteBaseUrl: 'https://conformance.aster-phase1-conformance.svc.cluster.local:8443',
        alias: 'aster-phase1',
        callbackUri,
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
          id: 'oidcc-basic-certification-test-plan',
          displayName: 'OpenID Connect Core: Basic Certification Profile Authorization server test',
          variant: {
            serverMetadata: 'discovery',
            clientRegistration: 'static_client',
            responseType: 'code',
            responseMode: 'default',
            clientAuthTypes: ['client_secret_basic', 'client_secret_post'],
          },
        },
        {
          id: 'oidcc-config-certification-test-plan',
          displayName:
            'OpenID Connect Core: Config Certification Profile Authorization server test',
          variant: { clientRegistration: 'static_client', serverMetadata: 'discovery' },
        },
      ],
    });
    expect(config.target).not.toHaveProperty('namespace');
    expect(config.target).not.toHaveProperty('tls');
    expect(JSON.stringify(config)).not.toMatch(
      /private Aster material path|private suite material path/iu
    );
    expect(Object.isFrozen(config)).toBe(true);
    expect(config.plans.every((plan) => Object.isFrozen(plan))).toBe(true);
  });

  it.each([
    [
      'suite repository',
      (value: Phase1Profile): void => {
        (value.conformance as { suiteRepository: string }).suiteRepository =
          'https://example.test/suite.git';
      },
    ],
    [
      'suite commit',
      (value: Phase1Profile): void => {
        (value.conformance as { suiteCommit: string }).suiteCommit = '1'.repeat(40);
      },
    ],
    [
      'client order',
      (value: Phase1Profile): void => {
        const clients = [...value.conformance.staticClients];
        (value.conformance as unknown as { staticClients: typeof clients }).staticClients = [
          clients[2]!,
          clients[1]!,
          clients[0]!,
        ];
      },
    ],
    [
      'plan order',
      (value: Phase1Profile): void => {
        const plans = [...value.conformance.plans];
        (value.conformance as unknown as { plans: typeof plans }).plans = [plans[1]!, plans[0]!];
      },
    ],
    [
      'derived URL',
      (value: Phase1Profile): void => {
        (value.conformance.target as { discoveryUrl: string }).discoveryUrl =
          'https://wrong.example';
      },
    ],
  ] as const)('rejects a mutated %s with one fixed diagnostic', (_name, mutate) => {
    const value = profile();
    mutate(value);

    expect(() => createPhase1ConformanceConfig(value)).toThrow(
      /^Invalid phase 1 conformance config$/u
    );
  });
});

/* eslint-enable @silverhand/fp/no-mutation */
