/* eslint-disable @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment -- The focused runtime fixture is deliberately structural and Jest asymmetric matchers are typed as any. */
import { compareJson } from '../../compare.js';
import { SymbolTable } from '../../symbol-table.js';
import { createProvisionedPhase1Fixture, type Phase1FixtureProvisioner } from '../fixtures.js';
import type { Phase1ScenarioRunContext } from '../model.js';
import { runPhase1ScenarioForTarget } from '../scenario-runtime.js';

import { runDiscoveryConfig } from './discovery-config.js';
import { phase1DifferentialScenarios } from './index.js';

const target = {
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
};

const profile = {
  fixtures: {
    dataTenant: {
      browserClientConfiguration: {
        localStorageKey: 'logto:demo-app:dev:config',
      },
    },
  },
  oidc: {
    issuerPath: '/oidc',
    discoveryPath: '/oidc/.well-known/openid-configuration',
    oauthAuthorizationServerDiscoveryPath: '/oidc/.well-known/oauth-authorization-server',
    authorizationPath: '/oidc/auth',
    tokenPath: '/oidc/token',
    userinfoPath: '/oidc/me',
    jwksPath: '/oidc/jwks',
    grants: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    responseModes: ['query'],
    pkceCodeChallengeMethods: ['S256'],
    tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
    scopesSupported: ['openid', 'offline_access', 'profile', 'email'],
    claimsParameterSupported: false,
    claimsSupported: ['sub', 'name', 'email'],
    subjectTypesSupported: ['public'],
    idTokenSigningAlgorithmsSupported: ['ES384'],
    authorizationResponseIssParameterSupported: true,
    requestUriParameterSupported: false,
    claimTypesSupported: ['normal'],
    jwksKeyMetadata: { kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
  },
};

const discovery = {
  issuer: 'https://oracle.example/oidc',
  authorization_endpoint: 'https://oracle.example/oidc/auth',
  token_endpoint: 'https://oracle.example/oidc/token',
  userinfo_endpoint: 'https://oracle.example/oidc/me',
  jwks_uri: 'https://oracle.example/oidc/jwks',
  grant_types_supported: ['implicit', 'authorization_code', 'refresh_token'],
  response_types_supported: ['code id_token', 'code'],
  response_modes_supported: ['form_post', 'query'],
  code_challenge_methods_supported: ['S256'],
  token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
  scopes_supported: ['openid', 'offline_access', 'profile', 'email'],
  claims_parameter_supported: false,
  claims_supported: ['sub', 'name', 'email'],
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: ['ES384'],
  authorization_response_iss_parameter_supported: true,
  request_uri_parameter_supported: false,
  claim_types_supported: ['normal'],
  backchannel_logout_supported: true,
};

const jwks = {
  keys: [
    {
      kty: 'EC',
      use: 'sig',
      alg: 'ES384',
      crv: 'P-384',
      kid: 'runtime-signing-key',
      x: 'public-x-coordinate',
      y: 'public-y-coordinate',
    },
  ],
};

const response = (body: unknown, mediaType = 'application/json') => ({
  status: 200,
  headers: [['content-type', mediaType] as const],
  body: JSON.stringify(body),
});

const context = (documents: readonly unknown[]): Phase1ScenarioRunContext => {
  const request = import.meta.jest.fn();

  for (const [index, document] of documents.entries()) {
    request.mockResolvedValueOnce(
      response(document, index === 2 ? 'application/jwk-set+json' : 'application/json')
    );
  }

  return {
    profile: profile as never,
    target,
    fixture: { public: { schemaVersion: 1, recipe: 'none', allocations: [] } } as never,
    signal: new AbortController().signal,
    protocol: {
      publicOidc: { request } as never,
      publicSymbols: new SymbolTable(),
      forAllocation: () => {
        throw new Error('unexpected allocated client');
      },
      symbolsFor: () => undefined as never,
    },
    projectFixtureState: async () => ({ schemaVersion: 1, recipe: 'none', allocations: [] }),
    projectScenarioState: async () => {
      throw new Error('unexpected scenario state read');
    },
  };
};

describe('discovery.config', () => {
  it('compares the complete selected discovery document and rejects extra metadata', async () => {
    const baseline = await runDiscoveryConfig(context([discovery, discovery, jwks]));
    const extra = { ...discovery, aster_extra_field: true };
    const changed = await runDiscoveryConfig(context([extra, extra, jwks]));

    expect(baseline.map(({ stepId }) => stepId)).toEqual([
      'oidc-discovery',
      'oauth-discovery',
      'jwks',
    ]);
    expect(baseline[0]?.value).toMatchObject({
      status: 200,
      body: { backchannel_logout_supported: true },
      sideEffects: { fixtureMutation: false },
    });
    expect(baseline[2]?.value).toMatchObject({
      body: {
        keys: [
          {
            alg: 'ES384',
            crv: 'P-384',
            kid: '<signing-key.kid.1>',
            kty: 'EC',
            publicKeyFingerprint: expect.any(String),
            use: 'sig',
          },
        ],
      },
    });
    expect(compareJson(baseline[0]?.value, changed[0]?.value)).toEqual([
      { path: '/body/aster_extra_field', candidate: true },
    ]);

    await expect(runDiscoveryConfig(context([discovery, extra, jwks]))).rejects.toThrow(
      'Phase 1 discovery endpoints are not equivalent'
    );
    await expect(
      runDiscoveryConfig(context([discovery, discovery, { ...jwks, private_metadata: true }]))
    ).rejects.toThrow('Phase 1 JWKS metadata is invalid');
  });

  it('runs the canonical registry entry through fixture cleanup and the Phase 1 runtime', async () => {
    const fixture = createProvisionedPhase1Fixture({
      public: { schemaVersion: 1, recipe: 'none', allocations: [] },
      passwords: [],
      clientSecrets: [],
    });
    const fixtureState = Object.freeze({
      schemaVersion: 1 as const,
      recipe: 'none' as const,
      allocations: Object.freeze([]),
    });
    const cleanup = import.meta.jest.fn(async () => {
      await Promise.resolve();
    });
    const provisioner: Phase1FixtureProvisioner = {
      provision: async (recipe) => {
        expect(recipe).toBe('none');
        return fixture;
      },
      projectState: async (activeFixture) => {
        expect(activeFixture).toBe(fixture);
        return fixtureState;
      },
      cleanup,
    };
    const direct = context([discovery, discovery, jwks]);
    const scenario = phase1DifferentialScenarios[0];

    if (!scenario || scenario.id !== 'discovery.config') {
      throw new Error('canonical discovery scenario is unavailable');
    }
    await expect(
      runPhase1ScenarioForTarget(scenario, {
        profile: profile as never,
        target,
        provisioner,
        createProtocolSession: () => direct.protocol,
        projectScenarioState: async () => {
          throw new Error('discovery must not request scenario state');
        },
      })
    ).resolves.toMatchObject({
      target: 'oracle',
      steps: [{ stepId: 'oidc-discovery' }, { stepId: 'oauth-discovery' }, { stepId: 'jwks' }],
    });
    expect(cleanup).toHaveBeenCalledWith(fixture);
  });
});

/* eslint-enable @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment */
