/* eslint-disable @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-unsafe-assignment -- The focused runtime fixture is deliberately structural and Jest asymmetric matchers are typed as any. */
import { exportJWK, generateKeyPair } from 'jose';

import { compareJson } from '../../compare.js';
import { SymbolTable } from '../../symbol-table.js';
import { createProvisionedPhase1Fixture, type Phase1FixtureProvisioner } from '../fixtures.js';
import type { Phase1ScenarioRunContext } from '../model.js';
import { runPhase1ScenarioForTarget } from '../scenario-runtime.js';

import { runDiscoveryConfig } from './discovery-config.js';
import { phase1DifferentialScenarios } from './index.js';

const target = (label: 'oracle' | 'candidate') => ({
  label,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
});

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

const selectedDiscovery = {
  issuer: discovery.issuer,
  authorization_endpoint: discovery.authorization_endpoint,
  token_endpoint: discovery.token_endpoint,
  userinfo_endpoint: discovery.userinfo_endpoint,
  jwks_uri: discovery.jwks_uri,
  claims_parameter_supported: profile.oidc.claimsParameterSupported,
  authorization_response_iss_parameter_supported:
    profile.oidc.authorizationResponseIssParameterSupported,
  request_uri_parameter_supported: profile.oidc.requestUriParameterSupported,
  grant_types_supported: profile.oidc.grants,
  response_types_supported: profile.oidc.responseTypes,
  response_modes_supported: profile.oidc.responseModes,
  code_challenge_methods_supported: profile.oidc.pkceCodeChallengeMethods,
  token_endpoint_auth_methods_supported: profile.oidc.tokenEndpointAuthMethods,
  scopes_supported: profile.oidc.scopesSupported,
  claims_supported: profile.oidc.claimsSupported,
  subject_types_supported: profile.oidc.subjectTypesSupported,
  id_token_signing_alg_values_supported: profile.oidc.idTokenSigningAlgorithmsSupported,
  claim_types_supported: profile.oidc.claimTypesSupported,
};
const candidateDiscovery = {
  ...selectedDiscovery,
  id_token_signing_alg_values_supported: ['RS256', 'ES384'],
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
const jwksRawHeaders = (body: unknown, tag: string) =>
  [
    ['content-length', String(Buffer.byteLength(JSON.stringify(body)))],
    ['etag', `"${tag}"`],
  ] as const;

const response = (
  body: unknown,
  mediaType = 'application/json',
  headers: ReadonlyArray<readonly [string, string]> = []
) => ({
  status: 200,
  headers: [['content-type', mediaType] as const, ...headers],
  body: JSON.stringify(body),
});

const context = (
  documents: readonly unknown[],
  implementation: 'oracle' | 'candidate' = 'oracle',
  jwksHeaders: ReadonlyArray<readonly [string, string]> = []
): Phase1ScenarioRunContext => {
  const request = import.meta.jest.fn();

  for (const [index, document] of documents.entries()) {
    request.mockResolvedValueOnce(
      response(
        document,
        index === 2 ? 'application/jwk-set+json' : 'application/json',
        index === 2 ? jwksHeaders : []
      )
    );
  }

  return {
    profile: {
      ...profile,
      fixtures: {
        dataTenant: {
          browserClientConfiguration: {
            localStorageKey:
              implementation === 'oracle'
                ? 'logto:demo-app:dev:config'
                : 'aster:demo-app:dev:config',
          },
        },
      },
    } as never,
    target: target(implementation),
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
  it('projects the approved discovery algorithm addition forward from oracle to candidate', async () => {
    const { publicKey } = await generateKeyPair('RS256');
    const published = {
      keys: [
        { ...(await exportJWK(publicKey)), alg: 'RS256', use: 'sig', kid: 'rsa-key' },
        ...jwks.keys,
      ],
    };
    const baseline = await runDiscoveryConfig(context([discovery, discovery, jwks]));
    const candidate = await runDiscoveryConfig(
      context([candidateDiscovery, candidateDiscovery, published], 'candidate')
    );

    expect(compareJson(baseline[0]?.value, candidate[0]?.value)).toEqual([]);
    expect(baseline[0]?.value.body).toMatchObject({
      id_token_signing_alg_values_supported: ['RS256', 'ES384'],
    });
    expect(candidate[0]?.value.body).toMatchObject({
      id_token_signing_alg_values_supported: ['RS256', 'ES384'],
    });
    await expect(
      runDiscoveryConfig(context([candidateDiscovery, candidateDiscovery, jwks]))
    ).rejects.toThrow('Phase 1 discovery field is invalid: id_token_signing_alg_values_supported');
    await Promise.all(
      [
        selectedDiscovery,
        { ...candidateDiscovery, id_token_signing_alg_values_supported: ['ES384', 'RS256'] },
        {
          ...candidateDiscovery,
          id_token_signing_alg_values_supported: ['RS256', 'ES384', 'HS256'],
        },
        { ...candidateDiscovery, aster_extra_field: true },
      ].map(async (invalid) => {
        await expect(
          runDiscoveryConfig(context([invalid, invalid, published], 'candidate'))
        ).rejects.toThrow();
      })
    );
  });

  it('validates candidate RSA and EC publication before comparing the common JWKS projection', async () => {
    const { publicKey } = await generateKeyPair('RS256');
    const { publicKey: largerPublicKey } = await generateKeyPair('RS256', { modulusLength: 3072 });
    const rsa = { ...(await exportJWK(publicKey)), alg: 'RS256', use: 'sig', kid: 'rsa-key' };
    const largeRsa = { ...rsa, ...(await exportJWK(largerPublicKey)) };
    const candidateJwks = { keys: [rsa, ...jwks.keys] };
    const oracle = await runDiscoveryConfig(context([discovery, discovery, jwks]));
    const candidate = await runDiscoveryConfig(
      context([candidateDiscovery, candidateDiscovery, candidateJwks], 'candidate')
    );

    expect(compareJson(oracle[2]?.value, candidate[2]?.value)).toEqual([]);
    expect(candidate[2]?.value.body).toEqual(oracle[2]?.value.body);

    const invalid = [
      ['wrong algorithm', { keys: [{ ...rsa, alg: 'PS256' }, ...jwks.keys] }],
      ['wrong use', { keys: [{ ...rsa, use: 'enc' }, ...jwks.keys] }],
      [
        'malformed additional RSA',
        { keys: [rsa, { ...rsa, kid: 'extra-rsa', use: 'enc' }, ...jwks.keys] },
      ],
      ['private member', { keys: [{ ...rsa, d: 'private-material' }, ...jwks.keys] }],
      ['unknown public member', { keys: [{ ...rsa, key_ops: ['verify'] }, ...jwks.keys] }],
      ['wrong exponent', { keys: [{ ...rsa, e: 'Aw' }, ...jwks.keys] }],
      ['padded exponent', { keys: [{ ...rsa, e: 'AQAB=' }, ...jwks.keys] }],
      ['short modulus', { keys: [{ ...rsa, n: rsa.n?.slice(2) }, ...jwks.keys] }],
      ['long modulus', { keys: [largeRsa, ...jwks.keys] }],
      [
        'modulus without high bit',
        { keys: [{ ...rsa, n: Buffer.alloc(256, 0x7f).toString('base64url') }, ...jwks.keys] },
      ],
      ['noncanonical modulus', { keys: [{ ...rsa, n: `${rsa.n}=` }, ...jwks.keys] }],
      ['duplicate kid', { keys: [{ ...rsa, kid: jwks.keys[0]?.kid }, ...jwks.keys] }],
      ['duplicate RSA kid', { keys: [rsa, rsa, ...jwks.keys] }],
      ['missing RSA', jwks],
      ['missing EC', { keys: [rsa] }],
      ['wrong EC algorithm', { keys: [rsa, { ...jwks.keys[0], alg: 'ES256' }] }],
      [
        'unapproved key family',
        { keys: [rsa, ...jwks.keys, { kid: 'other', kty: 'oct', k: 'secret' }] },
      ],
      ['extra JWKS field', { ...candidateJwks, metadata: true }],
    ] as const;

    await Promise.all(
      invalid.map(async ([, document]) => {
        await expect(
          runDiscoveryConfig(
            context([candidateDiscovery, candidateDiscovery, document], 'candidate')
          )
        ).rejects.toThrow('Phase 1 JWKS metadata is invalid');
      })
    );
    await expect(
      runDiscoveryConfig(context([discovery, discovery, candidateJwks]))
    ).rejects.toThrow('Phase 1 JWKS metadata is invalid');
  });

  it('rejects an even-modulus extra RSA key before comparing the common EC keys', async () => {
    const { publicKey } = await generateKeyPair('RS256');
    const rsa = { ...(await exportJWK(publicKey)), alg: 'RS256', use: 'sig', kid: 'rsa-key' };
    const evenModulus = Buffer.alloc(256, 0x80).toString('base64url');
    const malformedJwks = {
      keys: [rsa, { ...rsa, kid: 'extra-rsa', n: evenModulus }, ...jwks.keys],
    };

    await expect(
      runDiscoveryConfig(
        context([candidateDiscovery, candidateDiscovery, malformedJwks], 'candidate')
      )
    ).rejects.toThrow('Phase 1 JWKS metadata is invalid');
  });

  it('derives Content-Length and ETag from the validated common JWKS body', async () => {
    const { publicKey } = await generateKeyPair('RS256');
    const published = {
      keys: [
        { ...(await exportJWK(publicKey)), alg: 'RS256', use: 'sig', kid: 'rsa-key' },
        ...jwks.keys,
      ],
    };
    const oracleHeaders = jwksRawHeaders(jwks, 'oracle-raw-jwks');
    const candidateHeaders = jwksRawHeaders(published, 'candidate-raw-jwks');
    const oracle = await runDiscoveryConfig(
      context([discovery, discovery, jwks], 'oracle', oracleHeaders)
    );
    const candidate = await runDiscoveryConfig(
      context([candidateDiscovery, candidateDiscovery, published], 'candidate', candidateHeaders)
    );

    expect(candidateHeaders[0][1]).not.toBe(oracleHeaders[0][1]);
    expect(candidate[2]?.value.headers['content-length']).toEqual(
      oracle[2]?.value.headers['content-length']
    );
    expect(candidate[2]?.value.headers.etag).toEqual(oracle[2]?.value.headers.etag);
    expect(compareJson(oracle[2]?.value, candidate[2]?.value)).toEqual([]);
    await expect(
      runDiscoveryConfig(
        context(
          [candidateDiscovery, candidateDiscovery, { ...published, unknown: true }],
          'candidate',
          candidateHeaders
        )
      )
    ).rejects.toThrow('Phase 1 JWKS metadata is invalid');
  });

  it('projects approved oracle fields and rejects candidate extra metadata', async () => {
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
      body: {
        grant_types_supported: ['authorization_code', 'refresh_token'],
      },
      sideEffects: { fixtureMutation: false },
    });
    expect(baseline[0]?.value.body).not.toHaveProperty('backchannel_logout_supported');
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
    expect(compareJson(baseline[0]?.value, changed[0]?.value)).toEqual([]);

    await expect(
      runDiscoveryConfig(
        context(
          [{ ...selectedDiscovery, aster_extra_field: true }, selectedDiscovery, jwks],
          'candidate'
        )
      )
    ).rejects.toThrow('Phase 1 candidate discovery contains unapproved metadata');
    await expect(
      runDiscoveryConfig(context([selectedDiscovery, selectedDiscovery, jwks], 'candidate'))
    ).rejects.toThrow('Phase 1 candidate discovery contains unapproved metadata');

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
        target: target('oracle'),
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
