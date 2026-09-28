/* eslint-disable max-lines, no-await-in-loop, unicorn/consistent-function-scoping -- Each hostile response is exercised sequentially and the structural session fixture intentionally owns local throwing members. */
import type { TargetConfig } from '../../model.js';
import type { RawProtocolResponse } from '../../phase-1/clients/oidc.js';
import type { Phase1ProtocolSession } from '../../phase-1/scenario-runtime.js';
import { SymbolTable } from '../../symbol-table.js';

import { createPhase2BaseDiscoverySession, type Phase2BaseDiscoverySession } from './discovery.js';

const candidateTarget: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});

const baseDocument = Object.freeze({
  issuer: 'https://candidate.example/oidc',
  authorization_endpoint: 'https://candidate.example/oidc/auth',
  token_endpoint: 'https://candidate.example/oidc/token',
  userinfo_endpoint: 'https://candidate.example/oidc/me',
  jwks_uri: 'https://candidate.example/oidc/jwks',
  claims_parameter_supported: false,
  authorization_response_iss_parameter_supported: true,
  request_uri_parameter_supported: false,
  grant_types_supported: Object.freeze(['authorization_code', 'refresh_token']),
  response_types_supported: Object.freeze(['code']),
  response_modes_supported: Object.freeze(['query']),
  code_challenge_methods_supported: Object.freeze(['S256']),
  token_endpoint_auth_methods_supported: Object.freeze([
    'client_secret_basic',
    'client_secret_post',
    'none',
  ]),
  scopes_supported: Object.freeze(['openid', 'offline_access', 'profile', 'email']),
  claims_supported: Object.freeze(['sub', 'name', 'email']),
  subject_types_supported: Object.freeze(['public']),
  id_token_signing_alg_values_supported: Object.freeze(['RS256', 'ES384']),
  claim_types_supported: Object.freeze(['normal']),
});

const rawDocument = (overrides: Readonly<Record<string, unknown>> = {}) => ({
  ...baseDocument,
  grant_types_supported: [
    'authorization_code',
    'refresh_token',
    'client_credentials',
    'urn:ietf:params:oauth:grant-type:device_code',
  ],
  scopes_supported: ['openid', 'offline_access', 'profile', 'email', 'urn:aster:scope:sessions'],
  introspection_endpoint: 'https://candidate.example/oidc/token/introspection',
  revocation_endpoint: 'https://candidate.example/oidc/token/revocation',
  end_session_endpoint: 'https://candidate.example/oidc/session/end',
  device_authorization_endpoint: 'https://candidate.example/oidc/device/auth',
  ...overrides,
});

const response = (
  body: unknown,
  overrides: Partial<RawProtocolResponse> = {}
): RawProtocolResponse => {
  const text = typeof body === 'string' ? body : JSON.stringify(body);

  return Object.freeze({
    status: 200,
    headers: Object.freeze([
      Object.freeze(['content-type', 'application/json'] as const),
      Object.freeze(['content-length', String(Buffer.byteLength(text))] as const),
      Object.freeze(['cache-control', 'no-cache, max-age=0, must-revalidate'] as const),
    ]),
    body: text,
    ...overrides,
  });
};

const createSession = (
  documents: Readonly<Record<string, RawProtocolResponse>>
): Phase1ProtocolSession => {
  const request = async (operation: string, requestPath: string) => {
    const value = documents[`${operation}:${requestPath}`];

    if (!value) {
      throw new Error('unexpected request');
    }

    return value;
  };
  const forAllocation = () => {
    throw new Error('unexpected allocation');
  };
  const symbolsFor = (): SymbolTable | undefined => undefined;

  return Object.freeze({
    publicOidc: Object.freeze({ request, allocationRole: undefined }),
    publicSymbols: new SymbolTable(),
    forAllocation,
    symbolsFor,
  });
};

const createWrapped = (
  documents: Readonly<Record<string, RawProtocolResponse>>,
  overrides: Partial<Parameters<typeof createPhase2BaseDiscoverySession>[0]> = {}
): Phase2BaseDiscoverySession =>
  createPhase2BaseDiscoverySession({
    target: candidateTarget,
    scenarioId: 'discovery.config',
    session: createSession(documents),
    acceptedGrantTypes: Object.freeze(['authorization_code', 'refresh_token']),
    appendGrantTypes: Object.freeze([
      'client_credentials',
      'urn:ietf:params:oauth:grant-type:device_code',
    ] as const),
    endpointFieldsAppend: Object.freeze([
      'introspection_endpoint',
      'revocation_endpoint',
      'end_session_endpoint',
      'device_authorization_endpoint',
    ] as const),
    scopesSupportedAppend: Object.freeze(['urn:aster:scope:sessions'] as const),
    stillAbsent: Object.freeze(['registration_endpoint']),
    paths: Object.freeze({
      openid: 'oidc/.well-known/openid-configuration',
      oauth: 'oidc/.well-known/oauth-authorization-server',
      jwks: 'oidc/jwks',
    }),
    ...overrides,
  });

describe('Phase 2 base-preservation discovery adapter', () => {
  it('removes only the unique terminal grant and records both raw append proofs', async () => {
    const raw = rawDocument();
    const openid = response(raw);
    const oauth = response(raw);
    const jwks = response(
      { keys: [] },
      { headers: [['content-type', 'application/jwk-set+json']] }
    );
    const wrapped = createWrapped({
      'discovery-openid:oidc/.well-known/openid-configuration': openid,
      'discovery-oauth-authorization-server:oidc/.well-known/oauth-authorization-server': oauth,
      'discovery-jwks:oidc/jwks': jwks,
    });

    const projectedOpenid = await wrapped.session.publicOidc.request(
      'discovery-openid',
      'oidc/.well-known/openid-configuration',
      { includeCookies: false }
    );
    const projectedOauth = await wrapped.session.publicOidc.request(
      'discovery-oauth-authorization-server',
      'oidc/.well-known/oauth-authorization-server',
      { includeCookies: false }
    );
    const passthroughJwks = await wrapped.session.publicOidc.request(
      'discovery-jwks',
      'oidc/jwks',
      { includeCookies: false }
    );

    for (const projected of [projectedOpenid, projectedOauth]) {
      expect(JSON.parse(projected.body)).toEqual(baseDocument);
      expect(projected.status).toBe(200);
      expect(projected.headers.filter(([name]) => name !== 'content-length')).toEqual(
        openid.headers.filter(([name]) => name !== 'content-length')
      );
      expect(projected.headers.find(([name]) => name === 'content-length')?.[1]).toBe(
        String(Buffer.byteLength(projected.body))
      );
    }
    expect(passthroughJwks).toBe(jwks);
    expect(wrapped.proofs()).toEqual([
      expect.objectContaining({
        operation: 'discovery-openid',
        rawGrantTypes: [
          'authorization_code',
          'refresh_token',
          'client_credentials',
          'urn:ietf:params:oauth:grant-type:device_code',
        ],
        baseGrantTypes: ['authorization_code', 'refresh_token'],
        endpointFieldsAppend: [
          'introspection_endpoint',
          'revocation_endpoint',
          'end_session_endpoint',
          'device_authorization_endpoint',
        ],
      }),
      expect.objectContaining({
        operation: 'discovery-oauth-authorization-server',
        rawGrantTypes: [
          'authorization_code',
          'refresh_token',
          'client_credentials',
          'urn:ietf:params:oauth:grant-type:device_code',
        ],
        baseGrantTypes: ['authorization_code', 'refresh_token'],
      }),
    ]);
  });

  it.each([
    ['missing append', ['authorization_code', 'refresh_token']],
    [
      'wrong order',
      [
        'authorization_code',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:device_code',
        'client_credentials',
      ],
    ],
    [
      'duplicate append',
      [
        'authorization_code',
        'refresh_token',
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
        'client_credentials',
      ],
    ],
    [
      'replaced base grant',
      [
        'authorization_code',
        'implicit',
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
    ],
    [
      'extra grant',
      [
        'authorization_code',
        'refresh_token',
        'client_credentials',
        'urn:ietf:params:oauth:grant-type:device_code',
        'urn:ietf:params:oauth:grant-type:token-exchange',
      ],
    ],
  ])('rejects %s before deriving a base response', async (_name, grants) => {
    const raw = rawDocument({ grant_types_supported: grants });
    const wrapped = createWrapped({
      'discovery-openid:oidc/.well-known/openid-configuration': response(raw),
    });

    await expect(
      wrapped.session.publicOidc.request(
        'discovery-openid',
        'oidc/.well-known/openid-configuration'
      )
    ).rejects.toThrow('Invalid Phase 2 base-preservation discovery');
  });

  it.each(['registration_endpoint'])('rejects the still-absent %s field', async (field) => {
    const wrapped = createWrapped({
      'discovery-openid:oidc/.well-known/openid-configuration': response(
        rawDocument({ [field]: `https://candidate.example/${field}` })
      ),
    });

    await expect(
      wrapped.session.publicOidc.request(
        'discovery-openid',
        'oidc/.well-known/openid-configuration'
      )
    ).rejects.toThrow('Invalid Phase 2 base-preservation discovery');
  });

  it.each([
    ['missing introspection', { introspection_endpoint: undefined }],
    ['missing revocation', { revocation_endpoint: undefined }],
    [
      'swapped endpoints',
      {
        introspection_endpoint: 'https://candidate.example/oidc/token/revocation',
        revocation_endpoint: 'https://candidate.example/oidc/token/introspection',
      },
    ],
    [
      'wrong issuer',
      { introspection_endpoint: 'https://foreign.example/oidc/token/introspection' },
    ],
    ['malformed endpoint', { revocation_endpoint: null }],
    ['missing device authorization', { device_authorization_endpoint: undefined }],
    [
      'wrong device authorization',
      { device_authorization_endpoint: 'https://candidate.example/oidc/device' },
    ],
    [
      'foreign device authorization',
      { device_authorization_endpoint: 'https://foreign.example/oidc/device/auth' },
    ],
    [
      'swapped device authorization',
      {
        device_authorization_endpoint: 'https://candidate.example/oidc/session/end',
        end_session_endpoint: 'https://candidate.example/oidc/device/auth',
      },
    ],
  ])('rejects %s before stripping the approved endpoints', async (_name, overrides) => {
    const wrapped = createWrapped({
      'discovery-openid:oidc/.well-known/openid-configuration': response(rawDocument(overrides)),
    });
    await expect(
      wrapped.session.publicOidc.request(
        'discovery-openid',
        'oidc/.well-known/openid-configuration'
      )
    ).rejects.toThrow('Invalid Phase 2 base-preservation discovery');
  });

  it('rejects a duplicate raw device endpoint before recording an append proof', async () => {
    const raw = JSON.stringify(rawDocument()).replace(
      '"device_authorization_endpoint":"https://candidate.example/oidc/device/auth"',
      '"device_authorization_endpoint":"https://candidate.example/oidc/device/auth","device_authorization_endpoint":"https://candidate.example/oidc/device/auth"'
    );
    expect(raw.match(/"device_authorization_endpoint":/gu)).toHaveLength(2);
    const wrapped = createWrapped({
      'discovery-openid:oidc/.well-known/openid-configuration': response(raw),
    });
    await expect(
      wrapped.session.publicOidc.request(
        'discovery-openid',
        'oidc/.well-known/openid-configuration'
      )
    ).rejects.toThrow('Invalid Phase 2 base-preservation discovery');
    expect(() => wrapped.proofs()).toThrow('Invalid Phase 2 base-preservation discovery');
  });

  it('preserves the Unit 3 single-grant and three-endpoint append contract', async () => {
    const unit3Raw = {
      ...baseDocument,
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      scopes_supported: [
        'openid',
        'offline_access',
        'profile',
        'email',
        'urn:aster:scope:sessions',
      ],
      introspection_endpoint: 'https://candidate.example/oidc/token/introspection',
      revocation_endpoint: 'https://candidate.example/oidc/token/revocation',
      end_session_endpoint: 'https://candidate.example/oidc/session/end',
    };
    const wrapped = createWrapped(
      {
        'discovery-openid:oidc/.well-known/openid-configuration': response(unit3Raw),
        'discovery-oauth-authorization-server:oidc/.well-known/oauth-authorization-server':
          response(unit3Raw),
      },
      {
        appendGrantTypes: Object.freeze(['client_credentials'] as const),
        endpointFieldsAppend: Object.freeze([
          'introspection_endpoint',
          'revocation_endpoint',
          'end_session_endpoint',
        ] as const),
        stillAbsent: Object.freeze([
          'device_authorization_endpoint',
          'registration_endpoint',
        ] as const),
      }
    );

    const projected = await wrapped.session.publicOidc.request(
      'discovery-openid',
      'oidc/.well-known/openid-configuration'
    );
    await wrapped.session.publicOidc.request(
      'discovery-oauth-authorization-server',
      'oidc/.well-known/oauth-authorization-server'
    );

    expect(JSON.parse(projected.body)).toEqual(baseDocument);
    expect(wrapped.proofs()[0]).toMatchObject({
      rawGrantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
      endpointFieldsAppend: [
        'introspection_endpoint',
        'revocation_endpoint',
        'end_session_endpoint',
      ],
    });
  });

  it('rejects unsupported and cross-mixed append contracts before requesting discovery', () => {
    expect(() =>
      createWrapped({}, { appendGrantTypes: Object.freeze(['unexpected_grant']) as never })
    ).toThrow('Invalid Phase 2 base-preservation discovery');
    expect(() =>
      createWrapped(
        {},
        { endpointFieldsAppend: Object.freeze(['introspection_endpoint']) as never }
      )
    ).toThrow('Invalid Phase 2 base-preservation discovery');
    expect(() =>
      createWrapped(
        {},
        {
          appendGrantTypes: Object.freeze(['client_credentials'] as const),
          endpointFieldsAppend: Object.freeze([
            'introspection_endpoint',
            'revocation_endpoint',
            'end_session_endpoint',
            'device_authorization_endpoint',
          ] as const),
          stillAbsent: Object.freeze(['registration_endpoint'] as const),
        }
      )
    ).toThrow('Invalid Phase 2 base-preservation discovery');
  });

  it('rejects malformed, unsuccessful, mismatched, and header-drifted responses', async () => {
    const invalidResponses = [
      response('{'),
      response(rawDocument(), { status: 503 }),
      response(rawDocument(), { headers: [['content-type', 'text/html']] }),
      response(rawDocument(), {
        headers: [
          ['content-type', 'application/json'],
          ['content-length', '1'],
        ],
      }),
    ];

    for (const invalid of invalidResponses) {
      const wrapped = createWrapped({
        'discovery-openid:oidc/.well-known/openid-configuration': invalid,
      });

      await expect(
        wrapped.session.publicOidc.request(
          'discovery-openid',
          'oidc/.well-known/openid-configuration'
        )
      ).rejects.toThrow('Invalid Phase 2 base-preservation discovery');
    }

    const wrapped = createWrapped({
      'discovery-openid:oidc/.well-known/openid-configuration': response(rawDocument()),
      'discovery-oauth-authorization-server:oidc/.well-known/oauth-authorization-server': response(
        rawDocument({ issuer: 'https://changed.example/oidc' })
      ),
    });
    await wrapped.session.publicOidc.request(
      'discovery-openid',
      'oidc/.well-known/openid-configuration'
    );
    await expect(
      wrapped.session.publicOidc.request(
        'discovery-oauth-authorization-server',
        'oidc/.well-known/oauth-authorization-server'
      )
    ).rejects.toThrow('Invalid Phase 2 base-preservation discovery');
  });

  it('rejects oracle, non-discovery scenarios, wrong operations and paths without replacing session members', async () => {
    const source = createSession({});

    expect(() => createWrapped({}, { target: { ...candidateTarget, label: 'oracle' } })).toThrow(
      'Invalid Phase 2 base-preservation discovery'
    );
    expect(() => createWrapped({}, { scenarioId: 'token.authorization-code' })).toThrow(
      'Invalid Phase 2 base-preservation discovery'
    );

    const wrapped = createWrapped({}, { session: source });
    expect(wrapped.session.publicSymbols).toBe(source.publicSymbols);
    expect(wrapped.session.forAllocation).toBe(source.forAllocation);
    expect(wrapped.session.symbolsFor).toBe(source.symbolsFor);
    await expect(wrapped.session.publicOidc.request('token', 'oidc/token')).rejects.toThrow(
      'Invalid Phase 2 base-preservation discovery'
    );
    await expect(
      wrapped.session.publicOidc.request('discovery-openid', 'oidc/.well-known/wrong')
    ).rejects.toThrow('Invalid Phase 2 base-preservation discovery');
  });
});

/* eslint-enable max-lines, no-await-in-loop, unicorn/consistent-function-scoping */
