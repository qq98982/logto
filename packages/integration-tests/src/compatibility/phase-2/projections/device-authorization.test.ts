/* eslint-disable max-lines, @typescript-eslint/no-confusing-void-expression, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Negative controls deliberately construct cycles and accessors. */
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

import {
  assertDeviceAuthorizationEvidenceIsSanitized,
  compareDeviceAuthorizationProjections,
  projectDeviceCredentials,
  publishDeviceAuthorizationProjection,
  publishDeviceLifecycleProjection,
  type DeviceAuthorizationProjection,
  type DeviceLifecycleProjection,
} from './device-authorization.js';

const target = Object.freeze({
  label: 'candidate' as const,
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});
const oracleTarget = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
});

const lifecycleProjection = (): DeviceLifecycleProjection =>
  Object.freeze({
    kind: 'consent-write',
    status: 200,
    contentType: 'application/json',
    headers: Object.freeze({ 'cache-control': 'no-store' }),
    cookies: Object.freeze([]),
    challenge: undefined,
    location: undefined,
    oauthError: Object.freeze({ category: undefined, description: undefined }),
    facts: Object.freeze({
      marker: 'consent-recorded',
      redirect: Object.freeze({
        origin: 'https://candidate.example',
        path: '/oidc/device/resume',
        queryKeys: Object.freeze(['ticket']),
      }),
    }),
  });

const authorizationProjection = (): DeviceAuthorizationProjection =>
  Object.freeze({
    status: 200,
    contentType: 'application/json',
    headers: Object.freeze({ 'cache-control': 'no-store' }),
    keys: Object.freeze(['device_code', 'expires_in', 'user_code']),
    cookies: Object.freeze([]),
    challenge: undefined,
    location: undefined,
    oauthError: Object.freeze({ category: undefined, description: undefined }),
    userCodeShape: Object.freeze({
      length: 9,
      groups: Object.freeze([4, 4]),
      separator: '-',
      matchesReferencePattern: true,
    }),
    deviceCodeShape: Object.freeze({ length: 24 }),
    expiresIn: 600,
    interval: 5,
    tokenType: undefined,
    verificationUri: Object.freeze({
      origin: 'https://candidate.example',
      path: '/device',
      queryKeys: Object.freeze([]),
    }),
    verificationUriComplete: Object.freeze({
      origin: 'https://candidate.example',
      path: '/device',
      queryKeys: Object.freeze(['user_code']),
    }),
    experience: Object.freeze({
      title: 'Device verification',
      formAction: Object.freeze({
        origin: 'https://candidate.example',
        path: '/oidc/device',
        queryKeys: Object.freeze([]),
      }),
      inputNames: Object.freeze(['confirm', 'user_code', 'xsrf']),
      autoSubmit: false,
    }),
  });

describe('Phase 2 device authorization projection', () => {
  it('validates every authorization projection field and rejects malformed comparator input', () => {
    const valid = authorizationProjection();
    expect(publishDeviceAuthorizationProjection(valid)).toBe(valid);
    for (const invalid of [
      { ...valid, keys: ['user_code', 'device_code'] },
      { ...valid, keys: ['device_code', 'device_code'] },
      { ...valid, expiresIn: 0 },
      { ...valid, interval: 1.5 },
      { ...valid, userCodeShape: { ...valid.userCodeShape, groups: [4, 3] } },
      { ...valid, deviceCodeShape: { length: 0 } },
      {
        ...valid,
        verificationUri: {
          origin: 'https://candidate.example/path',
          path: '/device',
          queryKeys: [],
        },
      },
      {
        ...valid,
        verificationUriComplete: {
          origin: 'https://candidate.example',
          path: '/device',
          queryKeys: ['user_code', 'app_id'],
        },
      },
      { ...valid, experience: { ...valid.experience, autoSubmit: 'yes' } },
      { ...valid, experience: { ...valid.experience, extra: true } },
    ]) {
      expect(() => publishDeviceAuthorizationProjection(invalid as never)).toThrow(
        'Invalid Phase 2 device authorization projection'
      );
      expect(() => compareDeviceAuthorizationProjections(valid, invalid as never)).toThrow(
        'Invalid Phase 2 device authorization projection'
      );
    }
  });

  it('rejects hostile cookie arrays at every publisher entry without invoking index getters', () => {
    const calls: string[] = [];
    const hostileCookies: DeviceAuthorizationProjection['cookies'] = Object.defineProperty(
      [{ name: 'safe', options: [], clearing: false }],
      '0',
      {
        configurable: true,
        enumerable: true,
        get: () => {
          calls.push('called');
          throw new Error('private-cookie-getter-secret');
        },
      }
    );
    const authorization = authorizationProjection();
    const lifecycle = lifecycleProjection();
    const invalidAuthorization: DeviceAuthorizationProjection = {
      ...authorization,
      cookies: hostileCookies,
    };
    const invalidLifecycle: DeviceLifecycleProjection = {
      ...lifecycle,
      cookies: hostileCookies,
    };

    for (const invoke of [
      () => publishDeviceAuthorizationProjection(invalidAuthorization),
      () => publishDeviceLifecycleProjection(invalidLifecycle),
      () => compareDeviceAuthorizationProjections(authorization, invalidAuthorization),
      () => compareDeviceAuthorizationProjections(lifecycle, invalidLifecycle),
    ]) {
      expect(invoke).toThrow('Invalid Phase 2 device authorization projection');
      expect(invoke).not.toThrow(/private-cookie-getter-secret/u);
    }
    expect(calls).toEqual([]);
  });
  it('publishes only the exact lifecycle shape and reports exact comparator paths', () => {
    const projection = lifecycleProjection();
    expect(publishDeviceLifecycleProjection(projection)).toBe(projection);
    expect(
      compareDeviceAuthorizationProjections(projection, {
        ...projection,
        facts: Object.freeze({
          marker: 'consent-recorded',
          redirect: Object.freeze({
            origin: 'https://candidate.example',
            path: '/oidc/device/other',
            queryKeys: Object.freeze(['ticket']),
          }),
        }),
      } as DeviceLifecycleProjection)
    ).toEqual(['/facts/redirect/path']);
    expect(() => publishDeviceLifecycleProjection({ ...projection, extra: true } as never)).toThrow(
      'Invalid Phase 2 device authorization projection'
    );
    expect(() =>
      publishDeviceLifecycleProjection({
        ...projection,
        facts: { ...projection.facts, planted: true },
      } as never)
    ).toThrow('Invalid Phase 2 device authorization projection');
    expect(() =>
      publishDeviceLifecycleProjection({
        ...projection,
        facts: { marker: 'consent-recorded' },
      } as never)
    ).toThrow('Invalid Phase 2 device authorization projection');
  });

  it('publishes and compares every verified refresh introspection identity field', () => {
    const projection: DeviceLifecycleProjection = Object.freeze({
      ...lifecycleProjection(),
      kind: 'introspection',
      facts: Object.freeze({
        marker: 'introspection',
        active: true,
        credentialKind: 'refresh',
        subject: '<subject>',
        clientId: '<client>',
        issuer: '<target-issuer>',
        issuedAt: '<issued-at>',
        lifetimeSeconds: 1_209_600,
        scopes: Object.freeze(['offline_access', 'openid']),
      }),
    });

    expect(publishDeviceLifecycleProjection(projection)).toBe(projection);
    for (const [field, value] of [
      ['subject', '<wrong-subject>'],
      ['clientId', '<wrong-client>'],
      ['issuer', '<wrong-issuer>'],
    ] as const) {
      const invalid: DeviceLifecycleProjection = {
        ...projection,
        facts: { ...projection.facts, [field]: value },
      };
      expect(() => publishDeviceLifecycleProjection(invalid)).toThrow(
        'Invalid Phase 2 device authorization projection'
      );
      expect(() => compareDeviceAuthorizationProjections(projection, invalid)).toThrow(
        'Invalid Phase 2 device authorization projection'
      );
    }
    expect(
      compareDeviceAuthorizationProjections(projection, {
        ...projection,
        facts: { ...projection.facts, lifetimeSeconds: 1_209_599 },
      } as DeviceLifecycleProjection)
    ).toEqual(['/facts/lifetimeSeconds']);
  });

  it.each([
    ['sensitive key', { access_token: 'planted' }],
    ['raw device code key', { device_code: 'planted' }],
    ['raw user code key', { user_code: 'planted' }],
    ['raw xsrf key', { xsrf: 'planted' }],
    ['raw token key', { token: 'planted' }],
    ['raw password key', { password: 'planted' }],
    ['sensitive value', { marker: 'private-secret' }],
    ['credential value', { marker: 'Bearer planted-value' }],
    ['compact token', { marker: 'eyJhbGciOiJFUzM4NCJ9.e30.aaaaaaaaaaaaaaaa' }],
  ])('rejects %s planting', (_label, value) => {
    expect(() => assertDeviceAuthorizationEvidenceIsSanitized(value)).toThrow(
      'Invalid Phase 2 device authorization projection'
    );
  });

  it('rejects proxies, cycles and accessor properties without invoking them', () => {
    expect(() => assertDeviceAuthorizationEvidenceIsSanitized(new Proxy({}, {}))).toThrow(
      'Invalid Phase 2 device authorization projection'
    );
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => assertDeviceAuthorizationEvidenceIsSanitized(cyclic)).toThrow(
      'Invalid Phase 2 device authorization projection'
    );
    const calls: string[] = [];
    const accessor = Object.defineProperty({}, 'marker', {
      enumerable: true,
      get: () => {
        calls.push('called');
        return 'private-secret';
      },
    });
    expect(() => assertDeviceAuthorizationEvidenceIsSanitized(accessor)).toThrow(
      'Invalid Phase 2 device authorization projection'
    );
    expect(calls).toEqual([]);
    const numericCalls: string[] = [];
    const numericAccessor = Object.defineProperty(['safe'], '0', {
      configurable: true,
      enumerable: true,
      get: () => {
        numericCalls.push('called');
        return 'private-secret';
      },
    });
    expect(() => assertDeviceAuthorizationEvidenceIsSanitized(numericAccessor)).toThrow(
      'Invalid Phase 2 device authorization projection'
    );
    expect(numericCalls).toEqual([]);
  });

  it('publishes verified access and ID semantics plus opaque refresh rotation', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(publicKey);
    const issuer = 'https://candidate.example/oidc';
    const now = Math.floor(Date.now() / 1000);
    const accessClaims = {
      iss: issuer,
      aud: 'resource-api',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: 'openid offline_access read:profile',
      resource: 'resource-api',
      organization_id: 'org-1',
      jti: 'access-jti-1234',
      iat: now,
      exp: now + 3600,
    };
    const sign = async (type: string, claims: Record<string, unknown>): Promise<string> =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: 'ES384', kid: 'signing-key', typ: type })
        .sign(privateKey);
    const accessToken = await sign('at+jwt', accessClaims);
    const idClaims = {
      iss: issuer,
      aud: 'device-client',
      sub: 'subject-1',
      iat: now,
      exp: now + 3600,
      auth_time: now - 30,
      acr: 'urn:aster:loa:1',
      amr: ['pwd'],
      sid: 'session-id-1234',
      jti: 'id-token-jti-1234',
      username: 'phase2-user',
      preferred_username: 'phase2-user',
      name: 'Phase Two',
      picture: null,
      created_at: now - 100,
      updated_at: now - 10,
      email: 'phase2@example.com',
      email_verified: true,
      organizations: ['org-1', 'org-2'],
    };
    const idToken = await sign('JWT', idClaims);
    const projection = await projectDeviceCredentials({
      target,
      jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
      accessToken,
      idToken,
      refreshToken: 'next-opaque-refresh',
      previousRefreshToken: 'previous-opaque-refresh',
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
        scopes: ['openid', 'offline_access', 'read:profile'],
        resource: 'resource-api',
        organizationId: 'org-1',
      },
    });

    expect(projection).toMatchObject({
      access: {
        format: 'verified-jwt',
        header: {
          algorithm: '<verified-signing-algorithm>',
          keyId: '<verified-key>',
          type: 'at+jwt',
        },
        claims: {
          claimKeys: Object.keys(accessClaims).sort((left, right) => left.localeCompare(right)),
          claimTypes: {
            aud: 'string',
            client_id: 'string',
            exp: 'number',
            iat: 'number',
            iss: 'string',
            jti: 'string',
            organization_id: 'string',
            resource: 'string',
            scope: 'string',
            sub: 'string',
          },
          issuer: '<target-issuer>',
          audience: ['resource-api'],
          subject: '<subject>',
          clientId: '<client>',
          scopes: ['offline_access', 'openid', 'read:profile'],
          resource: 'resource-api',
          organizationId: 'org-1',
          jwtId: '<opaque-id>',
          issuedAt: '<issued-at>',
          lifetimeSeconds: 3600,
        },
        signature: { verified: true },
      },
      id: {
        format: 'verified-jwt',
        claims: {
          audience: ['device-client'],
          subject: '<subject>',
          issuedAt: '<issued-at>',
          lifetimeSeconds: 3600,
          jwtId: '<opaque-id>',
          organizations: { count: 2, expectedOrganizationMember: true },
          claimTypes: {
            email: 'string',
            email_verified: 'boolean',
            auth_time: 'number',
            acr: 'string',
            amr: 'string-array',
            sid: 'string',
            organizations: 'string-array',
            picture: 'null',
            preferred_username: 'string',
            created_at: 'number',
            updated_at: 'number',
          },
        },
        signature: { verified: true },
      },
      refresh: { format: 'opaque', present: true, rotated: true },
    });
    expect(JSON.stringify(projection)).not.toContain(accessToken);
    expect(JSON.stringify(projection)).not.toContain(idToken);
    expect(projection.id?.claims.claimKeys).toEqual(
      Object.keys(idClaims).sort((left, right) => left.localeCompare(right))
    );

    const arrayAudience = await projectDeviceCredentials({
      target,
      jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
      accessToken: await sign('at+jwt', {
        ...accessClaims,
        aud: ['resource-api', 'secondary-audience'],
      }),
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
        scopes: ['openid', 'offline_access', 'read:profile'],
        resource: 'resource-api',
        organizationId: 'org-1',
      },
    });
    expect(arrayAudience.access).toMatchObject({
      format: 'verified-jwt',
      claims: {
        audience: ['resource-api', 'secondary-audience'],
        claimTypes: { aud: 'string-array' },
      },
    });
  });

  it('verifies the selected resource audience without requiring a resource claim', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(publicKey);
    const now = Math.floor(Date.now() / 1000);
    const accessToken = await new SignJWT({
      iss: 'https://candidate.example/oidc',
      aud: 'resource-api',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: 'read',
      jti: 'resource-jti-1234',
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'ES384', kid: 'signing-key', typ: 'at+jwt' })
      .sign(privateKey);
    const projection = await projectDeviceCredentials({
      target,
      jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
      accessToken,
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
        accessFormat: 'verified-jwt',
        scopes: ['read'],
      },
    });

    expect(projection.access).toMatchObject({
      format: 'verified-jwt',
      claims: {
        audience: ['resource-api'],
        scopes: ['read'],
        claimKeys: ['aud', 'client_id', 'exp', 'iat', 'iss', 'jti', 'scope', 'sub'],
      },
      signature: { verified: true },
    });
    if (projection.access.format === 'opaque') {
      throw new TypeError('expected verified resource access token');
    }
    expect(projection.access.claims).not.toHaveProperty('resource');
    expect(compareDeviceAuthorizationProjections(projection, projection)).toEqual([]);
  });

  it('projects a resource-free access token as opaque and keeps absent ID and refresh absent', async () => {
    const { publicKey } = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(publicKey);
    const input = {
      target,
      jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
      accessToken: 'opaque-session-access',
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'device-client',
      },
    };

    await expect(projectDeviceCredentials(input)).resolves.toEqual({
      access: { format: 'opaque', present: true },
      id: undefined,
      refresh: undefined,
    });
    await expect(
      projectDeviceCredentials({
        ...input,
        accessToken: 'eyJhbGciOiJFUzM4NCJ9.e30.aaaaaaaaaaaaaaaa',
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');
  });

  it('keeps an initially resource-selected access token opaque when the contract says opaque', async () => {
    const { publicKey } = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(publicKey);
    const input = {
      target,
      jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
      accessToken: 'opaque-resource-access',
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
        accessFormat: 'opaque' as const,
        scopes: ['offline_access', 'openid', 'read'],
        resource: 'resource-api',
      },
    };

    await expect(projectDeviceCredentials(input)).resolves.toEqual({
      access: { format: 'opaque', present: true },
      id: undefined,
      refresh: undefined,
    });
    await expect(
      projectDeviceCredentials({
        ...input,
        expected: { ...input.expected, accessFormat: 'unexpected' as never },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');
  });

  it('normalizes the reference organization audience and rejects an organization_id claim', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const publicJwk = await exportJWK(publicKey);
    const now = Math.floor(Date.now() / 1000);
    const issuer = 'https://oracle.example/oidc';
    const accessToken = await new SignJWT({
      iss: issuer,
      aud: 'urn:logto:organization:org-1',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: '',
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'oracle-signing-key', typ: 'at+jwt' })
      .sign(privateKey);
    const idToken = await new SignJWT({
      iss: issuer,
      aud: 'device-client',
      sub: 'subject-1',
      organizations: ['org-1'],
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'oracle-signing-key', typ: 'JWT' })
      .sign(privateKey);

    const projection = await projectDeviceCredentials({
      target: oracleTarget,
      jwks: {
        keys: [{ ...publicJwk, alg: 'RS256', kid: 'oracle-signing-key', use: 'sig' }],
      },
      accessToken,
      idToken,
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'urn:logto:organization:org-1',
        accessFormat: 'verified-jwt',
        scopes: [],
        organizationId: 'org-1',
        accessOrganizationIdRequired: false,
      },
    });

    expect(projection.access).toMatchObject({
      format: 'verified-jwt',
      claims: {
        audience: ['urn:aster:organization:org-1'],
        scopes: [],
      },
    });
    if (projection.access.format === 'opaque') {
      throw new TypeError('expected verified organization access token');
    }
    expect(projection.access.claims).not.toHaveProperty('organizationId');
    expect(projection.id?.claims.organizations).toEqual({
      count: 1,
      expectedOrganizationMember: true,
    });

    const incorrectAccessToken = await new SignJWT({
      iss: issuer,
      aud: 'urn:logto:organization:org-1',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: '',
      organization_id: 'org-1',
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'oracle-signing-key', typ: 'at+jwt' })
      .sign(privateKey);
    await expect(
      projectDeviceCredentials({
        target: oracleTarget,
        jwks: { keys: [{ ...publicJwk, alg: 'RS256', kid: 'oracle-signing-key', use: 'sig' }] },
        accessToken: incorrectAccessToken,
        expected: {
          clientId: 'device-client',
          subjectId: 'subject-1',
          audience: 'urn:logto:organization:org-1',
          accessFormat: 'verified-jwt',
          scopes: [],
          organizationId: 'org-1',
          accessOrganizationIdRequired: false,
        },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');

    const scopedAccessToken = await new SignJWT({
      iss: issuer,
      aud: 'urn:logto:organization:org-1',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: 'urn:logto:scope:organizations',
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'oracle-signing-key', typ: 'at+jwt' })
      .sign(privateKey);
    const scopedProjection = await projectDeviceCredentials({
      target: oracleTarget,
      jwks: {
        keys: [{ ...publicJwk, alg: 'RS256', kid: 'oracle-signing-key', use: 'sig' }],
      },
      accessToken: scopedAccessToken,
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'urn:logto:organization:org-1',
        accessFormat: 'verified-jwt',
        scopes: ['urn:logto:scope:organizations'],
        accessOrganizationIdRequired: false,
      },
    });
    expect(scopedProjection.access).toMatchObject({
      format: 'verified-jwt',
      claims: {
        audience: ['urn:aster:organization:org-1'],
        scopes: ['urn:aster:scope:organizations'],
      },
    });
  });

  it('verifies oracle RSA tokens, preserves absent ID typ and rejects RSA for the candidate', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const publicJwk = await exportJWK(publicKey);
    const now = Math.floor(Date.now() / 1000);
    const issuer = 'https://oracle.example/oidc';
    const accessToken = await new SignJWT({
      iss: issuer,
      aud: 'resource-api',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: 'openid',
      resource: 'resource-api',
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'oracle-signing-key', typ: 'at+jwt' })
      .sign(privateKey);
    const idToken = await new SignJWT({
      iss: issuer,
      aud: 'device-client',
      sub: 'subject-1',
      iat: now,
      exp: now + 3600,
      picture: null,
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'oracle-signing-key' })
      .sign(privateKey);
    const jwks = {
      keys: [{ ...publicJwk, alg: 'RS256', kid: 'oracle-signing-key', use: 'sig' }],
    };
    const input = {
      target: oracleTarget,
      jwks,
      accessToken,
      idToken,
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
        scopes: ['openid'],
        resource: 'resource-api',
      },
    };

    const projection = await projectDeviceCredentials(input);
    expect(projection.access).toMatchObject({
      header: { algorithm: '<verified-signing-algorithm>', type: 'at+jwt' },
    });
    expect(projection.id).toMatchObject({
      header: { algorithm: '<verified-signing-algorithm>', keyId: '<verified-key>' },
    });
    expect(projection.id?.header).not.toHaveProperty('type');
    await expect(
      projectDeviceCredentials({
        ...input,
        target,
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');
    await expect(
      projectDeviceCredentials({
        ...input,
        jwks: {
          keys: [{ ...publicJwk, alg: 'ES384', kid: 'oracle-signing-key', use: 'sig' }],
        },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');
  });

  it('rejects missing, extra, wrongly typed profile and invalid organization JWT claims', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(publicKey);
    const now = Math.floor(Date.now() / 1000);
    const issuer = 'https://candidate.example/oidc';
    const sign = async (
      claims: Record<string, unknown>,
      type: 'at+jwt' | 'JWT' = 'JWT'
    ): Promise<string> =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: 'ES384', kid: 'signing-key', typ: type })
        .sign(privateKey);
    const accessToken = await sign(
      {
        iss: issuer,
        aud: 'resource-api',
        sub: 'subject-1',
        client_id: 'device-client',
        scope: 'openid organizations',
        resource: 'resource-api',
        organization_id: 'org-1',
        iat: now,
        exp: now + 3600,
        jti: 'access-jti-1234',
      },
      'at+jwt'
    );
    const validIdClaims = {
      iss: issuer,
      aud: 'device-client',
      sub: 'subject-1',
      iat: now,
      exp: now + 3600,
      username: 'phase2-user',
      email_verified: true,
      organizations: ['org-1'],
    };
    const project = async (idClaims: Record<string, unknown>): Promise<unknown> =>
      projectDeviceCredentials({
        target,
        jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
        accessToken,
        idToken: await sign(idClaims),
        expected: {
          clientId: 'device-client',
          subjectId: 'subject-1',
          audience: 'resource-api',
          scopes: ['openid', 'organizations'],
          resource: 'resource-api',
          organizationId: 'org-1',
        },
      });
    const { sub: _sub, ...missingSubject } = validIdClaims;
    for (const claims of [
      missingSubject,
      { ...validIdClaims, unexpected: 'extra' },
      { ...validIdClaims, email_verified: 'yes' },
      { ...validIdClaims, organizations: ['org-2'] },
      { ...validIdClaims, organizations: ['org-1', 'org-1'] },
      { ...validIdClaims, organizations: 'org-1' },
      { ...validIdClaims, amr: 'pwd' },
      { ...validIdClaims, address: { country: 42 } },
    ]) {
      // eslint-disable-next-line no-await-in-loop -- Each signed negative isolates one claim contract.
      await expect(project(claims)).rejects.toThrow(
        'Invalid Phase 2 device authorization projection'
      );
    }
    const invalidJtiAccess = await sign(
      {
        iss: issuer,
        aud: 'resource-api',
        sub: 'subject-1',
        client_id: 'device-client',
        scope: 'openid organizations',
        resource: 'resource-api',
        organization_id: 'org-1',
        iat: now,
        exp: now + 3600,
        jti: 'short',
      },
      'at+jwt'
    );
    await expect(
      projectDeviceCredentials({
        target,
        jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
        accessToken: invalidJtiAccess,
        expected: {
          clientId: 'device-client',
          subjectId: 'subject-1',
          audience: 'resource-api',
          scopes: ['openid', 'organizations'],
          resource: 'resource-api',
          organizationId: 'org-1',
        },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');
  });

  it('rejects a forged JWT, private JWKS material and mismatched claims', async () => {
    const pair = await generateKeyPair('ES384', { extractable: true });
    const attacker = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(pair.publicKey);
    const privateJwk = await exportJWK(pair.privateKey);
    const now = Math.floor(Date.now() / 1000);
    const forged = await new SignJWT({
      iss: 'https://candidate.example/oidc',
      aud: 'resource-api',
      sub: 'subject-1',
      client_id: 'device-client',
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'ES384', kid: 'signing-key' })
      .sign(attacker.privateKey);
    const input = {
      target,
      jwks: { keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }] },
      accessToken: forged,
      refreshToken: 'opaque-refresh',
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
      },
    };

    await expect(projectDeviceCredentials(input)).rejects.toThrow(
      'Invalid Phase 2 device authorization projection'
    );
    await expect(
      projectDeviceCredentials({
        ...input,
        jwks: { keys: [{ ...privateJwk, alg: 'ES384', kid: 'signing-key' }] },
      })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');
  });

  it('rejects invalid protected headers and token issue times with fixed diagnostics', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(publicKey);
    const now = Math.floor(Date.now() / 1000);
    const claims = {
      iss: 'https://candidate.example/oidc',
      aud: 'resource-api',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: 'openid',
      resource: 'resource-api',
      iat: now,
      exp: now + 3600,
    };
    const sign = async (
      header: Record<string, unknown>,
      overrides: Record<string, unknown> = {}
    ): Promise<string> =>
      new SignJWT({ ...claims, ...overrides })
        .setProtectedHeader(header as { [key: string]: unknown; alg: string })
        .sign(privateKey);
    const validAccess = await sign({ alg: 'ES384', kid: 'signing-key', typ: 'at+jwt' });
    const input = {
      target,
      jwks: {
        keys: [{ ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' }],
      },
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
        scopes: ['openid'],
        resource: 'resource-api',
      },
    };
    const invalidAccessTokens = [
      await sign({ alg: 'ES384', kid: 'signing-key' }),
      await sign({ alg: 'ES384', kid: 'signing-key', typ: 'JWT' }),
      await sign({ alg: 'ES384', kid: 'signing-key', typ: 'at+jwt', extra: 'header' }),
      await sign(
        { alg: 'ES384', kid: 'signing-key', typ: 'at+jwt' },
        { iat: now + 30, exp: now + 3600 }
      ),
      await sign(
        { alg: 'ES384', kid: 'signing-key', typ: 'at+jwt' },
        { iat: now - 61, exp: now + 3600 }
      ),
    ];
    for (const accessToken of invalidAccessTokens) {
      // eslint-disable-next-line no-await-in-loop -- Each compact token isolates one header/time rejection.
      await expect(projectDeviceCredentials({ ...input, accessToken })).rejects.toThrow(
        'Invalid Phase 2 device authorization projection'
      );
    }
    const idClaims = {
      iss: 'https://candidate.example/oidc',
      aud: 'device-client',
      sub: 'subject-1',
      iat: now,
      exp: now + 3600,
    };
    const invalidIdTokens = await Promise.all([
      new SignJWT(idClaims)
        .setProtectedHeader({ alg: 'ES384', kid: 'signing-key', typ: 'at+jwt' })
        .sign(privateKey),
      new SignJWT(idClaims)
        .setProtectedHeader({ alg: 'ES384', kid: 'signing-key', typ: 'JWT', extra: 'header' })
        .sign(privateKey),
    ]);
    for (const idToken of invalidIdTokens) {
      // eslint-disable-next-line no-await-in-loop -- Each compact token isolates one ID header rejection.
      await expect(
        projectDeviceCredentials({ ...input, accessToken: validAccess, idToken })
      ).rejects.toThrow('Invalid Phase 2 device authorization projection');
    }
  });

  it('rejects malformed, private, nested and oversized JWKS material before verification', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES384');
    const publicJwk = await exportJWK(publicKey);
    const now = Math.floor(Date.now() / 1000);
    const accessToken = await new SignJWT({
      iss: 'https://candidate.example/oidc',
      aud: 'resource-api',
      sub: 'subject-1',
      client_id: 'device-client',
      scope: 'openid',
      resource: 'resource-api',
      iat: now,
      exp: now + 3600,
    })
      .setProtectedHeader({ alg: 'ES384', kid: 'signing-key', typ: 'at+jwt' })
      .sign(privateKey);
    const baseKey = { ...publicJwk, alg: 'ES384', kid: 'signing-key', use: 'sig' };
    const input = {
      target,
      accessToken,
      expected: {
        clientId: 'device-client',
        subjectId: 'subject-1',
        audience: 'resource-api',
        scopes: ['openid'],
        resource: 'resource-api',
      },
    };
    for (const key of [
      { ...baseKey, d: 'private-key-material' },
      { ...baseKey, nested: { planted: true } },
      { ...baseKey, kid: 'k'.repeat(257) },
      { ...baseKey, x: 'a'.repeat(4096) },
      { ...baseKey, key_ops: ['sign'] },
      { ...baseKey, key_ops: ['verify', 'verify'] },
    ]) {
      // eslint-disable-next-line no-await-in-loop -- Each public-key mutation isolates one admission bound.
      await expect(projectDeviceCredentials({ ...input, jwks: { keys: [key] } })).rejects.toThrow(
        'Invalid Phase 2 device authorization projection'
      );
    }
    const getterCalls: string[] = [];
    const hostileKeys = Object.defineProperty([baseKey], '0', {
      configurable: true,
      enumerable: true,
      get: () => {
        getterCalls.push('called');
        return baseKey;
      },
    });
    await expect(
      projectDeviceCredentials({ ...input, jwks: { keys: hostileKeys } })
    ).rejects.toThrow('Invalid Phase 2 device authorization projection');
    expect(getterCalls).toEqual([]);
  });

  it('rejects extra credential projection fields in the exact comparator', () => {
    const projection = {
      access: { format: 'opaque', present: true },
      id: undefined,
      refresh: undefined,
    } as const;
    expect(() =>
      compareDeviceAuthorizationProjections(projection, {
        ...projection,
        access: { ...projection.access, length: 32 },
      } as never)
    ).toThrow('Invalid Phase 2 device authorization projection');
  });
});

/* eslint-enable max-lines, @typescript-eslint/no-confusing-void-expression, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
