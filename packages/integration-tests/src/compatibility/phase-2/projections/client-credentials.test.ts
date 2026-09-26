/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument -- Negative controls deliberately construct malformed objects outside the production projection types. */
import type { TargetConfig } from '../../model.js';
import type { SanitizedTokenObservation } from '../clients/client-credentials.js';
import type { Phase2FixturePublic } from '../fixtures.js';

import {
  assertClientCredentialsEvidenceIsSanitized,
  createClientCredentialsJwtAudit,
  createZeroClientCredentialsSideEffects,
  projectClientCredentialsObservation,
  type RawClientCredentialsProjectionInput,
} from './client-credentials.js';

const fixture: Phase2FixturePublic = Object.freeze({
  allocationId: 'projection-fixture',
  clients: Object.freeze({
    basic: Object.freeze({ id: 'basic-runtime', method: 'client_secret_basic' }),
    post: Object.freeze({ id: 'post-runtime', method: 'client_secret_post' }),
  }),
  resources: Object.freeze({
    primary: Object.freeze({
      id: 'resource-primary',
      indicator: 'https://phase2.example.invalid/api-primary',
    }),
    default: Object.freeze({
      id: 'resource-default',
      indicator: 'https://phase2.example.invalid/api-default',
    }),
  }),
  organization: Object.freeze({ id: 'organization-runtime', scopeName: 'organization:read' }),
  scopes: Object.freeze({
    read: Object.freeze({ id: 'read-scope', name: 'read' }),
    write: Object.freeze({ id: 'write-scope', name: 'write' }),
    unassigned: Object.freeze({ id: 'unassigned-scope', name: 'unassigned' }),
  }),
  boundary: Object.freeze({ primary: 'provisioned', foreign: 'unchanged' }),
});

const oracle: TargetConfig = Object.freeze({
  label: 'oracle',
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
});
const candidate: TargetConfig = Object.freeze({
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
});

const response = (
  target: TargetConfig,
  overrides: Partial<SanitizedTokenObservation> = {}
): SanitizedTokenObservation => ({
  status: 200,
  headers: {
    'access-control-allow-origin': '*',
    'access-control-expose-headers': 'WWW-Authenticate',
    [target.label === 'oracle' ? 'logto-core-request-id' : 'aster-core-request-id']:
      '0123456789abcdef',
    'cache-control': 'no-store',
    'content-length': '827',
    'content-type': 'application/json; charset=utf-8',
    'cross-origin-resource-policy': 'same-origin',
    'origin-agent-cluster': '?1',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'strict-transport-security': 'max-age=15552000; includeSubDomains',
    vary: 'Accept-Encoding, Origin',
    'x-content-type-options': 'nosniff',
    'x-download-options': 'noopen',
    'x-frame-options': 'SAMEORIGIN',
    'x-permitted-cross-domain-policies': 'none',
    'x-xss-protection': '0',
  },
  body: { expires_in: 3600, scope: 'read write', token_type: 'Bearer' },
  jwt: {
    header: { alg: 'ES384', kid: 'signing-key-1', typ: 'at+jwt' },
    claims: {
      aud: fixture.resources.primary.indicator,
      client_id: fixture.clients.basic.id,
      exp: 4600,
      iat: 1000,
      iss: `${target.coreUrl}oidc`,
      jti: '0123456789abcdef0123456789abcdef01234567890',
      scope: 'read write',
      sub: fixture.clients.basic.id,
    },
    signatureSha256: 'a'.repeat(64),
  },
  ...overrides,
});

const input = (
  target: TargetConfig,
  responseValue: SanitizedTokenObservation = response(target)
): RawClientCredentialsProjectionInput => {
  const issuedAt = responseValue.jwt?.claims.iat;
  const observedAt = typeof issuedAt === 'number' ? issuedAt * 1000 : 1000;
  const jwtProof = createClientCredentialsJwtAudit().verify(responseValue, observedAt, observedAt);
  return {
    target,
    fixture,
    response: responseValue,
    ...(jwtProof === undefined ? {} : { jwtProof }),
    authority: {
      decision: 'authorized',
      targetKind: 'resource',
      target: fixture.resources.primary.indicator,
      availableScopes: ['read', 'write'],
      effectiveScopes: ['read', 'write'],
    },
    signingUse: { generalKeyUse: 'verified', oidcIdTokenKeyUse: 'unchanged' },
    sideEffects: createZeroClientCredentialsSideEffects(),
  };
};

describe('Phase 2 client credentials projection', () => {
  it('produces equal target-independent resource evidence without token or signature hashes', () => {
    const oracleProjection = projectClientCredentialsObservation(input(oracle));
    const candidateProjection = projectClientCredentialsObservation(input(candidate));

    expect(oracleProjection).toEqual(candidateProjection);
    expect(oracleProjection.jwt).toEqual({
      header: { typ: 'at+jwt', alg: 'ES384', kid: '<verified-es384-key>' },
      claims: {
        iss: '<target-issuer>',
        aud: '<resource.primary>',
        sub: '<client.basic>',
        client_id: '<client.basic>',
        scope: 'read write',
        iat: '<issued-at>',
        exp: { afterIssuedAtSeconds: 3600 },
        jti: '<unique-jti>',
      },
      signature: { verified: true, algorithm: 'ES384' },
    });
    const serialized = JSON.stringify(oracleProjection);
    expect(serialized).not.toContain('signatureSha256');
    expect(serialized).not.toContain('access_token');
    expect(serialized).not.toContain('0123456789abcdef0123456789abcdef01234567890');
  });

  it('normalizes only the approved reference organization audience and request-id namespace', () => {
    const reference = response(oracle, {
      jwt: {
        ...response(oracle).jwt!,
        claims: {
          ...response(oracle).jwt!.claims,
          aud: 'urn:logto:organization:organization-runtime',
          organization_id: fixture.organization.id,
        },
      },
    });
    const aster = response(candidate, {
      jwt: {
        ...response(candidate).jwt!,
        claims: {
          ...response(candidate).jwt!.claims,
          aud: 'urn:aster:organization:organization-runtime',
          organization_id: fixture.organization.id,
        },
      },
    });
    const oracleProjection = projectClientCredentialsObservation({
      ...input(oracle, reference),
      authority: {
        decision: 'authorized',
        targetKind: 'organization',
        target: fixture.organization.id,
        availableScopes: ['organization:read'],
        effectiveScopes: ['organization:read'],
      },
    });
    const candidateProjection = projectClientCredentialsObservation({
      ...input(candidate, aster),
      authority: {
        decision: 'authorized',
        targetKind: 'organization',
        target: fixture.organization.id,
        availableScopes: ['organization:read'],
        effectiveScopes: ['organization:read'],
      },
    });
    expect(oracleProjection).toEqual(candidateProjection);
    expect(oracleProjection.jwt?.claims).toMatchObject({
      aud: 'urn:aster:organization:<organization.primary>',
      organization_id: '<organization.primary>',
    });
    expect(oracleProjection.http.headers).toHaveProperty(
      'aster-core-request-id',
      '<per-request-id>'
    );
  });

  it('projects the closed invalid-request authority decision for OAuth request errors', () => {
    const errorResponse: SanitizedTokenObservation = {
      status: 400,
      headers: {},
      body: {
        code: 'oidc.invalid_request',
        message: 'Request is invalid.',
        error: 'invalid_request',
        error_description: 'client authentication must only be provided using one mechanism',
      },
    };
    const projection = projectClientCredentialsObservation({
      ...input(candidate, errorResponse),
      authority: {
        decision: 'invalid-request',
        targetKind: 'none',
        target: null,
        availableScopes: [],
        effectiveScopes: [],
      },
      signingUse: { generalKeyUse: 'unchanged', oidcIdTokenKeyUse: 'unchanged' },
    });
    expect(projection.authority.decision).toBe('invalid-request');
    expect(projection.jwt).toBeNull();
  });

  it.each([
    [
      'unexpected response field',
      () => input(candidate, { ...response(candidate), extra: true } as any),
    ],
    [
      'unexpected body field',
      () =>
        input(candidate, {
          ...response(candidate),
          body: { ...response(candidate).body, extra: true },
        }),
    ],
    [
      'unexpected JWT header field',
      () =>
        input(candidate, {
          ...response(candidate),
          jwt: {
            ...response(candidate).jwt!,
            header: { ...response(candidate).jwt!.header, extra: true },
          },
        }),
    ],
    [
      'unexpected JWT claim',
      () =>
        input(candidate, {
          ...response(candidate),
          jwt: {
            ...response(candidate).jwt!,
            claims: { ...response(candidate).jwt!.claims, extra: true },
          },
        }),
    ],
    [
      'invalid signature fact',
      () =>
        input(candidate, {
          ...response(candidate),
          jwt: { ...response(candidate).jwt!, signatureSha256: 'invalid' },
        }),
    ],
    [
      'non-zero side effect',
      () =>
        ({
          ...input(candidate),
          sideEffects: { ...createZeroClientCredentialsSideEffects(), sessions: 1 },
        }) as any,
    ],
    [
      'legacy advanced signing fact',
      () =>
        ({
          ...input(candidate),
          signingUse: { generalKeyUse: 'advanced', oidcIdTokenKeyUse: 'unchanged' },
        }) as any,
    ],
  ])('rejects %s', (_name, create) => {
    expect(() => projectClientCredentialsObservation(create())).toThrow(
      'Invalid Phase 2 client credentials projection'
    );
  });

  it('rejects secret-shaped public evidence independently of projection construction', () => {
    expect(() => {
      assertClientCredentialsEvidenceIsSanitized({
        value: 'eyJhbGciOiJFUzM4NCJ9.e30.signaturevalue0000',
      });
    }).toThrow('Invalid Phase 2 client credentials projection');
    expect(() => {
      assertClientCredentialsEvidenceIsSanitized({ authorization: 'redacted' });
    }).toThrow('Invalid Phase 2 client credentials projection');
    expect(() => {
      assertClientCredentialsEvidenceIsSanitized({ jwk: { kty: 'EC', d: 'private' } });
    }).toThrow('Invalid Phase 2 client credentials projection');
    expect(() => {
      assertClientCredentialsEvidenceIsSanitized({ bearerHash: 'a'.repeat(64) });
    }).toThrow('Invalid Phase 2 client credentials projection');
  });

  it('allows aggregate cookie counts while rejecting cookie values', () => {
    expect(() => {
      assertClientCredentialsEvidenceIsSanitized({
        setCookieCount: 2,
        clearedCookieCount: 1,
      });
    }).not.toThrow();
    expect(() => {
      assertClientCredentialsEvidenceIsSanitized({ 'set-cookie': 'session=private' });
    }).toThrow('Invalid Phase 2 client credentials projection');
  });

  it('rejects duplicate JTI values and issued-at values outside the request window', () => {
    const audit = createClientCredentialsJwtAudit();
    const first = response(candidate);
    expect(audit.verify(first, 1_000_000, 1_000_999)).toBeDefined();
    expect(() => audit.verify(first, 1_000_000, 1_000_999)).toThrow(
      'Invalid Phase 2 client credentials projection'
    );

    const future = response(candidate, {
      jwt: {
        ...response(candidate).jwt!,
        claims: {
          ...response(candidate).jwt!.claims,
          iat: 1002,
          exp: 4602,
          jti: 'future0123456789abcdef0123456789abcdef0123456',
        },
      },
    });
    const old = response(candidate, {
      jwt: {
        ...response(candidate).jwt!,
        claims: {
          ...response(candidate).jwt!.claims,
          iat: 998,
          exp: 4598,
          jti: 'old0123456789abcdef0123456789abcdef012345678',
        },
      },
    });
    expect(() => audit.verify(future, 1_000_000, 1_000_999)).toThrow(
      'Invalid Phase 2 client credentials projection'
    );
    expect(() => audit.verify(old, 1_000_000, 1_000_999)).toThrow(
      'Invalid Phase 2 client credentials projection'
    );
  });

  it('requires the exact target issuer rather than an origin-compatible suffix', () => {
    const incorrect = response(candidate, {
      jwt: {
        ...response(candidate).jwt!,
        claims: {
          ...response(candidate).jwt!.claims,
          iss: 'https://candidate.example/incorrect/oidc',
        },
      },
    });
    expect(() => projectClientCredentialsObservation(input(candidate, incorrect))).toThrow(
      'Invalid Phase 2 client credentials projection'
    );
  });
});

/* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument */
