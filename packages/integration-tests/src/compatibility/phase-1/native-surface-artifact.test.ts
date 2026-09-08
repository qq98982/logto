import {
  assertCandidateNativeSurfaceArtifact,
  projectNativeSurfaceArtifact,
} from './native-surface-artifact.js';

describe('candidate native-surface artifact boundary', () => {
  it('accepts Aster markers while leaving arbitrary user text untouched', () => {
    expect(() => {
      assertCandidateNativeSurfaceArtifact({
        steps: {
          request: {
            value: {
              headers: { 'aster-core-request-id': ['<per-request-id>'] },
              cookies: [{ name: '_aster', path: '/' }],
              tokens: [
                {
                  claims: {
                    aud: 'urn:aster:organization:t-default',
                    scope:
                      'openid urn:aster:scope:organizations urn:aster:scope:organization_roles',
                  },
                },
              ],
              resource: 'urn:aster:resource:management',
              localStorageKey: 'aster:demo-app:dev:config',
              user: { name: 'Logto may appear in tenant-controlled text' },
            },
          },
        },
      });
    }).not.toThrow();
  });

  it('accepts real consent and missing-resource shapes without treating objects as marker strings', () => {
    const artifact = {
      consent: {
        resource: {
          indicator: 'https://api.example.com',
          permissions: [{ id: 'scope-id', name: 'read:profile' }],
        },
      },
      missingResourceScopes: [
        {
          resource: {
            indicator: 'https://api.example.com',
            scopes: [{ id: 'scope-id', name: 'read:profile' }],
          },
          scopes: [{ id: 'scope-id', name: 'read:profile' }],
        },
      ],
    };

    expect(() => {
      assertCandidateNativeSurfaceArtifact(artifact);
    }).not.toThrow();
  });

  it('projects a reference browser observation onto the Aster namespace and freezes it', () => {
    const projected = projectNativeSurfaceArtifact(
      {
        managementExchange: {
          resource: 'https://default.logto.app/api',
          responseScope: 'urn:logto:scope:organizations profile',
        },
        headers: { 'logto-core-request-id': ['<per-request-id>'] },
        cookies: [{ name: '_logto', path: '/' }],
        claims: {
          aud: 'urn:logto:organization:t-default',
          scope: 'openid urn:logto:scope:organization_roles',
        },
        customResource: 'https://default.logto.app/api',
      },
      'oracle'
    );

    expect(projected).toEqual({
      managementExchange: {
        resource: 'urn:aster:resource:management',
        responseScope: 'urn:aster:scope:organizations profile',
      },
      headers: { 'aster-core-request-id': ['<per-request-id>'] },
      cookies: [{ name: '_aster', path: '/' }],
      claims: {
        aud: 'urn:aster:organization:t-default',
        scope: 'openid urn:aster:scope:organization_roles',
      },
      customResource: 'https://default.logto.app/api',
    });
    expect(Object.isFrozen(projected)).toBe(true);
    expect(Object.isFrozen(projected.managementExchange)).toBe(true);
    expect(() => {
      assertCandidateNativeSurfaceArtifact(projected);
    }).not.toThrow();
  });

  it.each([
    { headers: { 'logto-core-request-id': ['<per-request-id>'] } },
    { cookies: [{ name: '_logto', path: '/' }] },
    { claims: { aud: 'urn:logto:organization:t-default' } },
    { claims: { scope: 'openid urn:logto:scope:organizations' } },
    { resource: 'https://default.logto.app/api' },
    { localStorageKey: 'logto:demo-app:dev:config' },
  ])('rejects a candidate legacy marker in a controlled field', (value) => {
    expect(() => {
      assertCandidateNativeSurfaceArtifact(value);
    }).toThrow('Invalid Phase 1 candidate native surface artifact');
  });

  it('does not reject upstream text in arbitrary user-controlled fields', () => {
    expect(() => {
      assertCandidateNativeSurfaceArtifact({
        username: 'logto-user',
        tenantName: 'Logto migration tenant',
        customDescription: 'uses urn:logto:custom811 as text',
        customResource: 'https://default.logto.app/api',
      });
    }).not.toThrow();
  });

  it('rejects proxy and cyclic artifacts with fixed diagnostics', () => {
    const cyclic: Record<string, unknown> = {};
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The negative fixture must contain an actual graph cycle.
    Object.defineProperty(cyclic, 'self', { enumerable: true, value: cyclic });

    expect(() => {
      assertCandidateNativeSurfaceArtifact(new Proxy({ accepted: true }, {}));
    }).toThrow('Invalid Phase 1 candidate native surface artifact');
    expect(() => {
      assertCandidateNativeSurfaceArtifact(cyclic);
    }).toThrow('Invalid Phase 1 candidate native surface artifact');
  });
});
