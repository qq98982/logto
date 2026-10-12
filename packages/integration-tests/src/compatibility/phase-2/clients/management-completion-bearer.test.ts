/* eslint-disable @typescript-eslint/no-empty-function, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake setup records ownership and compensation around a real signed JWT. */
import { exportJWK, generateKeyPair, SignJWT, type JSONWebKeySet } from 'jose';

import type { Phase2AdminRequest, Phase2AdminRequestFunction } from '../fixtures.js';

import {
  withManagementCompletionBearer,
  type ManagementCompletionAuthority,
} from './management-completion-bearer.js';

const target = {
  label: 'oracle' as const,
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};
const authority: ManagementCompletionAuthority = Object.freeze({
  resource: 'urn:aster:resource:management',
  scopeId: 'management-all-scope',
  scopeName: 'all',
  issuer: 'https://candidate.example/oidc',
  audience: 'urn:aster:resource:management',
  algorithm: 'ES384',
  tokenType: 'at+jwt',
  accessTokenTtlSeconds: 300,
});

const fixture = async (audience = authority.audience, clientId = 'management-client') => {
  const { privateKey, publicKey } = await generateKeyPair('ES384');
  const jwk = await exportJWK(publicKey);
  const jwks: JSONWebKeySet = { keys: [{ ...jwk, kid: 'management-key', alg: 'ES384' }] };
  const calls: Phase2AdminRequest[] = [];
  const setupRequest: Phase2AdminRequestFunction = async (input) => {
    calls.push(input);
    if (input.path === 'applications') {
      const name = Reflect.get(input.body as Record<string, unknown>, 'name');
      return { id: 'management-client', name, type: 'MachineToMachine' };
    }
    if (input.path.endsWith('/secrets')) {
      return [{ name: 'Default secret', value: 'private-client-secret', createdAt: 1 }];
    }
    if (input.path === 'roles') {
      const name = Reflect.get(input.body as Record<string, unknown>, 'name');
      return { id: 'management-role', name, type: 'MachineToMachine' };
    }
    return 204;
  };
  const bearer = await new SignJWT({ client_id: clientId, scope: 'all' })
    .setProtectedHeader({ alg: 'ES384', kid: 'management-key', typ: 'at+jwt' })
    .setIssuer(authority.issuer)
    .setAudience(audience)
    .setSubject(clientId)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
  return {
    calls,
    jwks,
    setupRequest,
    fetch: async () =>
      new Response(
        JSON.stringify({ access_token: bearer, token_type: 'Bearer', expires_in: 300 }),
        {
          status: 200,
        }
      ),
  };
};

test('leases a fully verified M2M Management bearer and cleans its owned role', async () => {
  const value = await fixture();
  const owned: string[] = [];
  const bindings: string[] = [];
  await expect(
    withManagementCompletionBearer({
      target,
      authority,
      jwks: value.jwks,
      setupRequest: value.setupRequest,
      fetch: value.fetch,
      captureOwnedApplication: (id) => owned.push(id),
      bindOwnedApplicationRole: async (applicationId, roleId) => {
        bindings.push(`${applicationId}:${roleId}`);
      },
      use: async (bearer) => bearer.split('.').length === 3,
    })
  ).resolves.toBe(true);
  expect(owned).toEqual(['management-client']);
  expect(bindings).toEqual(['management-client:management-role']);
  expect(value.calls.at(-1)).toMatchObject({
    method: 'DELETE',
    path: 'roles/management-role',
  });
});

test('uses the private admin-tenant fixture lease for Candidate', async () => {
  const value = await fixture(authority.audience, 'aster-mgmt-m2m');
  const tokenUrls: string[] = [];
  let cleaned = false;
  await expect(
    withManagementCompletionBearer({
      target: { ...target, label: 'candidate' },
      authority,
      jwks: value.jwks,
      setupRequest: async () => {
        throw new Error('public setup must not run for Candidate');
      },
      fetch: async (input) => {
        tokenUrls.push(String(input));
        return value.fetch();
      },
      captureOwnedApplication: () => {},
      bindOwnedApplicationRole: async () => {},
      withCandidateManagementMachineClient: async (secret, use) => {
        expect(secret.length).toBeGreaterThanOrEqual(12);
        try {
          return await use({
            clientId: 'aster-mgmt-m2m',
            resource: authority.resource,
            scope: 'all',
            tokenEndpointAuthMethod: 'client_secret_basic',
            grantType: 'client_credentials',
            accessTokenAlg: 'ES384',
            accessTokenType: 'at+jwt',
            accessTokenTtlSeconds: 300,
          });
        } finally {
          cleaned = true;
        }
      },
      use: async () => true,
    })
  ).resolves.toBe(true);
  expect(tokenUrls).toEqual(['https://candidate-admin.example/oidc/token']);
  expect(cleaned).toBe(true);
  expect(value.calls).toEqual([]);
});

test('captures a Reference application before rejecting a malformed create echo', async () => {
  const owned: string[] = [];
  await expect(
    withManagementCompletionBearer({
      target,
      authority,
      jwks: { keys: [] },
      setupRequest: async () => ({
        id: 'created-before-bad-echo',
        name: 'wrong-name',
        type: 'MachineToMachine',
      }),
      captureOwnedApplication: (id) => owned.push(id),
      bindOwnedApplicationRole: async () => {},
      use: async () => true,
    })
  ).rejects.toThrow('Invalid Common Management M2M bearer (application)');
  expect(owned).toEqual(['created-before-bad-echo']);
});

test('rejects a wrong audience and still cleans the role', async () => {
  const value = await fixture('urn:wrong');
  await expect(
    withManagementCompletionBearer({
      target,
      authority,
      jwks: value.jwks,
      setupRequest: value.setupRequest,
      fetch: value.fetch,
      captureOwnedApplication: () => {},
      bindOwnedApplicationRole: async () => {},
      use: async () => true,
    })
  ).rejects.toThrow('Invalid Common Management M2M bearer');
  expect(value.calls.at(-1)).toMatchObject({
    method: 'DELETE',
    path: 'roles/management-role',
  });
});
/* eslint-enable @typescript-eslint/no-empty-function, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
