/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The fake request counter proves the bounded call sequence. */
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import type { TargetConfig } from '../../model.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import {
  createManagementUser,
  createManagementUserMutationObserver,
  readDefaultManagementUserRoleIds,
  readManagementUserRoles,
  updateManagementUser,
  verifyManagementResourceAccess,
} from './management-users.js';

test('projects credential-free Management users and exact default role membership', async () => {
  let callCount = 0;
  let createBody: unknown;
  const request: Phase2AdminRequestFunction = async (input) => {
    callCount += 1;
    if (input.method === 'POST' && input.path === 'users') {
      createBody = input.body;
    }
    if (input.path.endsWith('/roles')) {
      return [{ id: 'default', isDefault: true }];
    }
    const body =
      typeof input.body === 'object' && input.body !== null ? input.body : Object.freeze({});
    const name: unknown = Reflect.get(body, 'name');
    const primaryEmail: unknown = Reflect.get(body, 'primaryEmail');
    const primaryPhone: unknown = Reflect.get(body, 'primaryPhone');
    return Object.freeze({
      id: 'owner',
      name: name ?? null,
      primaryEmail: primaryEmail ?? 'old@example.invalid',
      primaryPhone: primaryPhone ?? null,
      hasPassword: true,
      updatedAt: 2,
    });
  };
  const created = await createManagementUser(request, {
    email: 'new@example.invalid',
    password: 'private',
  });
  expect(created).toEqual({
    id: 'owner',
    name: undefined,
    primaryEmail: 'new@example.invalid',
    primaryPhone: undefined,
    hasPassword: true,
    updatedAt: 2,
  });
  expect(created).not.toHaveProperty('password');
  expect(createBody).toEqual({
    primaryEmail: 'new@example.invalid',
    password: 'private',
  });
  expect(await readManagementUserRoles(request, created.id)).toEqual([
    { id: 'default', isDefault: true },
  ]);
  await expect(
    updateManagementUser(request, { id: created.id, name: 'Updated', phone: '8613000000000' })
  ).resolves.toMatchObject({ id: 'owner', name: 'Updated', primaryPhone: '8613000000000' });
  expect(callCount).toBe(3);
});

test.each(['passwordEncrypted', 'passwordHash', 'mfaVerifications'] as const)(
  'rejects credential-bearing Management user response field %s',
  async (field) => {
    let capturedOwnedId: string | undefined;
    await expect(
      createManagementUser(
        async () => ({
          id: 'owner',
          name: null,
          primaryEmail: 'new@example.invalid',
          primaryPhone: null,
          hasPassword: true,
          [field]: field === 'mfaVerifications' ? [] : 'private',
          updatedAt: 2,
        }),
        { email: 'new@example.invalid', password: 'private' },
        (id) => {
          capturedOwnedId = id;
        }
      )
    ).rejects.toThrow('Invalid Common Management user transport');
    expect(capturedOwnedId).toBe('owner');
  }
);

test('fails closed when the first role page cannot prove completeness', async () => {
  await expect(
    readDefaultManagementUserRoleIds(async () =>
      Array.from({ length: 100 }, (_, index) => ({
        id: `role-${index}`,
        type: 'User',
        isDefault: index === 99,
      }))
    )
  ).rejects.toThrow('Invalid Common Management user transport');
});

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};

test('verifies signed resource access claims against the pinned JWKS', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES384');
  const publicJwk = await exportJWK(publicKey);
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    sub: 'owner',
    client_id: 'client',
    scope: 'read:profile',
  })
    .setProtectedHeader({ alg: 'ES384', kid: 'management-key', typ: 'at+jwt' })
    .setIssuer('https://candidate.example/oidc')
    .setAudience('https://resource.example/')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
  const jwks = { keys: [{ ...publicJwk, kid: 'management-key', use: 'sig', alg: 'ES384' }] };
  await expect(
    verifyManagementResourceAccess(token, jwks, {
      issuer: 'https://candidate.example/oidc',
      audience: 'https://resource.example/',
      subject: 'owner',
      clientId: 'client',
      scope: 'read:profile',
    })
  ).resolves.toBeUndefined();
  await expect(
    verifyManagementResourceAccess(token, jwks, {
      issuer: 'https://candidate.example/oidc',
      audience: 'https://resource.example/',
      subject: 'other',
      clientId: 'client',
      scope: 'read:profile',
    })
  ).rejects.toThrow('Invalid Common Management user transport');
});

test.each([
  ['guard.invalid_input', 400],
  ['auth.unauthorized', 401],
  ['user.email_already_in_use', 422],
  ['user.email_already_in_use', 409],
] as const)(
  'closes Management mutation error %s without response details',
  async (code, status) => {
    await expect(
      createManagementUserMutationObserver(
        target,
        () => new Headers({ authorization: 'Bearer private' }),
        async () => new Response(JSON.stringify({ code, message: 'private detail' }), { status })
      )({
        method: 'PATCH',
        path: 'users/owner',
        body: { primaryEmail: 'invalid' },
      })
    ).resolves.toEqual({ status, error: code });
  }
);
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
