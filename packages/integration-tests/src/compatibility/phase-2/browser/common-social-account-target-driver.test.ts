/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- Hostile partial fixtures prove admission occurs before capability use. */
import {
  createOwnedGoogleUser,
  runCommonSocialAccountForTarget,
  runIndependentSocialCleanup,
  withOwnedGoogleCurrentProof,
  withOwnedSocialCollisionUser,
} from './common-social-account-target-driver.js';

const target = {
  label: 'candidate' as const,
  coreUrl: 'https://core.test/',
  adminUrl: 'https://admin.test/',
};

test('rejects an aborted social Account target before discovery or fixture authority', async () => {
  const calls: string[] = [];
  const fetchMock: typeof fetch = async () => {
    calls.push('fetch');
    throw new Error('must not fetch');
  };
  await expect(
    runCommonSocialAccountForTarget({
      id: 'common.account.google-link',
      target,
      fixture: {} as never,
      signal: AbortSignal.abort(),
      jwks: { keys: [] },
      fetch: fetchMock,
    })
  ).rejects.toThrow('Invalid Common social Account target composition');
  expect(calls).toEqual([]);
});

test('rejects a missing provider runtime before opening a credential lease', async () => {
  const calls: string[] = [];
  const fetchMock: typeof fetch = async () => {
    calls.push('fetch');
    throw new Error('must not fetch');
  };
  await expect(
    runCommonSocialAccountForTarget({
      id: 'common.account.wechat-link',
      target,
      fixture: { status: { client: {} } } as never,
      signal: new AbortController().signal,
      jwks: { keys: [] },
      fetch: fetchMock,
    })
  ).rejects.toThrow('Invalid Common social Account target composition');
  expect(calls).toEqual([]);
});

test('releases a collision identity by deleting only its owned user after failed use', async () => {
  const requests: Array<Readonly<{ method: string; path: string }>> = [];
  await expect(
    withOwnedSocialCollisionUser(
      async (request) => {
        requests.push({ method: request.method, path: request.path });
        return request.method === 'POST' ? { id: 'owned-collision-user' } : 204;
      },
      async (ownerId) => {
        expect(ownerId).toBe('owned-collision-user');
        throw new Error('collision assertion failed');
      }
    )
  ).rejects.toThrow('collision assertion failed');
  expect(requests).toEqual([
    { method: 'POST', path: 'users' },
    { method: 'DELETE', path: 'users/owned-collision-user' },
  ]);
});

test('always removes its owned social user when provider or policy restoration fails', async () => {
  const calls: string[] = [];
  await expect(
    runIndependentSocialCleanup(
      async () => {
        calls.push('restore');
        throw new Error('private restoration error');
      },
      async () => {
        calls.push('delete-owned-user');
      }
    )
  ).rejects.toThrow('Owned social cleanup failed');
  expect(calls).toEqual(['restore', 'delete-owned-user']);
});

test('uses the owned Google user password as current Account permission proof', async () => {
  const requests: Array<
    Readonly<{ path: string; authorization: string | undefined; body: unknown }>
  > = [];
  const result = await withOwnedGoogleCurrentProof(
    { target, bearer: 'opaque-owner-access', password: 'private-password' },
    async (proofId) => proofId === 'password-proof',
    async (input, init) => {
      const url = new URL(input instanceof Request ? input.url : input);
      requests.push({
        path: url.pathname,
        authorization: new Headers(init?.headers).get('authorization') ?? undefined,
        body: JSON.parse(String(init?.body)),
      });
      return new Response(JSON.stringify({ verificationRecordId: 'password-proof' }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      });
    }
  );
  expect(result).toBe(true);
  expect(requests).toEqual([
    {
      path: '/api/verifications/password',
      authorization: 'Bearer opaque-owner-access',
      body: { password: 'private-password' },
    },
  ]);
});

test('creates the owned Google user with its provider email and current-proof password', async () => {
  const requests: unknown[] = [];
  const userId = await createOwnedGoogleUser(
    async (request) => {
      requests.push(request);
      return { id: 'owned-google-user' };
    },
    'owner@example.invalid',
    'private-password'
  );
  expect(userId).toBe('owned-google-user');
  expect(requests).toEqual([
    {
      method: 'POST',
      path: 'users',
      body: { primaryEmail: 'owner@example.invalid', password: 'private-password' },
      expectedStatuses: [200, 201],
      responseKind: 'object',
    },
  ]);
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
