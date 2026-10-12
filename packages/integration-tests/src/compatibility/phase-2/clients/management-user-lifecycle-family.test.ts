import {
  observeActiveUserInfo,
  observeRevokedRefresh,
  observeRevokedUserInfo,
} from './management-user-lifecycle-family.js';

const target = {
  label: 'candidate' as const,
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};
const fetcher: typeof fetch = async (input: URL | RequestInfo) =>
  new Response(
    JSON.stringify({
      error: String(input).includes('/me') ? 'invalid_token' : 'invalid_grant',
    }),
    { status: String(input).includes('/me') ? 401 : 400 }
  );
test('projects only public revocation status and code', async () => {
  await expect(observeRevokedUserInfo(target, 'opaque-access', fetcher)).resolves.toEqual({
    status: 401,
    code: 'invalid_token',
  });
  await expect(
    observeRevokedRefresh(
      target,
      { status: { client: { id: 'client' } } } as never,
      'opaque-refresh',
      fetcher
    )
  ).resolves.toEqual({ status: 400, code: 'invalid_grant' });
});

test('binds a fresh UserInfo response to the expected public subject', async () => {
  await expect(
    observeActiveUserInfo(
      target,
      'fresh-access',
      async () => new Response(JSON.stringify({ sub: 'owned-user' }), { status: 200 })
    )
  ).resolves.toEqual({ status: 200, subject: 'owned-user' });
  await expect(
    observeActiveUserInfo(
      target,
      'fresh-access',
      async () => new Response(JSON.stringify({ sub: 'owned-user' }), { status: 401 })
    )
  ).rejects.toThrow('Invalid Common Management lifecycle family transport');
});
