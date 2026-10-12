/* eslint-disable @silverhand/fp/no-mutating-methods -- The request journal proves the identity entry order and rejected-proof stop point. */
import { createEmailCodeIdentityDriver } from './email-code-identity.js';

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });

test('binds the delivered email code to its requested handle before identification', async () => {
  const requests: Array<Readonly<{ path: string; body: unknown }>> = [];
  const recipients: string[] = [];
  await createEmailCodeIdentityDriver({
    email: 'owned@example.invalid',
    takeCode: async (email) => {
      recipients.push(email);
      return '123456';
    },
  })({
    request: async (path, _method, body) => {
      requests.push({ path, body });
      return path.endsWith('verification-code') || path.endsWith('/verify')
        ? json({ verificationId: 'owned-private-proof' })
        : new Response(null, { status: 204 });
    },
  });
  expect(recipients).toEqual(['owned@example.invalid']);
  expect(requests.map(({ path }) => path)).toEqual([
    '/api/experience',
    '/api/experience/verification/verification-code',
    '/api/experience/verification/verification-code/verify',
    '/api/experience/identification',
  ]);
  expect(requests[2]?.body).toEqual({
    identifier: { type: 'email', value: 'owned@example.invalid' },
    verificationId: 'owned-private-proof',
    code: '123456',
  });
  expect(requests[3]?.body).toEqual({ verificationId: 'owned-private-proof' });
});

test.each(['foreign-private-proof', undefined])(
  'refuses identification when verification does not return the owned handle (%s)',
  async (returned) => {
    const paths: string[] = [];
    await expect(
      createEmailCodeIdentityDriver({
        email: 'owned@example.invalid',
        takeCode: async () => '123456',
      })({
        request: async (path) => {
          paths.push(path);
          if (path === '/api/experience') {
            return new Response(null, { status: 204 });
          }
          return json({
            verificationId: path.endsWith('/verify') ? returned : 'owned-private-proof',
          });
        },
      })
    ).rejects.toThrow();
    expect(paths).not.toContain('/api/experience/identification');
  }
);
/* eslint-enable @silverhand/fp/no-mutating-methods */
