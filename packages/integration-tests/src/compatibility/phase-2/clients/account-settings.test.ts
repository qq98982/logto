/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Request capture verifies exact private header/body placement. */
import type { TargetConfig } from '../../model.js';

import {
  createAccountPasswordProof,
  observeAccountPasswordProof,
  updateAccountEmail,
  updateAccountPhone,
  updateAccountPassword,
  verifyAccountEmailProof,
  verifyAccountPhoneProof,
} from './account-settings.js';

const target = (label: 'oracle' | 'candidate'): TargetConfig => ({
  label,
  coreUrl: `https://${label}.example/`,
  adminUrl: `https://${label}-admin.example/`,
});

const response = (status: number, body?: unknown): Response =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    ...(body === undefined ? {} : { headers: { 'content-type': 'application/json' } }),
  });

test.each([
  ['oracle', 'logto-verification-id'],
  ['candidate', 'aster-verification-id'],
] as const)(
  'keeps the %s current proof private and sends its exact header',
  async (label, header) => {
    const requests: Array<Readonly<{ url: URL; init: RequestInit }>> = [];
    const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
      requests.push({ url: new URL(String(input)), init: init ?? {} });
      return requests.length === 1
        ? response(201, { verificationRecordId: 'private-current-proof' })
        : response(204);
    }) as typeof fetch;
    const result = await createAccountPasswordProof(
      { target: target(label), bearer: 'private-bearer', password: 'private-password' },
      async (lease) => {
        expect(() => JSON.stringify(lease)).toThrow('Invalid Common Account settings transport');
        return updateAccountPassword(
          {
            target: target(label),
            bearer: 'private-bearer',
            password: 'private-new-password',
            verificationRecordId: lease.getVerificationRecordId(),
          },
          requestFetch
        );
      },
      requestFetch
    );
    expect(result).toEqual({ status: 204, error: 'none' });
    expect(requests.map(({ url }) => url.pathname)).toEqual([
      '/api/verifications/password',
      '/api/my-account/password',
    ]);
    expect(new Headers(requests[1]?.init.headers).get(header)).toBe('private-current-proof');
    expect(new Headers(requests[1]?.init.headers).get('authorization')).toBe(
      'Bearer private-bearer'
    );
  }
);

test('sends separate current and destination proofs for email change', async () => {
  let request: Readonly<{ url: URL; init: RequestInit }> | undefined;
  const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    request = { url: new URL(String(input)), init: init ?? {} };
    return response(422, { code: 'user.email_already_in_use' });
  }) as typeof fetch;
  const result = await updateAccountEmail(
    {
      target: target('candidate'),
      bearer: 'private-bearer',
      email: 'new@example.invalid',
      currentVerificationRecordId: 'private-current-proof',
      destinationVerificationRecordId: 'private-destination-proof',
    },
    requestFetch
  );
  expect(result).toEqual({ status: 422, error: 'user.email_already_in_use' });
  expect(request?.url.pathname).toBe('/api/my-account/primary-email');
  expect(new Headers(request?.init.headers).get('aster-verification-id')).toBe(
    'private-current-proof'
  );
  expect(JSON.parse(String(request?.init.body))).toEqual({
    email: 'new@example.invalid',
    newIdentifierVerificationRecordId: 'private-destination-proof',
  });
});

test('uses the public verificationId wire field for destination email proof', async () => {
  let body: unknown;
  const requestFetch = (async (_input: URL | RequestInfo, init?: RequestInit) => {
    body = JSON.parse(String(init?.body));
    return response(200);
  }) as typeof fetch;

  await expect(
    verifyAccountEmailProof(
      {
        target: target('oracle'),
        bearer: 'private-bearer',
        email: 'new@example.invalid',
        code: 'private-code',
        verificationRecordId: 'private-record',
      },
      requestFetch
    )
  ).resolves.toEqual({ status: 200, error: 'none' });
  expect(body).toEqual({
    identifier: { type: 'email', value: 'new@example.invalid' },
    verificationId: 'private-record',
    code: 'private-code',
  });
  expect(body).not.toHaveProperty('verificationRecordId');
});

test('uses phone destination proof and mutation wire contracts', async () => {
  const requests: Array<Readonly<{ url: URL; init: RequestInit }>> = [];
  const requestFetch = (async (input: URL | RequestInfo, init?: RequestInit) => {
    requests.push({ url: new URL(String(input)), init: init ?? {} });
    return response(requests.length === 1 ? 200 : 422, {
      ...(requests.length === 1 ? {} : { code: 'user.phone_already_in_use' }),
    });
  }) as typeof fetch;

  await expect(
    verifyAccountPhoneProof(
      {
        target: target('candidate'),
        bearer: 'private-bearer',
        phone: '8613000000000',
        code: 'private-code',
        verificationRecordId: 'private-destination-proof',
      },
      requestFetch
    )
  ).resolves.toEqual({ status: 200, error: 'none' });
  await expect(
    updateAccountPhone(
      {
        target: target('candidate'),
        bearer: 'private-bearer',
        phone: '8613000000000',
        currentVerificationRecordId: 'private-current-proof',
        destinationVerificationRecordId: 'private-destination-proof',
      },
      requestFetch
    )
  ).resolves.toEqual({ status: 422, error: 'user.phone_already_in_use' });
  expect(requests.map(({ url }) => url.pathname)).toEqual([
    '/api/verifications/verification-code/verify',
    '/api/my-account/primary-phone',
  ]);
  expect(JSON.parse(String(requests[0]?.init.body))).toEqual({
    identifier: { type: 'phone', value: '8613000000000' },
    verificationId: 'private-destination-proof',
    code: 'private-code',
  });
  expect(JSON.parse(String(requests[1]?.init.body))).toEqual({
    phone: '8613000000000',
    newIdentifierVerificationRecordId: 'private-destination-proof',
  });
  expect(new Headers(requests[1]?.init.headers).get('aster-verification-id')).toBe(
    'private-current-proof'
  );
});

test('maps only closed public Account errors', async () => {
  const requestFetch = (async () =>
    response(500, { code: 'private.secret.detail' })) as typeof fetch;
  await expect(
    updateAccountPassword(
      { target: target('oracle'), bearer: 'private-bearer', password: 'private-password' },
      requestFetch
    )
  ).resolves.toEqual({ status: 500, error: 'unknown' });
});

test('observes old-password invalid credentials without treating transport failures as rejection', async () => {
  const rejected = (async () =>
    response(401, { code: 'session.invalid_credentials' })) as typeof fetch;
  await expect(
    observeAccountPasswordProof(
      { target: target('oracle'), bearer: 'private-bearer', password: 'private-old-password' },
      rejected
    )
  ).resolves.toEqual({ status: 401, error: 'session.invalid_credentials' });
  const unavailable = (async () => {
    throw new Error('private network detail');
  }) as typeof fetch;
  await expect(
    observeAccountPasswordProof(
      { target: target('oracle'), bearer: 'private-bearer', password: 'private-old-password' },
      unavailable
    )
  ).rejects.toThrow('private network detail');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
