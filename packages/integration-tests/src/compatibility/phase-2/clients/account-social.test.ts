/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, @typescript-eslint/no-loop-func, unicorn/consistent-function-scoping -- Request capture proves header and proof ownership without exposing credentials. */
import { inspect } from 'node:util';

import type { TargetConfig } from '../../model.js';

import {
  observeAccountSocialMutation,
  readAccountSocialProfile,
  withAccountSocialProof,
} from './account-social.js';

const target = (label: 'oracle' | 'candidate'): TargetConfig => ({
  label,
  coreUrl: 'https://core.example/',
  adminUrl: 'https://admin.example/',
});
const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

test('Account social verification uses the owned callback and a private expiring proof lease', async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  let saved: { getVerificationRecordId(): string } | undefined;
  const requestFetch: typeof fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return calls.length === 1
      ? json(
          {
            verificationRecordId: 'private-proof',
            authorizationUri: 'https://accounts.google.com/authorize',
            expiresAt: new Date(Date.now() + 300_000).toISOString(),
          },
          201
        )
      : json({ verificationRecordId: 'private-proof' });
  };
  const value = await withAccountSocialProof(
    {
      target: target('candidate'),
      bearer: 'private-access',
      connectorId: 'owned-connector',
      redirectUri: 'https://client.example/callback',
      takeProviderCode: async (uri, state) => {
        expect(uri).toBe('https://accounts.google.com/authorize');
        expect(state).toMatch(/^[A-Za-z0-9_-]+$/u);
        return 'private-provider-code';
      },
    },
    async (proof) => {
      saved = proof;
      expect(proof.getVerificationRecordId()).toBe('private-proof');
      expect(inspect(proof)).not.toContain('private-proof');
      expect(() => JSON.stringify(proof)).toThrow();
      return true;
    },
    requestFetch
  );
  expect(value).toBe(true);
  expect(() => saved?.getVerificationRecordId()).toThrow();
  expect(calls.map(({ url }) => new URL(url).pathname)).toEqual([
    '/api/verifications/social',
    '/api/verifications/social/verify',
  ]);
  expect(JSON.parse(String(calls[1]?.init?.body))).toEqual({
    verificationRecordId: 'private-proof',
    connectorData: {
      code: 'private-provider-code',
      redirectUri: 'https://client.example/callback',
    },
  });
  expect(
    calls.every(
      ({ init }) => new Headers(init?.headers).get('authorization') === 'Bearer private-access'
    )
  ).toBe(true);
});

test('Account social link keeps current permission distinct from its destination proof on both targets', async () => {
  for (const label of ['oracle', 'candidate'] as const) {
    const requestFetch: typeof fetch = async (url, init) => {
      const headers = new Headers(init?.headers);
      expect(new URL(String(url)).pathname).toBe('/api/my-account/identities');
      expect(headers.get(`${label === 'oracle' ? 'logto' : 'aster'}-verification-id`)).toBe(
        'private-current'
      );
      expect(JSON.parse(String(init?.body))).toEqual({
        newIdentifierVerificationRecordId: 'private-destination',
      });
      return new Response(null, { status: 204 });
    };
    expect(
      await observeAccountSocialMutation(
        {
          target: target(label),
          bearer: 'private-access',
          operation: 'link',
          provider: 'google',
          permissionId: 'private-current',
          destinationProofId: 'private-destination',
        },
        requestFetch
      )
    ).toEqual({ status: 204, error: 'none' });
  }
});

test('Account social denials preserve exact public status and error while refusing raw payload publication', async () => {
  const requestFetch: typeof fetch = async () =>
    json({ code: 'user.identity_already_in_use', providerToken: 'private-provider-token' }, 422);
  expect(
    await observeAccountSocialMutation(
      {
        target: target('candidate'),
        bearer: 'private-access',
        operation: 'unlink',
        provider: 'wechat',
        permissionId: 'private-current',
      },
      requestFetch
    )
  ).toEqual({ status: 422, error: 'user.identity_already_in_use' });
});

test('Account social profile compares the selected authority and rejects credential-bearing output', async () => {
  const requestFetch: typeof fetch = async () =>
    json({
      id: 'owner',
      identities: { google: { userId: 'selected-subject' }, wechat: { userId: 'other-subject' } },
      passwordHash: 'private-hash',
    });
  expect(
    await readAccountSocialProfile(
      {
        target: target('candidate'),
        bearer: 'private-access',
        provider: 'google',
        expectedOwner: 'owner',
        expectedSocialSubject: 'selected-subject',
      },
      requestFetch
    )
  ).toEqual({ status: 200, ownerMatches: true, identityMatches: true, credentialsAbsent: false });
  expect(
    await readAccountSocialProfile(
      {
        target: target('candidate'),
        bearer: 'private-access',
        provider: 'wechat',
        expectedOwner: 'owner',
        expectedSocialSubject: 'selected-subject',
      },
      requestFetch
    )
  ).toEqual({ status: 200, ownerMatches: true, identityMatches: false, credentialsAbsent: false });
});

test('Failed or expired provider verification never hands out an Account destination proof', async () => {
  let used = false;
  const requestFetch: typeof fetch = async () =>
    json(
      {
        verificationRecordId: 'private-proof',
        authorizationUri: 'https://accounts.google.com/authorize',
        expiresAt: new Date(0).toISOString(),
      },
      201
    );
  await expect(
    withAccountSocialProof(
      {
        target: target('candidate'),
        bearer: 'private-access',
        connectorId: 'owned-connector',
        redirectUri: 'https://client.example/callback',
        takeProviderCode: async () => 'private-code',
      },
      async () => {
        used = true;
      },
      requestFetch
    )
  ).rejects.toThrow('Invalid Common Account social transport');
  expect(used).toBe(false);
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, @typescript-eslint/no-loop-func, unicorn/consistent-function-scoping */
