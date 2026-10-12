/* eslint-disable @silverhand/fp/no-mutation, @typescript-eslint/no-unnecessary-condition -- Real signed JWTs and public HTTP state model observable logout and offline preservation outcomes. */
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import type { TargetConfig } from '../../model.js';

import {
  runCommonSessionLogoutPreservation,
  type CommonLogoutPreservationRuntime,
} from './common-session-logout-preservation.js';

const target: TargetConfig = {
  label: 'candidate',
  coreUrl: 'https://identity.example/',
  adminUrl: 'https://admin.example/',
};
const issuer = 'https://identity.example/oidc';
const pair = await generateKeyPair('ES384');
const jwks = {
  keys: [{ ...(await exportJWK(pair.publicKey)), kid: 'owned-key', alg: 'ES384', use: 'sig' }],
};
const json = (body: unknown) =>
  new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } });

const fixture = (foreignNotification = false) => {
  const state = { present: true, attempts: 0, cleaned: 0, posts: 0 };
  const runtime: CommonLogoutPreservationRuntime = {
    withAttempt: async (input, use) => {
      state.attempts += 1;
      state.present = true;
      const now = Math.floor(Date.now() / 1000);
      const idToken = await new SignJWT({
        sub: 'owned-subject',
        sid: 'owned-session',
        nonce: 'private-nonce',
      })
        .setProtectedHeader({ alg: 'ES384', kid: 'owned-key' })
        .setIssuer(issuer)
        .setAudience('owned-client')
        .setIssuedAt(now)
        .setExpirationTime(now + 3600)
        .sign(pair.privateKey);
      const logoutToken = await new SignJWT({
        sub: 'owned-subject',
        sid: foreignNotification ? 'foreign-session' : 'owned-session',
        jti: 'owned-notification-id',
        events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      })
        .setProtectedHeader({ alg: 'ES384', typ: 'logout+jwt', kid: 'owned-key' })
        .setIssuer(issuer)
        .setAudience('owned-client')
        .setIssuedAt(now)
        .setExpirationTime(now + 120)
        .sign(pair.privateKey);
      const consumed = { value: false };
      try {
        return await use(
          {
            subject: 'owned-subject',
            clientId: 'owned-client',
            issuer,
            session: {
              access: 'private-access',
              refresh: 'private-refresh',
              getIdToken: () => idToken,
              getCookieHeader: () => 'aster-session=private-cookie',
              getExpectedNonce: () => 'private-nonce',
              toJSON: (): never => {
                throw new Error('private session');
              },
            },
            withCurrentProof: async (operation) => operation('private-current-proof'),
          },
          {
            consume: async () => {
              if (consumed.value) {
                return;
              }
              consumed.value = true;
              return logoutToken;
            },
            deliveryStatus: async () => (input.delivery === 'accepted' ? 204 : 503),
          }
        );
      } finally {
        state.cleaned += 1;
      }
    },
  };
  const requestFetch: typeof fetch = async (url, init) => {
    const endpoint = new URL(String(url));
    if (endpoint.pathname.startsWith('/api/my-account/sessions')) {
      const headers = new Headers(init?.headers);
      expect(headers.get('authorization')).toBe('Bearer private-access');
      expect(headers.get('aster-verification-id')).toBe('private-current-proof');
      if (init?.method === 'DELETE') {
        expect(endpoint.pathname).toBe('/api/my-account/sessions/owned-session');
        state.present = false;
        return new Response(null, { status: 204 });
      }
      return json({
        sessions: state.present
          ? [
              {
                accountId: 'owned-subject',
                payload: { accountId: 'owned-subject', uid: 'owned-session' },
              },
            ]
          : [],
      });
    }
    if (endpoint.pathname === '/oidc/session/end') {
      expect(new Headers(init?.headers).get('cookie')).toBe('aster-session=private-cookie');
      return new Response(
        '<form method="post" action="/oidc/session/end/confirm"><input name="xsrf" value="private-xsrf"></form>',
        { headers: { 'content-type': 'text/html' } }
      );
    }
    if (endpoint.pathname === '/oidc/session/end/confirm') {
      state.posts += 1;
      state.present = false;
      return new Response(null, {
        status: 303,
        headers: { location: 'https://identity.example/signed-out' },
      });
    }
    if (endpoint.pathname === '/oidc/token') {
      expect(state.present).toBe(false);
      expect(new URLSearchParams(String(init?.body)).get('refresh_token')).toBe('private-refresh');
      return json({
        token_type: 'Bearer',
        access_token: 'private-rotated-access',
        refresh_token: 'private-rotated-refresh',
      });
    }
    if (endpoint.pathname === '/oidc/me') {
      expect(new Headers(init?.headers).get('authorization')).toBe('Bearer private-rotated-access');
      return json({ sub: 'owned-subject' });
    }
    throw new Error('unexpected public operation');
  };
  return { state, runtime, requestFetch };
};

test('Every selected identity removes its exact session while preserving offline grant across RP, failed delivery and Account deletion', async () => {
  const owned = fixture();
  const projection = await runCommonSessionLogoutPreservation({
    target,
    jwks,
    runtime: owned.runtime,
    fetch: owned.requestFetch,
  });
  expect(projection.methods.map(({ method }) => method)).toEqual([
    'google',
    'email-code',
    'wechat-native',
  ]);
  expect(
    projection.methods.every(
      (value) =>
        value.sessionRemoved &&
        value.offlineRefreshRotated &&
        value.failureSessionRemoved &&
        value.failureOfflineRefreshRotated &&
        value.accountSessionRemoved &&
        value.accountOfflineRefreshRotated
    )
  ).toBe(true);
  expect(
    projection.methods.every(
      ({ signedNotification }) =>
        signedNotification.sessionBound &&
        signedNotification.subjectBound &&
        signedNotification.nonceAbsent
    )
  ).toBe(true);
  expect(owned.state.attempts).toBe(9);
  expect(owned.state.cleaned).toBe(9);
  expect(owned.state.posts).toBe(6);
});

test('A correctly signed notification for another session fails the comparison and releases its owned fixture', async () => {
  const owned = fixture(true);
  await expect(
    runCommonSessionLogoutPreservation({
      target,
      jwks,
      runtime: owned.runtime,
      fetch: owned.requestFetch,
    })
  ).rejects.toThrow('Invalid Common signed backchannel logout');
  expect(owned.state.cleaned).toBe(1);
});
/* eslint-enable @silverhand/fp/no-mutation, @typescript-eslint/no-unnecessary-condition */
