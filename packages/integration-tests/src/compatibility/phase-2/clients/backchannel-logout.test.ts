import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { verifyCommonBackchannelLogout } from './backchannel-logout.js';

const now = 2_000_000_000;
const issuer = 'https://identity.example/oidc';
const identity = {
  subject: 'owned-subject',
  sessionId: 'owned-session',
  toJSON: (): never => {
    throw new Error('private identity');
  },
};
const keys = await generateKeyPair('ES384');
const publicKey = {
  ...(await exportJWK(keys.publicKey)),
  kid: 'owned-key',
  alg: 'ES384',
  use: 'sig',
};
const jwks = { keys: [publicKey] };
const signed = async (overrides: Record<string, unknown> = {}, typ = 'logout+jwt') =>
  new SignJWT({
    sub: identity.subject,
    sid: identity.sessionId,
    jti: 'owned-message-identifier',
    iat: now,
    exp: now + 120,
    events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    ...overrides,
  })
    .setProtectedHeader({ alg: 'ES384', typ, kid: publicKey.kid })
    .setIssuer(issuer)
    .setAudience('owned-client')
    .sign(keys.privateKey);

test('Backchannel notification verifies same-target signature and exact client, owner, SID and event', async () => {
  expect(
    await verifyCommonBackchannelLogout({
      token: await signed(),
      jwks,
      issuer,
      clientId: 'owned-client',
      identity,
      now,
    })
  ).toEqual({
    algorithm: 'ES384',
    tokenType: 'logout+jwt',
    issuerBound: true,
    audienceBound: true,
    subjectBound: true,
    sessionBound: true,
    eventBound: true,
    nonceAbsent: true,
    uniqueIdentifierPresent: true,
    lifetimeSeconds: 120,
  });
});

test.each([
  { sid: 'foreign-session' },
  { sub: 'foreign-subject' },
  { nonce: 'forbidden-nonce' },
  { exp: now + 121 },
  { iat: now + 60, exp: now + 180 },
  { jti: '' },
  { events: {} },
  { events: { 'http://schemas.openid.net/event/backchannel-logout': { data: 'forbidden' } } },
  { privateToken: 'forbidden-extension' },
])(
  'Backchannel notification rejects a signed but unbound or malformed payload %j',
  async (overrides) => {
    await expect(
      verifyCommonBackchannelLogout({
        token: await signed(overrides),
        jwks,
        issuer,
        clientId: 'owned-client',
        identity,
        now,
      })
    ).rejects.toThrow('Invalid Common signed backchannel logout');
  }
);

test('Backchannel notification rejects foreign key, issuer, audience and JWT type', async () => {
  const token = await signed();
  await expect(
    verifyCommonBackchannelLogout({
      token,
      jwks: { keys: [] },
      issuer,
      clientId: 'owned-client',
      identity,
      now,
    })
  ).rejects.toThrow();
  await expect(
    verifyCommonBackchannelLogout({
      token,
      jwks,
      issuer: 'https://foreign.example/oidc',
      clientId: 'owned-client',
      identity,
      now,
    })
  ).rejects.toThrow();
  await expect(
    verifyCommonBackchannelLogout({
      token,
      jwks,
      issuer,
      clientId: 'foreign-client',
      identity,
      now,
    })
  ).rejects.toThrow();
  await expect(
    verifyCommonBackchannelLogout({
      token: await signed({}, 'JWT'),
      jwks,
      issuer,
      clientId: 'owned-client',
      identity,
      now,
    })
  ).rejects.toThrow();
});
