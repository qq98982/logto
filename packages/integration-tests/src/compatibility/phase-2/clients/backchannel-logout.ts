import { inspect } from 'node:util';

import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

import type { IssuedPublicUserSession } from './user-token-issuance.js';

export type BoundLogoutIdentity = Readonly<{
  subject: string;
  sessionId: string;
  toJSON(): never;
}>;
export type BackchannelLogoutProjection = Readonly<{
  algorithm: 'ES384';
  tokenType: 'logout+jwt';
  issuerBound: true;
  audienceBound: true;
  subjectBound: true;
  sessionBound: true;
  eventBound: true;
  nonceAbsent: true;
  uniqueIdentifierPresent: true;
  lifetimeSeconds: 120;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Common signed backchannel logout');
};
const bounded = (value: unknown, max = 16_384): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= max ? value : fail();

export const verifyBoundLogoutIdentity = async (
  input: Readonly<{
    session: IssuedPublicUserSession;
    jwks: Readonly<JSONWebKeySet>;
    issuer: string;
    clientId: string;
    subject: string;
    now?: number;
  }>
): Promise<BoundLogoutIdentity> => {
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const verified = await jwtVerify(
    bounded(input.session.getIdToken()),
    createLocalJWKSet(input.jwks),
    {
      algorithms: ['ES384'],
      issuer: bounded(input.issuer),
      audience: bounded(input.clientId),
      currentDate: new Date(now * 1000),
      requiredClaims: ['sub', 'sid', 'iat', 'exp'],
    }
  ).catch(fail);
  if (
    verified.payload.sub !== input.subject ||
    typeof verified.payload.iat !== 'number' ||
    verified.payload.iat > now + 15 ||
    !input.session.getExpectedNonce ||
    verified.payload.nonce !== input.session.getExpectedNonce()
  ) {
    return fail();
  }
  const sessionId = bounded(verified.payload.sid, 128);
  return Object.freeze({
    subject: input.subject,
    sessionId,
    toJSON: fail,
    [inspect.custom]: () => 'BoundLogoutIdentity(<redacted>)',
  });
};

// eslint-disable-next-line complexity -- All signed logout bindings are checked together before publication.
export const verifyCommonBackchannelLogout = async (
  input: Readonly<{
    token: string;
    jwks: Readonly<JSONWebKeySet>;
    issuer: string;
    clientId: string;
    identity: BoundLogoutIdentity;
    now?: number;
  }>
): Promise<BackchannelLogoutProjection> => {
  const now = input.now ?? Math.floor(Date.now() / 1000);
  const verified = await jwtVerify(bounded(input.token), createLocalJWKSet(input.jwks), {
    algorithms: ['ES384'],
    issuer: bounded(input.issuer),
    audience: bounded(input.clientId),
    currentDate: new Date(now * 1000),
    requiredClaims: ['sub', 'sid', 'jti', 'iat', 'exp', 'events'],
  }).catch(fail);
  const { payload, protectedHeader } = verified;
  const events: unknown = Reflect.get(payload, 'events');
  const event: unknown =
    typeof events === 'object' && events !== null && !Array.isArray(events)
      ? Reflect.get(events, 'http://schemas.openid.net/event/backchannel-logout')
      : undefined;
  if (
    protectedHeader.typ !== 'logout+jwt' ||
    payload.sub !== input.identity.subject ||
    payload.sid !== input.identity.sessionId ||
    payload.aud !== input.clientId ||
    typeof payload.iat !== 'number' ||
    typeof payload.exp !== 'number' ||
    !Number.isSafeInteger(payload.iat) ||
    payload.iat > now + 15 ||
    payload.exp - payload.iat !== 120 ||
    Object.hasOwn(payload, 'nonce') ||
    typeof payload.jti !== 'string' ||
    !/^[A-Za-z0-9._~-]{8,128}$/u.test(payload.jti) ||
    typeof events !== 'object' ||
    events === null ||
    Object.keys(events).length !== 1 ||
    typeof event !== 'object' ||
    event === null ||
    Array.isArray(event) ||
    Object.keys(event).length > 0 ||
    Object.keys(payload).some(
      (key) => !['iss', 'aud', 'sub', 'sid', 'jti', 'iat', 'exp', 'events'].includes(key)
    )
  ) {
    return fail();
  }
  return Object.freeze({
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
};
