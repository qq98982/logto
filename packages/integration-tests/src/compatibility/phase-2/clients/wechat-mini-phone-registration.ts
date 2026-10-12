/* eslint-disable max-lines, max-params -- The request assertions keep the observed sequences explicit. */
import { isDeepStrictEqual } from 'node:util';

import type { CommonExperienceSession } from './common-experience.js';

const fail = (stage: string): never => {
  throw new TypeError(`WeChat Mini phone registration failed: ${stage}`);
};

const value = (record: Readonly<Record<string, unknown>>, key: string): string => {
  const item = record[key];
  return typeof item === 'string' && item.length > 0 && Buffer.byteLength(item) <= 4096
    ? item
    : fail(key);
};
const status = async (
  session: CommonExperienceSession,
  path: string,
  method: 'GET' | 'POST' | 'PUT',
  expected: number,
  body?: Readonly<Record<string, unknown>>
) => {
  const response = await session.request(path, method, body);
  if (response.getStatus() !== expected) {
    fail(path);
  }
  return response;
};
const miniAuthorization = async (
  input: Readonly<{
    session: CommonExperienceSession;
    connectorId: string;
    providerRedirectUri: string;
    providerState: string;
  }>
) => {
  const authorization = await status(
    input.session,
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/authorization-uri`,
    'POST',
    200,
    { redirectUri: input.providerRedirectUri, state: input.providerState }
  );
  if (value(authorization.getRecord(), 'authorizationUri') !== 'box-ai-wechat-mini://authorize') {
    fail('authorization-uri');
  }
  return value(authorization.getRecord(), 'verificationId');
};

/** Executes the observed 13-call Mini registration sequence over the real cookie-bound transport. */
export const runWechatMiniPhoneRegistration = async (
  input: Readonly<{
    session: CommonExperienceSession;
    authorizationPath: string;
    connectorId: string;
    providerRedirectUri: string;
    providerState: string;
    providerCode: string;
    phone: string;
    callbackScheme: 'box-ai-wechat-mini:';
    armPhoneCode(): Promise<void>;
    getPhoneCode(): Promise<string>;
  }>
) => {
  await status(input.session, input.authorizationPath, 'GET', 303);
  await status(input.session, '/api/experience', 'PUT', 204, { interactionEvent: 'SignIn' });
  const socialId = await miniAuthorization(input);
  await status(
    input.session,
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
    'POST',
    200,
    { verificationId: socialId, connectorData: { code: input.providerCode } }
  );
  const missing = await input.session.request('/api/experience/identification', 'POST', {
    verificationId: socialId,
  });
  if (missing.getStatus() !== 404 || missing.getRecord().code !== 'user.identity_not_exist') {
    fail('social-identification');
  }
  await status(input.session, '/api/experience/interaction-event', 'PUT', 204, {
    interactionEvent: 'Register',
  });
  await status(input.session, '/api/experience/profile', 'POST', 204, {
    type: 'social',
    verificationId: socialId,
  });
  await input.armPhoneCode();
  const phoneRequest = await status(
    input.session,
    '/api/experience/verification/verification-code',
    'POST',
    200,
    { interactionEvent: 'Register', identifier: { type: 'phone', value: input.phone } }
  );
  const phoneId = value(phoneRequest.getRecord(), 'verificationId');
  const code = await input.getPhoneCode();
  if (!/^\d{6}$/u.test(code)) {
    fail('phone-code');
  }
  await status(
    input.session,
    '/api/experience/verification/verification-code/verify',
    'POST',
    200,
    { verificationId: phoneId, code, identifier: { type: 'phone', value: input.phone } }
  );
  await status(input.session, '/api/experience/profile', 'POST', 204, {
    type: 'phone',
    verificationId: phoneId,
  });
  await status(input.session, '/api/experience/identification', 'POST', 201, {});
  const submitted = await status(input.session, '/api/experience/submit', 'POST', 200);
  const redirectTo = value(submitted.getRecord(), 'redirectTo');
  const resumed = await status(input.session, redirectTo, 'GET', 303);
  const location = resumed.getLocation();
  if (!location || new URL(location).protocol !== input.callbackScheme) {
    fail('oidc-resume');
  }
  return Object.freeze({
    calls: 13 as const,
    registered: true as const,
    unionIdRequired: true as const,
    callbackScheme: input.callbackScheme,
  });
};

export const runWechatMiniExistingOwner = async (
  input: Readonly<{
    session: CommonExperienceSession;
    authorizationPath: string;
    connectorId: string;
    providerRedirectUri: string;
    providerState: string;
    providerCode: string;
  }>
) => {
  await status(input.session, input.authorizationPath, 'GET', 303);
  await status(input.session, '/api/experience', 'PUT', 204, { interactionEvent: 'SignIn' });
  const socialId = await miniAuthorization(input);
  await status(
    input.session,
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
    'POST',
    200,
    { verificationId: socialId, connectorData: { code: input.providerCode } }
  );
  await status(input.session, '/api/experience/identification', 'POST', 204, {
    verificationId: socialId,
  });
  return Object.freeze({
    calls: 5 as const,
    existingOwner: true as const,
    unionIdRequired: true as const,
  });
};

export type WechatMiniProviderControlKind = 'noUnionId' | 'invalidCode' | 'malformedProvider';
export const runWechatMiniProviderControl = async (
  input: Readonly<{
    session: CommonExperienceSession;
    authorizationPath: string;
    connectorId: string;
    providerRedirectUri: string;
    providerState: string;
    providerCode: string;
    kind: WechatMiniProviderControlKind;
  }>
) => {
  await status(input.session, input.authorizationPath, 'GET', 303);
  await status(input.session, '/api/experience', 'PUT', 204, { interactionEvent: 'SignIn' });
  const verificationId = await miniAuthorization(input);
  const response = await input.session.request(
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
    'POST',
    { verificationId, connectorData: { code: input.providerCode } }
  );
  const expected =
    input.kind === 'noUnionId'
      ? { status: 400, error: 'connector.wechat_unionid_required' as const }
      : input.kind === 'malformedProvider'
        ? { status: 400, error: 'connector.invalid_response' as const }
        : { status: 401, error: 'connector.social_auth_code_invalid' as const };
  if (response.getStatus() !== expected.status || response.getRecord().code !== expected.error) {
    fail(`provider-${input.kind}`);
  }
  return Object.freeze({ ...expected, accepted: false as const });
};

export const runWechatMiniProviderReplay = async (
  input: Readonly<{
    firstSession: CommonExperienceSession;
    replaySession: CommonExperienceSession;
    firstAuthorizationPath: string;
    replayAuthorizationPath: string;
    connectorId: string;
    providerRedirectUri: string;
    providerState: string;
    providerCode: string;
  }>
) => {
  const initialize = async (session: CommonExperienceSession, authorizationPath: string) => {
    await status(session, authorizationPath, 'GET', 303);
    await status(session, '/api/experience', 'PUT', 204, { interactionEvent: 'SignIn' });
    return miniAuthorization({ ...input, session });
  };
  const firstId = await initialize(input.firstSession, input.firstAuthorizationPath);
  await status(
    input.firstSession,
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
    'POST',
    200,
    { verificationId: firstId, connectorData: { code: input.providerCode } }
  );
  const replayId = await initialize(input.replaySession, input.replayAuthorizationPath);
  const replay = await input.replaySession.request(
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
    'POST',
    { verificationId: replayId, connectorData: { code: input.providerCode } }
  );
  if (
    replay.getStatus() !== 401 ||
    replay.getRecord().code !== 'connector.social_auth_code_invalid'
  ) {
    fail('provider-replay');
  }
  return Object.freeze({
    firstStatus: 200 as const,
    status: 401 as const,
    error: 'connector.social_auth_code_invalid' as const,
    accepted: false as const,
  });
};

export const runWechatMiniCrossInteractionControl = async (
  input: Readonly<{
    ownerSession: CommonExperienceSession;
    foreignSession: CommonExperienceSession;
    ownerAuthorizationPath: string;
    foreignAuthorizationPath: string;
    connectorId: string;
    providerRedirectUri: string;
    providerState: string;
    providerCode: string;
  }>
) => {
  const initialize = async (session: CommonExperienceSession, authorizationPath: string) => {
    await status(session, authorizationPath, 'GET', 303);
    await status(session, '/api/experience', 'PUT', 204, { interactionEvent: 'SignIn' });
    return miniAuthorization({ ...input, session });
  };
  const ownerVerificationId = await initialize(input.ownerSession, input.ownerAuthorizationPath);
  await initialize(input.foreignSession, input.foreignAuthorizationPath);
  const response = await input.foreignSession.request(
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
    'POST',
    { verificationId: ownerVerificationId, connectorData: { code: input.providerCode } }
  );
  if (
    response.getStatus() !== 404 ||
    response.getRecord().code !== 'session.verification_session_not_found'
  ) {
    fail('cross-interaction');
  }
  return Object.freeze({
    status: 404 as const,
    error: 'session.verification_session_not_found' as const,
    accepted: false as const,
  });
};

export const assertWechatMiniPhoneCollision = async (
  input: Readonly<{
    session: CommonExperienceSession;
    phoneVerificationId: string;
    ownerBefore: unknown;
    foreignOwnerBefore: unknown;
    readOwner(): Promise<unknown>;
    readForeignOwner(): Promise<unknown>;
  }>
) => {
  const response = await input.session.request('/api/experience/profile', 'POST', {
    type: 'phone',
    verificationId: input.phoneVerificationId,
  });
  if (response.getStatus() !== 422 || response.getRecord().code !== 'user.phone_already_in_use') {
    fail('phone-collision');
  }
  const [ownerAfter, foreignOwnerAfter] = await Promise.all([
    input.readOwner(),
    input.readForeignOwner(),
  ]);
  if (
    !isDeepStrictEqual(ownerAfter, input.ownerBefore) ||
    !isDeepStrictEqual(foreignOwnerAfter, input.foreignOwnerBefore)
  ) {
    fail('phone-collision-preservation');
  }
  return Object.freeze({
    status: 422 as const,
    error: 'user.phone_already_in_use' as const,
    partialOwnerCreated: false as const,
    ownersPreserved: true as const,
  });
};

export const prepareWechatMiniPhoneCollision = async (
  input: Readonly<{
    session: CommonExperienceSession;
    authorizationPath: string;
    connectorId: string;
    providerRedirectUri: string;
    providerState: string;
    providerCode: string;
    phone: string;
    armPhoneCode(): Promise<void>;
    getPhoneCode(): Promise<string>;
  }>
) => {
  await status(input.session, input.authorizationPath, 'GET', 303);
  await status(input.session, '/api/experience', 'PUT', 204, { interactionEvent: 'SignIn' });
  const socialId = await miniAuthorization(input);
  await status(
    input.session,
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
    'POST',
    200,
    { verificationId: socialId, connectorData: { code: input.providerCode } }
  );
  const missing = await input.session.request('/api/experience/identification', 'POST', {
    verificationId: socialId,
  });
  if (missing.getStatus() !== 404 || missing.getRecord().code !== 'user.identity_not_exist') {
    fail('collision-social-identification');
  }
  await status(input.session, '/api/experience/interaction-event', 'PUT', 204, {
    interactionEvent: 'Register',
  });
  await status(input.session, '/api/experience/profile', 'POST', 204, {
    type: 'social',
    verificationId: socialId,
  });
  await input.armPhoneCode();
  const phoneRequest = await status(
    input.session,
    '/api/experience/verification/verification-code',
    'POST',
    200,
    { interactionEvent: 'Register', identifier: { type: 'phone', value: input.phone } }
  );
  const phoneVerificationId = value(phoneRequest.getRecord(), 'verificationId');
  const code = await input.getPhoneCode();
  if (!/^\d{6}$/u.test(code)) {
    fail('collision-phone-code');
  }
  await status(
    input.session,
    '/api/experience/verification/verification-code/verify',
    'POST',
    200,
    {
      verificationId: phoneVerificationId,
      code,
      identifier: { type: 'phone', value: input.phone },
    }
  );
  return phoneVerificationId;
};
/* eslint-enable max-lines, max-params */
