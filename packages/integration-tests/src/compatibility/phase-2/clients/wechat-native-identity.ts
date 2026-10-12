/* eslint-disable complexity, max-params, no-restricted-syntax -- Parsed JSON and explicit transport assertions remain bounded and shape-checked before use. */
import { randomUUID } from 'node:crypto';

import type { CommonExperienceSession } from './common-experience.js';
import type { NativeSocialIdentityDriver } from './user-token-issuance.js';

const fail = (): never => {
  throw new TypeError('Invalid Common WeChat Native identity flow');
};
const record = async (response: Response): Promise<Record<string, unknown>> => {
  const text = await response.text();
  if (Buffer.byteLength(text) > 16 * 1024) {
    return fail();
  }
  const value: unknown = JSON.parse(text);
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : fail();
};
const bounded = (value: unknown): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 4096
    ? value
    : fail();

export const createWechatNativeIdentityDriver =
  (
    input: Readonly<{
      connectorId: string;
      redirectUri: string;
      state: string;
      appId: string;
      universalLink: string;
      takeProviderCode(): Promise<string>;
    }>
  ): NativeSocialIdentityDriver =>
  async ({ request }) => {
    const initialized = await request('/api/experience', 'PUT', { interactionEvent: 'SignIn' });
    if (initialized.status !== 204) {
      return fail();
    }
    await initialized.body?.cancel();
    const authorization = await request(
      `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/authorization-uri`,
      'POST',
      { redirectUri: input.redirectUri, state: input.state }
    );
    if (authorization.status !== 200) {
      return fail();
    }
    const authorizationBody = await record(authorization);
    const verificationId = bounded(authorizationBody.verificationId);
    const authorizationUri = new URL(bounded(authorizationBody.authorizationUri));
    if (
      authorizationUri.protocol !== 'wechat:' ||
      authorizationUri.host !== '' ||
      authorizationUri.pathname !== '' ||
      [...authorizationUri.searchParams.keys()].length !== 3 ||
      authorizationUri.searchParams.get('app_id') !== input.appId ||
      authorizationUri.searchParams.getAll('state').length !== 1 ||
      authorizationUri.searchParams.get('state') !== input.state ||
      authorizationUri.searchParams.get('universal_link') !== input.universalLink
    ) {
      return fail();
    }
    const code = bounded(await input.takeProviderCode());
    const verified = await request(
      `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
      'POST',
      { verificationId, connectorData: { code } }
    );
    const verifiedBody = await record(verified);
    if (verified.status !== 200 || bounded(verifiedBody.verificationId) !== verificationId) {
      return fail();
    }
    const identified = await request('/api/experience/identification', 'POST', { verificationId });
    if (identified.status !== 204) {
      return fail();
    }
    await identified.body?.cancel();
  };

const experienceStatus = async (
  session: CommonExperienceSession,
  path: string,
  method: 'GET' | 'POST' | 'PUT',
  expected: number,
  body?: Readonly<Record<string, unknown>>
) => {
  const response = await session.request(path, method, body);
  return response.getStatus() === expected ? response : fail();
};
const initializeNativeVerification = async (
  input: Readonly<{
    session: CommonExperienceSession;
    authorizationPath: string;
    connectorId: string;
    redirectUri: string;
    state: string;
    appId: string;
    universalLink: string;
  }>
) => {
  await experienceStatus(input.session, input.authorizationPath, 'GET', 303);
  await experienceStatus(input.session, '/api/experience', 'PUT', 204, {
    interactionEvent: 'SignIn',
  });
  const response = await experienceStatus(
    input.session,
    `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/authorization-uri`,
    'POST',
    200,
    { redirectUri: input.redirectUri, state: input.state }
  );
  const authorizationUri = new URL(bounded(response.getRecord().authorizationUri));
  if (
    authorizationUri.protocol !== 'wechat:' ||
    authorizationUri.host !== '' ||
    authorizationUri.pathname !== '' ||
    [...authorizationUri.searchParams.keys()].length !== 3 ||
    authorizationUri.searchParams.get('app_id') !== input.appId ||
    authorizationUri.searchParams.getAll('state').length !== 1 ||
    authorizationUri.searchParams.get('state') !== input.state ||
    authorizationUri.searchParams.get('universal_link') !== input.universalLink
  ) {
    return fail();
  }
  return bounded(response.getRecord().verificationId);
};

export type WechatNativeProviderControlProjection = Readonly<{
  noUnionId: Readonly<{ status: 400; error: 'connector.wechat_unionid_required'; accepted: false }>;
  invalidCode: Readonly<{
    status: 401;
    error: 'connector.social_auth_code_invalid';
    accepted: false;
  }>;
  malformedProvider: Readonly<{
    status: 400;
    error: 'connector.invalid_response';
    accepted: false;
  }>;
  replay: Readonly<{
    firstStatus: 200;
    status: 401;
    error: 'connector.social_auth_code_invalid';
    accepted: false;
  }>;
  crossInteraction: Readonly<{
    status: 404;
    error: 'session.verification_session_not_found';
    accepted: false;
  }>;
}>;

export const runWechatNativeProviderControls = async (
  input: Readonly<{
    connectorId: string;
    redirectUri: string;
    appId: string;
    universalLink: string;
    createSession(): CommonExperienceSession;
    authorizationPath(): string;
    takeControlCode(
      kind: 'noUnionId' | 'invalidCode' | 'malformedProvider' | 'replay'
    ): Promise<string>;
  }>
): Promise<WechatNativeProviderControlProjection> => {
  const verify = async <
    const Status extends 400 | 401,
    const ErrorCode extends
      | 'connector.wechat_unionid_required'
      | 'connector.social_auth_code_invalid'
      | 'connector.invalid_response',
  >(
    kind: 'noUnionId' | 'invalidCode' | 'malformedProvider',
    expectedStatus: Status,
    expectedError: ErrorCode
  ) => {
    const session = input.createSession();
    try {
      const verificationId = await initializeNativeVerification({
        ...input,
        session,
        authorizationPath: input.authorizationPath(),
        state: bounded(randomUUID()),
      });
      const response = await session.request(
        `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
        'POST',
        {
          verificationId,
          connectorData: { code: await input.takeControlCode(kind) },
        }
      );
      if (response.getStatus() !== expectedStatus || response.getRecord().code !== expectedError) {
        return fail();
      }
      return Object.freeze({
        status: expectedStatus,
        error: expectedError,
        accepted: false as const,
      });
    } finally {
      session.close();
    }
  };
  const replayCode = await input.takeControlCode('replay');
  const replaySessions = [input.createSession(), input.createSession()] as const;
  const crossSessions = [input.createSession(), input.createSession()] as const;
  try {
    const replayIds = await Promise.all(
      replaySessions.map(async (session) =>
        initializeNativeVerification({
          ...input,
          session,
          authorizationPath: input.authorizationPath(),
          state: bounded(randomUUID()),
        })
      )
    );
    await experienceStatus(
      replaySessions[0],
      `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
      'POST',
      200,
      { verificationId: replayIds[0], connectorData: { code: replayCode } }
    );
    const replayResponse = await replaySessions[1].request(
      `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
      'POST',
      { verificationId: replayIds[1], connectorData: { code: replayCode } }
    );
    if (
      replayResponse.getStatus() !== 401 ||
      replayResponse.getRecord().code !== 'connector.social_auth_code_invalid'
    ) {
      return fail();
    }
    const crossIds = await Promise.all(
      crossSessions.map(async (session) =>
        initializeNativeVerification({
          ...input,
          session,
          authorizationPath: input.authorizationPath(),
          state: bounded(randomUUID()),
        })
      )
    );
    const crossResponse = await crossSessions[1].request(
      `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`,
      'POST',
      {
        verificationId: crossIds[0],
        connectorData: { code: 'ownership-is-checked-before-provider-code' },
      }
    );
    if (
      crossResponse.getStatus() !== 404 ||
      crossResponse.getRecord().code !== 'session.verification_session_not_found'
    ) {
      return fail();
    }
    const [noUnionId, invalidCode, malformedProvider] = await Promise.all([
      verify('noUnionId', 400, 'connector.wechat_unionid_required'),
      verify('invalidCode', 401, 'connector.social_auth_code_invalid'),
      verify('malformedProvider', 400, 'connector.invalid_response'),
    ]);
    return Object.freeze({
      noUnionId,
      invalidCode,
      malformedProvider,
      replay: Object.freeze({
        firstStatus: 200 as const,
        status: 401 as const,
        error: 'connector.social_auth_code_invalid' as const,
        accepted: false as const,
      }),
      crossInteraction: Object.freeze({
        status: 404 as const,
        error: 'session.verification_session_not_found' as const,
        accepted: false as const,
      }),
    });
  } finally {
    replaySessions[0].close();
    replaySessions[1].close();
    crossSessions[0].close();
    crossSessions[1].close();
  }
};
/* eslint-enable complexity, max-params, no-restricted-syntax */
