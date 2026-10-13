/* eslint-disable complexity, max-lines, no-await-in-loop, @silverhand/fp/no-mutating-methods, unicorn/no-await-expression-member -- Each real identity entry owns its bounded session correlation, current proof and signed notification in one sequential logout attempt. */
import type { JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import {
  verifyBoundLogoutIdentity,
  verifyCommonBackchannelLogout,
  type BackchannelLogoutProjection,
} from '../clients/backchannel-logout.js';
import { createCommonExperienceSession } from '../clients/common-experience.js';
import { observeLogoutSession } from '../clients/logout-session.js';
import type { IssuedPublicUserSession } from '../clients/user-token-issuance.js';

export type LogoutEntryMethod = 'google' | 'email-code' | 'wechat-native';
export type OwnedLogoutSession = Readonly<{
  session: IssuedPublicUserSession;
  subject: string;
  clientId: string;
  issuer: string;
  withCurrentProof<Result>(use: (proofId: string) => Promise<Result>): Promise<Result>;
}>;
export type CommonLogoutPreservationRuntime = Readonly<{
  withAttempt<Result>(
    input: Readonly<{
      method: LogoutEntryMethod;
      delivery: 'accepted' | 'rejected';
      operation: 'rp' | 'account';
    }>,
    use: (
      session: OwnedLogoutSession,
      receiver: Readonly<{
        consume(): Promise<string | undefined>;
        deliveryStatus(): Promise<number>;
      }>
    ) => Promise<Result>
  ): Promise<Result>;
}>;
export type CommonLogoutMethodProjection = Readonly<{
  method: LogoutEntryMethod;
  rpLogoutStatus: 303;
  signedNotification: BackchannelLogoutProjection;
  sessionRemoved: true;
  offlineRefreshRotated: true;
  offlineProfilePreserved: true;
  receiverConsumedOnce: true;
  deliveryFailureStatus: 503;
  failureSessionRemoved: true;
  failureOfflineRefreshRotated: true;
  failureProfilePreserved: true;
  accountDeleteStatus: 204;
  accountSessionRemoved: true;
  accountOfflineRefreshRotated: true;
  accountProfilePreserved: true;
}>;
export type CommonLogoutPreservationProjection = Readonly<{
  methods: readonly CommonLogoutMethodProjection[];
}>;
const fail = (stage: string): never => {
  throw new TypeError(`Invalid Common identity logout (${stage})`);
};
const bounded = (value: unknown, max = 16_384): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= max
    ? value
    : fail('field');
const privateSessionUid = (value: unknown): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= 4096 &&
  ![...value].some((character) => {
    const codePoint = character.codePointAt(0);

    return codePoint !== undefined && (codePoint <= 31 || codePoint === 127);
  })
    ? value
    : fail('session-uid');

const withAccountTransport = async <Result>(
  input: Readonly<{ target: TargetConfig; bearer: string; proofId: string; fetch: typeof fetch }>,
  use: (session: ReturnType<typeof createCommonExperienceSession>) => Promise<Result>
): Promise<Result> => {
  const session = createCommonExperienceSession({
    target: input.target,
    clientId: 'owned-logout-account',
    fetch: async (url, init) => {
      const headers = new Headers(init?.headers);
      headers.set('authorization', `Bearer ${bounded(input.bearer)}`);
      headers.set(
        input.target.label === 'oracle' ? 'logto-verification-id' : 'aster-verification-id',
        bounded(input.proofId)
      );
      return input.fetch(url, { ...init, headers });
    },
  });
  try {
    return await use(session);
  } finally {
    session.close();
  }
};
const boundSessionUid = async (
  input: Readonly<{
    target: TargetConfig;
    bearer: string;
    proofId: string;
    sessionId: string;
    subject: string;
    clientId: string;
    fetch: typeof fetch;
  }>
) =>
  withAccountTransport(input, async (session) => {
    const response = await session.request('/api/my-account/sessions', 'GET');
    const { sessions } = response.getRecord();
    if (response.getStatus() !== 200 || !Array.isArray(sessions) || sessions.length > 100) {
      return fail('session-read');
    }
    const current = sessions.flatMap((value: unknown) => {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return fail('session-shape');
      }
      const payload: unknown = Reflect.get(value, 'payload');
      if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
        return fail('session-shape');
      }
      if (
        Reflect.get(value, 'accountId') !== input.subject ||
        Reflect.get(payload, 'accountId') !== input.subject
      ) {
        return fail('foreign-session');
      }
      const authorizations: unknown = Reflect.get(payload, 'authorizations');
      if (
        typeof authorizations !== 'object' ||
        authorizations === null ||
        Array.isArray(authorizations)
      ) {
        return [];
      }
      const authorization: unknown = Reflect.get(authorizations, input.clientId);
      if (
        typeof authorization !== 'object' ||
        authorization === null ||
        Array.isArray(authorization) ||
        Reflect.get(authorization, 'sid') !== input.sessionId
      ) {
        return [];
      }
      return [privateSessionUid(Reflect.get(payload, 'uid'))];
    });
    if (current.length > 1) {
      return fail('duplicate-session');
    }
    return current[0];
  });

const rotateOrdinaryRefresh = async (
  input: Readonly<{ target: TargetConfig; owner: OwnedLogoutSession; fetch: typeof fetch }>
) => {
  const session = createCommonExperienceSession({
    target: input.target,
    clientId: input.owner.clientId,
    fetch: input.fetch,
  });
  try {
    const response = await session.request(
      '/oidc/token',
      'POST',
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: input.owner.clientId,
        refresh_token: input.owner.session.refresh,
      })
    );
    const record = response.getRecord();
    const access = bounded(record.access_token);
    const refresh = bounded(record.refresh_token);
    if (
      response.getStatus() !== 200 ||
      record.token_type !== 'Bearer' ||
      access.includes('.') ||
      refresh === input.owner.session.refresh ||
      access === refresh
    ) {
      return fail('offline-refresh');
    }
    const profileTransport = createCommonExperienceSession({
      target: input.target,
      clientId: input.owner.clientId,
      fetch: async (url, init) => {
        const headers = new Headers(init?.headers);
        headers.set('authorization', `Bearer ${access}`);
        return input.fetch(url, { ...init, headers });
      },
    });
    try {
      const profile = await profileTransport.request('/oidc/me', 'GET');
      if (profile.getStatus() !== 200 || profile.getRecord().sub !== input.owner.subject) {
        return fail('offline-profile');
      }
    } finally {
      profileTransport.close();
    }
  } finally {
    session.close();
  }
};

export const runCommonSessionLogoutPreservation = async (
  input: Readonly<{
    target: TargetConfig;
    jwks: Readonly<JSONWebKeySet>;
    runtime: CommonLogoutPreservationRuntime;
    fetch?: typeof fetch;
  }>
): Promise<CommonLogoutPreservationProjection> => {
  const requestFetch = input.fetch ?? fetch;
  const results: CommonLogoutMethodProjection[] = [];
  for (const method of ['google', 'email-code', 'wechat-native'] as const) {
    const attempt = async (delivery: 'accepted' | 'rejected', operation: 'rp' | 'account') =>
      input.runtime.withAttempt({ method, delivery, operation }, async (owner, receiver) => {
        const identity = await verifyBoundLogoutIdentity({
          session: owner.session,
          jwks: input.jwks,
          issuer: owner.issuer,
          clientId: owner.clientId,
          subject: owner.subject,
        });
        return owner.withCurrentProof(async (proofId) => {
          const bound = {
            target: input.target,
            bearer: owner.session.access,
            proofId,
            sessionId: identity.sessionId,
            subject: owner.subject,
            clientId: owner.clientId,
            fetch: requestFetch,
          };
          const boundUid = await boundSessionUid(bound);
          if (!boundUid) {
            return fail('session-before');
          }
          const status =
            operation === 'rp'
              ? (
                  await observeLogoutSession(
                    {
                      target: input.target,
                      method: 'GET',
                      path: '/oidc/session/end',
                      form: [
                        ['client_id', owner.clientId],
                        ['id_token_hint', owner.session.getIdToken()],
                      ],
                      initialCookieHeader: owner.session.getCookieHeader(),
                      confirm: true,
                    },
                    requestFetch
                  )
                ).status
              : await withAccountTransport(
                  {
                    target: input.target,
                    bearer: owner.session.access,
                    proofId,
                    fetch: requestFetch,
                  },
                  async (session) =>
                    (
                      await session.request(
                        `/api/my-account/sessions/${encodeURIComponent(boundUid)}`,
                        'DELETE'
                      )
                    ).getStatus()
                );
          if (status !== (operation === 'rp' ? 303 : 204)) {
            return fail('logout-status');
          }
          if (await boundSessionUid(bound)) {
            return fail('session-after');
          }
          await rotateOrdinaryRefresh({ target: input.target, owner, fetch: requestFetch });
          if (operation === 'account') {
            return { status };
          }
          const token = await receiver.consume();
          if (!token) {
            return fail('notification-missing');
          }
          const signed = await verifyCommonBackchannelLogout({
            token,
            jwks: input.jwks,
            issuer: owner.issuer,
            clientId: owner.clientId,
            identity,
          });
          if ((await receiver.consume()) !== undefined) {
            return fail('notification-replay');
          }
          const deliveryStatus = await receiver.deliveryStatus();
          if (deliveryStatus !== (delivery === 'accepted' ? 204 : 503)) {
            return fail('delivery-status');
          }
          return { status, signed, deliveryStatus };
        });
      });
    const positive = await attempt('accepted', 'rp');
    const negative = await attempt('rejected', 'rp');
    await attempt('accepted', 'account');
    if (
      !('signed' in positive) ||
      !positive.signed ||
      !('signed' in negative) ||
      !negative.signed
    ) {
      return fail('notification');
    }
    results.push(
      Object.freeze({
        method,
        rpLogoutStatus: 303,
        signedNotification: positive.signed,
        sessionRemoved: true,
        offlineRefreshRotated: true,
        offlineProfilePreserved: true,
        receiverConsumedOnce: true,
        deliveryFailureStatus: 503,
        failureSessionRemoved: true,
        failureOfflineRefreshRotated: true,
        failureProfilePreserved: true,
        accountDeleteStatus: 204,
        accountSessionRemoved: true,
        accountOfflineRefreshRotated: true,
        accountProfilePreserved: true,
      })
    );
  }
  return Object.freeze({ methods: Object.freeze(results) });
};
/* eslint-enable complexity, max-lines, no-await-in-loop, @silverhand/fp/no-mutating-methods, unicorn/no-await-expression-member */
