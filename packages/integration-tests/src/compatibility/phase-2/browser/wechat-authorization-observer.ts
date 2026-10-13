/* eslint-disable complexity, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One intercepted provider redirect yields one closed observation. */
import {
  registerPlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

import { parseWechatProviderCallback } from './wechat-provider-callback-client.js';

export type WechatAuthorizationObservation = Readonly<{
  requestCount: number;
  queryShapeExact: boolean;
  clientMatched: boolean;
  callbackMatched: boolean;
  responseTypeCode: boolean;
  scopeExact: boolean;
  stateFormatValid: boolean;
  stateRoundTrip: boolean;
  fulfilledOnce: boolean;
}>;

const statePattern = /^[A-Za-z0-9_-]{11}$/u;
const codePattern = /^[^\u0000-\u001F\u007F]{1,4096}$/u;
const expectedKeys = ['appid', 'redirect_uri', 'response_type', 'scope', 'state'].toSorted();
const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export const createWechatAuthorizationObserver = (
  input: Readonly<{
    connectorId: string;
    clientId: string;
    oidcClientId?: string;
    channel: 'web' | 'h5';
    targetOrigin: string;
    takeCode(): Promise<string>;
  }>
): Readonly<{
  capability: PlaywrightExternalAuthorizationCapability;
  observation(): WechatAuthorizationObservation;
}> => {
  const origin = new URL(input.targetOrigin);
  if (origin.href !== `${origin.origin}/` || origin.username || origin.password || origin.hash) {
    throw new TypeError('Invalid WeChat authorization observer');
  }
  const callback = new URL(`/callback/${encodeURIComponent(input.connectorId)}`, origin);
  const providerOrigin = 'https://open.weixin.qq.com';
  const providerPath = input.channel === 'web' ? '/connect/qrconnect' : '/connect/oauth2/authorize';
  const scope = input.channel === 'web' ? 'snsapi_login' : 'snsapi_userinfo';
  let requestCount = 0;
  let used = false;
  let callbackUrl: string | undefined;
  let callbackState: string | undefined;
  let observation: WechatAuthorizationObservation = Object.freeze({
    requestCount: 0,
    queryShapeExact: false,
    clientMatched: false,
    callbackMatched: false,
    responseTypeCode: false,
    scopeExact: false,
    stateFormatValid: false,
    stateRoundTrip: false,
    fulfilledOnce: false,
  });
  const capability = registerPlaywrightExternalAuthorizationCapability(
    async (method, url, route) => {
      if (url.origin !== providerOrigin || url.pathname !== providerPath) {
        if (
          input.channel !== 'h5' ||
          url.origin !== origin.origin ||
          url.pathname !==
            `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`
        ) {
          return false;
        }
        if (!callbackUrl || !callbackState) {
          return false;
        }
        if (method !== 'POST') {
          return false;
        }
        if (
          url.search ||
          url.hash ||
          typeof route.request !== 'function' ||
          typeof route.fetch !== 'function'
        ) {
          throw new TypeError('Invalid WeChat H5 verification request');
        }
        const request = route.request();
        const postData = request.postData();
        if (!postData || Buffer.byteLength(postData) > 64 * 1024) {
          throw new TypeError('Invalid WeChat H5 verification request');
        }
        let body: unknown;
        try {
          // JSON.parse is typed as any; the result remains unknown until the exact shape checks below.
          // eslint-disable-next-line no-restricted-syntax
          body = JSON.parse(postData) as unknown;
        } catch {
          throw new TypeError('Invalid WeChat H5 verification body');
        }
        if (!isRecord(body)) {
          throw new TypeError('Invalid WeChat H5 verification body');
        }
        const exact = parseWechatProviderCallback({
          callbackUrl,
          expectedCallbackUrl: callback.href,
          expectedState: callbackState,
        });
        const envelope = body;
        if (
          Object.keys(envelope).toSorted().join('\0') !==
            ['connectorData', 'verificationId'].join('\0') ||
          typeof envelope.verificationId !== 'string' ||
          !codePattern.test(envelope.verificationId) ||
          !isRecord(envelope.connectorData)
        ) {
          throw new TypeError('Invalid WeChat H5 verification body');
        }
        const row = envelope.connectorData;
        const keys = Object.keys(row).toSorted().join('\0');
        const ui =
          (keys === ['code', 'redirectUri'].toSorted().join('\0') ||
            (keys === ['app_id', 'code', 'redirectUri'].toSorted().join('\0') &&
              typeof input.oidcClientId === 'string' &&
              row.app_id === input.oidcClientId) ||
            (keys === ['app_id', 'code', 'redirectUri', 'wechat_redirect'].toSorted().join('\0') &&
              typeof input.oidcClientId === 'string' &&
              row.app_id === input.oidcClientId &&
              row.wechat_redirect === '') ||
            (keys === ['code', 'redirectUri', 'state'].toSorted().join('\0') &&
              row.state === exact.state)) &&
          row.code === exact.code &&
          row.redirectUri === callback.href;
        const strict =
          keys === ['code', 'state'].toSorted().join('\0') &&
          row.code === exact.code &&
          row.state === exact.state;
        if (!ui && !strict) {
          throw new TypeError('Invalid WeChat H5 verification body');
        }
        const canonicalPostData = JSON.stringify({
          verificationId: envelope.verificationId,
          connectorData: exact,
        });
        const response = await route.fetch({
          postData: canonicalPostData,
        });
        await route.fulfill({ response });
        callbackUrl = undefined;
        callbackState = undefined;
        return true;
      }
      requestCount += 1;
      const keys = [...url.searchParams.keys()];
      const state = url.searchParams.get('state');
      const facts = {
        queryShapeExact:
          keys.length === expectedKeys.length &&
          new Set(keys).size === expectedKeys.length &&
          keys.toSorted().every((key, index) => key === expectedKeys[index]),
        clientMatched: url.searchParams.get('appid') === input.clientId,
        callbackMatched: url.searchParams.get('redirect_uri') === callback.href,
        responseTypeCode: url.searchParams.get('response_type') === 'code',
        scopeExact: url.searchParams.get('scope') === scope,
        stateFormatValid: state !== null && statePattern.test(state),
      };
      if (
        method !== 'GET' ||
        url.username ||
        url.password ||
        (input.channel === 'h5'
          ? Boolean(url.hash) && url.hash !== '#wechat_redirect'
          : Boolean(url.hash)) ||
        requestCount !== 1 ||
        used ||
        !Object.values(facts).every(Boolean)
      ) {
        return false;
      }
      const code = await input.takeCode();
      if (!codePattern.test(code)) {
        return false;
      }
      const location = new URL(callback);
      location.searchParams.set('code', code);
      location.searchParams.set('state', state ?? '');
      callbackUrl = location.href;
      callbackState = state ?? '';
      used = true;
      await route.fulfill({ status: 302, headers: { location: location.href }, body: '' });
      observation = Object.freeze({
        requestCount,
        ...facts,
        stateRoundTrip: true,
        fulfilledOnce: true,
      });
      return true;
    }
  );
  return Object.freeze({ capability, observation: () => observation });
};
/* eslint-enable complexity, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
