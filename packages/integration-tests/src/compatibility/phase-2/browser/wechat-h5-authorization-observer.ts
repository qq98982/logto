/* eslint-disable complexity, no-use-extend-native/no-use-extend-native, no-useless-call, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/require-array-sort-compare -- The browser route owns a one-shot provider callback. */
import {
  registerPlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationRoute,
} from '../../phase-1/browser/playwright-session.js';

import { parseWechatProviderCallback } from './wechat-provider-callback-client.js';

const fail = (): never => {
  throw new TypeError('Invalid WeChat H5 browser callback');
};
const bounded = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 4096;

export const createWechatH5AuthorizationObserver = (
  input: Readonly<{
    connectorId: string;
    clientId: string;
    targetOrigin: string;
    takeCode(): Promise<string>;
  }>
): PlaywrightExternalAuthorizationCapability => {
  const target = new URL(input.targetOrigin);
  const callback = new URL(`/callback/${encodeURIComponent(input.connectorId)}`, target);
  const verifyPath = `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`;
  let callbackUrl: string | undefined;
  let expectedState: string | undefined;
  let providerHandled = false;
  let verifyHandled = false;
  return registerPlaywrightExternalAuthorizationCapability(
    async (method, url, route: PlaywrightExternalAuthorizationRoute) => {
      if (
        url.origin === 'https://open.weixin.qq.com' &&
        url.pathname === '/connect/oauth2/authorize'
      ) {
        const keys = [...url.searchParams.keys()].toSorted();
        const state = url.searchParams.get('state');
        if (
          providerHandled ||
          method !== 'GET' ||
          keys.join(',') !== 'appid,redirect_uri,response_type,scope,state' ||
          url.searchParams.get('appid') !== input.clientId ||
          url.searchParams.get('redirect_uri') !== callback.href ||
          url.searchParams.get('response_type') !== 'code' ||
          url.searchParams.get('scope') !== 'snsapi_base' ||
          !bounded(state)
        ) {
          return false;
        }
        const code = await input.takeCode();
        if (!bounded(code)) {
          return fail();
        }
        const destination = new URL(callback);
        destination.searchParams.set('code', code);
        destination.searchParams.set('state', state);
        callbackUrl = destination.href;
        expectedState = state;
        providerHandled = true;
        await route.fulfill({ status: 302, headers: { location: destination.href }, body: '' });
        return true;
      }
      if (url.origin !== target.origin || url.pathname !== verifyPath) {
        return false;
      }
      if (
        verifyHandled ||
        method !== 'POST' ||
        url.search ||
        url.hash ||
        !callbackUrl ||
        !expectedState ||
        typeof route.fetch !== 'function' ||
        typeof route.request !== 'function'
      ) {
        return fail();
      }
      const request = route.request.call(route);
      const body: unknown = request.postDataJSON();
      if (typeof body !== 'object' || body === null || Array.isArray(body)) {
        return fail();
      }
      const connectorData: unknown = Reflect.get(body, 'connectorData');
      if (
        typeof connectorData !== 'object' ||
        connectorData === null ||
        Array.isArray(connectorData)
      ) {
        return fail();
      }
      const callbackData = parseWechatProviderCallback({
        callbackUrl,
        expectedCallbackUrl: callback.href,
        expectedState,
      });
      if (
        Reflect.ownKeys(body).toSorted().join(',') !== 'connectorData,verificationId' ||
        !bounded(Reflect.get(body, 'verificationId')) ||
        Reflect.ownKeys(connectorData).toSorted().join(',') !== 'app_id,code,redirectUri' ||
        Reflect.get(connectorData, 'code') !== callbackData.code ||
        Reflect.get(connectorData, 'redirectUri') !== callback.href ||
        Reflect.get(connectorData, 'app_id') !== input.clientId
      ) {
        return fail();
      }
      const rewritten = { ...body, connectorData: callbackData };
      verifyHandled = true;
      const response = await route.fetch.call(route, { postData: JSON.stringify(rewritten) });
      await route.fulfill({ response });
      return true;
    }
  );
};
/* eslint-enable complexity, no-use-extend-native/no-use-extend-native, no-useless-call, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/require-array-sort-compare */
