/* eslint-disable complexity, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One intercepted provider redirect yields one closed observation. */
import {
  registerPlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

export type WechatWebAuthorizationObservation = Readonly<{
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

export const createWechatWebAuthorizationObserver = (
  input: Readonly<{
    connectorId: string;
    clientId: string;
    targetOrigin: string;
    callbackMode?: 'normal' | 'missing-state' | 'wrong-state' | 'wrong-callback';
    takeCode(): Promise<string>;
  }>
): Readonly<{
  capability: PlaywrightExternalAuthorizationCapability;
  observation(): WechatWebAuthorizationObservation;
  retryPath(): string | undefined;
}> => {
  const origin = new URL(input.targetOrigin);
  if (origin.href !== `${origin.origin}/` || origin.username || origin.password || origin.hash) {
    throw new TypeError('Invalid WeChat authorization observer');
  }
  const callback = new URL(`/callback/${encodeURIComponent(input.connectorId)}`, origin);
  const providerOrigin = 'https://open.weixin.qq.com';
  const providerPath = '/connect/qrconnect';
  const scope = 'snsapi_login';
  let requestCount = 0;
  let used = false;
  let retryPath: string | undefined;
  let observation: WechatWebAuthorizationObservation = Object.freeze({
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
        return false;
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
        Boolean(url.hash) ||
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
      const location = new URL(
        input.callbackMode === 'wrong-callback'
          ? `/callback/wrong-${encodeURIComponent(input.connectorId)}`
          : callback,
        origin
      );
      location.searchParams.set('code', code);
      if (input.callbackMode !== 'missing-state') {
        location.searchParams.set(
          'state',
          input.callbackMode === 'wrong-state' ? `${state ?? ''}x` : (state ?? '')
        );
      }
      if (input.callbackMode && input.callbackMode !== 'normal') {
        const correct = new URL(callback);
        correct.searchParams.set('code', code);
        correct.searchParams.set('state', state ?? '');
        retryPath = `${correct.pathname}${correct.search}`;
      }
      used = true;
      await route.fulfill({
        status: 302,
        headers: { location: location.href },
        body: '',
      });
      observation = Object.freeze({
        requestCount,
        ...facts,
        stateRoundTrip: input.callbackMode === undefined || input.callbackMode === 'normal',
        fulfilledOnce: true,
      });
      return true;
    }
  );
  return Object.freeze({ capability, observation: () => observation, retryPath: () => retryPath });
};
/* eslint-enable complexity, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
