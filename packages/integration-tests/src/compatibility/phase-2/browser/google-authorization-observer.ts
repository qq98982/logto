/* eslint-disable complexity, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One-use authorization interception retains only closed facts. */
import {
  registerPlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

export type GoogleAuthorizationObservation = Readonly<{
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
const expectedKeys = ['client_id', 'redirect_uri', 'response_type', 'state', 'scope'].toSorted();

const createAuthorizationObserver = (
  input: Readonly<{
    connectorId: string;
    clientId: string;
    targetOrigin: string;
    takeCode(): Promise<string>;
  }>,
  callbackState: 'round-trip' | 'mismatch'
): Readonly<{
  capability: PlaywrightExternalAuthorizationCapability;
  observation(): GoogleAuthorizationObservation;
}> => {
  const origin = new URL(input.targetOrigin);
  if (origin.href !== `${origin.origin}/` || origin.username || origin.password || origin.hash) {
    throw new TypeError('Invalid Google authorization observer');
  }
  const callback = new URL(`/callback/${encodeURIComponent(input.connectorId)}`, origin);
  let requestCount = 0;
  let used = false;
  let fulfilled = false;
  let observation: GoogleAuthorizationObservation = Object.freeze({
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
      if (url.origin !== 'https://accounts.google.com' || url.pathname !== '/o/oauth2/v2/auth') {
        return false;
      }
      requestCount += 1;
      const keys = [...url.searchParams.keys()];
      const queryShapeExact =
        keys.length === 5 &&
        new Set(keys).size === 5 &&
        keys.toSorted().every((key, index) => key === expectedKeys[index]);
      const state = url.searchParams.get('state');
      const facts = {
        queryShapeExact,
        clientMatched: url.searchParams.get('client_id') === input.clientId,
        callbackMatched: url.searchParams.get('redirect_uri') === callback.href,
        responseTypeCode: url.searchParams.get('response_type') === 'code',
        scopeExact: url.searchParams.get('scope') === 'openid profile email',
        stateFormatValid: state !== null && statePattern.test(state),
      };
      if (
        method !== 'GET' ||
        url.username ||
        url.password ||
        url.hash ||
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
      const returnedState =
        callbackState === 'mismatch'
          ? `${(state ?? '').slice(0, 10)}${state?.endsWith('x') ? 'y' : 'x'}`
          : (state ?? '');
      location.searchParams.set('state', returnedState);
      used = true;
      await route.fulfill({ status: 302, headers: { location: location.href }, body: '' });
      fulfilled = true;
      observation = Object.freeze({
        requestCount,
        ...facts,
        stateRoundTrip: returnedState === state,
        fulfilledOnce: true,
      });
      return true;
    }
  );
  return Object.freeze({ capability, observation: () => observation });
};
export const createGoogleAuthorizationObserver = (
  input: Parameters<typeof createAuthorizationObserver>[0]
) => createAuthorizationObserver(input, 'round-trip');
export const createGoogleAuthorizationWrongStateTestControl = (
  input: Parameters<typeof createAuthorizationObserver>[0]
) => createAuthorizationObserver(input, 'mismatch');
/* eslint-enable complexity, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
