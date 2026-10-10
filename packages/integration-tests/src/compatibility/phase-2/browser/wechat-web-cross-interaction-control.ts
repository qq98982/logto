/* eslint-disable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One-use route interception retains private proof material only inside the browser control. */
import { createRequire } from 'node:module';
import { isDeepStrictEqual } from 'node:util';

import type { APIResponse, APIRequest } from '@playwright/test';

import {
  invokePlaywrightExternalAuthorizationCapability,
  registerPlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

export type WechatWebCrossInteractionError =
  | 'none'
  | 'session.verification_session_not_found'
  | 'entity.not_found'
  | 'guard.invalid_input'
  | 'connector.general'
  | 'unknown';

export type WechatWebCrossInteractionObservation = Readonly<{
  requestCount: number;
  firstStatus: 200;
  firstOutcome: 'verified';
  secondStatus: number | 'unavailable';
  secondError: WechatWebCrossInteractionError;
  secondAccepted: boolean | 'unknown';
  ownerPreserved: true;
}>;

const fail = (): never => {
  throw new TypeError('Invalid WeChat Web cross-interaction control');
};
const maximumBodyBytes = 65_536;
// Runtime loading keeps Playwright external to the ESM bundle; its published type validates the port.
// eslint-disable-next-line no-restricted-syntax
const { request: playwrightRequest } = createRequire(import.meta.url)('@playwright/test') as {
  request: APIRequest;
};
const boundedBody = async (response: APIResponse): Promise<Record<string, unknown>> => {
  const bytes = await response.body();
  if (bytes.byteLength > maximumBodyBytes) {
    return fail();
  }
  try {
    const value: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
    return typeof value === 'object' && value !== null && !Array.isArray(value)
      ? Object.fromEntries(Object.entries(value))
      : fail();
  } catch {
    return fail();
  }
};
type ForeignInteractionRequest = (
  input: Readonly<{
    target: URL;
    verifyUrl: URL;
    headers: Readonly<Record<string, string>>;
    postData: Uint8Array;
  }>
) => Promise<Readonly<{ status: number; body: Record<string, unknown> }>>;
const requestInForeignInteraction: ForeignInteractionRequest = async (input) => {
  const context = await playwrightRequest.newContext({
    baseURL: input.target.origin,
    extraHTTPHeaders: input.headers,
  });
  try {
    const initialized = await context.put('/api/experience', {
      data: { interactionEvent: 'SignIn' },
    });
    if (initialized.status() !== 200) {
      return fail();
    }
    const response = await context.fetch(input.verifyUrl.href, {
      method: 'POST',
      data: input.postData,
    });
    return Object.freeze({ status: response.status(), body: await boundedBody(response) });
  } finally {
    await context.dispose();
  }
};
const closedError = (value: unknown): WechatWebCrossInteractionError => {
  switch (value) {
    case undefined: {
      return 'none';
    }
    case 'session.verification_session_not_found':
    case 'entity.not_found':
    case 'guard.invalid_input':
    case 'connector.general': {
      return value;
    }
    default: {
      return 'unknown';
    }
  }
};
export const createWechatWebCrossInteractionTestControl = (
  input: Readonly<{
    authorization: PlaywrightExternalAuthorizationCapability;
    targetOrigin: string;
    connectorId: string;
    foreignInteractionRequest?: ForeignInteractionRequest;
    ownerSnapshot(): Promise<unknown>;
  }>
): Readonly<{
  capability: PlaywrightExternalAuthorizationCapability;
  observation(): WechatWebCrossInteractionObservation | undefined;
}> => {
  const target = new URL(input.targetOrigin);
  const expectedPath = `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`;
  let intercepted = false;
  let observation: WechatWebCrossInteractionObservation | undefined;
  const capability = registerPlaywrightExternalAuthorizationCapability(
    async (method, url, route) => {
      if (
        await invokePlaywrightExternalAuthorizationCapability(
          input.authorization,
          method,
          url,
          route
        )
      ) {
        return true;
      }
      if (url.origin !== target.origin || url.pathname !== expectedPath) {
        return false;
      }
      if (intercepted) {
        return fail();
      }
      if (
        method !== 'POST' ||
        url.search ||
        url.hash ||
        typeof route.fetch !== 'function' ||
        typeof route.request !== 'function'
      ) {
        return false;
      }
      intercepted = true;
      const fetchRoute = route.fetch;
      const { request } = route;
      const first = await fetchRoute.call(route);
      const firstBody = await boundedBody(first);
      const { verificationId } = firstBody;
      if (
        first.status() !== 200 ||
        typeof verificationId !== 'string' ||
        verificationId.length === 0 ||
        Buffer.byteLength(verificationId) > 4096 ||
        /[\u0000-\u001F\u007F]/u.test(verificationId)
      ) {
        return fail();
      }
      const before = structuredClone(await input.ownerSnapshot());
      const originalRequest = request.call(route);
      const headers = Object.fromEntries(
        Object.entries(await originalRequest.allHeaders()).filter(
          ([name]) => name !== 'cookie' && name !== 'content-length'
        )
      );
      const postData = originalRequest.postDataBuffer();
      if (!postData || postData.byteLength > maximumBodyBytes) {
        return fail();
      }
      const second = await (input.foreignInteractionRequest ?? requestInForeignInteraction)({
        target,
        verifyUrl: url,
        headers,
        postData,
      });
      const after = structuredClone(await input.ownerSnapshot());
      if (!isDeepStrictEqual(before, after)) {
        return fail();
      }
      const secondError = closedError(second.body.code);
      const secondAccepted =
        second.status === 200 && secondError === 'none'
          ? true
          : secondError === 'none' || secondError === 'unknown'
            ? ('unknown' as const)
            : false;
      observation = Object.freeze({
        requestCount: 1,
        firstStatus: 200,
        firstOutcome: 'verified',
        secondStatus: second.status,
        secondError,
        secondAccepted,
        ownerPreserved: true,
      });
      await route.fulfill({ response: first });
      return true;
    }
  );
  return Object.freeze({ capability, observation: () => observation });
};
/* eslint-enable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
