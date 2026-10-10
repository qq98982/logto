/* eslint-disable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One-use route interception retains private proof material only inside the browser control. */
import { isDeepStrictEqual } from 'node:util';

import type { APIResponse, Request } from '@playwright/test';

import {
  invokePlaywrightExternalAuthorizationCapability,
  registerPlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationRoute,
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
    request: Request;
    registerCleanup(cleanup: () => Promise<void>): void;
    reportStage(stage: ForeignInteractionStage): void;
  }>
) => Promise<Readonly<{ status: number; body: Record<string, unknown> }>>;
type ForeignInteractionStage =
  | 'browser'
  | 'context'
  | 'init-request'
  | 'init-status'
  | 'replay-request'
  | 'replay-body'
  | 'cleanup';
export type WechatWebCrossInteractionFailureStage =
  | ForeignInteractionStage
  | 'not-observed'
  | 'after-control'
  | 'first-response'
  | 'owner-before'
  | 'request'
  | 'owner-after'
  | 'fulfill';
const failForeign = (stage: ForeignInteractionStage): never => {
  throw new TypeError(`Invalid WeChat Web cross-interaction ${stage}`);
};
const requestInForeignInteraction: ForeignInteractionRequest = async (input) => {
  input.reportStage('browser');
  const browser = (() => {
    try {
      return input.request.frame().page().context().browser();
    } catch {
      return failForeign('browser');
    }
  })();
  if (!browser) {
    return failForeign('browser');
  }
  input.reportStage('context');
  const context = await browser
    .newContext({ acceptDownloads: false, locale: 'en', serviceWorkers: 'block' })
    .catch(() => failForeign('context'));
  input.registerCleanup(async () => context.close());
  input.reportStage('init-request');
  const initialized = await context.request
    .put(new URL('/api/experience', input.target).href, {
      data: { interactionEvent: 'SignIn' },
      headers: input.headers,
      maxRedirects: 0,
    })
    .catch(() => failForeign('init-request'));
  const initializedStatus = initialized.status();
  await initialized.dispose().catch(() => failForeign('cleanup'));
  if (initializedStatus !== 204) {
    input.reportStage('init-status');
    return failForeign('init-status');
  }
  input.reportStage('replay-request');
  const response = await context.request
    .fetch(input.verifyUrl.href, {
      method: 'POST',
      data: input.postData,
      headers: input.headers,
      maxRedirects: 0,
    })
    .catch(() => failForeign('replay-request'));
  input.reportStage('replay-body');
  const body = await boundedBody(response).catch(() => failForeign('replay-body'));
  const responseStatus = response.status();
  await response.dispose().catch(() => failForeign('cleanup'));
  return Object.freeze({ status: responseStatus, body });
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
  failureStage(): WechatWebCrossInteractionFailureStage | undefined;
  observation(): WechatWebCrossInteractionObservation | undefined;
}> => {
  const target = new URL(input.targetOrigin);
  const expectedPath = `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`;
  let intercepted = false;
  let failureStage: WechatWebCrossInteractionFailureStage | undefined = 'not-observed';
  let observation: WechatWebCrossInteractionObservation | undefined;
  let cleanupForeign: (() => Promise<void>) | undefined;
  const handler = async (method: string, url: URL, route: PlaywrightExternalAuthorizationRoute) => {
    if (
      await invokePlaywrightExternalAuthorizationCapability(input.authorization, method, url, route)
    ) {
      return true;
    }
    if (url.origin !== target.origin || url.pathname !== expectedPath) {
      return false;
    }
    if (intercepted) {
      failureStage = 'request';
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
    failureStage = 'first-response';
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
    failureStage = 'owner-before';
    const before = structuredClone(await input.ownerSnapshot());
    failureStage = 'request';
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
      request: originalRequest,
      registerCleanup: (cleanup) => {
        cleanupForeign = cleanup;
      },
      reportStage: (stage) => {
        failureStage = stage;
      },
    });
    failureStage = 'owner-after';
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
    failureStage = 'fulfill';
    await route.fulfill({ response: first });
    failureStage = 'cleanup';
    await cleanupForeign?.().catch(() => failForeign('cleanup'));
    cleanupForeign = undefined;
    failureStage = undefined;
    return true;
  };
  const capability = registerPlaywrightExternalAuthorizationCapability(
    async (method, url, route) => {
      try {
        return await handler(method, url, route);
      } catch {
        await route.abort().catch(() => false);
        failureStage ??= 'cleanup';
        await cleanupForeign?.().catch(() => {
          failureStage = 'cleanup';
        });
        cleanupForeign = undefined;
        return true;
      }
    }
  );
  return Object.freeze({
    capability,
    failureStage: () => failureStage,
    observation: () => observation,
  });
};
/* eslint-enable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
