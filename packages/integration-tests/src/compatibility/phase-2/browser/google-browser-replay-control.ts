/* eslint-disable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One-use route interception retains private proof material only inside the browser control. */
import { isDeepStrictEqual } from 'node:util';

import type { APIResponse } from '@playwright/test';

import {
  invokePlaywrightExternalAuthorizationCapability,
  registerPlaywrightExternalAuthorizationCapability,
  type PlaywrightExternalAuthorizationCapability,
} from '../../phase-1/browser/playwright-session.js';

export type GoogleBrowserReplayError =
  | 'none'
  | 'session.verification_session_not_found'
  | 'entity.not_found'
  | 'guard.invalid_input'
  | 'connector.general'
  | 'unknown';

export type GoogleBrowserReplayObservation = Readonly<{
  requestCount: number;
  firstStatus: 200;
  firstOutcome: 'verified';
  secondStatus: number | 'unavailable';
  secondError: GoogleBrowserReplayError;
  secondAccepted: boolean | 'unknown';
  ownerPreserved: true;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Google browser replay control');
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
const closedError = (value: unknown): GoogleBrowserReplayError => {
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
const mergedCookie = (
  requestCookie: string | undefined,
  responseHeaders: ReadonlyArray<Readonly<{ name: string; value: string }>>
): string | undefined => {
  const cookies = new Map<string, string>();
  for (const entry of requestCookie?.split(';') ?? []) {
    const separator = entry.indexOf('=');
    if (separator > 0) {
      cookies.set(entry.slice(0, separator).trim(), entry.slice(separator + 1).trim());
    }
  }
  for (const header of responseHeaders) {
    if (header.name.toLowerCase() !== 'set-cookie') {
      continue;
    }
    const pair = header.value.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    if (separator > 0) {
      cookies.set(pair.slice(0, separator).trim(), pair.slice(separator + 1).trim());
    }
  }
  return cookies.size > 0
    ? [...cookies].map(([name, value]) => `${name}=${value}`).join('; ')
    : undefined;
};

export const createGoogleBrowserReplayTestControl = (
  input: Readonly<{
    authorization: PlaywrightExternalAuthorizationCapability;
    targetOrigin: string;
    connectorId: string;
    ownerSnapshot(): Promise<unknown>;
  }>
): Readonly<{
  capability: PlaywrightExternalAuthorizationCapability;
  observation(): GoogleBrowserReplayObservation | undefined;
}> => {
  const target = new URL(input.targetOrigin);
  const expectedPath = `/api/experience/verification/social/${encodeURIComponent(input.connectorId)}/verify`;
  let intercepted = false;
  let observation: GoogleBrowserReplayObservation | undefined;
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
      const headers = { ...(await request.call(route).allHeaders()) };
      const cookie = mergedCookie(headers.cookie, first.headersArray());
      if (cookie) {
        headers.cookie = cookie;
      }
      const second = await fetchRoute.call(route, { headers });
      const secondBody = await boundedBody(second);
      const after = structuredClone(await input.ownerSnapshot());
      if (!isDeepStrictEqual(before, after)) {
        return fail();
      }
      const secondError = closedError(secondBody.code);
      const secondAccepted =
        second.status() === 200 && secondError === 'none'
          ? true
          : secondError === 'none' || secondError === 'unknown'
            ? ('unknown' as const)
            : false;
      observation = Object.freeze({
        requestCount: 1,
        firstStatus: 200,
        firstOutcome: 'verified',
        secondStatus: second.status(),
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
