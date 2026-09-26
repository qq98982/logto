/* eslint-disable @silverhand/fp/no-mutation -- The private cookie jar is intentionally updated only inside one bounded browser flow. */
import type { TargetConfig } from '../../model.js';
import type { LogoutSessionProjection } from '../projections/logout-session.js';
import { projectLogoutSessionResponse } from '../projections/logout-session.js';

export type LogoutSessionObservation = Readonly<{
  target: TargetConfig;
  method: 'GET' | 'POST';
  path: string;
  form?: ReadonlyArray<readonly [string, string]>;
  bearer?: string;
  confirm?: boolean;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 logout session observation');
};

const readText = async (response: Response): Promise<string> => {
  const maximum = 64 * 1024;
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > maximum)) {
    return fail();
  }
  const text = await response.text();
  return Buffer.byteLength(text) <= maximum ? text : fail();
};

const mergeCookies = (jar: Map<string, string>, response: Response): void => {
  for (const cookie of response.headers.getSetCookie()) {
    const pair = cookie.split(';', 1)[0] ?? '';
    const separator = pair.indexOf('=');
    if (separator <= 0 || pair.length > 8192) {
      return fail();
    }
    jar.set(pair.slice(0, separator), pair.slice(separator + 1));
  }
  if (jar.size > 16) {
    return fail();
  }
};

const cookieHeader = (jar: Map<string, string>): string =>
  [...jar].map(([name, value]) => `${name}=${value}`).join('; ');

const send = async (
  input: LogoutSessionObservation,
  cookies: Map<string, string>,
  requestFetch: typeof fetch
): Promise<Readonly<{ response: Response; body: string }>> => {
  const url = new URL(input.path, input.target.coreUrl);
  const headers = new Headers();
  if (cookies.size > 0) {
    headers.set('cookie', cookieHeader(cookies));
  }
  if (input.bearer !== undefined) {
    headers.set('authorization', `Bearer ${input.bearer}`);
  }
  const form = input.form === undefined ? undefined : new URLSearchParams();
  for (const [name, value] of input.form ?? []) {
    form?.append(name, value);
  }
  if (input.method === 'GET' && form) {
    url.search = form.toString();
  }
  if (input.method === 'POST') {
    headers.set('content-type', 'application/x-www-form-urlencoded');
  }
  const response = await requestFetch(url, {
    method: input.method,
    headers,
    ...(input.method === 'POST' && form ? { body: form } : {}),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  mergeCookies(cookies, response);
  return Object.freeze({ response, body: await readText(response) });
};

export const observeLogoutSession = async (
  input: LogoutSessionObservation,
  requestFetch: typeof fetch = fetch
): Promise<LogoutSessionProjection> => {
  const cookies = new Map<string, string>();
  const first = await send(input, cookies, requestFetch);
  if (!input.confirm) {
    return projectLogoutSessionResponse(input.target.coreUrl, first.response, first.body);
  }
  if (first.response.status !== 200 || !first.body.includes('name="xsrf"')) {
    return fail();
  }
  const xsrf = /name=["']xsrf["'][^>]*value=["']([^"']+)["']/iu.exec(first.body)?.[1];
  const actionValue = /<form\b[^>]*action=["']([^"']+)["']/iu.exec(first.body)?.[1];
  if (!xsrf || !actionValue) {
    return fail();
  }
  const action = (() => {
    try {
      return new URL(actionValue, input.target.coreUrl);
    } catch {
      return fail();
    }
  })();
  const target = new URL(input.target.coreUrl);
  if (action.origin !== target.origin || action.hash !== '') {
    return fail();
  }
  const confirmed = await send(
    {
      target: input.target,
      method: 'POST',
      path: `${action.pathname}${action.search}`,
      form: [
        ['xsrf', xsrf],
        ['logout', 'yes'],
      ],
    },
    cookies,
    requestFetch
  );
  return projectLogoutSessionResponse(input.target.coreUrl, confirmed.response, confirmed.body);
};

export const observeAccountSessionBoundary = async (
  input: Readonly<{
    target: TargetConfig;
    kind: 'missing-verification' | 'wrong-password';
    bearer: string;
  }>,
  requestFetch: typeof fetch = fetch
): Promise<LogoutSessionProjection> => {
  const url = new URL(
    input.kind === 'missing-verification'
      ? '/api/my-account/sessions'
      : '/api/verifications/password',
    input.target.coreUrl
  );
  const response = await requestFetch(url, {
    method: input.kind === 'missing-verification' ? 'GET' : 'POST',
    headers: {
      authorization: `Bearer ${input.bearer}`,
      ...(input.kind === 'wrong-password' ? { 'content-type': 'application/json' } : {}),
    },
    ...(input.kind === 'wrong-password'
      ? { body: JSON.stringify({ password: 'known-wrong-password' }) }
      : {}),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  return projectLogoutSessionResponse(input.target.coreUrl, response, await readText(response));
};

/* eslint-enable @silverhand/fp/no-mutation */
