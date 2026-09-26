/* eslint-disable complexity, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The private cookie jar and workflow stage are intentionally updated only inside bounded browser flows. */
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
  initialCookieHeader?: string;
}>;

export type AccountSessionWorkflowObservation = Readonly<{
  verification: LogoutSessionProjection;
  sessions: LogoutSessionProjection;
  deletion: LogoutSessionProjection;
  sessionsAfterDeletion: LogoutSessionProjection;
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

const seedCookies = (jar: Map<string, string>, value: string | undefined): void => {
  if (value === undefined) {
    return;
  }
  for (const pair of value.split(';')) {
    const separator = pair.indexOf('=');
    const name = pair.slice(0, separator).trim();
    const cookieValue = pair.slice(separator + 1).trim();
    if (
      separator <= 0 ||
      !/^[A-Za-z0-9!#$%&'*+.^_|~-]{1,128}$/u.test(name) ||
      cookieValue.length === 0 ||
      Buffer.byteLength(cookieValue) > 4096 ||
      /[\u0000-\u001F\u007F;]/u.test(cookieValue)
    ) {
      return fail();
    }
    jar.set(name, cookieValue);
  }
};

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
  seedCookies(cookies, input.initialCookieHeader);
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

export const observeAccountSessionWorkflow = async (
  input: Readonly<{ target: TargetConfig; bearer: string; password: string }>,
  requestFetch: typeof fetch = fetch
): Promise<AccountSessionWorkflowObservation> => {
  let stage: 'verification' | 'list' | 'delete' | 'list-after-delete' = 'verification';
  try {
    const sendAccount = async (
      path: string,
      method: 'GET' | 'POST' | 'DELETE',
      verification?: string,
      body?: string
    ): Promise<Readonly<{ response: Response; text: string }>> => {
      const response = await requestFetch(new URL(path, input.target.coreUrl), {
        method,
        headers: {
          authorization: `Bearer ${input.bearer}`,
          ...(verification
            ? {
                [input.target.label === 'oracle'
                  ? 'logto-verification-record-id'
                  : 'aster-verification-id']: verification,
              }
            : {}),
          ...(body ? { 'content-type': 'application/json' } : {}),
        },
        ...(body ? { body } : {}),
        redirect: 'manual',
        signal: AbortSignal.timeout(10_000),
      });
      return Object.freeze({ response, text: await readText(response) });
    };

    const verified = await sendAccount(
      '/api/verifications/password',
      'POST',
      undefined,
      JSON.stringify({ password: input.password })
    );
    if (verified.response.status !== 201) {
      return fail();
    }
    const verifiedBody = recordJson(verified.text);
    const verification = verifiedBody.verificationRecordId;
    if (
      typeof verification !== 'string' ||
      verification.length === 0 ||
      verification.length > 4096
    ) {
      return fail();
    }
    const verificationProjection = projectLogoutSessionResponse(
      input.target.coreUrl,
      verified.response,
      verified.text
    );

    stage = 'list';
    const listed = await sendAccount('/api/my-account/sessions', 'GET', verification);
    if (listed.response.status !== 200) {
      return fail();
    }
    const listedBody = recordJson(listed.text);
    if (!Array.isArray(listedBody.sessions)) {
      return fail();
    }
    const current = listedBody.sessions
      .map((session) => recordJsonValue(session))
      .find((session) => session.isCurrent === true);
    const payload = current && recordJsonValue(current.payload);
    const sessionId = payload?.uid;
    if (typeof sessionId !== 'string' || sessionId.length === 0 || sessionId.length > 128) {
      return fail();
    }
    const sessionsProjection = projectLogoutSessionResponse(
      input.target.coreUrl,
      listed.response,
      listed.text
    );

    stage = 'delete';
    const deleted = await sendAccount(
      `/api/my-account/sessions/${encodeURIComponent(sessionId)}`,
      'DELETE',
      verification
    );
    if (deleted.response.status !== 204) {
      return fail();
    }
    const deletionProjection = projectLogoutSessionResponse(
      input.target.coreUrl,
      deleted.response,
      deleted.text
    );

    stage = 'list-after-delete';
    const after = await sendAccount('/api/my-account/sessions', 'GET', verification);
    if (after.response.status !== 200) {
      return fail();
    }
    return Object.freeze({
      verification: verificationProjection,
      sessions: sessionsProjection,
      deletion: deletionProjection,
      sessionsAfterDeletion: projectLogoutSessionResponse(
        input.target.coreUrl,
        after.response,
        after.text
      ),
    });
  } catch {
    throw new TypeError(`Invalid Phase 2 Account session workflow (${stage})`);
  }
};

const recordJson = (text: string): Record<string, unknown> => {
  try {
    return recordJsonValue(JSON.parse(text) as unknown);
  } catch {
    return fail();
  }
};

const recordJsonValue = (value: unknown): Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return fail();
  }
  return value as Record<string, unknown>;
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

/* eslint-enable complexity, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
