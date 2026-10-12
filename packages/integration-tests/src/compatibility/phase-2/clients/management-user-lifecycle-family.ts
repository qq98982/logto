/* eslint-disable no-control-regex, @typescript-eslint/no-unsafe-assignment -- The bounded parser reads external OAuth error JSON. */
import type { TargetConfig } from '../../model.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

const fail = (): never => {
  throw new TypeError('Invalid Common Management lifecycle family transport');
};
const bounded = (value: string): string =>
  value.length > 0 && value.length <= 8192 && !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();
const responseCode = async (response: Response): Promise<string> => {
  const text = await response.text();
  if (Buffer.byteLength(text) > 4096) {
    return fail();
  }
  try {
    const value: unknown = JSON.parse(text);
    const code =
      typeof value === 'object' && value !== null
        ? (Reflect.get(value, 'error') ?? Reflect.get(value, 'code'))
        : undefined;
    return typeof code === 'string' && code.length <= 128 ? code : 'none';
  } catch {
    return 'none';
  }
};

export const observeActiveUserInfo = async (
  target: TargetConfig,
  access: string,
  requestFetch: typeof fetch = fetch
) => {
  const response = await requestFetch(new URL('/oidc/me', target.coreUrl), {
    headers: { authorization: `Bearer ${bounded(access)}` },
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  const text = await response.text();
  if (response.status !== 200 || Buffer.byteLength(text) > 4096) {
    return fail();
  }
  try {
    const value: unknown = JSON.parse(text);
    const subject =
      typeof value === 'object' && value !== null && !Array.isArray(value)
        ? Reflect.get(value, 'sub')
        : undefined;
    return Object.freeze({
      status: 200 as const,
      subject: typeof subject === 'string' && subject.length <= 256 ? bounded(subject) : fail(),
    });
  } catch {
    return fail();
  }
};

export const observeRevokedUserInfo = async (
  target: TargetConfig,
  access: string,
  requestFetch: typeof fetch = fetch
) => {
  const response = await requestFetch(new URL('/oidc/me', target.coreUrl), {
    headers: { authorization: `Bearer ${bounded(access)}` },
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  return Object.freeze({ status: response.status, code: await responseCode(response) });
};

export const observeRevokedRefresh = async (
  target: TargetConfig,
  fixture: Pick<ProvisionedPhase2Fixture, 'status'>,
  refresh: string,
  requestFetch: typeof fetch = fetch
) => {
  const clientId = fixture.status?.client.id ?? fail();
  const response = await requestFetch(new URL('/oidc/token', target.coreUrl), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: bounded(refresh),
      client_id: clientId,
    }),
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000),
  });
  return Object.freeze({ status: response.status, code: await responseCode(response) });
};
/* eslint-enable no-control-regex, @typescript-eslint/no-unsafe-assignment */
