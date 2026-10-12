/* eslint-disable complexity, @typescript-eslint/member-ordering -- This boundary validates a bounded untrusted Management response. */
import type { TargetConfig } from '../../model.js';

export type ManagementCompletionObservation = Readonly<{
  status: number;
  code: string;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Common Management control observation');
};
const sensitiveName =
  /(?:authorization|cookie|password|secret|token|credential|private|encrypted|hash)/iu;

export const observeManagementCompletionRequest = async (
  input: Readonly<{
    target: TargetConfig;
    createHeaders(): Headers;
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
    path: string;
    body?: unknown;
    fetch?: typeof fetch;
  }>
): Promise<ManagementCompletionObservation> => {
  if (!/^[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,2048}$/u.test(input.path)) {
    return fail();
  }
  const headers = input.createHeaders();
  if (input.body !== undefined) {
    headers.set('content-type', 'application/json');
  }
  const response = await (input.fetch ?? fetch)(
    new URL(`/api/${input.path}`, input.target.coreUrl),
    {
      method: input.method,
      headers,
      ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    }
  );
  const text = await response.text();
  if (Buffer.byteLength(text) > 16 * 1024) {
    return fail();
  }
  const value: unknown = JSON.parse(text);
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Reflect.ownKeys(value).some((key) => typeof key !== 'string' || sensitiveName.test(key))
  ) {
    return fail();
  }
  const code: unknown = Reflect.get(value, 'code') ?? Reflect.get(value, 'error');
  if (typeof code !== 'string' || code.length === 0 || Buffer.byteLength(code) > 256) {
    return fail();
  }
  return Object.freeze({ status: response.status, code });
};
/* eslint-enable complexity, @typescript-eslint/member-ordering */
