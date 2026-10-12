/* eslint-disable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment -- Exact callback parsing is one closed validation boundary. */
import { types as nodeTypes } from 'node:util';

export type WechatProviderCallbackData = Readonly<{ code: string; state: string }>;

const fail = (): never => {
  throw new TypeError('Invalid WeChat provider callback');
};

const ownString = (input: Record<string, unknown>, key: string): string => {
  const descriptor = Object.getOwnPropertyDescriptor(input, key);
  if (!descriptor || !Object.hasOwn(descriptor, 'value') || typeof descriptor.value !== 'string') {
    return fail();
  }
  const { value } = descriptor;
  if (!value || Buffer.byteLength(value) > 2048 || /[\u0000-\u001F\u007F]/u.test(value)) {
    return fail();
  }
  return value;
};

export const parseWechatProviderCallback = (
  input: Readonly<{
    callbackUrl: string;
    expectedCallbackUrl: string;
    expectedState: string;
  }>
): WechatProviderCallbackData => {
  if (
    nodeTypes.isProxy(input) ||
    Object.getPrototypeOf(input) !== Object.prototype ||
    Reflect.ownKeys(input).length !== 3
  ) {
    return fail();
  }
  const callbackUrl = ownString(input, 'callbackUrl');
  const expectedCallbackUrl = ownString(input, 'expectedCallbackUrl');
  const expectedState = ownString(input, 'expectedState');
  let callback: URL;
  let expected: URL;
  try {
    callback = new URL(callbackUrl);
    expected = new URL(expectedCallbackUrl);
  } catch {
    return fail();
  }
  if (
    callback.username ||
    callback.password ||
    callback.hash ||
    expected.username ||
    expected.password ||
    expected.search ||
    expected.hash ||
    callback.origin !== expected.origin ||
    callback.pathname !== expected.pathname
  ) {
    return fail();
  }
  const keys = [...callback.searchParams.keys()];
  if (
    keys.length !== 2 ||
    new Set(keys).size !== 2 ||
    !keys.includes('code') ||
    !keys.includes('state')
  ) {
    return fail();
  }
  const codeValues = callback.searchParams.getAll('code');
  const stateValues = callback.searchParams.getAll('state');
  const code = codeValues[0];
  const state = stateValues[0];
  if (
    codeValues.length !== 1 ||
    stateValues.length !== 1 ||
    !code ||
    !state ||
    Buffer.byteLength(code) > 2048 ||
    Buffer.byteLength(state) > 2048 ||
    state !== expectedState
  ) {
    return fail();
  }
  return Object.freeze({ code, state });
};
/* eslint-enable complexity, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment */
