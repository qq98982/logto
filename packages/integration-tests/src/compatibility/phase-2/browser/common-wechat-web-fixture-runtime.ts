/* eslint-disable complexity, no-bitwise, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This boundary validates one private provider descriptor and scopes its credentials; the regex rejects ASCII controls. */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import type { CommonWechatWebFixtureRuntime } from '../scenarios/common-wechat-web.js';

import type {
  WechatProviderCredentialLease,
  WechatProviderTargetConfiguration,
} from './common-wechat-web-target-driver.js';
import {
  createDockerWechatWebProviderControl,
  prepareWechatWebProviderLease,
} from './wechat-web-provider-lease.js';

const fields = Object.freeze([
  'schemaVersion',
  'container',
  'project',
  'service',
  'image',
  'configFile',
  'receiptFile',
  'healthDiagnosticFile',
  'dockerHome',
  'apiVersion',
  'wechatSubject',
  'originalOwnerEmail',
  'unionId',
  'channel',
  'clientId',
  'clientSecret',
]);
const fail = (): never => {
  throw new TypeError('Invalid Common WeChat Web fixture runtime');
};
const bounded = (value: unknown, maximum = 4096): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();

const readPrivateJson = async (file: string): Promise<Record<string, unknown>> => {
  try {
    if (!path.isAbsolute(file) || path.normalize(file) !== file) {
      return fail();
    }
    const [before, resolved] = await Promise.all([lstat(file), realpath(file)]);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.uid !== process.getuid?.() ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600 ||
      before.size < 2 ||
      before.size > 65_536 ||
      resolved !== file
    ) {
      return fail();
    }
    const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = await handle.stat();
      if (
        opened.dev !== before.dev ||
        opened.ino !== before.ino ||
        opened.mode !== before.mode ||
        opened.nlink !== before.nlink ||
        opened.size !== before.size ||
        opened.mtimeMs !== before.mtimeMs
      ) {
        return fail();
      }
      const bytes = await handle.readFile();
      const after = await handle.stat();
      if (
        after.dev !== opened.dev ||
        after.ino !== opened.ino ||
        after.size !== opened.size ||
        after.mtimeMs !== opened.mtimeMs
      ) {
        return fail();
      }
      const value: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
      if (
        typeof value !== 'object' ||
        value === null ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype ||
        Object.keys(value).toSorted().join('\0') !== fields.toSorted().join('\0')
      ) {
        return fail();
      }
      return Object.fromEntries(Object.entries(value));
    } finally {
      await handle.close();
    }
  } catch {
    return fail();
  }
};

export const readCommonWechatWebFixtureRuntime = async (
  file: string,
  controlSocket: string
): Promise<CommonWechatWebFixtureRuntime> => {
  const row = await readPrivateJson(file);
  if (row.schemaVersion !== 1 || row.channel !== 'web' || row.wechatSubject !== row.unionId) {
    return fail();
  }
  const apiVersion = bounded(row.apiVersion, 32);
  if (!/^[1-9][0-9]*\.[0-9]+\.[0-9]+$/u.test(apiVersion)) {
    return fail();
  }
  const control = createDockerWechatWebProviderControl({
    socket: bounded(controlSocket),
    home: bounded(row.dockerHome),
    apiVersion,
  });
  const provider: WechatProviderTargetConfiguration = Object.freeze({
    wechatSubject: bounded(row.wechatSubject),
    originalOwnerEmail: bounded(row.originalOwnerEmail),
  });
  const config = Object.freeze({
    control,
    container: bounded(row.container),
    project: bounded(row.project),
    service: bounded(row.service),
    image: bounded(row.image),
    configFile: bounded(row.configFile),
    receiptFile: bounded(row.receiptFile),
    healthDiagnosticFile: bounded(row.healthDiagnosticFile),
  });
  const clientId = bounded(row.clientId);
  const clientSecret = bounded(row.clientSecret);
  const unionId = bounded(row.unionId);
  let active = false;
  return Object.freeze({
    provider,
    withProviderCredentialLease: async <Result>(
      use: (lease: WechatProviderCredentialLease) => Promise<Result>
    ): Promise<Result> => {
      if (active || typeof use !== 'function') {
        return fail();
      }
      active = true;
      const lease = Object.freeze({
        getClientId: () => (active ? clientId : fail()),
        getClientSecret: () => (active ? clientSecret : fail()),
        toJSON: (): never => fail(),
      });
      try {
        return await use(lease);
      } finally {
        active = false;
      }
    },
    prepareProvider: async (input) => {
      if (input.subject !== unionId) {
        return fail();
      }
      return prepareWechatWebProviderLease({ ...config, ...input });
    },
  });
};
/* eslint-enable complexity, no-bitwise, no-control-regex, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
