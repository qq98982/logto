/* eslint-disable complexity, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This boundary validates one private provider descriptor and scopes its credentials. */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

import type { CommonGoogleExistingOwnerFixtureRuntime } from '../scenarios/common-google-existing-owner.js';

import type {
  GoogleProviderCredentialLease,
  GoogleProviderTargetConfiguration,
} from './common-google-existing-owner-target-driver.js';
import { createDockerGoogleProviderControl } from './google-provider-lease.js';

const providerInputKeys = Object.freeze([
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
  'googleSubject',
  'originalOwnerEmail',
  'changedProviderEmail',
  'expectedUserinfoMethod',
  'clientId',
  'clientSecret',
]);
const fail = (): never => {
  throw new TypeError('Invalid Common Google existing-owner fixture runtime');
};
const bounded = (value: unknown, maximum = 4096): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  ![...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 0x20 || code === 0x7f;
  })
    ? value
    : fail();

const readPrivateJson = async (filePath: string): Promise<Record<string, unknown>> => {
  try {
    if (!path.isAbsolute(filePath) || path.normalize(filePath) !== filePath) {
      return fail();
    }
    const [before, resolved] = await Promise.all([lstat(filePath), realpath(filePath)]);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.uid !== process.getuid?.() ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600 ||
      before.size < 2 ||
      before.size > 65_536 ||
      resolved !== filePath
    ) {
      return fail();
    }
    const handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = await handle.stat();
      if (
        opened.dev !== before.dev ||
        opened.ino !== before.ino ||
        opened.uid !== before.uid ||
        opened.mode !== before.mode ||
        opened.nlink !== before.nlink ||
        opened.size !== before.size ||
        opened.mtimeMs !== before.mtimeMs
      ) {
        return fail();
      }
      const bytes = await handle.readFile();
      const [after, pathAfter] = await Promise.all([handle.stat(), lstat(filePath)]);
      if (
        after.dev !== opened.dev ||
        after.ino !== opened.ino ||
        after.mode !== opened.mode ||
        after.nlink !== opened.nlink ||
        after.size !== opened.size ||
        after.mtimeMs !== opened.mtimeMs ||
        pathAfter.isSymbolicLink() ||
        pathAfter.dev !== opened.dev ||
        pathAfter.ino !== opened.ino ||
        pathAfter.uid !== opened.uid ||
        pathAfter.mode !== opened.mode ||
        pathAfter.nlink !== opened.nlink ||
        pathAfter.size !== opened.size ||
        pathAfter.mtimeMs !== opened.mtimeMs
      ) {
        return fail();
      }
      const value: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
      if (
        typeof value !== 'object' ||
        value === null ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype ||
        Object.keys(value).toSorted().join('\0') !== providerInputKeys.toSorted().join('\0')
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

export const readCommonGoogleExistingOwnerFixtureRuntime = async (
  filePath: string,
  controlSocket: string
): Promise<CommonGoogleExistingOwnerFixtureRuntime> => {
  const row = await readPrivateJson(filePath);
  if (
    row.schemaVersion !== 1 ||
    (row.expectedUserinfoMethod !== 'GET' && row.expectedUserinfoMethod !== 'POST')
  ) {
    return fail();
  }
  const dockerHome = bounded(row.dockerHome);
  const apiVersion = bounded(row.apiVersion, 32);
  if (!/^[1-9][0-9]*\.[0-9]+\.[0-9]+$/u.test(apiVersion)) {
    return fail();
  }
  const configuration: GoogleProviderTargetConfiguration = Object.freeze({
    control: createDockerGoogleProviderControl({
      socket: bounded(controlSocket),
      home: dockerHome,
      apiVersion,
    }),
    container: bounded(row.container),
    project: bounded(row.project),
    service: bounded(row.service),
    image: bounded(row.image),
    configFile: bounded(row.configFile),
    receiptFile: bounded(row.receiptFile),
    healthDiagnosticFile: bounded(row.healthDiagnosticFile),
    googleSubject: bounded(row.googleSubject),
    originalOwnerEmail: bounded(row.originalOwnerEmail),
    changedProviderEmail: bounded(row.changedProviderEmail),
    expectedUserinfoMethod: row.expectedUserinfoMethod,
  });
  const clientId = bounded(row.clientId);
  const clientSecret = bounded(row.clientSecret);
  let active = false;
  return Object.freeze({
    provider: configuration,
    withProviderCredentialLease: async <Result>(
      use: (lease: GoogleProviderCredentialLease) => Promise<Result>
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
  });
};
/* eslint-enable complexity, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
