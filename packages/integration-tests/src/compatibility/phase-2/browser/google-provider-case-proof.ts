/* eslint-disable complexity, curly, no-bitwise, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types -- Secure bounded reader validates one exact receipt atomically. */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';

const changedEmailMessage = 'Invalid Google changed-email provider receipt';
const replayMessage = 'Invalid Google replay provider receipt';
const wrongStateMessage = 'Invalid Google wrong-state provider receipt';
const keys = [
  'tokenRequestCount',
  'userinfoRequestCount',
  'userinfoGetObserved',
  'userinfoPostObserved',
  'grantTypeExact',
  'callbackUriExact',
  'clientAuthenticationExact',
  'issuedBearerObserved',
  'stableSubjectCaseConsumed',
  'changedEmailCaseConsumed',
  'wrongStateControlCodeConsumed',
  'replayRejected',
].toSorted();
const receiptFail = (message: string): never => {
  throw new TypeError(message);
};

const readGoogleProviderReceipt = async (
  path: string,
  message: string
): Promise<Record<string, unknown>> => {
  try {
    const uid = process.getuid?.();
    const before = await lstat(path);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      uid === undefined ||
      before.uid !== uid ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600 ||
      before.size < 2 ||
      before.size > 65_536 ||
      (await realpath(path)) !== path
    )
      receiptFail(message);
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    let bytes: Buffer;
    try {
      const opened = await handle.stat();
      if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size)
        receiptFail(message);
      bytes = await handle.readFile();
    } finally {
      await handle.close();
    }
    const value: unknown = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
    if (
      typeof value !== 'object' ||
      value === null ||
      Array.isArray(value) ||
      Object.keys(value).toSorted().join('\0') !== keys.join('\0')
    )
      receiptFail(message);
    return value as Record<string, unknown>;
  } catch {
    return receiptFail(message);
  }
};

export const assertGoogleChangedEmailProviderReceipt = async (
  path: string,
  expectedUserinfoMethod: 'GET' | 'POST'
): Promise<void> => {
  try {
    const row = await readGoogleProviderReceipt(path, changedEmailMessage);
    if (
      row.tokenRequestCount !== 2 ||
      row.userinfoRequestCount !== 2 ||
      row.userinfoGetObserved !== (expectedUserinfoMethod === 'GET') ||
      row.userinfoPostObserved !== (expectedUserinfoMethod === 'POST') ||
      row.grantTypeExact !== true ||
      row.callbackUriExact !== true ||
      row.clientAuthenticationExact !== true ||
      row.issuedBearerObserved !== true ||
      row.stableSubjectCaseConsumed !== true ||
      row.changedEmailCaseConsumed !== true ||
      row.wrongStateControlCodeConsumed !== false ||
      typeof row.replayRejected !== 'boolean'
    )
      receiptFail(changedEmailMessage);
  } catch {
    receiptFail(changedEmailMessage);
  }
};

export const assertGoogleWrongStateProviderReceipt = async (
  path: string,
  expectedUserinfoMethod: 'GET' | 'POST'
): Promise<void> => {
  try {
    const row = await readGoogleProviderReceipt(path, wrongStateMessage);
    if (
      row.tokenRequestCount !== 1 ||
      row.userinfoRequestCount !== 1 ||
      row.userinfoGetObserved !== (expectedUserinfoMethod === 'GET') ||
      row.userinfoPostObserved !== (expectedUserinfoMethod === 'POST') ||
      row.grantTypeExact !== true ||
      row.callbackUriExact !== true ||
      row.clientAuthenticationExact !== true ||
      row.issuedBearerObserved !== true ||
      row.stableSubjectCaseConsumed !== true ||
      row.changedEmailCaseConsumed !== false ||
      row.wrongStateControlCodeConsumed !== false ||
      typeof row.replayRejected !== 'boolean'
    )
      receiptFail(wrongStateMessage);
  } catch {
    receiptFail(wrongStateMessage);
  }
};

export const assertGoogleReplayProviderReceipt = async (
  path: string,
  expectedUserinfoMethod: 'GET' | 'POST'
): Promise<void> => {
  try {
    const row = await readGoogleProviderReceipt(path, replayMessage);
    const denialObserved =
      (row.tokenRequestCount === 2 && row.replayRejected === false) ||
      (row.tokenRequestCount === 3 && row.replayRejected === true);
    if (
      !denialObserved ||
      row.userinfoRequestCount !== 2 ||
      row.userinfoGetObserved !== (expectedUserinfoMethod === 'GET') ||
      row.userinfoPostObserved !== (expectedUserinfoMethod === 'POST') ||
      row.grantTypeExact !== true ||
      row.callbackUriExact !== true ||
      row.clientAuthenticationExact !== true ||
      row.issuedBearerObserved !== true ||
      row.stableSubjectCaseConsumed !== true ||
      row.changedEmailCaseConsumed !== true ||
      row.wrongStateControlCodeConsumed !== false
    )
      receiptFail(replayMessage);
  } catch {
    receiptFail(replayMessage);
  }
};
/* eslint-enable complexity, curly, no-bitwise, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types */
