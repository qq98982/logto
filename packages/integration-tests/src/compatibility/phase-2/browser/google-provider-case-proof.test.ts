/* eslint-disable no-await-in-loop -- Sequential rewrites exercise one owned inode. */
import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  assertGoogleChangedEmailProviderReceipt,
  assertGooglePrimaryRegistrationProviderReceipt,
  assertGoogleReplayProviderReceipt,
  assertGoogleSessionProviderReceipt,
  assertGoogleWrongStateProviderReceipt,
} from './google-provider-case-proof.js';

const valid = {
  tokenRequestCount: 2,
  userinfoRequestCount: 2,
  userinfoGetObserved: true,
  userinfoPostObserved: false,
  grantTypeExact: true,
  callbackUriExact: true,
  clientAuthenticationExact: true,
  issuedBearerObserved: true,
  stableSubjectCaseConsumed: true,
  changedEmailCaseConsumed: true,
  wrongStateControlCodeConsumed: false,
  unverifiedEmailControlConsumed: false,
  occupiedEmailControlConsumed: false,
  replayRejected: false,
};
test('proves registration and both denied provider claims were consumed exactly once', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/google-registration-proof-');
  const file = path.join(root, 'receipt');
  const registration = {
    ...valid,
    tokenRequestCount: 3,
    userinfoRequestCount: 3,
    changedEmailCaseConsumed: false,
    unverifiedEmailControlConsumed: true,
    occupiedEmailControlConsumed: true,
  };
  await writeFile(file, JSON.stringify(registration), { mode: 0o600 });
  await expect(
    assertGooglePrimaryRegistrationProviderReceipt(file, 'GET')
  ).resolves.toBeUndefined();
  for (const value of [
    { ...registration, tokenRequestCount: 2 },
    { ...registration, unverifiedEmailControlConsumed: false },
    { ...registration, occupiedEmailControlConsumed: false },
    { ...registration, changedEmailCaseConsumed: true },
  ]) {
    await writeFile(file, JSON.stringify(value), { mode: 0o600 });
    await expect(assertGooglePrimaryRegistrationProviderReceipt(file, 'GET')).rejects.toThrow(
      'Invalid Google registration provider receipt'
    );
  }
  await rm(root, { recursive: true, force: true });
});
test('accepts only the complete two-case provider receipt', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/google-proof-');
  const file = path.join(root, 'receipt');
  await writeFile(file, JSON.stringify(valid), { mode: 0o600 });
  await expect(assertGoogleChangedEmailProviderReceipt(file, 'GET')).resolves.toBeUndefined();
  await expect(assertGoogleChangedEmailProviderReceipt(file, 'POST')).rejects.toThrow(
    'Invalid Google changed-email provider receipt'
  );
  await writeFile(
    file,
    JSON.stringify({ ...valid, userinfoGetObserved: false, userinfoPostObserved: true }),
    { mode: 0o600 }
  );
  await expect(assertGoogleChangedEmailProviderReceipt(file, 'POST')).resolves.toBeUndefined();
  for (const value of [
    { ...valid, changedEmailCaseConsumed: false },
    { ...valid, wrongStateControlCodeConsumed: true },
    { ...valid, tokenRequestCount: 1 },
    { ...valid, userinfoGetObserved: true, userinfoPostObserved: true },
    { ...valid, secret: 'private' },
  ]) {
    await writeFile(file, JSON.stringify(value), { mode: 0o600 });
    await expect(assertGoogleChangedEmailProviderReceipt(file, 'GET')).rejects.toThrow(
      'Invalid Google changed-email provider receipt'
    );
  }
  await chmod(file, 0o644);
  await expect(assertGoogleChangedEmailProviderReceipt(file, 'GET')).rejects.toThrow();
  const link = path.join(root, 'link');
  await symlink(file, link);
  await expect(assertGoogleChangedEmailProviderReceipt(link, 'GET')).rejects.toThrow();
  await rm(root, { recursive: true, force: true });
});

test('accepts only the two-call Google session receipt without the Account wrong-state control', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/google-session-proof-');
  const file = path.join(root, 'receipt');
  await writeFile(file, JSON.stringify(valid), { mode: 0o600 });
  await expect(assertGoogleSessionProviderReceipt(file, 'GET')).resolves.toBeUndefined();
  for (const value of [
    { ...valid, tokenRequestCount: 3 },
    { ...valid, userinfoRequestCount: 3 },
    { ...valid, stableSubjectCaseConsumed: false },
    { ...valid, changedEmailCaseConsumed: false },
    { ...valid, wrongStateControlCodeConsumed: true },
  ]) {
    await writeFile(file, JSON.stringify(value), { mode: 0o600 });
    await expect(assertGoogleSessionProviderReceipt(file, 'GET')).rejects.toThrow(
      'Invalid Google session provider receipt'
    );
  }
  await rm(root, { recursive: true, force: true });
});

test('proves the wrong-state code never reaches Token or UserInfo', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/google-wrong-state-proof-');
  const file = path.join(root, 'receipt');
  const wrongStateReceipt = {
    ...valid,
    tokenRequestCount: 1,
    userinfoRequestCount: 1,
    changedEmailCaseConsumed: false,
  };
  await writeFile(file, JSON.stringify(wrongStateReceipt), { mode: 0o600 });
  await expect(assertGoogleWrongStateProviderReceipt(file, 'GET')).resolves.toBeUndefined();
  for (const value of [
    { ...wrongStateReceipt, tokenRequestCount: 2 },
    { ...wrongStateReceipt, userinfoRequestCount: 2 },
    { ...wrongStateReceipt, changedEmailCaseConsumed: true },
    { ...wrongStateReceipt, wrongStateControlCodeConsumed: true },
  ]) {
    await writeFile(file, JSON.stringify(value), { mode: 0o600 });
    await expect(assertGoogleWrongStateProviderReceipt(file, 'GET')).rejects.toThrow(
      'Invalid Google wrong-state provider receipt'
    );
  }
  await rm(root, { recursive: true, force: true });
});

test('accepts exact local and upstream replay denial receipts', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/google-replay-proof-');
  const file = path.join(root, 'receipt');
  await writeFile(file, JSON.stringify(valid), { mode: 0o600 });
  await expect(assertGoogleReplayProviderReceipt(file, 'GET')).resolves.toBeUndefined();
  const upstreamReplay = { ...valid, tokenRequestCount: 3, replayRejected: true };
  await writeFile(file, JSON.stringify(upstreamReplay), { mode: 0o600 });
  await expect(assertGoogleReplayProviderReceipt(file, 'GET')).resolves.toBeUndefined();
  for (const value of [
    { ...valid, tokenRequestCount: 3 },
    { ...valid, replayRejected: true },
    { ...upstreamReplay, tokenRequestCount: 4 },
    { ...upstreamReplay, userinfoRequestCount: 3 },
    { ...upstreamReplay, grantTypeExact: false },
    { ...upstreamReplay, callbackUriExact: false },
    { ...upstreamReplay, clientAuthenticationExact: false },
    { ...upstreamReplay, issuedBearerObserved: false },
    { ...upstreamReplay, stableSubjectCaseConsumed: false },
    { ...upstreamReplay, changedEmailCaseConsumed: false },
    { ...upstreamReplay, wrongStateControlCodeConsumed: true },
    { ...upstreamReplay, secret: 'private' },
  ]) {
    await writeFile(file, JSON.stringify(value), { mode: 0o600 });
    await expect(assertGoogleReplayProviderReceipt(file, 'GET')).rejects.toThrow(
      'Invalid Google replay provider receipt'
    );
  }
  await rm(root, { recursive: true, force: true });
});
/* eslint-enable no-await-in-loop */
