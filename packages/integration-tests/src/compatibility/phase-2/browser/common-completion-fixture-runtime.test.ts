/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- The launch fake captures the exact pinned browser options. */
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import {
  createCommonH5BrowserObserver,
  readCommonCompletionFixtureRuntime,
} from './common-completion-fixture-runtime.js';

const target: TargetConfig = {
  label: 'oracle',
  coreUrl: 'https://localhost:3351/',
  adminUrl: 'http://127.0.0.1:3411/',
};
const inertRequest = (async () => {
  throw new TypeError('Management must not be reached during descriptor admission');
}) as Phase2AdminRequestFunction;
const inertObserver = Object.freeze({}) as Phase1BrowserGroupObserver;
const base = {
  schemaVersion: 1,
  target,
  googleProviderInput: '/private/google.json',
  webProviderInput: '/private/web.json',
  h5: {
    listenUrl: 'https://localhost:3351',
    caFile: '/private/h5-ca.pem',
    spkiFile: '/private/h5.spki',
  },
  wechat: {
    container: 'owned-wechat',
    project: 'owned',
    service: 'wechat',
    image: `sha256:${'a'.repeat(64)}`,
    configFile: '/private/config.json',
    receiptFile: '/private/receipt.ndjson',
    healthDiagnosticFile: '/private/health.json',
    dockerHome: '/private/docker-home',
    apiVersion: '4.9.4',
    clientId: 'client',
    clientSecret: 'secret',
    unionId: 'subject',
    collisionUnionId: 'collision',
    ownerEmail: 'owner@example.invalid',
    phone: '+15555550101',
    smsAccessSecret: 'sms-secret',
    universalLink: 'https://native.example.invalid/',
  },
  pwned: { clear: {}, compromised: {}, unavailable: {} },
  backchannel: { accepted: {}, rejected: {} },
};
const withDescriptor = async (value: unknown, use: (file: string) => Promise<void>) => {
  const root = await mkdtemp('/var/tmp/henry-build/common-completion-runtime-');
  const file = path.join(root, 'descriptor.json');
  try {
    await writeFile(file, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    await use(file);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};
const read = async (filePath: string) =>
  readCommonCompletionFixtureRuntime({
    filePath,
    controlSocket: '/private/control.sock',
    target,
    managementRequest: inertRequest,
    h5Observer: inertObserver,
  });

test('rejects a descriptor missing the required real SMS code socket before container I/O', async () => {
  await withDescriptor(base, async (file) => {
    await expect(read(file)).rejects.toThrow('Invalid Common completion fixture runtime');
  });
});

test('rejects unknown descriptor fields before container I/O', async () => {
  await withDescriptor({ ...base, unknown: true }, async (file) => {
    await expect(read(file)).rejects.toThrow('Invalid Common completion fixture runtime');
  });
});

test('rejects a descriptor bound to another target before container I/O', async () => {
  await withDescriptor({ ...base, target: { ...target, label: 'candidate' } }, async (file) => {
    await expect(read(file)).rejects.toThrow('Invalid Common completion fixture runtime');
  });
});

test('constructs capabilities from the emitted private descriptor without container I/O', async () => {
  const runtime = await readCommonCompletionFixtureRuntime({
    filePath:
      '/var/tmp/henry-build/aster-common206-completion/runtime-common/oracle-descriptor.json',
    controlSocket: '/run/user/1000/podman/podman.sock',
    target,
    managementRequest: inertRequest,
    h5Observer: inertObserver,
  });
  expect(runtime.h5Target).toEqual(target);
  expect(runtime.h5Trust.caFile).toMatch(/h5-loopback-ca\.pem$/u);
  expect(runtime.wechat.mini.wechatSubject).toBe(runtime.wechat.native.wechatSubject);
  await runtime.wechat.h5.withProviderCredentialLease(async (lease) => {
    expect(lease.getClientId()).toBe(runtime.wechat.mini.clientId);
    expect(lease.getSmsAccessSecret?.()).toBe(runtime.wechat.mini.smsAccessSecret);
    expect(() => lease.toJSON()).toThrow('Invalid Common completion fixture runtime');
  });
});

test('admits one pinned SPKI and CA without enabling global insecure TLS', async () => {
  const spkiFile =
    '/var/tmp/henry-build/aster-common206-completion/runtime-h5/h5-loopback-server.spki';
  const caFile = '/var/tmp/henry-build/aster-common206-completion/runtime-h5/h5-loopback-ca.pem';
  const launches: unknown[] = [];
  const observer = await createCommonH5BrowserObserver(
    {
      launch: async (options) => {
        launches.push(options);
        return {} as never;
      },
    },
    { spkiFile, caFile }
  );
  await expect(
    observer.runInFreshContext('experience', new AbortController().signal, target, async () => {})
  ).rejects.toThrow();
  expect(launches).toHaveLength(1);
  expect(launches[0]).toMatchObject({
    args: [expect.stringMatching(/^--ignore-certificate-errors-spki-list=[A-Za-z0-9+/]{43}=$/u)],
    env: { NODE_EXTRA_CA_CERTS: caFile },
  });
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
