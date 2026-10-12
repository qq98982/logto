/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- The launch fake and owned SMS socket capture ordered runtime behavior. */
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
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
    smsAccessKeyId: 'sms-id',
    smsAccessSecret: 'sms-secret',
    smsSignName: 'Aster Test',
    smsTemplates: {
      Register: 'SMS_REGISTER',
      SignIn: 'SMS_SIGN_IN',
      ForgotPassword: 'SMS_FORGOT_PASSWORD',
      Generic: 'SMS_GENERIC',
    },
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
const withControlledEmittedDescriptor = async (
  use: (filePath: string) => Promise<void>,
  sms = Object.freeze({
    accessKeyId: 'controlled-sms-id',
    accessKeySecret: 'controlled-sms-secret',
    signName: 'Controlled Sign',
    templates: {
      Register: 'CONTROLLED_REGISTER_TEMPLATE',
      SignIn: 'CONTROLLED_SIGN_IN_TEMPLATE',
      ForgotPassword: 'CONTROLLED_FORGOT_TEMPLATE',
      Generic: 'CONTROLLED_GENERIC_TEMPLATE',
    },
  })
) => {
  const smsRoot = await mkdtemp('/var/tmp/henry-build/common-completion-sms-');
  const smsConfigurationFile = path.join(smsRoot, 'configuration.json');
  const smsProviderInput = path.join(smsRoot, 'input.json');
  const smsSocket = path.join(smsRoot, 'sms.sock');
  const controlCapability = 'controlled-sms-capability';
  await writeFile(
    smsConfigurationFile,
    JSON.stringify({
      schemaVersion: 1,
      accessKeyId: sms.accessKeyId,
      accessKeySecret: sms.accessKeySecret,
      signName: sms.signName,
      templates: sms.templates,
      controlCapability,
    }),
    { mode: 0o600 }
  );
  await writeFile(
    smsProviderInput,
    JSON.stringify({
      schemaVersion: 1,
      configurationFile: smsConfigurationFile,
      controlSocket: smsSocket,
    }),
    { mode: 0o600 }
  );
  let armed = false;
  const server = createServer({ allowHalfOpen: true }, (connection) => {
    let body = '';
    connection.on('data', (chunk: Uint8Array) => {
      body += Buffer.from(chunk).toString('utf8');
    });
    connection.on('end', () => {
      const command = JSON.parse(body) as Record<string, string>;
      const exact =
        command.capability === controlCapability &&
        command.recipient === '15555550101' &&
        command.purpose === 'Register';
      if (exact && command.operation === 'arm' && !armed) {
        armed = true;
        connection.end('{"ok":true}\n');
      } else if (exact && command.operation === 'take' && armed) {
        armed = false;
        connection.end('{"ok":true,"code":"123456"}\n');
      } else {
        connection.end('{"ok":false}\n');
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(smsSocket, resolve);
  });
  await chmod(smsSocket, 0o600);
  const emitted = JSON.parse(
    await readFile(
      '/var/tmp/henry-build/aster-common206-completion/runtime-common/oracle-descriptor.json',
      'utf8'
    )
  ) as typeof base;
  const { smsCodeSocket: _legacySmsCodeSocket, ...emittedWechat } =
    emitted.wechat as typeof emitted.wechat & {
      smsCodeSocket?: string;
    };
  await withDescriptor(
    {
      ...emitted,
      wechat: {
        ...emittedWechat,
        clientId: 'controlled-wechat-client',
        clientSecret: 'controlled-wechat-secret',
        unionId: 'controlled-wechat-subject',
        collisionUnionId: 'controlled-wechat-collision',
        smsAccessKeyId: sms.accessKeyId,
        smsAccessSecret: sms.accessKeySecret,
        smsSignName: sms.signName,
        smsTemplates: sms.templates,
        smsProviderInput,
      },
    },
    use
  ).finally(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
    await rm(smsRoot, { recursive: true, force: true });
  });
};

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
  await withControlledEmittedDescriptor(async (filePath) => {
    const runtime = await read(filePath);
    expect(runtime.h5Target).toEqual(target);
    expect(runtime.h5Trust.caFile).toMatch(/h5-loopback-ca\.pem$/u);
    expect(runtime.wechat.mini.wechatSubject).toBe(runtime.wechat.native.wechatSubject);
    await runtime.wechat.h5.withProviderCredentialLease(async (lease) => {
      expect(lease.getClientId()).toBe('controlled-wechat-client');
      expect(lease.getSmsConfiguration?.()).toEqual({
        accessKeyId: 'controlled-sms-id',
        accessKeySecret: 'controlled-sms-secret',
        signName: 'Controlled Sign',
        templates: {
          Register: 'CONTROLLED_REGISTER_TEMPLATE',
          SignIn: 'CONTROLLED_SIGN_IN_TEMPLATE',
          ForgotPassword: 'CONTROLLED_FORGOT_TEMPLATE',
          Generic: 'CONTROLLED_GENERIC_TEMPLATE',
        },
      });
      await lease.armSmsRegistration?.('15555550101');
      await expect(lease.takeSmsRegistrationCode?.('15555550101')).resolves.toBe('123456');
      expect(() => lease.toJSON()).toThrow('Invalid Common completion fixture runtime');
    });
    expect(runtime.wechat.mini.smsConfiguration).toEqual({
      accessKeyId: 'controlled-sms-id',
      accessKeySecret: 'controlled-sms-secret',
      signName: 'Controlled Sign',
      templates: {
        Register: 'CONTROLLED_REGISTER_TEMPLATE',
        SignIn: 'CONTROLLED_SIGN_IN_TEMPLATE',
        ForgotPassword: 'CONTROLLED_FORGOT_TEMPLATE',
        Generic: 'CONTROLLED_GENERIC_TEMPLATE',
      },
    });
    await runtime.wechat.mini.withSmsProviderLease(async (lease) => {
      await lease.arm('15555550101', 'Register');
      await expect(lease.takeCode('15555550101', 'Register')).resolves.toBe('123456');
    });
  });
});

test('leases the complete owned SMS transport configuration to both provisioning markets', async () => {
  const sms = Object.freeze({
    accessKeyId: 'controlled-sms-id',
    accessKeySecret: 'controlled-sms-secret',
    signName: 'Controlled Sign',
    templates: {
      Register: 'CONTROLLED_REGISTER_TEMPLATE',
      SignIn: 'CONTROLLED_SIGN_IN_TEMPLATE',
      ForgotPassword: 'CONTROLLED_FORGOT_TEMPLATE',
      Generic: 'CONTROLLED_GENERIC_TEMPLATE',
    },
  });
  await withControlledEmittedDescriptor(async (filePath) => {
    const runtime = await read(filePath);
    await runtime.withProvisioningEnvironments(
      async ({ globalEnvironment, chinaNativeEnvironment }) => {
        const signName = Buffer.from(sms.signName, 'utf8').toString('base64');
        for (const environment of [globalEnvironment, chinaNativeEnvironment]) {
          expect(environment.BOX_AI_SMS_ACCESS_KEY_ID).toBe(sms.accessKeyId);
          expect(environment.BOX_AI_SMS_ACCESS_KEY_SECRET).toBe(sms.accessKeySecret);
          expect(environment.BOX_AI_SMS_SIGN_NAME_BASE64).toBe(signName);
          expect(environment.BOX_AI_SMS_TEMPLATE_CODE).toBe(sms.templates.Register);
        }
        expect(globalEnvironment.BOX_AI_SMS_CONNECTOR_FACTORY_ID).toBe(
          'aliyun-short-message-service'
        );
        await expect(runtime.withProvisioningEnvironments(async () => {})).rejects.toThrow(
          'Invalid Common completion fixture runtime'
        );
      }
    );
    await expect(runtime.withProvisioningEnvironments(async () => 'released')).resolves.toBe(
      'released'
    );
  }, sms);
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
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
