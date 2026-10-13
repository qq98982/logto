/* eslint-disable complexity, max-lines, no-bitwise, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This boundary validates one closed private descriptor before constructing runtime capabilities. */
import { X509Certificate } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import type { Browser, BrowserType } from '@playwright/test';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { createPlaywrightBrowserGroupObserver } from '../../phase-1/browser/playwright-session.js';
import { takePhase2VerificationCode, type Phase2AdminRequestFunction } from '../fixtures.js';
import type { CommonCompletionFixtureRuntime } from '../scenarios/common-completion-runner.js';

import { readCommonGoogleExistingOwnerFixtureRuntime } from './common-google-existing-owner-fixture-runtime.js';
import { readCommonWechatWebFixtureRuntime } from './common-wechat-web-fixture-runtime.js';
import { createDockerGoogleProviderControl } from './google-provider-lease.js';
import {
  createOwnedPasswordCompromiseFixture,
  withOwnedBackchannelReceiver,
  type OwnedPrivateService,
} from './owned-policy-logout-fixtures.js';
import {
  prepareOwnedWechatMiniProvider,
  prepareOwnedWechatNativeProvider,
} from './owned-wechat-code-provider.js';
import { withSmsProviderLease, type SmsProviderLease } from './sms-provider-lease.js';
import {
  createDockerWechatBrowserProviderControl,
  prepareWechatBrowserProviderLease,
} from './wechat-browser-provider-lease.js';

const fail = (): never => {
  throw new TypeError('Invalid Common completion fixture runtime');
};
const rootKeys = [
  'schemaVersion',
  'target',
  'googleProviderInput',
  'webProviderInput',
  'h5',
  'password',
  'h5Wechat',
  'wechat',
  'pwned',
  'backchannel',
].toSorted();
const targetKeys = ['label', 'coreUrl', 'adminUrl'].toSorted();
const h5Keys = ['listenUrl', 'caFile', 'spkiFile'].toSorted();
const passwordKeys = [...h5Keys, 'smtpSocket'].toSorted();
const h5WechatKeys = [
  'container',
  'project',
  'service',
  'image',
  'configFile',
  'receiptFile',
  'healthDiagnosticFile',
  'dockerHome',
  'apiVersion',
].toSorted();
const wechatKeys = [
  'container',
  'project',
  'service',
  'image',
  'configFile',
  'receiptFile',
  'healthDiagnosticFile',
  'dockerHome',
  'apiVersion',
  'clientId',
  'clientSecret',
  'unionId',
  'collisionUnionId',
  'ownerEmail',
  'phone',
  'smsAccessKeyId',
  'smsAccessSecret',
  'smsSignName',
  'smsTemplates',
  'smsProviderInput',
  'universalLink',
].toSorted();
const serviceKeys = [
  'container',
  'project',
  'service',
  'image',
  'receiptFile',
  'configFile',
  'dockerHome',
  'apiVersion',
];
const receiverKeys = [
  'container',
  'project',
  'service',
  'image',
  'receiptFile',
  'socketFile',
  'dockerHome',
  'apiVersion',
];
const bounded = (value: unknown, maximum = 4096): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();
const object = (value: unknown): Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype
    ? Object.fromEntries(Object.entries(value))
    : fail();
const exact = (value: unknown, keys: readonly string[]) => {
  const row = object(value);
  if (Object.keys(row).toSorted().join('\0') !== [...keys].toSorted().join('\0')) {
    return fail();
  }
  return row;
};
const absolute = (value: unknown) => {
  const selected = bounded(value);
  return path.isAbsolute(selected) && path.normalize(selected) === selected ? selected : fail();
};
const readPrivateJson = async (file: string) => {
  absolute(file);
  const [before, resolved] = await Promise.all([lstat(file), realpath(file)]).catch(fail);
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
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW).catch(fail);
  try {
    const opened = await handle.stat();
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
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
    return exact(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)), rootKeys);
  } finally {
    await handle.close();
  }
};
const readPinnedTrustFile = async (file: string): Promise<string> => {
  absolute(file);
  const [before, resolved] = await Promise.all([lstat(file), realpath(file)]).catch(fail);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== process.getuid?.() ||
    before.nlink !== 1 ||
    ![0o400, 0o444].includes(before.mode & 0o777) ||
    before.size < 2 ||
    before.size > 65_536 ||
    resolved !== file
  ) {
    return fail();
  }
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW).catch(fail);
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
    const after = await handle.stat();
    if (
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs
    ) {
      return fail();
    }
    return new TextDecoder('utf8', { fatal: true }).decode(bytes);
  } finally {
    await handle.close();
  }
};

export const createCommonH5BrowserObserver = async (
  browserType: Pick<BrowserType<Browser>, 'launch'>,
  trust: Readonly<{ spkiFile: string; caFile: string }>
): Promise<Phase1BrowserGroupObserver> => {
  const [spkiText, caText] = await Promise.all([
    readPinnedTrustFile(trust.spkiFile),
    readPinnedTrustFile(trust.caFile),
  ]);
  const spki = spkiText.endsWith('\n') ? spkiText.slice(0, -1) : spkiText;
  if (
    !/^[A-Za-z0-9+/]{43}=$/u.test(spki) ||
    Buffer.from(spki, 'base64').byteLength !== 32 ||
    !caText.startsWith('-----BEGIN CERTIFICATE-----\n') ||
    !caText.endsWith('-----END CERTIFICATE-----\n') ||
    caText.indexOf('-----BEGIN CERTIFICATE-----') !==
      caText.lastIndexOf('-----BEGIN CERTIFICATE-----')
  ) {
    return fail();
  }
  try {
    const certificate = new X509Certificate(caText);
    if (!certificate.ca) {
      return fail();
    }
  } catch {
    return fail();
  }
  const pinnedBrowser = Object.freeze({
    launch: async (options?: Parameters<BrowserType<Browser>['launch']>[0]) => {
      const inherited = options?.args ?? [];
      if (inherited.some((arg) => arg.startsWith('--ignore-certificate-errors'))) {
        return fail();
      }
      return browserType.launch({
        ...options,
        args: [...inherited, `--ignore-certificate-errors-spki-list=${spki}`],
        env: { ...process.env, ...options?.env, NODE_EXTRA_CA_CERTS: absolute(trust.caFile) },
      });
    },
  });
  return createPlaywrightBrowserGroupObserver(pinnedBrowser);
};
const sameTarget = (row: Record<string, unknown>, target: TargetConfig) => {
  const selected = exact(row.target, targetKeys);
  if (
    selected.label !== target.label ||
    selected.coreUrl !== target.coreUrl ||
    selected.adminUrl !== target.adminUrl
  ) {
    return fail();
  }
};
const dockerControl = (row: Record<string, unknown>, controlSocket: string) => {
  const apiVersion = bounded(row.apiVersion, 32);
  if (!/^[1-9][0-9]*\.[0-9]+\.[0-9]+$/u.test(apiVersion)) {
    return fail();
  }
  return createDockerGoogleProviderControl({
    socket: absolute(controlSocket),
    home: absolute(row.dockerHome),
    apiVersion,
  });
};
const service = (value: unknown, controlSocket: string, receiver: boolean): OwnedPrivateService => {
  const row = exact(value, receiver ? receiverKeys : serviceKeys);
  return Object.freeze({
    control: dockerControl(row, controlSocket),
    container: bounded(row.container),
    project: bounded(row.project),
    service: bounded(row.service),
    image: bounded(row.image),
    receiptFile: absolute(row.receiptFile),
    ...(receiver
      ? { socketFile: absolute(row.socketFile) }
      : { configFile: absolute(row.configFile) }),
  });
};

export type CommonCompletionIdentityRuntime = Omit<CommonCompletionFixtureRuntime, 'management'> &
  Readonly<{
    h5Trust: Readonly<{ caFile: string; spkiFile: string }>;
    withProvisioningEnvironments<Result>(
      use: (
        environments: Readonly<{
          globalEnvironment: Readonly<Record<string, string>>;
          chinaNativeEnvironment: Readonly<Record<string, string>>;
        }>
      ) => Promise<Result>
    ): Promise<Result>;
  }>;

export const readCommonCompletionFixtureRuntime = async (
  input: Readonly<{
    filePath: string;
    controlSocket: string;
    target: TargetConfig;
    managementRequest: Phase2AdminRequestFunction;
    h5Observer?: Phase1BrowserGroupObserver;
    h5BrowserType?: Pick<BrowserType<Browser>, 'launch'>;
  }>
): Promise<CommonCompletionIdentityRuntime> => {
  const row = await readPrivateJson(input.filePath);
  if (row.schemaVersion !== 1) {
    return fail();
  }
  sameTarget(row, input.target);
  const browserTarget = (value: unknown, keys = h5Keys) => {
    const source = exact(value, keys);
    const listen = new URL(bounded(source.listenUrl));
    if (
      listen.protocol !== 'https:' ||
      listen.username ||
      listen.password ||
      listen.pathname !== '/' ||
      listen.search ||
      listen.hash
    ) {
      return fail();
    }
    return Object.freeze({
      target: Object.freeze({ ...input.target, coreUrl: `${listen.origin}/` }),
      caFile: absolute(source.caFile),
      spkiFile: absolute(source.spkiFile),
    });
  };
  const h5 = browserTarget(row.h5);
  const passwordSource = exact(row.password, passwordKeys);
  const passwordBrowser = browserTarget(passwordSource, passwordKeys);
  const passwordSmtpSocket = absolute(passwordSource.smtpSocket);
  const passwordSmtpSocketName =
    input.target.label === 'oracle' ? 'oracle-smtp.sock' : 'password-smtp.sock';
  if (!passwordSmtpSocket.endsWith(`/${passwordSmtpSocketName}`)) {
    return fail();
  }
  if (passwordBrowser.caFile !== h5.caFile || passwordBrowser.spkiFile !== h5.spkiFile) {
    return fail();
  }
  const listen = new URL(h5.target.coreUrl);
  if (
    listen.protocol !== 'https:' ||
    listen.username ||
    listen.password ||
    listen.pathname !== '/' ||
    listen.search ||
    listen.hash
  ) {
    return fail();
  }
  const h5Target = h5.target;
  const { caFile } = h5;
  const { spkiFile } = h5;
  if ((input.h5Observer === undefined) === (input.h5BrowserType === undefined)) {
    return fail();
  }
  const h5Observer =
    input.h5Observer ??
    (await createCommonH5BrowserObserver(input.h5BrowserType ?? fail(), { caFile, spkiFile }));
  const wechat = exact(row.wechat, wechatKeys);
  const h5Wechat = exact(row.h5Wechat, h5WechatKeys);
  const smsProviderInput = absolute(wechat.smsProviderInput);
  const smsAccessKeyId = bounded(wechat.smsAccessKeyId);
  const smsAccessSecret = bounded(wechat.smsAccessSecret);
  const smsSignNameBase64 = Buffer.from(bounded(wechat.smsSignName), 'utf8').toString('base64');
  const smsTemplatesRow = exact(wechat.smsTemplates, [
    'Register',
    'SignIn',
    'ForgotPassword',
    'Generic',
  ]);
  const smsConfiguration = Object.freeze({
    accessKeyId: smsAccessKeyId,
    accessKeySecret: smsAccessSecret,
    signName: bounded(wechat.smsSignName),
    templates: Object.freeze({
      Register: bounded(smsTemplatesRow.Register),
      SignIn: bounded(smsTemplatesRow.SignIn),
      ForgotPassword: bounded(smsTemplatesRow.ForgotPassword),
      Generic: bounded(smsTemplatesRow.Generic),
    }),
  });
  const smsTemplateCode = smsConfiguration.templates.Register;
  const apiVersion = bounded(wechat.apiVersion, 32);
  const providerControl = createDockerWechatBrowserProviderControl({
    socket: absolute(input.controlSocket),
    home: absolute(wechat.dockerHome),
    apiVersion,
  });
  const h5ApiVersion = bounded(h5Wechat.apiVersion, 32);
  const h5ProviderControl = createDockerWechatBrowserProviderControl({
    socket: absolute(input.controlSocket),
    home: absolute(h5Wechat.dockerHome),
    apiVersion: h5ApiVersion,
  });
  const providerBase = Object.freeze({
    control: providerControl,
    container: bounded(wechat.container),
    project: bounded(wechat.project),
    service: bounded(wechat.service),
    image: bounded(wechat.image),
    configFile: absolute(wechat.configFile),
    receiptFile: absolute(wechat.receiptFile),
    clientId: bounded(wechat.clientId),
    clientSecret: bounded(wechat.clientSecret),
    wechatSubject: bounded(wechat.unionId),
    collisionWechatSubject: bounded(wechat.collisionUnionId),
    phone: bounded(wechat.phone),
  });
  const [google, web] = await Promise.all([
    readCommonGoogleExistingOwnerFixtureRuntime(
      absolute(row.googleProviderInput),
      input.controlSocket
    ),
    readCommonWechatWebFixtureRuntime(absolute(row.webProviderInput), input.controlSocket),
  ]);
  const pwned = exact(row.pwned, ['clear', 'compromised', 'unavailable']);
  const backchannel = exact(row.backchannel, ['accepted', 'rejected']);
  const password = createOwnedPasswordCompromiseFixture(
    {
      clear: service(pwned.clear, input.controlSocket, false),
      compromised: service(pwned.compromised, input.controlSocket, false),
      unavailable: service(pwned.unavailable, input.controlSocket, false),
    },
    input.target.label
  );
  const receivers = {
    accepted: service(backchannel.accepted, input.controlSocket, true),
    rejected: service(backchannel.rejected, input.controlSocket, true),
  } as const;
  let credentialActive = false;
  const credential = async <Result>(
    use: (
      lease: Readonly<{
        getClientId(): string;
        getClientSecret(): string;
        getSmsConfiguration(): typeof smsConfiguration;
        armSmsRegistration(recipient: string): Promise<void>;
        takeSmsRegistrationCode(recipient: string): Promise<string>;
        toJSON(): never;
      }>
    ) => Promise<Result>
  ) => {
    if (credentialActive || typeof use !== 'function') {
      return fail();
    }
    credentialActive = true;
    const available = () => (credentialActive ? true : fail());
    try {
      return await withSmsProviderLease(smsProviderInput, async (smsLease) => {
        const leasedConfiguration = Object.freeze({
          accessKeyId: smsLease.configuration.accessKeyId,
          accessKeySecret: smsLease.configuration.accessKeySecret,
          signName: smsLease.configuration.signName,
          templates: Object.freeze(
            Object.fromEntries(
              smsLease.configuration.templates.map(({ usageType, templateCode }) => [
                usageType,
                templateCode,
              ])
            )
          ),
        });
        if (!isDeepStrictEqual(leasedConfiguration, smsConfiguration)) {
          return fail();
        }
        return use(
          Object.freeze({
            getClientId: () => {
              available();
              return bounded(wechat.clientId);
            },
            getClientSecret: () => {
              available();
              return bounded(wechat.clientSecret);
            },
            getSmsConfiguration: () => {
              available();
              return smsConfiguration;
            },
            armSmsRegistration: async (recipient: string) => smsLease.arm(recipient, 'Register'),
            takeSmsRegistrationCode: async (recipient: string) =>
              smsLease.takeCode(recipient, 'Register'),
            toJSON: (): never => fail(),
          })
        );
      });
    } finally {
      credentialActive = false;
    }
  };
  const native = {
    managementRequest: input.managementRequest,
    clientId: bounded(wechat.clientId),
    clientSecret: bounded(wechat.clientSecret),
    universalLink: bounded(wechat.universalLink),
    wechatSubject: bounded(wechat.unionId),
    prepareProvider: async () => prepareOwnedWechatNativeProvider(providerBase),
  };
  const h5Runtime: CommonCompletionFixtureRuntime['wechat']['h5'] = {
    provider: {
      wechatSubject: bounded(wechat.unionId),
      registrationPhone: bounded(wechat.phone),
    },
    withProviderCredentialLease: credential,
    prepareProvider: async (providerInput) =>
      prepareWechatBrowserProviderLease({
        ...providerInput,
        control: h5ProviderControl,
        container: bounded(h5Wechat.container),
        project: bounded(h5Wechat.project),
        service: bounded(h5Wechat.service),
        image: bounded(h5Wechat.image),
        configFile: absolute(h5Wechat.configFile),
        receiptFile: absolute(h5Wechat.receiptFile),
        healthDiagnosticFile: absolute(h5Wechat.healthDiagnosticFile),
        role: input.target.label,
        channel: 'h5',
        smsAccessSecret,
      }),
  };
  const receiver: CommonCompletionFixtureRuntime['logout']['withReceiver'] = async (
    delivery,
    expectedNotification,
    use
  ) => withOwnedBackchannelReceiver({ delivery, expectedNotification, services: receivers }, use);
  let environmentActive = false;
  const withProvisioningEnvironments: CommonCompletionIdentityRuntime['withProvisioningEnvironments'] =
    async (use) => {
      if (environmentActive || typeof use !== 'function') {
        return fail();
      }
      environmentActive = true;
      try {
        return await google.withProviderCredentialLease(async (googleLease) =>
          credential(async (wechatLease) =>
            use(
              Object.freeze({
                globalEnvironment: Object.freeze({
                  BOX_AI_GOOGLE_CLIENT_ID: googleLease.getClientId(),
                  BOX_AI_GOOGLE_CLIENT_SECRET: googleLease.getClientSecret(),
                  BOX_AI_SMS_ACCESS_KEY_ID: smsAccessKeyId,
                  BOX_AI_SMS_ACCESS_KEY_SECRET: smsAccessSecret,
                  BOX_AI_SMS_SIGN_NAME_BASE64: smsSignNameBase64,
                  BOX_AI_SMS_TEMPLATE_CODE: smsTemplateCode,
                  BOX_AI_SMS_CONNECTOR_FACTORY_ID: 'aliyun-short-message-service',
                }),
                chinaNativeEnvironment: Object.freeze({
                  BOX_AI_SMS_ACCESS_KEY_ID: smsAccessKeyId,
                  BOX_AI_SMS_ACCESS_KEY_SECRET: smsAccessSecret,
                  BOX_AI_SMS_SIGN_NAME_BASE64: smsSignNameBase64,
                  BOX_AI_SMS_TEMPLATE_CODE: smsTemplateCode,
                  BOX_AI_WECHAT_CHANNELS: 'native',
                  BOX_AI_WECHAT_NATIVE_APP_ID: wechatLease.getClientId(),
                  BOX_AI_WECHAT_NATIVE_APP_SECRET: wechatLease.getClientSecret(),
                  BOX_AI_WECHAT_NATIVE_UNIVERSAL_LINKS: bounded(wechat.universalLink),
                }),
              })
            )
          )
        );
      } finally {
        environmentActive = false;
      }
    };
  return Object.freeze({
    google,
    web,
    password,
    passwordTarget: passwordBrowser.target,
    takePasswordRecoveryCode: async (recipient: string) =>
      takePhase2VerificationCode(passwordSmtpSocket, passwordSmtpSocketName, recipient),
    h5Target,
    h5Observer,
    h5Trust: Object.freeze({ caFile, spkiFile }),
    withProvisioningEnvironments,
    logout: Object.freeze({
      google,
      native: {
        providerClientId: native.clientId,
        providerClientSecret: native.clientSecret,
        wechatSubject: native.wechatSubject,
        universalLink: native.universalLink,
        prepareProvider: native.prepareProvider,
      },
      withReceiver: receiver,
    }),
    wechat: Object.freeze({
      h5: h5Runtime,
      mini: {
        managementRequest: input.managementRequest,
        clientId: native.clientId,
        clientSecret: native.clientSecret,
        wechatSubject: native.wechatSubject,
        ownerEmail: bounded(wechat.ownerEmail),
        phone: providerBase.phone,
        smsConfiguration,
        withSmsProviderLease: async <Result>(use: (lease: SmsProviderLease) => Promise<Result>) =>
          withSmsProviderLease(smsProviderInput, use),
        prepareProvider: async () => prepareOwnedWechatMiniProvider(providerBase),
      },
      native,
    }),
  });
};
/* eslint-enable complexity, max-lines, no-bitwise, no-control-regex, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
