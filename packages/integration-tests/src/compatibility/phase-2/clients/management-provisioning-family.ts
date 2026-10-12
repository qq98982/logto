/* eslint-disable no-await-in-loop, @typescript-eslint/ban-types, @typescript-eslint/no-non-null-assertion, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The bounded child runner owns process state and private credential cleanup. */
import { spawn } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const fail = (): never => {
  throw new TypeError('Invalid Common Management provisioning family runner');
};
const scripts = Object.freeze([
  'provision-email-connector.mjs',
  'provision-google-connector.mjs',
  'provision-sms-connector.mjs',
  'provision-wechat-connectors.mjs',
  'provision-client.mjs',
]);
const directory = fileURLToPath(
  new URL(
    '../../../../src/compatibility/phase-2/testing/management-provisioning-family/',
    import.meta.url
  )
);
const privateRoot = '/var/tmp/henry-build';
const allowed = new Set([
  'PATH',
  'BOX_AI_LOGTO_BOOTSTRAP_ENDPOINT',
  'BOX_AI_LOGTO_ENDPOINT',
  'BOX_AI_PUBLIC_BASE_URL',
  'BOX_AI_MARKET',
  'BOX_AI_LOGTO_MANAGEMENT_TOKEN',
  'BOX_AI_LOGTO_CREDENTIAL_DIR',
  'BOX_AI_SMTP_HOST',
  'BOX_AI_SMTP_PORT',
  'BOX_AI_SMTP_SECURITY',
  'BOX_AI_SMTP_FROM_NAME',
  'BOX_AI_SMTP_FROM_EMAIL',
  'BOX_AI_SMTP_USERNAME',
  'BOX_AI_SMTP_PASSWORD',
  'BOX_AI_GOOGLE_CLIENT_ID',
  'BOX_AI_GOOGLE_CLIENT_SECRET',
  'BOX_AI_SMS_ACCESS_KEY_ID',
  'BOX_AI_SMS_ACCESS_KEY_SECRET',
  'BOX_AI_SMS_SIGN_NAME_BASE64',
  'BOX_AI_SMS_TEMPLATE_CODE',
  'BOX_AI_SMS_CONNECTOR_FACTORY_ID',
  'BOX_AI_WECHAT_CHANNELS',
  'BOX_AI_WECHAT_WEB_APP_ID',
  'BOX_AI_WECHAT_WEB_APP_SECRET',
  'BOX_AI_WECHAT_H5_APP_ID',
  'BOX_AI_WECHAT_H5_APP_SECRET',
  'BOX_AI_WECHAT_MINI_APP_ID',
  'BOX_AI_WECHAT_MINI_APP_SECRET',
  'BOX_AI_WECHAT_NATIVE_APP_ID',
  'BOX_AI_WECHAT_NATIVE_APP_SECRET',
  'BOX_AI_WECHAT_NATIVE_UNIVERSAL_LINKS',
]);

type ProvisionerOutcome = 'completed' | 'ownership-refused';
const ownershipRefusal = 'Error: multiple applications use the Box-AI application name';
export const classifyManagementProvisioningClientRefusal = (
  code: number | null,
  timedOut: boolean,
  output: string,
  secretPresent: boolean
): ProvisionerOutcome | undefined => {
  if (timedOut || secretPresent || Buffer.byteLength(output) > 64 * 1024) {
    return undefined;
  }
  if (code === 0) {
    return 'completed';
  }
  return typeof code === 'number' && code > 0 && output.split(/\r?\n/u).includes(ownershipRefusal)
    ? 'ownership-refused'
    : undefined;
};
const run = async (
  script: string,
  environment: Readonly<Record<string, string>>,
  admitOwnershipRefusal = false
): Promise<ProvisionerOutcome> =>
  new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(directory, script)], {
      env: environment,
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let timedOut = false;
    let killTimer: NodeJS.Timeout | undefined;
    const capture = (chunk: Buffer) => {
      bytes += chunk.byteLength;
      if (bytes > 64 * 1024) {
        timedOut = true;
        try {
          process.kill(-child.pid!, 'SIGTERM');
        } catch {}
        return;
      }
      chunks.push(chunk);
    };
    child.stdout.on('data', capture);
    child.stderr.on('data', capture);
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        process.kill(-child.pid!, 'SIGTERM');
      } catch {}
      killTimer = setTimeout(() => {
        try {
          process.kill(-child.pid!, 'SIGKILL');
        } catch {}
      }, 5000);
    }, 30_000);
    child.once('error', (error) => {
      clearTimeout(timer);
      if (killTimer) {
        clearTimeout(killTimer);
      }
      reject(error);
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (killTimer) {
        clearTimeout(killTimer);
      }
      const output = Buffer.concat(chunks).toString('utf8');
      const secrets = Object.entries(environment)
        .filter(([name]) => /TOKEN|SECRET|PASSWORD/u.test(name))
        .map(([, value]) => value);
      const outcome = classifyManagementProvisioningClientRefusal(
        code,
        timedOut,
        output,
        secrets.some((secret) => secret.length > 0 && output.includes(secret))
      );
      if (!outcome || (outcome === 'ownership-refused' && !admitOwnershipRefusal)) {
        reject(new TypeError('Invalid Common Management provisioner execution'));
      } else {
        resolve(outcome);
      }
    });
  });

export const withManagementProvisioningFamily = async <Result>(
  input: Readonly<{
    environment: Readonly<Record<string, string>>;
    use(
      value: Readonly<{ getClientId(): string; getClientSecret(): string; toJSON(): never }>
    ): Promise<Result>;
  }>
): Promise<Result> => {
  if (Object.keys(input.environment).some((name) => !allowed.has(name))) {
    return fail();
  }
  await mkdir(privateRoot, { recursive: true, mode: 0o700 });
  const credentialDirectory = await mkdtemp(
    path.join(privateRoot, 'phase2-management-provisioning-')
  );
  await chmod(credentialDirectory, 0o700);
  const environment = Object.freeze({
    ...input.environment,
    BOX_AI_LOGTO_CREDENTIAL_DIR: credentialDirectory,
  });
  let clientId = '';
  let clientSecret = '';
  try {
    for (const script of scripts) {
      await run(script, environment);
    }
    const clientIdFile = await readFile(path.join(credentialDirectory, 'client-id'), 'utf8');
    const clientSecretFile = await readFile(
      path.join(credentialDirectory, 'client-secret'),
      'utf8'
    );
    clientId = clientIdFile.trim();
    clientSecret = clientSecretFile.trim();
    if (!clientId || !clientSecret || clientId.length > 256 || clientSecret.length > 512) {
      return fail();
    }
    return await input.use(
      Object.freeze({
        getClientId: () => clientId,
        getClientSecret: () => clientSecret,
        toJSON: fail,
      })
    );
  } finally {
    clientId = '';
    clientSecret = '';
    await rm(credentialDirectory, { recursive: true, force: true });
  }
};

export const observeManagementProvisioningClientRefusal = async (
  inputEnvironment: Readonly<Record<string, string>>
): Promise<boolean> => {
  if (Object.keys(inputEnvironment).some((name) => !allowed.has(name))) {
    return fail();
  }
  await mkdir(privateRoot, { recursive: true, mode: 0o700 });
  const credentialDirectory = await mkdtemp(
    path.join(privateRoot, 'phase2-management-provisioning-refusal-')
  );
  await chmod(credentialDirectory, 0o700);
  try {
    const outcome = await run(
      'provision-client.mjs',
      Object.freeze({
        ...inputEnvironment,
        BOX_AI_LOGTO_CREDENTIAL_DIR: credentialDirectory,
      }),
      true
    );
    return outcome === 'ownership-refused';
  } finally {
    await rm(credentialDirectory, { recursive: true, force: true });
  }
};
/* eslint-enable no-await-in-loop, @typescript-eslint/ban-types, @typescript-eslint/no-non-null-assertion, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
