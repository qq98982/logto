/* eslint-disable complexity, no-bitwise, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- One private lease owns bounded socket retrieval, checked JSON narrowing and file identity checks. */
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createConnection } from 'node:net';
import path from 'node:path';

const failure = 'Invalid SMS provider lease';
const fail = (): never => {
  throw new TypeError(failure);
};
const maximumBytes = 16_384;
export type SmsPurpose = 'SignIn' | 'Register' | 'ForgotPassword' | 'Generic';
const purposes: readonly SmsPurpose[] = ['SignIn', 'Register', 'ForgotPassword', 'Generic'];
const exactKeys = (value: unknown, keys: readonly string[]): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const safeString = (value: unknown, maximum = 512): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/\p{Cc}/u.test(value);
const safePath = (value: unknown): value is string =>
  safeString(value, 4096) && path.isAbsolute(value) && path.normalize(value) === value;
const readPrivateJson = async (file: string): Promise<unknown> => {
  const before = await lstat(file);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.uid !== process.getuid?.() ||
    before.nlink !== 1 ||
    (before.mode & 0o777) !== 0o600 ||
    before.size < 2 ||
    before.size > maximumBytes ||
    (await realpath(file)) !== file
  ) {
    return fail();
  }
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const current = await handle.stat();
    if (current.dev !== before.dev || current.ino !== before.ino || current.size !== before.size) {
      return fail();
    }
    const bytes = await handle.readFile();
    if (bytes.byteLength !== before.size) {
      return fail();
    }
    return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)) as unknown;
  } finally {
    await handle.close();
  }
};
const admitSocket = async (socket: string): Promise<void> => {
  if (!safePath(socket) || Buffer.byteLength(socket) > 100) {
    return fail();
  }
  const directory = path.dirname(socket);
  const parent = await lstat(directory);
  const state = await lstat(socket);
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    parent.uid !== process.getuid?.() ||
    (parent.mode & 0o777) !== 0o700 ||
    (await realpath(directory)) !== directory ||
    !state.isSocket() ||
    state.isSymbolicLink() ||
    state.uid !== process.getuid() ||
    (state.mode & 0o777) !== 0o600 ||
    state.nlink !== 1
  ) {
    return fail();
  }
};
const controlRequest = async (
  socket: string,
  request: Readonly<Record<string, string>>
): Promise<unknown> => {
  try {
    await admitSocket(socket);
  } catch {
    return fail();
  }
  return new Promise<unknown>((resolve, reject) => {
    const connection = createConnection(socket);
    let body = '';
    let done = false;
    const finish = (error?: boolean, value?: unknown) => {
      if (done) {
        return;
      }
      done = true;
      connection.destroy();
      if (error) {
        reject(new TypeError(failure));
      } else {
        resolve(value);
      }
    };
    connection.setTimeout(5000, () => {
      finish(true);
    });
    connection.once('error', () => {
      finish(true);
    });
    connection.once('connect', () => connection.end(`${JSON.stringify(request)}\n`));
    connection.on('data', (chunk: Uint8Array) => {
      if (Buffer.byteLength(body) + chunk.byteLength > 4096) {
        finish(true);
        return;
      }
      body += Buffer.from(chunk).toString('utf8');
    });
    connection.once('end', () => {
      try {
        if (!body.endsWith('\n') || body.slice(0, -1).includes('\n')) {
          finish(true);
          return;
        }
        finish(false, JSON.parse(body) as unknown);
      } catch {
        finish(true);
      }
    });
    connection.once('close', () => {
      if (!done) {
        finish(true);
      }
    });
  });
};
export type SmsProviderLease = Readonly<{
  configuration: Readonly<{
    accessKeyId: string;
    accessKeySecret: string;
    signName: string;
    templates: ReadonlyArray<Readonly<{ usageType: SmsPurpose; templateCode: string }>>;
  }>;
  arm(recipient: string, purpose: SmsPurpose): Promise<void>;
  takeCode(recipient: string, purpose: SmsPurpose): Promise<string>;
}>;
export const withSmsProviderLease = async <Result>(
  inputFile: string,
  use: (lease: SmsProviderLease) => Promise<Result>
): Promise<Result> => {
  let active = true;
  let consumerEntered = false;
  const armed = new Map<string, Readonly<{ recipient: string; purpose: SmsPurpose }>>();
  let releaseArmed: (() => Promise<void>) | undefined;
  try {
    if (!safePath(inputFile)) {
      return fail();
    }
    const input = await readPrivateJson(inputFile);
    if (
      !exactKeys(input, ['schemaVersion', 'configurationFile', 'controlSocket']) ||
      input.schemaVersion !== 1 ||
      !safePath(input.configurationFile) ||
      !safePath(input.controlSocket)
    ) {
      return fail();
    }
    const config = await readPrivateJson(input.configurationFile);
    if (
      !exactKeys(config, [
        'schemaVersion',
        'accessKeyId',
        'accessKeySecret',
        'signName',
        'templates',
        'controlCapability',
      ]) ||
      config.schemaVersion !== 1 ||
      !safeString(config.accessKeyId) ||
      !safeString(config.accessKeySecret) ||
      !safeString(config.signName) ||
      !safeString(config.controlCapability) ||
      !exactKeys(config.templates, purposes) ||
      purposes.some(
        (purpose) => !safeString((config.templates as Record<string, unknown>)[purpose])
      )
    ) {
      return fail();
    }
    const socket = input.controlSocket;
    const capability = config.controlCapability;
    const { templates } = config;
    const configuration = Object.freeze({
      accessKeyId: config.accessKeyId,
      accessKeySecret: config.accessKeySecret,
      signName: config.signName,
      templates: Object.freeze(
        purposes.map((purpose) =>
          Object.freeze({ usageType: purpose, templateCode: templates[purpose] as string })
        )
      ),
      toJSON: fail,
    });
    const command = async (
      operation: 'arm' | 'take' | 'release',
      recipient: string,
      purpose: SmsPurpose
    ) => {
      if (!active || !/^[0-9]{1,32}$/u.test(recipient) || !purposes.includes(purpose)) {
        return fail();
      }
      const result = await controlRequest(socket, { operation, capability, recipient, purpose });
      if (operation === 'arm' || operation === 'release') {
        if (!exactKeys(result, ['ok']) || result.ok !== true) {
          return fail();
        }
      } else if (
        !exactKeys(result, ['ok', 'code']) ||
        result.ok !== true ||
        typeof result.code !== 'string' ||
        !/^[0-9]{6}$/u.test(result.code)
      ) {
        return fail();
      }
      return result;
    };
    releaseArmed = async () => {
      await Promise.all(
        [...armed.values()].map(async ({ recipient, purpose }) =>
          command('release', recipient, purpose)
        )
      );
      armed.clear();
    };
    consumerEntered = true;
    return await use(
      Object.freeze({
        configuration,
        toJSON: fail,
        arm: async (recipient: string, purpose: SmsPurpose) => {
          await command('arm', recipient, purpose);
          armed.set(
            `${recipient.length}:${recipient}${purpose}`,
            Object.freeze({ recipient, purpose })
          );
        },
        takeCode: async (recipient: string, purpose: SmsPurpose) => {
          const result = await command('take', recipient, purpose);
          armed.delete(`${recipient.length}:${recipient}${purpose}`);
          return result.code as string;
        },
      })
    );
  } catch (error: unknown) {
    if (consumerEntered) {
      throw error;
    }
    return fail();
  } finally {
    try {
      if (consumerEntered && releaseArmed) {
        await releaseArmed();
      }
    } finally {
      active = false;
    }
  }
};

/* eslint-enable complexity, no-bitwise, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
