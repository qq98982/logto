#!/usr/bin/env node
import { createHmac, timingSafeEqual } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, lstat, open, realpath, unlink } from 'node:fs/promises';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createNetServer } from 'node:net';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const failure = 'Aster Phase 2 SMS provider fixture failed';
const maximumFileBytes = 64 * 1024;
const maximumBodyBytes = 16 * 1024;
const maximumControlBytes = 4 * 1024;
const maximumRequests = 100;
const maximumConcurrentRequests = 16;
const maximumActiveTuples = 100;
const providerHost = 'dysmsapi.aliyuncs.com';
const fixedParameters = Object.freeze({
  Action: 'SendSms',
  Format: 'json',
  RegionId: 'cn-hangzhou',
  SignatureMethod: 'HMAC-SHA1',
  SignatureVersion: '1.0',
  Version: '2017-05-25',
});
const fail = () => {
  throw new TypeError(failure);
};
const exactKeys = (value, keys) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const bounded = (value, maximum = 4096) =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();
const tupleKey = (recipient, purpose) => `${recipient.length}:${recipient}${purpose}`;
const readOwnedFile = async (file, modes) => {
  const before = await lstat(file);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.uid !== process.getuid() ||
    before.nlink !== 1 ||
    !modes.has(before.mode & 0o777) ||
    before.size <= 0 ||
    before.size > maximumFileBytes ||
    (await realpath(file)) !== file
  ) fail();
  const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      opened.mode !== before.mode
    ) fail();
    return await handle.readFile();
  } finally {
    await handle.close();
  }
};
export const parseSmsProviderConfiguration = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'accessKeyId',
      'accessKeySecret',
      'signName',
      'templates',
      'controlCapability',
    ]) ||
    value.schemaVersion !== 1 ||
    typeof value.templates !== 'object' ||
    value.templates === null ||
    Array.isArray(value.templates)
  ) fail();
  const entries = Object.entries(value.templates);
  if (entries.length === 0 || entries.length > 16) fail();
  const templates = Object.create(null);
  for (const [purposeValue, templateValue] of entries) {
    const purpose = bounded(purposeValue, 64);
    if (!/^[A-Za-z0-9._~-]+$/u.test(purpose)) fail();
    templates[purpose] = bounded(templateValue, 128);
  }
  if (new Set(Object.values(templates)).size !== entries.length) fail();
  return Object.freeze({
    accessKeyId: bounded(value.accessKeyId, 128),
    accessKeySecret: bounded(value.accessKeySecret, 512),
    signName: bounded(value.signName, 128),
    templates: Object.freeze(templates),
    controlCapability: bounded(value.controlCapability, 512),
  });
};
const readConfiguration = async (file) => {
  try {
    const bytes = await readOwnedFile(file, new Set([0o600]));
    return parseSmsProviderConfiguration(
      JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes))
    );
  } catch {
    return fail();
  }
};
const rfc3986 = (value) =>
  encodeURIComponent(value).replace(/[!'()*]/gu, (character) =>
    `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  );
export const signAliyunSmsParameters = (parameters, secret) => {
  const canonical = Object.entries(parameters)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, value]) => `${rfc3986(key)}=${rfc3986(value)}`)
    .join('&');
  return createHmac('sha1', `${secret}&`)
    .update(`POST&%2F&${rfc3986(canonical)}`)
    .digest('base64');
};
const sameSecret = (left, right) => {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
};
const readRequestBody = async (request) => {
  const declared = request.headers['content-length'];
  if (
    declared !== undefined &&
    (!/^(?:0|[1-9]\d*)$/u.test(declared) || Number(declared) > maximumBodyBytes)
  ) fail();
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximumBodyBytes) {
      request.destroy();
      fail();
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
};
const writeJson = (response, status, value) => {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-length': String(Buffer.byteLength(body)),
    'content-type': 'application/json',
  });
  response.end(body);
};

const admitReceipt = async (file) => {
  const before = await lstat(file);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.uid !== process.getuid() ||
    before.nlink !== 1 ||
    (before.mode & 0o777) !== 0o600 ||
    before.size > maximumFileBytes ||
    (await realpath(file)) !== file
  ) fail();
  const handle = await open(file, fsConstants.O_RDWR | fsConstants.O_NOFOLLOW);
  const opened = await handle.stat();
  if (
    opened.dev !== before.dev || opened.ino !== before.ino ||
    opened.mode !== before.mode || opened.nlink !== 1
  ) {
    await handle.close();
    fail();
  }
  return Object.freeze({
    handle,
    identity: Object.freeze({ dev: opened.dev, ino: opened.ino, mode: opened.mode }),
  });
};

const writeReceipt = async (file, receipt, facts) => {
  const before = await lstat(file);
  const opened = await receipt.handle.stat();
  if (
    before.isSymbolicLink() || !before.isFile() || before.uid !== process.getuid() ||
    before.nlink !== 1 || before.dev !== receipt.identity.dev ||
    before.ino !== receipt.identity.ino || before.mode !== receipt.identity.mode ||
    opened.dev !== receipt.identity.dev || opened.ino !== receipt.identity.ino ||
    opened.mode !== receipt.identity.mode || opened.nlink !== 1 ||
    (await realpath(file)) !== file
  ) fail();
  const bytes = Buffer.from(`${JSON.stringify({ schemaVersion: 1, facts })}\n`);
  await receipt.handle.truncate(0);
  const { bytesWritten } = await receipt.handle.write(bytes, 0, bytes.length, 0);
  if (bytesWritten !== bytes.length) fail();
  await receipt.handle.sync();
  const pathAfter = await lstat(file);
  if (
    pathAfter.isSymbolicLink() ||
    pathAfter.dev !== receipt.identity.dev ||
    pathAfter.ino !== receipt.identity.ino ||
    pathAfter.mode !== receipt.identity.mode ||
    pathAfter.nlink !== 1
  ) fail();
};

const validateSocketLocation = async (socketPath) => {
  bounded(socketPath, 100);
  if (Buffer.byteLength(socketPath) > 100) fail();
  const parent = dirname(socketPath);
  const stat = await lstat(parent);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid() ||
    (stat.mode & 0o777) !== 0o700 ||
    (await realpath(parent)) !== parent
  ) fail();
  try {
    await lstat(socketPath);
    fail();
  } catch (error) {
    if (!(error && typeof error === 'object' && error.code === 'ENOENT')) throw error;
  }
};

const validRecipient = (value) =>
  typeof value === 'string' && /^[+]?[1-9]\d{5,19}$/u.test(value);
const validPurpose = (value, templates) =>
  typeof value === 'string' && Object.hasOwn(templates, value);
const parseTemplateCode = (value) => {
  try {
    const parsed = JSON.parse(value);
    return exactKeys(parsed, ['code']) && /^[0-9]{6}$/u.test(parsed.code)
      ? parsed.code
      : undefined;
  } catch {
    return undefined;
  }
};

export const startSmsProviderFixture = async ({
  certificateFile,
  privateKeyFile,
  configurationFile,
  receiptFile,
  controlSocket,
  host = '0.0.0.0',
  port = 443,
}) => {
  if (typeof host !== 'string' || !Number.isInteger(port) || port < 0 || port > 65_535) fail();
  await validateSocketLocation(controlSocket);
  const [certificate, privateKey, configuration] = await Promise.all([
    readOwnedFile(certificateFile, new Set([0o400, 0o444, 0o600])),
    readOwnedFile(privateKeyFile, new Set([0o400, 0o600])),
    readConfiguration(configurationFile),
  ]);
  const armed = new Set();
  const deliveries = new Map();
  const nonces = new Set();
  const facts = { accepted: 0, rejected: 0, duplicateNonce: 0, lastAccepted: false };
  let receiptChain = Promise.resolve();
  let receipt;
  let totalRequests = 0;
  let activeRequests = 0;
  const record = (accepted, duplicateNonce = false) => {
    if (accepted) facts.accepted += 1;
    else facts.rejected += 1;
    if (duplicateNonce) facts.duplicateNonce += 1;
    facts.lastAccepted = accepted;
    const snapshot = Object.freeze({ ...facts });
    receiptChain = receiptChain.then(() => writeReceipt(receiptFile, receipt, snapshot));
    return receiptChain;
  };
  let closed = false;
  const arm = (recipient, purpose) => {
    if (closed) return false;
    if (!validRecipient(recipient) || !validPurpose(purpose, configuration.templates)) return false;
    const key = tupleKey(recipient, purpose);
    if (
      armed.has(key) || deliveries.has(key) ||
      armed.size + deliveries.size >= maximumActiveTuples
    ) return false;
    armed.add(key);
    return true;
  };
  const takeCode = (recipient, purpose) => {
    if (closed) return undefined;
    if (!validRecipient(recipient) || !validPurpose(purpose, configuration.templates)) return undefined;
    const key = tupleKey(recipient, purpose);
    const code = deliveries.get(key);
    if (code !== undefined) deliveries.delete(key);
    return code;
  };

  const control = createNetServer((socket) => {
    socket.setTimeout(2000, () => socket.destroy());
    let bytes = Buffer.alloc(0);
    let answered = false;
    const answer = (value) => {
      if (answered) return;
      answered = true;
      socket.end(`${JSON.stringify(value)}\n`);
    };
    socket.on('data', (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length > maximumControlBytes) return answer({ ok: false });
      const newline = bytes.indexOf(0x0a);
      if (newline === -1) return;
      if (newline !== bytes.length - 1) return answer({ ok: false });
      try {
        const value = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes.subarray(0, newline)));
        if (
          !exactKeys(value, ['operation', 'capability', 'recipient', 'purpose']) ||
          !sameSecret(value.capability, configuration.controlCapability)
        ) return answer({ ok: false });
        if (value.operation === 'arm') return answer({ ok: arm(value.recipient, value.purpose) });
        if (value.operation === 'take') {
          const code = takeCode(value.recipient, value.purpose);
          return answer(code === undefined ? { ok: false } : { ok: true, code });
        }
      } catch {}
      return answer({ ok: false });
    });
    socket.on('error', () => {});
  });

  const https = createHttpsServer({ cert: certificate, key: privateKey }, (request, response) => {
    void (async () => {
      if (
        request.method === 'GET' &&
        request.url === '/healthz' &&
        request.headers.host === providerHost
      ) {
        response.writeHead(204, { 'cache-control': 'no-store' });
        response.end();
        return;
      }
      totalRequests += 1;
      if (totalRequests > maximumRequests || activeRequests >= maximumConcurrentRequests) {
        await record(false);
        return writeJson(response, 503, {
          Code: 'InvalidRequest', Message: 'InvalidRequest', RequestId: 'aster-fixture',
        });
      }
      activeRequests += 1;
      try {
        const contentType = request.headers['content-type'];
        const body = await readRequestBody(request);
        const form = new URLSearchParams(new TextDecoder('utf8', { fatal: true }).decode(body));
        const required = [
          ...Object.keys(fixedParameters),
          'AccessKeyId', 'PhoneNumbers', 'Signature', 'SignatureNonce',
          'SignName', 'TemplateCode', 'TemplateParam', 'Timestamp',
        ];
        const actual = [...form.keys()];
        const singleton = actual.length === required.length && new Set(actual).size === actual.length;
        const parameters = Object.fromEntries(form);
        const nonce = parameters.SignatureNonce;
        const duplicateNonce = typeof nonce === 'string' && nonces.has(nonce);
        const purpose = Object.entries(configuration.templates)
          .find(([, template]) => template === parameters.TemplateCode)?.[0];
        const code = parseTemplateCode(parameters.TemplateParam);
        const unsigned = { ...parameters };
        delete unsigned.Signature;
        const expectedSignature = signAliyunSmsParameters(unsigned, configuration.accessKeySecret);
        const valid =
          request.method === 'POST' &&
          request.url === '/' &&
          request.headers.host === providerHost &&
          contentType === 'application/x-www-form-urlencoded' &&
          singleton &&
          required.toSorted().every((key, index) => key === actual.toSorted()[index]) &&
          Object.entries(fixedParameters).every(([key, value]) => parameters[key] === value) &&
          parameters.AccessKeyId === configuration.accessKeyId &&
          parameters.SignName === configuration.signName &&
          validRecipient(parameters.PhoneNumbers) &&
          purpose !== undefined &&
          code !== undefined &&
          typeof nonce === 'string' &&
          Buffer.byteLength(nonce) >= 8 &&
          Buffer.byteLength(nonce) <= 128 &&
          /^[A-Za-z0-9._~-]+$/u.test(nonce) &&
          typeof parameters.Timestamp === 'string' &&
          /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(parameters.Timestamp) &&
          Number.isFinite(Date.parse(parameters.Timestamp)) &&
          typeof parameters.Signature === 'string' &&
          sameSecret(parameters.Signature, expectedSignature) &&
          !duplicateNonce &&
          armed.delete(tupleKey(parameters.PhoneNumbers, purpose));
        if (!valid) {
          await record(false, duplicateNonce);
          return writeJson(response, 400, {
            Code: 'InvalidRequest', Message: 'InvalidRequest', RequestId: 'aster-fixture',
          });
        }
        nonces.add(nonce);
        await record(true);
        deliveries.set(tupleKey(parameters.PhoneNumbers, purpose), code);
        return writeJson(response, 200, {
          Code: 'OK', Message: 'OK', RequestId: 'aster-fixture', BizId: 'aster-fixture',
        });
      } finally {
        activeRequests -= 1;
      }
    })().catch(async () => {
      try { await record(false); } catch {}
      if (!response.headersSent) writeJson(response, 400, {
        Code: 'InvalidRequest', Message: 'InvalidRequest', RequestId: 'aster-fixture',
      });
      else response.destroy();
    });
  });
  https.requestTimeout = 3000;
  https.headersTimeout = 3000;

  try {
    receipt = await admitReceipt(receiptFile);
    await writeReceipt(receiptFile, receipt, facts);
    await new Promise((resolve, reject) => {
      control.once('error', reject);
      control.listen(controlSocket, resolve);
    });
    await chmod(controlSocket, 0o600);
    const socketIdentity = await lstat(controlSocket);
    if (
      !socketIdentity.isSocket() ||
      socketIdentity.uid !== process.getuid() ||
      socketIdentity.nlink !== 1 ||
      (socketIdentity.mode & 0o777) !== 0o600 ||
      (await realpath(controlSocket)) !== controlSocket
    ) fail();
    await new Promise((resolve, reject) => {
      https.once('error', reject);
      https.listen(port, host, resolve);
    });
  } catch (error) {
    control.close();
    await receipt?.handle.close();
    await unlink(controlSocket).catch(() => {});
    throw error;
  }
  const address = https.address();
  if (!address || typeof address === 'string') fail();
  return Object.freeze({
    port: address.port,
    arm,
    takeCode,
    close: async () => {
      closed = true;
      await Promise.all([
        new Promise((resolve, reject) => https.close((error) => error ? reject(error) : resolve())),
        new Promise((resolve, reject) => control.close((error) => error ? reject(error) : resolve())),
      ]);
      try {
        await receiptChain;
      } finally {
        await receipt.handle.close();
        armed.clear();
        deliveries.clear();
        nonces.clear();
        await unlink(controlSocket).catch((error) => {
          if (!(error && typeof error === 'object' && error.code === 'ENOENT')) throw error;
        });
      }
    },
  });
};

const main = () => startSmsProviderFixture({
  certificateFile: bounded(process.env.ASTER_SMS_PROVIDER_CERTIFICATE_FILE),
  privateKeyFile: bounded(process.env.ASTER_SMS_PROVIDER_PRIVATE_KEY_FILE),
  configurationFile: bounded(process.env.ASTER_SMS_PROVIDER_CONFIGURATION_FILE),
  receiptFile: bounded(process.env.ASTER_SMS_PROVIDER_RECEIPT_FILE),
  controlSocket: bounded(process.env.ASTER_SMS_PROVIDER_CONTROL_SOCKET, 100),
  host: bounded(process.env.ASTER_SMS_PROVIDER_HOST),
  port: Number(process.env.ASTER_SMS_PROVIDER_PORT),
});

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main()
    .then((fixture) => {
      for (const signal of ['SIGINT', 'SIGTERM']) {
        process.once(signal, async () => {
          await fixture.close();
          process.exit(0);
        });
      }
    })
    .catch(() => {
      process.stderr.write(`${failure}\n`);
      process.exitCode = 1;
    });
}
