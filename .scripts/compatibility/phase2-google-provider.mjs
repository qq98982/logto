#!/usr/bin/env node
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createServer } from 'node:https';
import { fileURLToPath } from 'node:url';

const maximumBytes = 64 * 1024;
const maximumRequests = 100;
const failure = 'Aster Phase 2 Google provider fixture failed';
const tokenHost = 'oauth2.googleapis.com';
const userinfoHost = 'openidconnect.googleapis.com';
const startupStages = new Set(['certificate-read','key-read','config-read','config-validate','receipt-read-or-write','server-create','listen']);
const startupKinds = new Set(['input','file-missing','file-permission','bind','tls','unknown']);

class ProviderStartupError extends Error {
  constructor(stage, kind) {
    super(failure);
    this.stage = startupStages.has(stage) ? stage : 'config-validate';
    this.kind = startupKinds.has(kind) ? kind : 'unknown';
  }
}

const errorCode = (error) =>
  typeof error === 'object' && error !== null && typeof error.code === 'string' ? error.code : '';
const startupKind = (stage, error) => {
  const code = errorCode(error);
  if (code === 'ENOENT') return 'file-missing';
  if (code === 'EACCES' || code === 'EPERM') return 'file-permission';
  if (stage === 'listen' && ['EADDRINUSE','EACCES'].includes(code)) return 'bind';
  if (stage === 'server-create') return 'tls';
  return error instanceof TypeError ? 'input' : 'unknown';
};
const atStartup = async (stage, operation) => {
  try { return await operation(); } catch (error) { throw new ProviderStartupError(stage,startupKind(stage,error)); }
};

const fail = () => {
  throw new TypeError(failure);
};

const boundedString = (value, maximum = 4096) =>
  typeof value === 'string' &&
  value.length > 0 &&
  Buffer.byteLength(value) <= maximum &&
  !/[\u0000-\u001F\u007F]/u.test(value)
    ? value
    : fail();

const exactKeys = (value, keys) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');

const readOwnedFile = async (file, allowedModes = new Set([0o600])) => {
  const before = await lstat(file);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.uid !== process.getuid() ||
    before.nlink !== 1 ||
    !allowedModes.has(before.mode & 0o777) ||
    before.size <= 0 ||
    before.size > maximumBytes ||
    (await realpath(file)) !== file
  ) {
    return fail();
  }
  const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size
    ) {
      return fail();
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
};

const parseProfile = (value) => {
  if (
    !exactKeys(value, ['sub', 'email', 'emailVerified']) ||
    value.emailVerified !== true
  ) {
    return fail();
  }
  return Object.freeze({
    sub: boundedString(value.sub, 512),
    email: boundedString(value.email, 1024),
    email_verified: true,
  });
};

const parseCase = (value) => {
  if (!exactKeys(value, ['code', 'accessToken', 'profile'])) {
    return fail();
  }
  return Object.freeze({
    code: boundedString(value.code),
    accessToken: boundedString(value.accessToken),
    profile: parseProfile(value.profile),
  });
};

const parseTargetBinding = (targetOriginValue, connectorIdValue, callbackValue) => {
  const connectorId = boundedString(connectorIdValue, 128);
  if (!/^[A-Za-z0-9._~-]+$/u.test(connectorId)) {
    return fail();
  }
  let targetOrigin;
  let callback;
  try {
    targetOrigin = new URL(boundedString(targetOriginValue));
    callback = new URL(boundedString(callbackValue));
  } catch {
    return fail();
  }
  if (
    !['http:', 'https:'].includes(targetOrigin.protocol) ||
    targetOrigin.origin !== targetOrigin.href.replace(/\/$/u, '') ||
    targetOrigin.username ||
    targetOrigin.password ||
    targetOrigin.search ||
    targetOrigin.hash ||
    callback.origin !== targetOrigin.origin ||
    callback.href !== new URL(`/callback/${encodeURIComponent(connectorId)}`, targetOrigin).href ||
    callback.username ||
    callback.password ||
    callback.search ||
    callback.hash
  ) {
    return fail();
  }
  return Object.freeze({
    targetOrigin: targetOrigin.origin,
    connectorId,
    callbackUri: callback.href,
  });
};

const readConfiguration = async (file) => {
  const bytes = await readOwnedFile(file);
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
  } catch {
    return fail();
  }
  if (
    !exactKeys(value, [
      'schemaVersion',
      'clientId',
      'clientSecret',
      'targetOrigin',
      'connectorId',
      'callbackUri',
      'stable',
      'changedEmail',
      'wrongStateControl',
    ]) ||
    value.schemaVersion !== 1
  ) {
    return fail();
  }
  const stable = parseCase(value.stable);
  const changedEmail = parseCase(value.changedEmail);
  const wrongStateControl = parseCase(value.wrongStateControl);
  const target = parseTargetBinding(value.targetOrigin, value.connectorId, value.callbackUri);
  if (
    new Set([stable.code, changedEmail.code, wrongStateControl.code]).size !== 3 ||
    new Set([stable.accessToken, changedEmail.accessToken, wrongStateControl.accessToken]).size !== 3 ||
    stable.profile.sub !== changedEmail.profile.sub ||
    stable.profile.sub !== wrongStateControl.profile.sub ||
    stable.profile.email === changedEmail.profile.email
  ) {
    return fail();
  }
  return Object.freeze({
    clientId: boundedString(value.clientId, 512),
    clientSecret: boundedString(value.clientSecret),
    ...target,
    stable,
    changedEmail,
    wrongStateControl,
  });
};

const readRequestBody = async (request) => {
  const declared = request.headers['content-length'];
  if (
    declared !== undefined &&
    (!/^(?:0|[1-9]\d*)$/u.test(declared) || Number(declared) > maximumBytes)
  ) {
    return fail();
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximumBytes) {
      request.destroy();
      return fail();
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

const writeReceipt = async (file, receipt) => {
  const before = await lstat(file).catch(fail);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.uid !== process.getuid() ||
    before.nlink !== 1 ||
    (before.mode & 0o777) !== 0o600 ||
    (await realpath(file).catch(fail)) !== file
  ) {
    return fail();
  }
  const handle = await open(file, fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const opened = await handle.stat();
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.uid !== before.uid ||
      opened.nlink !== 1 ||
      (opened.mode & 0o777) !== 0o600 ||
      !opened.isFile()
    ) {
      return fail();
    }
    await handle.truncate(0);
    await handle.writeFile(`${JSON.stringify(receipt)}\n`, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
};

export const startGoogleProviderFixture = async ({
  certificateFile,
  privateKeyFile,
  configurationFile,
  receiptFile,
  host = '127.0.0.1',
  port = 0,
}) => {
  if (
    !['127.0.0.1', '0.0.0.0'].includes(host) ||
    !Number.isInteger(port) ||
    port < 0 ||
    port > 65_535
  ) {
    return fail();
  }
  const certificate = await atStartup('certificate-read', async () => readOwnedFile(certificateFile, new Set([0o400, 0o444, 0o600])));
  const privateKey = await atStartup('key-read', async () => readOwnedFile(privateKeyFile, new Set([0o400, 0o600])));
  const configurationBytes = await atStartup('config-read', async () => readOwnedFile(configurationFile));
  const configuration = await atStartup('config-validate', async () => {
    let value;
    try { value = JSON.parse(new TextDecoder('utf8',{fatal:true}).decode(configurationBytes)); } catch { return fail(); }
    if (!exactKeys(value,['schemaVersion','clientId','clientSecret','targetOrigin','connectorId','callbackUri','stable','changedEmail','wrongStateControl']) || value.schemaVersion!==1) return fail();
    const stable=parseCase(value.stable),changedEmail=parseCase(value.changedEmail),wrongStateControl=parseCase(value.wrongStateControl),target=parseTargetBinding(value.targetOrigin,value.connectorId,value.callbackUri);
    if(new Set([stable.code,changedEmail.code,wrongStateControl.code]).size!==3||new Set([stable.accessToken,changedEmail.accessToken,wrongStateControl.accessToken]).size!==3||stable.profile.sub!==changedEmail.profile.sub||stable.profile.sub!==wrongStateControl.profile.sub||stable.profile.email===changedEmail.profile.email)return fail();
    return Object.freeze({clientId:boundedString(value.clientId,512),clientSecret:boundedString(value.clientSecret),...target,stable,changedEmail,wrongStateControl});
  });
  const cases = new Map([
    [configuration.stable.code, Object.freeze({ name: 'stable', value: configuration.stable })],
    [
      configuration.changedEmail.code,
      Object.freeze({ name: 'changedEmail', value: configuration.changedEmail }),
    ],
    [configuration.wrongStateControl.code,Object.freeze({name:'wrongStateControl',value:configuration.wrongStateControl})],
  ]);
  const issued = new Map();
  const consumedCodes = new Set();
  const state = {
    tokenRequestCount: 0,
    userinfoRequestCount: 0,
    userinfoGetObserved: false,
    userinfoPostObserved: false,
    grantTypeExact: true,
    callbackUriExact: true,
    clientAuthenticationExact: true,
    issuedBearerObserved: false,
    stableSubjectCaseConsumed: false,
    changedEmailCaseConsumed: false,
    wrongStateControlCodeConsumed: false,
    replayRejected: false,
  };
  let receiptWrites = Promise.resolve();
  const snapshot = () => Object.freeze({ ...state });
  const persist = () => {
    receiptWrites = receiptWrites.then(async () => writeReceipt(receiptFile, snapshot()));
    return receiptWrites;
  };
  await atStartup('receipt-read-or-write', persist);
  const server = await atStartup('server-create', async () => createServer({ cert: certificate, key: privateKey }, async (request, response) => {
    const deadline = setTimeout(() => request.destroy(), 3000);
    deadline.unref();
    const clearDeadline = () => clearTimeout(deadline);
    request.once('close', clearDeadline);
    response.once('finish', clearDeadline);
    try {
      if (state.tokenRequestCount + state.userinfoRequestCount >= maximumRequests) {
        writeJson(response, 429, { error: 'rate_limited' });
        return;
      }
      const url = new URL(request.url ?? '/', 'https://fixture.invalid');
      const authority = (request.headers.host ?? '').split(':', 1)[0];
      if (request.method === 'GET' && url.pathname === '/healthz' && !url.search) {
        response.writeHead(204).end();
        return;
      }
      if (
        request.method === 'POST' &&
        authority === tokenHost &&
        url.pathname === '/token' &&
        !url.search
      ) {
        state.tokenRequestCount += 1;
        const contentType = request.headers['content-type'];
        if (contentType !== 'application/x-www-form-urlencoded') {
          state.grantTypeExact = false;
          await persist();
          writeJson(response, 400, { error: 'invalid_request' });
          return;
        }
        const form = new URLSearchParams((await readRequestBody(request)).toString('utf8'));
        const entries = [...form.entries()];
        const keys = entries.map(([key]) => key);
        const exactForm =
          entries.length === 5 &&
          new Set(keys).size === 5 &&
          ['code', 'client_id', 'client_secret', 'redirect_uri', 'grant_type'].every((key) =>
            keys.includes(key)
          );
        const code = form.get('code') ?? '';
        const selected = cases.get(code);
        state.grantTypeExact &&= exactForm && form.get('grant_type') === 'authorization_code';
        state.callbackUriExact &&= exactForm && form.get('redirect_uri') === configuration.callbackUri;
        state.clientAuthenticationExact &&=
          exactForm &&
          form.get('client_id') === configuration.clientId &&
          form.get('client_secret') === configuration.clientSecret;
        if (
          !exactForm ||
          form.get('grant_type') !== 'authorization_code' ||
          form.get('redirect_uri') !== configuration.callbackUri ||
          form.get('client_id') !== configuration.clientId ||
          form.get('client_secret') !== configuration.clientSecret ||
          !selected ||
          consumedCodes.has(code)
        ) {
          if (consumedCodes.has(code)) {
            state.replayRejected = true;
          }
          await persist();
          writeJson(response, 400, { error: 'invalid_grant' });
          return;
        }
        consumedCodes.add(code);
        if (selected.name === 'wrongStateControl') state.wrongStateControlCodeConsumed = true;
        issued.set(selected.value.accessToken, selected);
        await persist();
        writeJson(response, 200, {
          access_token: selected.value.accessToken,
          scope: 'openid profile email',
          token_type: 'Bearer',
        });
        return;
      }
      if (
        ['GET', 'POST'].includes(request.method ?? '') &&
        authority === userinfoHost &&
        url.pathname === '/v1/userinfo' &&
        !url.search
      ) {
        state.userinfoRequestCount += 1;
        if (request.method === 'POST' && (await readRequestBody(request)).length !== 0) {
          await persist();
          writeJson(response, 400, { error: 'invalid_request' });
          return;
        }
        const authorization = request.headers.authorization ?? '';
        const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
        const selected = issued.get(token);
        if (!selected) {
          await persist();
          writeJson(response, 401, { error: 'invalid_token' });
          return;
        }
        state.issuedBearerObserved = true;
        state.userinfoGetObserved ||= request.method === 'GET';
        state.userinfoPostObserved ||= request.method === 'POST';
        issued.delete(token);
        if (selected.name === 'stable') {
          state.stableSubjectCaseConsumed = true;
        } else {
          state.changedEmailCaseConsumed = true;
        }
        await persist();
        writeJson(response, 200, selected.value.profile);
        return;
      }
      writeJson(response, 404, { error: 'not_found' });
    } catch {
      if (!response.headersSent) {
        writeJson(response, 400, { error: 'invalid_request' });
      } else {
        response.destroy();
      }
    }
  }));
  server.maxConnections = 16;
  await atStartup('listen', async () => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  }));
  const address = server.address();
  if (typeof address !== 'object' || address === null) {
    return fail();
  }
  return Object.freeze({
    address: Object.freeze({ host, port: address.port }),
    snapshot,
    close: async () => {
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      await receiptWrites;
    },
  });
};

const directEntry = process.argv[1] ? fileURLToPath(import.meta.url) === process.argv[1] : false;
if (directEntry) {
  startGoogleProviderFixture({
    certificateFile: process.env.ASTER_GOOGLE_PROVIDER_CERTIFICATE_FILE,
    privateKeyFile: process.env.ASTER_GOOGLE_PROVIDER_PRIVATE_KEY_FILE,
    configurationFile: process.env.ASTER_GOOGLE_PROVIDER_CONFIGURATION_FILE,
    receiptFile: process.env.ASTER_GOOGLE_PROVIDER_RECEIPT_FILE,
    host: process.env.ASTER_GOOGLE_PROVIDER_HOST ?? '0.0.0.0',
    port: Number(process.env.ASTER_GOOGLE_PROVIDER_PORT ?? '443'),
  })
    .then((fixture) => {
      for (const signal of ['SIGINT', 'SIGTERM']) {
        process.once(signal, async () => {
          await fixture.close();
          process.exit(0);
        });
      }
    })
    .catch((error) => {
      const stage = error instanceof ProviderStartupError ? error.stage : 'config-validate';
      const kind = error instanceof ProviderStartupError ? error.kind : 'unknown';
      process.stderr.write(`${failure} (${stage}-${kind})\n`);
      process.exitCode = 1;
    });
}
