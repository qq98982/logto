#!/usr/bin/env node
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createServer } from 'node:https';
import { fileURLToPath } from 'node:url';

const failure = 'Aster Phase 2 WeChat provider fixture failed';
const maximumBytes = 64 * 1024;
const fail = () => { throw new TypeError(failure); };
const exactKeys = (value, keys) => typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const bounded = (value, maximum = 4096) => typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum && !/[\u0000-\u001F\u007F]/u.test(value) ? value : fail();

const readOwnedFile = async (file, modes = new Set([0o400, 0o440, 0o600])) => {
  const before = await lstat(file);
  if (before.isSymbolicLink() || !before.isFile() || before.uid !== process.getuid() || before.nlink !== 1 || !modes.has(before.mode & 0o777) || before.size <= 0 || before.size > maximumBytes || await realpath(file) !== file) return fail();
  const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) return fail();
    return await handle.readFile();
  } finally { await handle.close(); }
};

export const parseWechatProviderConfiguration = (value) => {
  const codeKeys = ['setup', 'browser', 'account', 'foreignAccount', 'noUnionId', 'invalidCode', 'replay', 'malformedProvider'];
  if (!exactKeys(value, ['schemaVersion', 'appId', 'appSecret', 'unionId', 'codes']) || value.schemaVersion !== 1 || !exactKeys(value.codes, codeKeys)) return fail();
  const codes = Object.freeze(Object.fromEntries(codeKeys.map((key) => [key, bounded(value.codes[key])])));
  if (new Set(Object.values(codes)).size !== codeKeys.length) return fail();
  return Object.freeze({ appId: bounded(value.appId, 512), appSecret: bounded(value.appSecret), unionId: bounded(value.unionId, 512), codes: Object.freeze(codes) });
};
const readConfiguration = async (file) => {
  try { return parseWechatProviderConfiguration(JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(await readOwnedFile(file)))); } catch { return fail(); }
};
const exactQuery = (url, keys) => {
  const actual = [...url.searchParams.keys()];
  return actual.length === keys.length && new Set(actual).size === keys.length && actual.toSorted().every((key, index) => key === [...keys].toSorted()[index]);
};
const writeJson = (response, status, value) => {
  const body = JSON.stringify(value);
  response.writeHead(status, { 'cache-control': 'no-store', 'content-length': String(Buffer.byteLength(body)), 'content-type': 'application/json' });
  response.end(body);
};
const writeReceipt = async (file, facts) => {
  const before = await lstat(file);
  if (before.isSymbolicLink() || !before.isFile() || before.uid !== process.getuid() || before.nlink !== 1 || (before.mode & 0o777) !== 0o600 || await realpath(file) !== file) return fail();
  const handle = await open(file, fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.uid !== before.uid || opened.nlink !== 1 || opened.mode !== before.mode) return fail();
    await handle.truncate(0);
    await handle.writeFile(`${JSON.stringify({ schemaVersion: 1, facts })}\n`, 'utf8');
    await handle.sync();
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(file)]);
    if (after.dev !== opened.dev || after.ino !== opened.ino || pathAfter.isSymbolicLink() || pathAfter.dev !== opened.dev || pathAfter.ino !== opened.ino || pathAfter.mode !== opened.mode || pathAfter.nlink !== 1) return fail();
  } finally { await handle.close(); }
};

export const startWechatProviderFixture = async ({ certificateFile, privateKeyFile, configurationFile, receiptFile, host = '0.0.0.0', port = 443 }) => {
  if (typeof host !== 'string' || !Number.isInteger(port) || port < 0 || port > 65_535) fail();
  const [certificate, privateKey, configuration] = await Promise.all([
    readOwnedFile(certificateFile, new Set([0o400, 0o444, 0o600])),
    readOwnedFile(privateKeyFile, new Set([0o400, 0o600])),
    readConfiguration(configurationFile),
  ]);
  const acceptedCodes = new Map([
    [configuration.codes.setup, { behavior: 'positive', phase: 'setup' }],
    [configuration.codes.browser, { behavior: 'positive', phase: 'browser' }],
    [configuration.codes.account, { behavior: 'positive', phase: 'browser' }],
    [configuration.codes.foreignAccount, { behavior: 'positive', phase: 'browser' }],
    [configuration.codes.noUnionId, { behavior: 'no-union-id', phase: 'browser' }],
    [configuration.codes.replay, { behavior: 'positive', phase: 'browser' }],
  ]);
  const issuedTokens = new Map();
  const facts = [];
  const record = async (fact) => { facts.push(Object.freeze(fact)); await writeReceipt(receiptFile, facts); };
  const server = createServer({ cert: certificate, key: privateKey }, (request, response) => {
    void (async () => {
      const url = new URL(request.url ?? '/', 'https://api.weixin.qq.com');
      if (url.pathname === '/healthz' && request.method === 'GET') { response.writeHead(204, { 'cache-control': 'no-store' }); response.end(); return; }
      if (url.pathname === '/sns/oauth2/access_token') {
        const code = url.searchParams.get('code');
        const shapeValid = request.method === 'GET' && exactQuery(url, ['appid', 'secret', 'code', 'grant_type']) && url.searchParams.get('appid') === configuration.appId && url.searchParams.get('secret') === configuration.appSecret && url.searchParams.get('grant_type') === 'authorization_code' && code !== null;
        if (shapeValid && code === configuration.codes.malformedProvider) {
          response.writeHead(200, { 'cache-control': 'no-store', 'content-type': 'application/json' });
          response.end('{');
          return;
        }
        const selected = shapeValid && code !== null ? acceptedCodes.get(code) : undefined;
        const valid = selected !== undefined && acceptedCodes.delete(code);
        if (!valid) return writeJson(response, 200, { errcode: 40029, errmsg: 'invalid code' });
        const token = `owned-${code}`;
        issuedTokens.set(token, selected);
        await record({ kind: 'token', phase: selected.phase, method: 'GET', exact: true });
        return writeJson(response, 200, { access_token: token, openid: 'owned-openid', expires_in: 300 });
      }
      if (url.pathname === '/sns/userinfo') {
        const token = url.searchParams.get('access_token');
        const selected = token === null ? undefined : issuedTokens.get(token);
        const valid = request.method === 'GET' && exactQuery(url, ['access_token', 'openid']) && url.searchParams.get('openid') === 'owned-openid' && token !== null && selected !== undefined && issuedTokens.delete(token);
        if (!valid) return writeJson(response, 200, { errcode: 40014, errmsg: 'invalid token' });
        const unionIdPresent = selected.behavior === 'positive';
        await record({ kind: 'userinfo', phase: selected.phase, method: 'GET', exact: true, unionIdPresent, unionIdMatches: unionIdPresent });
        return writeJson(response, 200, { openid: 'owned-openid', ...(unionIdPresent && { unionid: configuration.unionId }), nickname: 'Owned WeChat' });
      }
      return writeJson(response, 404, { error: 'not_found' });
    })().catch(() => { if (!response.headersSent) writeJson(response, 500, { error: 'fixture_failure' }); else response.destroy(); });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  const address = server.address();
  if (!address || typeof address === 'string') fail();
  return Object.freeze({ port: address.port, close: async () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())) });
};

const main = async () => startWechatProviderFixture({
  certificateFile: bounded(process.env.ASTER_WECHAT_PROVIDER_CERTIFICATE_FILE),
  privateKeyFile: bounded(process.env.ASTER_WECHAT_PROVIDER_PRIVATE_KEY_FILE),
  configurationFile: bounded(process.env.ASTER_WECHAT_PROVIDER_CONFIGURATION_FILE),
  receiptFile: bounded(process.env.ASTER_WECHAT_PROVIDER_RECEIPT_FILE),
  host: bounded(process.env.ASTER_WECHAT_PROVIDER_HOST),
  port: Number(process.env.ASTER_WECHAT_PROVIDER_PORT),
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
