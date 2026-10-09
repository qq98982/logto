import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import { test } from 'node:test';
import { promisify } from 'node:util';

import { parseWechatProviderConfiguration, startWechatProviderFixture } from './phase2-wechat-provider.mjs';

const execute = promisify(execFile);

const valid = () => ({
  schemaVersion: 1,
  appId: 'owned-app',
  appSecret: 'private-secret',
  unionId: 'stable-union',
  codes: {
    setup: 'setup-code', browser: 'browser-code', noUnionId: 'no-union-code',
    invalidCode: 'invalid-code', replay: 'replay-code', malformedProvider: 'malformed-code',
  },
});

test('accepts the exact Web-only provider configuration without serializing secrets', () => {
  const parsed = parseWechatProviderConfiguration(valid());
  assert.equal(parsed.appId, 'owned-app');
  assert.equal(parsed.unionId, 'stable-union');
  assert.equal(parsed.codes.browser, 'browser-code');
});

test('rejects extra keys, duplicate codes, and missing UnionID', () => {
  for (const value of [
    { ...valid(), smsAccessSecret: 'not-web' },
    { ...valid(), codes: { ...valid().codes, browser: 'setup-code' } },
    { ...valid(), unionId: '' },
  ]) assert.throws(() => parseWechatProviderConfiguration(value), /WeChat provider fixture failed/u);
});

test('serves exact token and userinfo exchanges and rejects replayed codes', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/wechat-provider-test.');
  const key = `${root}/server.key`;
  const certificate = `${root}/server.pem`;
  const configuration = `${root}/configuration.json`;
  const receipt = `${root}/receipt.json`;
  await execute('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-subj', '/CN=api.weixin.qq.com', '-keyout', key, '-out', certificate]);
  await Promise.all([chmod(key, 0o600), chmod(certificate, 0o600), chmod(root, 0o700),
    writeFile(configuration, `${JSON.stringify(valid())}\n`, { mode: 0o600 }),
    writeFile(receipt, '', { mode: 0o600 })]);
  const fixture = await startWechatProviderFixture({ certificateFile: certificate, privateKeyFile: key,
    configurationFile: configuration, receiptFile: receipt, host: '127.0.0.1', port: 0 });
  const request = async (pathname) => new Promise((resolve, reject) => {
    const call = https.get({ hostname: '127.0.0.1', port: fixture.port, path: pathname,
      rejectUnauthorized: false }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
    });
    call.on('error', reject);
  });
  try {
    const tokenPath = '/sns/oauth2/access_token?appid=owned-app&secret=private-secret&code=setup-code&grant_type=authorization_code';
    const token = await request(tokenPath);
    assert.equal(token.openid, 'owned-openid');
    const profile = await request(`/sns/userinfo?access_token=${token.access_token}&openid=owned-openid`);
    assert.equal(profile.unionid, 'stable-union');
    assert.equal((await request(tokenPath)).errcode, 40029);
    const noUnion = await request('/sns/oauth2/access_token?appid=owned-app&secret=private-secret&code=no-union-code&grant_type=authorization_code');
    const noUnionProfile = await request(`/sns/userinfo?access_token=${noUnion.access_token}&openid=owned-openid`);
    assert.equal(Object.hasOwn(noUnionProfile, 'unionid'), false);
    const invalid = await request('/sns/oauth2/access_token?appid=owned-app&secret=private-secret&code=invalid-code&grant_type=authorization_code');
    assert.equal(invalid.errcode, 40029);
    const replayPath = '/sns/oauth2/access_token?appid=owned-app&secret=private-secret&code=replay-code&grant_type=authorization_code';
    assert.equal((await request(replayPath)).openid, 'owned-openid');
    assert.equal((await request(replayPath)).errcode, 40029);
    const recorded = JSON.parse(await readFile(receipt, 'utf8'));
    assert.deepEqual(recorded.facts, [
      { kind: 'token', phase: 'setup', method: 'GET', exact: true },
      { kind: 'userinfo', phase: 'setup', method: 'GET', exact: true,
        unionIdPresent: true, unionIdMatches: true },
      { kind: 'token', phase: 'browser', method: 'GET', exact: true },
      { kind: 'userinfo', phase: 'browser', method: 'GET', exact: true,
        unionIdPresent: false, unionIdMatches: false },
      { kind: 'token', phase: 'browser', method: 'GET', exact: true },
    ]);
  } finally { await fixture.close(); await rm(root, { recursive: true, force: true }); }
});
