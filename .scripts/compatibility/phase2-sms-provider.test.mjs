import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { createConnection } from 'node:net';
import path from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import {
  signAliyunSmsParameters,
  startSmsProviderFixture,
} from './phase2-sms-provider.mjs';

const execute = promisify(execFile);
const accessKeyId = 'owned-access-key';
const accessKeySecret = 'owned-access-secret';
const signName = 'Aster Test';
const controlCapability = 'owned-control-capability';
const templates = Object.freeze({ signIn: 'SMS_SIGN_IN', register: 'SMS_REGISTER' });

const createFixture = async ({ keyMode = 0o400, configMode = 0o600, receiptMode = 0o600 } = {}) => {
  const root = await mkdtemp('/var/tmp/henry-build/phase2-sms-provider-test-');
  const keyFile = path.join(root, 'server.key');
  const certificateFile = path.join(root, 'server.pem');
  const configurationFile = path.join(root, 'configuration.json');
  const receiptFile = path.join(root, 'receipt.json');
  const controlSocket = path.join(root, 'control.sock');
  try {
    await execute('/usr/bin/openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-sha256',
      '-addext', 'subjectAltName=DNS:dysmsapi.aliyuncs.com',
      '-subj', '/CN=dysmsapi.aliyuncs.com', '-keyout', keyFile, '-out', certificateFile,
    ]);
    await writeFile(configurationFile, `${JSON.stringify({
      schemaVersion: 1,
      accessKeyId,
      accessKeySecret,
      signName,
      templates,
      controlCapability,
    })}\n`, { mode: configMode });
    await writeFile(receiptFile, '', { mode: receiptMode });
    await Promise.all([
      chmod(root, 0o700), chmod(keyFile, keyMode), chmod(certificateFile, 0o400),
      chmod(configurationFile, configMode), chmod(receiptFile, receiptMode),
    ]);
    return { root, keyFile, certificateFile, configurationFile, receiptFile, controlSocket };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
};

const start = (fixture) => startSmsProviderFixture({
  certificateFile: fixture.certificateFile,
  privateKeyFile: fixture.keyFile,
  configurationFile: fixture.configurationFile,
  receiptFile: fixture.receiptFile,
  controlSocket: fixture.controlSocket,
  host: '127.0.0.1',
  port: 0,
});

const baseParameters = ({
  recipient = '15551234567',
  templateCode = templates.signIn,
  code = '482901',
  nonce = 'nonce-00000001',
} = {}) => ({
  AccessKeyId: accessKeyId,
  Action: 'SendSms',
  Format: 'json',
  PhoneNumbers: recipient,
  RegionId: 'cn-hangzhou',
  SignatureMethod: 'HMAC-SHA1',
  SignatureNonce: nonce,
  SignatureVersion: '1.0',
  SignName: signName,
  TemplateCode: templateCode,
  TemplateParam: JSON.stringify({ code }),
  Timestamp: '2026-10-11T01:02:03Z',
  Version: '2017-05-25',
});

const send = async (fixture, provider, parameters, { host = 'dysmsapi.aliyuncs.com', signature } = {}) => {
  const form = new URLSearchParams({
    ...parameters,
    Signature: signature ?? signAliyunSmsParameters(parameters, accessKeySecret),
  }).toString();
  const certificate = await readFile(fixture.certificateFile);
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      hostname: '127.0.0.1',
      servername: 'dysmsapi.aliyuncs.com',
      port: provider.port,
      path: '/',
      method: 'POST',
      ca: certificate,
      headers: {
        host,
        'content-type': 'application/x-www-form-urlencoded',
        'content-length': String(Buffer.byteLength(form)),
      },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.once('end', () => resolve({
        status: response.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
      }));
    });
    request.once('error', reject);
    request.end(form);
  });
};

const health = async (fixture, provider, host = 'dysmsapi.aliyuncs.com') => {
  const certificate = await readFile(fixture.certificateFile);
  return new Promise((resolve, reject) => {
    const request = httpsRequest({
      hostname: '127.0.0.1', servername: 'dysmsapi.aliyuncs.com', port: provider.port,
      path: '/healthz', method: 'GET', ca: certificate,
      headers: { host },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.once('end', () => resolve({ status: response.statusCode, bytes: Buffer.concat(chunks).length }));
    });
    request.once('error', reject);
    request.end();
  });
};

const control = (socketPath, value) => new Promise((resolve, reject) => {
  const socket = createConnection(socketPath);
  const chunks = [];
  socket.setTimeout(2000, () => socket.destroy(new Error('control timeout')));
  socket.once('connect', () => socket.end(`${JSON.stringify(value)}\n`));
  socket.on('data', (chunk) => chunks.push(chunk));
  socket.once('end', () => {
    try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
    catch (error) { reject(error); }
  });
  socket.once('error', reject);
});

const command = (operation, recipient = '15551234567', purpose = 'signIn', capability = controlCapability) => ({
  operation, capability, recipient, purpose,
});

test('accepts the exact Aliyun HTTPS RPC contract and exposes its code only through one-shot control', async () => {
  const fixture = await createFixture();
  let provider;
  try {
    provider = await start(fixture);
    assert.deepEqual(await health(fixture, provider), { status: 204, bytes: 0 });
    assert.equal((await lstat(fixture.controlSocket)).mode & 0o777, 0o600);
    assert.deepEqual(await control(fixture.controlSocket, command('arm')), { ok: true });
    const result = await send(fixture, provider, baseParameters());
    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), {
      Code: 'OK', Message: 'OK', RequestId: 'aster-fixture', BizId: 'aster-fixture',
    });
    assert.deepEqual(await control(fixture.controlSocket, command('take')), { ok: true, code: '482901' });
    assert.deepEqual(await control(fixture.controlSocket, command('take')), { ok: false });
    const receipt = await readFile(fixture.receiptFile, 'utf8');
    assert.deepEqual(JSON.parse(receipt), {
      schemaVersion: 1,
      facts: { accepted: 1, rejected: 0, duplicateNonce: 0, lastAccepted: true },
    });
    assert.equal(receipt.includes('482901'), false);
    assert.equal(result.body.includes('482901'), false);
    assert.equal(result.body.includes(accessKeyId), false);
  } finally {
    await provider?.close();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('uses the canonical Aliyun HMAC-SHA1 signing algorithm', () => {
  assert.equal(
    signAliyunSmsParameters(baseParameters(), accessKeySecret),
    'Man+CwXNhluIXbQlCJN3yCo697Y='
  );
});

test('rejects invalid signature, host, template, recipient, and unarmed purpose without leaking values', async () => {
  const fixture = await createFixture();
  let provider;
  try {
    provider = await start(fixture);
    const cases = [
      [baseParameters({ nonce: 'nonce-invalid-signature' }), { signature: 'wrong' }],
      [baseParameters({ nonce: 'nonce-invalid-host' }), { host: 'example.invalid' }],
      [baseParameters({ nonce: 'nonce-invalid-template', templateCode: 'SMS_OTHER' }), {}],
      [baseParameters({ nonce: 'nonce-invalid-recipient', recipient: 'not-a-phone' }), {}],
      [baseParameters({ nonce: 'nonce-unarmed-purpose', templateCode: templates.register }), {}],
    ];
    assert.deepEqual(await control(fixture.controlSocket, command('arm')), { ok: true });
    for (const [parameters, options] of cases) {
      const result = await send(fixture, provider, parameters, options);
      assert.equal(result.status, 400);
      assert.deepEqual(JSON.parse(result.body), {
        Code: 'InvalidRequest', Message: 'InvalidRequest', RequestId: 'aster-fixture',
      });
      assert.equal(result.body.includes(parameters.TemplateParam), false);
    }
    const valid = await send(fixture, provider, baseParameters({ nonce: 'nonce-still-armed' }));
    assert.equal(valid.status, 200);
  } finally {
    await provider?.close();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('rejects health requests for any host other than the exact provider host', async () => {
  const fixture = await createFixture();
  let provider;
  try {
    provider = await start(fixture);
    const result = await health(fixture, provider, 'example.invalid');
    assert.equal(result.status, 400);
    assert.ok(result.bytes > 0);
  } finally {
    await provider?.close();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('wrong recipient, purpose, and capability cannot consume an owner delivery', async () => {
  const fixture = await createFixture();
  let provider;
  try {
    provider = await start(fixture);
    await control(fixture.controlSocket, command('arm'));
    assert.equal((await send(fixture, provider, baseParameters())).status, 200);
    assert.deepEqual(await control(fixture.controlSocket, command('take', '15550000000')), { ok: false });
    assert.deepEqual(await control(fixture.controlSocket, command('take', '15551234567', 'register')), { ok: false });
    assert.deepEqual(await control(fixture.controlSocket, command('take', '15551234567', 'signIn', 'wrong')), { ok: false });
    assert.deepEqual(await control(fixture.controlSocket, command('take')), { ok: true, code: '482901' });
  } finally {
    await provider?.close();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('rejects a replayed nonce while preserving the newly armed delivery slot', async () => {
  const fixture = await createFixture();
  let provider;
  try {
    provider = await start(fixture);
    await control(fixture.controlSocket, command('arm'));
    const parameters = baseParameters();
    assert.equal((await send(fixture, provider, parameters)).status, 200);
    assert.deepEqual(await control(fixture.controlSocket, command('take')), { ok: true, code: '482901' });
    assert.deepEqual(await control(fixture.controlSocket, command('arm')), { ok: true });
    assert.equal((await send(fixture, provider, parameters)).status, 400);
    assert.equal((await send(fixture, provider, baseParameters({ nonce: 'nonce-after-replay' }))).status, 200);
    const receipt = JSON.parse(await readFile(fixture.receiptFile, 'utf8'));
    assert.equal(receipt.facts.duplicateNonce, 1);
  } finally {
    await provider?.close();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('rejects unsafe private-file admission and malformed TLS material', async () => {
  const cases = [
    { options: { configMode: 0o644 } },
    { options: { keyMode: 0o644 } },
    { options: { receiptMode: 0o644 } },
  ];
  for (const { options } of cases) {
    const fixture = await createFixture(options);
    try {
      await assert.rejects(start(fixture), { message: 'Aster Phase 2 SMS provider fixture failed' });
    } finally { await rm(fixture.root, { recursive: true, force: true }); }
  }
  const fixture = await createFixture();
  try {
    await chmod(fixture.keyFile, 0o600);
    await writeFile(fixture.keyFile, 'not a key', { mode: 0o600 });
    await assert.rejects(start(fixture));
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test('rejects receipt symlinks and removes the owned control socket on close', async () => {
  const fixture = await createFixture();
  const target = path.join(fixture.root, 'receipt-target.json');
  try {
    await writeFile(target, '', { mode: 0o600 });
    await rm(fixture.receiptFile);
    await symlink(target, fixture.receiptFile);
    await assert.rejects(start(fixture), { message: 'Aster Phase 2 SMS provider fixture failed' });
    await rm(fixture.receiptFile);
    await writeFile(fixture.receiptFile, '', { mode: 0o600 });
    const provider = await start(fixture);
    assert.equal((await lstat(fixture.controlSocket)).isSocket(), true);
    await provider.close();
    await assert.rejects(lstat(fixture.controlSocket), { code: 'ENOENT' });
  } finally { await rm(fixture.root, { recursive: true, force: true }); }
});

test('keeps the startup receipt identity for the whole lease', async () => {
  const fixture = await createFixture();
  let provider;
  try {
    provider = await start(fixture);
    await rm(fixture.receiptFile);
    await writeFile(fixture.receiptFile, '', { mode: 0o600 });
    await control(fixture.controlSocket, command('arm'));
    const result = await send(fixture, provider, baseParameters());
    assert.equal(result.status, 400);
    assert.deepEqual(JSON.parse(result.body), {
      Code: 'InvalidRequest', Message: 'InvalidRequest', RequestId: 'aster-fixture',
    });
    assert.equal(await readFile(fixture.receiptFile, 'utf8'), '');
    assert.equal(provider.takeCode('15551234567', 'signIn'), undefined);
  } finally {
    await provider?.close().catch(() => {});
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('bounds active delivery tuples and rejects exported operations after close', async () => {
  const fixture = await createFixture();
  const provider = await start(fixture);
  try {
    for (let index = 0; index < 100; index += 1) {
      assert.equal(provider.arm(`1555123${String(index).padStart(4, '0')}`, 'signIn'), true);
    }
    assert.equal(provider.arm('15559999999', 'signIn'), false);
  } finally {
    await provider.close();
    await rm(fixture.root, { recursive: true, force: true });
  }
  assert.equal(provider.arm('15551234567', 'signIn'), false);
  assert.equal(provider.takeCode('15551234567', 'signIn'), undefined);
});
