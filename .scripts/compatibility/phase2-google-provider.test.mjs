import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { get } from 'node:https';
import path from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import { startGoogleProviderFixture } from './phase2-google-provider.mjs';

const execute = promisify(execFile);
const failure = 'Aster Phase 2 Google provider fixture failed';

const probeCase = (suffix, email) => ({
  code: `code-${suffix}`,
  accessToken: `access-${suffix}`,
  profile: { sub: 'stable-subject', email, emailVerified: true },
});

const createFixture = async ({ certificateMode = 0o444, keyMode = 0o400, configMode = 0o600 } = {}) => {
  const root = await mkdtemp('/var/tmp/henry-build/phase2-google-provider-test-');
  try {
    const caKey = path.join(root, 'ca.key');
    const caFile = path.join(root, 'ca.pem');
    const keyFile = path.join(root, 'server.key');
    const requestFile = path.join(root, 'server.csr');
    const extensionFile = path.join(root, 'server.ext');
    const certificateFile = path.join(root, 'server.pem');
    const configurationFile = path.join(root, 'configuration.json');
    const receiptFile = path.join(root, 'receipt.json');
    await execute('/usr/bin/openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-sha256',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
      '-subj',
      '/CN=Aster Google Provider Test CA',
      '-keyout',
      caKey,
      '-out',
      caFile,
    ]);
    await execute('/usr/bin/openssl', [
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-sha256',
      '-subj',
      '/CN=google-provider-test.aster.invalid',
      '-keyout',
      keyFile,
      '-out',
      requestFile,
    ]);
    await writeFile(
      extensionFile,
      [
        'basicConstraints=critical,CA:FALSE',
        'keyUsage=critical,digitalSignature,keyEncipherment',
        'subjectAltName=DNS:oauth2.googleapis.com,DNS:openidconnect.googleapis.com',
        'extendedKeyUsage=serverAuth',
        '',
      ].join('\n'),
      { mode: 0o600 }
    );
    await execute('/usr/bin/openssl', [
      'x509',
      '-req',
      '-days',
      '1',
      '-sha256',
      '-set_serial',
      '1',
      '-in',
      requestFile,
      '-CA',
      caFile,
      '-CAkey',
      caKey,
      '-extfile',
      extensionFile,
      '-out',
      certificateFile,
    ]);
    const targetOrigin = 'https://core.example.invalid';
    const connectorId = 'google-test';
    await writeFile(
      configurationFile,
      `${JSON.stringify({
        schemaVersion: 1,
        clientId: 'test-client',
        clientSecret: 'test-client-secret',
        targetOrigin,
        connectorId,
        callbackUri: `${targetOrigin}/callback/${connectorId}`,
        stable: probeCase('stable', 'owner@example.invalid'),
        changedEmail: probeCase('changed', 'changed@example.invalid'),
        wrongStateControl: probeCase('wrong-state', 'changed@example.invalid'),
      })}\n`,
      { mode: configMode }
    );
    await writeFile(receiptFile, '', { mode: 0o600 });
    await Promise.all([
      chmod(caKey, 0o400),
      chmod(caFile, 0o444),
      chmod(keyFile, keyMode),
      chmod(certificateFile, certificateMode),
      chmod(configurationFile, configMode),
    ]);
    return { root, caFile, keyFile, certificateFile, configurationFile, receiptFile };
  } catch (error) {
    await rm(root, { recursive: true, force: true });
    throw error;
  }
};

const startupFailure = async (fixture) => {
  try {
    const provider = await startGoogleProviderFixture({
      certificateFile: fixture.certificateFile,
      privateKeyFile: fixture.keyFile,
      configurationFile: fixture.configurationFile,
      receiptFile: fixture.receiptFile,
      port: 0,
    });
    await provider.close();
    assert.fail('provider unexpectedly started');
  } catch (error) {
    return {
      message: error instanceof Error ? error.message : '',
      stage: typeof error === 'object' && error !== null ? error.stage : undefined,
      kind: typeof error === 'object' && error !== null ? error.kind : undefined,
    };
  }
};

const healthStatus = async (fixture, port) => {
  const ca = await readFile(fixture.caFile);
  return new Promise((resolve, reject) => {
    const request = get(
      {
        hostname: '127.0.0.1',
        servername: 'oauth2.googleapis.com',
        port,
        path: '/healthz',
        headers: { host: 'oauth2.googleapis.com' },
        ca,
      },
      (response) => {
        response.resume();
        response.once('end', () => resolve(response.statusCode));
      }
    );
    request.once('error', reject);
    request.setTimeout(2000, () => {
      request.destroy(new Error('health timeout'));
    });
  });
};

test('serves health 204 with the runner certificate and private-key modes', async () => {
  const fixture = await createFixture();
  let provider;
  try {
    provider = await startGoogleProviderFixture({
      certificateFile: fixture.certificateFile,
      privateKeyFile: fixture.keyFile,
      configurationFile: fixture.configurationFile,
      receiptFile: fixture.receiptFile,
      port: 0,
    });
    assert.equal(await healthStatus(fixture, provider.address.port), 204);
  } finally {
    await provider?.close();
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('rejects a group/world-readable private key at the closed key stage', async () => {
  const fixture = await createFixture({ keyMode: 0o644 });
  try {
    assert.deepEqual(await startupFailure(fixture), {
      message: failure,
      stage: 'key-read',
      kind: 'input',
    });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test('keeps private configuration restricted to mode 0600', async () => {
  const fixture = await createFixture({ configMode: 0o644 });
  try {
    assert.deepEqual(await startupFailure(fixture), {
      message: failure,
      stage: 'config-read',
      kind: 'input',
    });
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});
