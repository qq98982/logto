#!/usr/bin/env node

import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { chmod, mkdir, writeFile } from 'node:fs/promises';

const origin = 'http://localhost:3312';
const outputDirectory = '/var/tmp/henry-build/aster-phase2-token-status-oracle';
const timeout = AbortSignal.timeout(180_000);

const admin = async (method, path, body) => {
  const response = await fetch(new URL(`/api/${path}`, origin), {
    method,
    headers: {
      'development-user-id': 'integration-test-admin-user',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: timeout,
  });
  if (!response.ok) {
    throw new Error(`management request failed: ${method} ${path}: ${response.status}`);
  }
  return response.status === 204 ? undefined : response.json();
};

const probe = async (kind, name, fields, authorization) => {
  const response = await fetch(new URL(`/oidc/token/${kind}`, origin), {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(authorization === undefined ? {} : { authorization }),
    },
    body: new URLSearchParams(fields),
    signal: timeout,
  });
  const body = await response.text();
  return {
    kind,
    name,
    status: response.status,
    headers: Object.fromEntries(
      ['content-type', 'cache-control', 'www-authenticate', 'access-control-allow-origin']
        .filter((key) => response.headers.has(key))
        .map((key) => [key, response.headers.get(key)]),
    ),
    body: body.length ? JSON.parse(body) : null,
  };
};

await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
const marker = randomBytes(6).toString('hex');
const results = [];
const created = [];
const secrets = [];
let failed;
try {
  const application = await admin('POST', 'applications', {
    name: `Phase 2 status probe ${marker}`,
    type: 'Traditional',
    oidcClientMetadata: {
      redirectUris: ['http://localhost:3000/callback'],
      postLogoutRedirectUris: [],
    },
  });
  created.push(`applications/${encodeURIComponent(application.id)}`);
  const [secret] = await admin('GET', `applications/${encodeURIComponent(application.id)}/secrets`);
  secrets.push(secret.value);
  const basic = `Basic ${Buffer.from(`${application.id}:${secret.value}`).toString('base64')}`;
  secrets.push(basic);
  for (const kind of ['introspection', 'revocation']) {
    for (const [name, token, hint] of [
      ['unknown', 'unknown-token', 'access_token'],
      ['unknown-no-hint', 'unknown-token', undefined],
      ['jwt-shape', 'aaa.bbb.ccc', 'access_token'],
      ['missing', undefined, undefined],
    ]) {
      const fields = {};
      if (token !== undefined) fields.token = token;
      if (hint !== undefined) fields.token_type_hint = hint;
      results.push(await probe(kind, `basic-${name}`, fields, basic));
      if (name === 'unknown') {
        results.push(await probe(kind, 'no-auth', fields));
        results.push(await probe(kind, 'post-unknown', {
          ...fields,
          client_id: application.id,
          client_secret: secret.value,
        }));
        results.push(await probe(kind, 'unknown-extension', {
          ...fields,
          aster_probe_extension: 'bounded',
        }, basic));
        results.push(await probe(kind, 'wrong-basic', fields,
          `Basic ${Buffer.from(`${application.id}:invalid-proof`).toString('base64')}`));
      }
    }
    results.push(await probe(kind, 'duplicate-token', [
      ['token', 'unknown-token'], ['token', 'unknown-token'],
    ], basic));
  }
} catch (error) {
  failed = error;
} finally {
  for (const path of created.toReversed()) {
    try {
      await admin('DELETE', path);
    } catch (error) {
      failed ??= error;
    }
  }
}
if (failed) throw failed;
const path = `${outputDirectory}/minimal-${marker}.json`;
const serialized = `${JSON.stringify(results, null, 2)}\n`;
if (secrets.some((secret) => serialized.includes(secret)) || /Bearer\s+[A-Za-z0-9._~-]+/u.test(serialized)) {
  throw new Error('status probe output contains credential material');
}
await writeFile(path, serialized, { flag: 'wx', mode: 0o600 });
await chmod(path, 0o600);
console.log(path);
