/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Private file and lease lifecycle tests require owned temporary state. */
import { chmod, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { readCommonGoogleExistingOwnerFixtureRuntime } from './common-google-existing-owner-fixture-runtime.js';

const row = Object.freeze({
  schemaVersion: 1,
  container: 'google-provider-oracle',
  project: 'phase2-google-oracle',
  service: 'google-provider',
  image: `sha256:${'a'.repeat(64)}`,
  configFile: '/private/google-config.json',
  receiptFile: '/private/google-receipt.json',
  healthDiagnosticFile: '/private/google-health.json',
  dockerHome: '/private/docker-home',
  apiVersion: '5.0.0',
  googleSubject: 'immutable-google-subject',
  originalOwnerEmail: 'owner@example.invalid',
  changedProviderEmail: 'changed@example.invalid',
  expectedUserinfoMethod: 'GET',
  clientId: 'private-client-id',
  clientSecret: 'private-client-secret',
});

const createInput = async (value: unknown = row) => {
  const root = await mkdtemp('/var/tmp/henry-build/google-fixture-runtime-');
  const file = path.join(root, 'provider.json');
  await writeFile(file, JSON.stringify(value), { mode: 0o600 });
  return { root, file };
};

test('reads one exact private provider descriptor and scopes nonserializable credentials', async () => {
  const input = await createInput();
  const runtime = await readCommonGoogleExistingOwnerFixtureRuntime(
    input.file,
    '/private/podman.sock'
  );
  expect(runtime.provider).toMatchObject({
    container: row.container,
    project: row.project,
    service: row.service,
    image: row.image,
    expectedUserinfoMethod: 'GET',
  });
  let retained: { getClientId(): string; getClientSecret(): string; toJSON(): never } | undefined;
  await expect(
    runtime.withProviderCredentialLease(async (lease) => {
      retained = lease;
      expect(lease.getClientId()).toBe(row.clientId);
      expect(lease.getClientSecret()).toBe(row.clientSecret);
      expect(() => JSON.stringify(lease)).toThrow(
        'Invalid Common Google existing-owner fixture runtime'
      );
      await expect(runtime.withProviderCredentialLease(async () => null)).rejects.toThrow(
        'Invalid Common Google existing-owner fixture runtime'
      );
      return 'complete';
    })
  ).resolves.toBe('complete');
  expect(() => retained?.getClientId()).toThrow(
    'Invalid Common Google existing-owner fixture runtime'
  );
  expect(JSON.stringify(runtime.provider)).not.toMatch(/private-client/u);
  await rm(input.root, { recursive: true, force: true });
});

test.each([
  ['extra key', { ...row, extra: true }],
  ['invalid version', { ...row, apiVersion: 'latest' }],
  ['invalid method', { ...row, expectedUserinfoMethod: 'PATCH' }],
  ['control character', { ...row, googleSubject: 'subject\nprivate' }],
] as const)('rejects an exact-schema violation: %s', async (_name, value) => {
  const input = await createInput(value);
  await expect(
    readCommonGoogleExistingOwnerFixtureRuntime(input.file, '/private/podman.sock')
  ).rejects.toThrow('Invalid Common Google existing-owner fixture runtime');
  await rm(input.root, { recursive: true, force: true });
});

test('rejects loose permissions and symbolic-link inputs', async () => {
  const input = await createInput();
  await chmod(input.file, 0o640);
  await expect(
    readCommonGoogleExistingOwnerFixtureRuntime(input.file, '/private/podman.sock')
  ).rejects.toThrow('Invalid Common Google existing-owner fixture runtime');
  await chmod(input.file, 0o600);
  const link = path.join(input.root, 'provider-link.json');
  await symlink(input.file, link);
  await expect(
    readCommonGoogleExistingOwnerFixtureRuntime(link, '/private/podman.sock')
  ).rejects.toThrow('Invalid Common Google existing-owner fixture runtime');
  await rm(input.root, { recursive: true, force: true });
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
