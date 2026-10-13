import { stat } from 'node:fs/promises';
import path from 'node:path';

import {
  classifyManagementProvisioningClientRefusal,
  resolveManagementProvisioningDirectory,
} from './management-provisioning-family.js';

test('resolves the pinned provisioner scripts from source and compiled module locations', () => {
  const expected = path.join(
    path.sep,
    'workspace',
    'packages',
    'integration-tests',
    'src',
    'compatibility',
    'phase-2',
    'testing',
    'management-provisioning-family'
  );
  expect(
    resolveManagementProvisioningDirectory(
      'file:///workspace/packages/integration-tests/src/compatibility/phase-2/clients/management-provisioning-family.ts'
    )
  ).toBe(expected);
  expect(
    resolveManagementProvisioningDirectory(
      'file:///workspace/packages/integration-tests/lib/chunk-EXAMPLE.js'
    )
  ).toBe(expected);
  expect(() => resolveManagementProvisioningDirectory('file:///workspace/lib/chunk.js')).toThrow(
    'Invalid Common Management provisioning family runner'
  );
});

test('resolves every pinned provisioner script from the emitted test location', async () => {
  const directory = resolveManagementProvisioningDirectory(import.meta.url);
  const scripts = [
    'provision-email-connector.mjs',
    'provision-google-connector.mjs',
    'provision-sms-connector.mjs',
    'provision-wechat-connectors.mjs',
    'provision-client.mjs',
  ];
  await expect(
    Promise.all(
      scripts.map(async (script) => {
        const entry = await stat(path.join(directory, script));
        return entry.isFile();
      })
    )
  ).resolves.toEqual([true, true, true, true, true]);
});

test('admits only the selected reaped ownership refusal', () => {
  expect(
    classifyManagementProvisioningClientRefusal(
      1,
      false,
      'Error: multiple applications use the Box-AI application name\n    at provision-client.mjs',
      false
    )
  ).toBe('ownership-refused');
  expect(classifyManagementProvisioningClientRefusal(1, false, 'network failure', false)).toBe(
    undefined
  );
  expect(
    classifyManagementProvisioningClientRefusal(
      1,
      true,
      'Error: multiple applications use the Box-AI application name',
      false
    )
  ).toBeUndefined();
  expect(
    classifyManagementProvisioningClientRefusal(
      1,
      false,
      'Error: multiple applications use the Box-AI application name',
      true
    )
  ).toBeUndefined();
});
