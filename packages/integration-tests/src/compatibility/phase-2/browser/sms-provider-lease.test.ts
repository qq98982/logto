/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Owned socket state models one recipient delivery and one take operation. */
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import path from 'node:path';

import { withSmsProviderLease, type SmsProviderLease } from './sms-provider-lease.js';

const configuration = {
  schemaVersion: 1,
  accessKeyId: 'owned-test-id',
  accessKeySecret: 'owned-test-secret',
  signName: 'owned-test-sign',
  controlCapability: 'owned-control-capability',
  templates: {
    SignIn: 'sign-in',
    Register: 'register',
    ForgotPassword: 'recovery',
    Generic: 'generic',
  },
};
const withFixture = async (use: (inputFile: string, secretFile: string) => Promise<void>) => {
  const directory = await mkdtemp('/var/tmp/henry-build/sms-lease-');
  await chmod(directory, 0o700);
  const control = path.join(directory, 'c');
  await mkdir(control, { mode: 0o700 });
  const socket = path.join(control, 's.sock');
  const secretFile = path.join(directory, 'config.json');
  const inputFile = path.join(directory, 'input.json');
  await writeFile(secretFile, JSON.stringify(configuration), { mode: 0o600 });
  await writeFile(
    inputFile,
    JSON.stringify({ schemaVersion: 1, configurationFile: secretFile, controlSocket: socket }),
    { mode: 0o600 }
  );
  let armed = false;
  let taken = false;
  const server = createServer({ allowHalfOpen: true }, (connection) => {
    let bytes = '';
    connection.on('data', (chunk: Uint8Array) => {
      bytes += Buffer.from(chunk).toString('utf8');
    });
    connection.on('end', () => {
      const request = JSON.parse(bytes) as Record<string, string>;
      const valid =
        request.capability === configuration.controlCapability &&
        request.recipient === '8613800000000' &&
        request.purpose === 'SignIn';
      if (valid && request.operation === 'arm' && !armed) {
        armed = true;
        connection.end('{"ok":true}\n');
      } else if (valid && request.operation === 'take' && armed && !taken) {
        taken = true;
        connection.end('{"ok":true,"code":"123456"}\n');
      } else {
        connection.end('{"ok":false}\n');
      }
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(socket, resolve);
    });
    await chmod(socket, 0o600);
    await use(inputFile, secretFile);
  } finally {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
    await rm(directory, { recursive: true, force: true });
  }
};
it('binds retrieval to exact recipient and purpose while preserving the owner code after foreign denial', async () => {
  await withFixture(async (inputFile) => {
    await withSmsProviderLease(inputFile, async (lease) => {
      await lease.arm('8613800000000', 'SignIn');
      await expect(lease.takeCode('8613800000001', 'SignIn')).rejects.toThrow(
        'Invalid SMS provider lease'
      );
      await expect(lease.takeCode('8613800000000', 'Register')).rejects.toThrow(
        'Invalid SMS provider lease'
      );
      await expect(lease.takeCode('8613800000000', 'SignIn')).resolves.toBe('123456');
      await expect(lease.takeCode('8613800000000', 'SignIn')).rejects.toThrow(
        'Invalid SMS provider lease'
      );
    });
  });
});
it('keeps provider credentials nonserializable and revokes escaped lease operations', async () => {
  let escaped: SmsProviderLease | undefined;
  await withFixture(async (inputFile) => {
    await withSmsProviderLease(inputFile, async (lease) => {
      escaped = lease;
      expect(lease.configuration.templates.map((template) => template.usageType)).toEqual([
        'SignIn',
        'Register',
        'ForgotPassword',
        'Generic',
      ]);
      expect(() => JSON.stringify(lease)).toThrow('Invalid SMS provider lease');
      expect(() => JSON.stringify(lease.configuration)).toThrow('Invalid SMS provider lease');
    });
    await expect(escaped?.arm('8613800000000', 'SignIn')).rejects.toThrow(
      'Invalid SMS provider lease'
    );
  });
});
it('rejects public or oversized configuration with a fixed credential-free error', async () => {
  await withFixture(async (inputFile, secretFile) => {
    await chmod(secretFile, 0o644);
    await expect(withSmsProviderLease(inputFile, async () => true)).rejects.toThrow(
      'Invalid SMS provider lease'
    );
    await chmod(secretFile, 0o600);
    await writeFile(secretFile, 'x'.repeat(16_385));
    await expect(withSmsProviderLease(inputFile, async () => true)).rejects.toThrow(
      'Invalid SMS provider lease'
    );
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
