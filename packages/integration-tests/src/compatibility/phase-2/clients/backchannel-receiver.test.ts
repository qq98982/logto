/* eslint-disable @silverhand/fp/no-mutation -- The real owned Unix socket verifies bounded one-time token delivery. */
import { chmod, mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';

import { consumeOwnedBackchannelNotification } from './backchannel-receiver.js';

const withReceiver = async (reply: string, use: (socketPath: string) => Promise<void>) => {
  const root = await mkdtemp('/var/tmp/henry-build/backchannel-unit-');
  await chmod(root, 0o700);
  const socketPath = `${root}/receive.sock`;
  const used = { value: false };
  const server = net.createServer((connection) => {
    connection.once('data', (data: Uint8Array) => {
      expect(Buffer.from(data).toString('utf8')).toBe('CONSUME\n');
      connection.end(used.value ? 'EMPTY\n' : reply);
      used.value = true;
    });
  });
  await new Promise<void>((resolve) => {
    server.listen(socketPath, resolve);
  });
  await chmod(socketPath, 0o600);
  try {
    await use(socketPath);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
    await rm(root, { recursive: true });
  }
};

test('Owned backchannel socket delivers a private compact token exactly once', async () => {
  await withReceiver('private.token.signature\n', async (socketPath) => {
    expect(await consumeOwnedBackchannelNotification(socketPath)).toBe('private.token.signature');
    expect(await consumeOwnedBackchannelNotification(socketPath)).toBeUndefined();
  });
});

test.each(['raw-secret\n', 'private.token.signature\nextra\n', 'x'.repeat(16_386)])(
  'Owned backchannel socket refuses malformed or oversized response',
  async (reply) => {
    await withReceiver(reply, async (socketPath) => {
      await expect(consumeOwnedBackchannelNotification(socketPath)).rejects.toThrow(
        'Invalid Common backchannel receiver'
      );
    });
  }
);

test('Owned backchannel socket refuses open permissions before consuming a notification', async () => {
  await withReceiver('private.token.signature\n', async (socketPath) => {
    await chmod(socketPath, 0o666);
    await expect(consumeOwnedBackchannelNotification(socketPath)).rejects.toThrow();
    await chmod(socketPath, 0o600);
    expect(await consumeOwnedBackchannelNotification(socketPath)).toBe('private.token.signature');
  });
});
/* eslint-enable @silverhand/fp/no-mutation */
