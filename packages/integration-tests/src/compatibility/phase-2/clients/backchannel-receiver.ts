/* eslint-disable complexity, no-bitwise, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Socket identity and one-time bounded delivery stay in one private IPC scope. */
import { lstat, realpath } from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';

const fail = (): never => {
  throw new TypeError('Invalid Common backchannel receiver');
};

/** Consumes a notification once from the owned receiver; the token never enters an artifact. */
export const consumeOwnedBackchannelNotification = async (
  socketPath: string,
  signal?: AbortSignal
): Promise<string | undefined> => {
  if (
    !path.isAbsolute(socketPath) ||
    Buffer.byteLength(socketPath) > 100 ||
    socketPath !== (await realpath(socketPath).catch(fail))
  ) {
    return fail();
  }
  const parent = await lstat(path.dirname(socketPath)).catch(fail);
  const socket = await lstat(socketPath).catch(fail);
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    (parent.mode & 0o777) !== 0o700 ||
    parent.uid !== process.getuid?.() ||
    !socket.isSocket() ||
    socket.isSymbolicLink() ||
    socket.nlink !== 1 ||
    (socket.mode & 0o777) !== 0o600 ||
    socket.uid !== process.getuid() ||
    signal?.aborted
  ) {
    return fail();
  }
  return new Promise<string | undefined>((resolve, reject) => {
    const connection = net.createConnection(socketPath);
    const chunks: Uint8Array[] = [];
    const size = { value: 0 };
    const finished = { value: false };
    const settle = (value?: string, error = false) => {
      if (finished.value) {
        return;
      }
      finished.value = true;
      signal?.removeEventListener('abort', aborted);
      connection.destroy();
      if (error) {
        reject(new TypeError('Invalid Common backchannel receiver'));
      } else {
        resolve(value);
      }
    };
    const aborted = () => {
      settle(undefined, true);
    };
    signal?.addEventListener('abort', aborted, { once: true });
    connection.setTimeout(10_000, aborted);
    connection.once('connect', () => connection.end('CONSUME\n'));
    connection.on('data', (chunk: Uint8Array) => {
      size.value += chunk.byteLength;
      if (size.value > 16 * 1024 + 1) {
        settle(undefined, true);
        return;
      }
      chunks.push(chunk);
    });
    connection.once('error', aborted);
    connection.once('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      if (body === 'EMPTY\n') {
        settle();
      } else if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\n$/u.test(body)) {
        settle(body.slice(0, -1));
      } else {
        settle(undefined, true);
      }
    });
    connection.once('close', () => {
      if (!finished.value) {
        settle(undefined, true);
      }
    });
  });
};
/* eslint-enable complexity, no-bitwise, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
