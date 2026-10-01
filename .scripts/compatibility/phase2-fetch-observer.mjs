import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import https from 'node:https';
import { pathToFileURL } from 'node:url';

const MAX_BODY_BYTES = 64 * 1024;
const MAX_RECEIPTS = 64;
const MAX_RECEIPT_BYTES = 16 * 1024;
const routes = new Set(['/text', '/json', '/post', '/not-found', '/redirect', '/final']);

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error('observer configuration invalid');
  return value;
};

const exactPrivateFile = async (file) => {
  if (!file.startsWith('/') || file !== await realpath(file)) throw new Error('observer path invalid');
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink()) throw new Error('observer receipt file invalid');
  const handle = await open(file, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
  const metadata = await handle.stat();
  if (!metadata.isFile() || metadata.nlink !== 1 || (metadata.mode & 0o777) !== 0o600 ||
      metadata.uid !== process.getuid() || metadata.dev !== before.dev || metadata.ino !== before.ino) {
    await handle.close();
    throw new Error('observer receipt file invalid');
  }
  if (metadata.size !== 0) {
    await handle.close();
    throw new Error('observer receipt file not empty');
  }
  return handle;
};

const receipt = (method, path, headerMatches, bodyMatches) =>
  JSON.stringify({ method, path, headerMatches, bodyMatches });

export const startFetchObserver = async ({
  address = '0.0.0.0',
  port = 8443,
  deniedPort,
  certificateFile,
  privateKeyFile,
  receiptFile,
}) => {
  if (deniedPort !== undefined &&
      (!Number.isInteger(deniedPort) || deniedPort < 0 || deniedPort > 65535 ||
       (deniedPort !== 0 && deniedPort === port))) {
    throw new Error('observer denied port invalid');
  }
  const receipts = await exactPrivateFile(receiptFile);
  let cert;
  let key;
  try {
    [cert, key] = await Promise.all([readFile(certificateFile), readFile(privateKeyFile)]);
  } catch (error) {
    await receipts.close();
    throw error;
  }
  let writeChain = Promise.resolve();
  let receiptCount = 0;
  let receiptBytes = 0;
  let receiptFailed = false;
  const append = (value) => {
    if (receiptFailed) return Promise.reject(new Error('observer receipt unavailable'));
    const operation = writeChain.then(async () => {
      if (receiptFailed) throw new Error('observer receipt unavailable');
      const line = `${value}\n`;
      const bytes = Buffer.byteLength(line);
      if (receiptCount >= MAX_RECEIPTS || receiptBytes + bytes > MAX_RECEIPT_BYTES) {
        receiptFailed = true;
        throw new Error('observer receipt limit reached');
      }
      try {
        const lineBytes = Buffer.from(line);
        let offset = 0;
        while (offset < lineBytes.length) {
          const { bytesWritten } = await receipts.write(
            lineBytes,
            offset,
            lineBytes.length - offset
          );
          if (bytesWritten < 1) throw new Error('observer receipt write failed');
          offset += bytesWritten;
        }
        await receipts.sync();
      } catch (error) {
        receiptFailed = true;
        throw error;
      }
      receiptCount += 1;
      receiptBytes += bytes;
    });
    writeChain = operation.catch(() => {});
    return operation;
  };
  const startServer = async (listenPort) => {
    let boundPort = listenPort;
    const server = https.createServer({ cert, key }, (request, response) => {
      const chunks = [];
      let size = 0;
      let oversized = false;
      let url;
      const expectedOrigin = `https://fetch-observer.aster.test:${boundPort}`;
      const requestTarget = request.url ?? '/';
      try {
        if (!requestTarget.startsWith('/') || requestTarget.startsWith('//')) {
          throw new Error('observer request target invalid');
        }
        url = new URL(requestTarget, expectedOrigin);
      } catch {
        url = undefined;
      }
      request.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) {
          oversized = true;
          request.socket.destroy();
        }
        else chunks.push(chunk);
      });
      request.on('error', () => {});
      request.on('end', () => {
        if (oversized || response.destroyed) return;
        if (!url || url.origin !== expectedOrigin ||
            request.headers.host !== `fetch-observer.aster.test:${boundPort}` ||
            request.socket.servername !== 'fetch-observer.aster.test' ||
            url.search !== '' || url.hash !== '') {
          response.writeHead(400, { 'content-type': 'text/plain', connection: 'close' }).end('bad request');
          return;
        }
        if (url.pathname === '/reset-connection') {
          const body = Buffer.concat(chunks);
          if (request.method !== 'GET' || body.length !== 0) {
            response.writeHead(400, { 'content-type': 'text/plain', connection: 'close' }).end('bad request');
            return;
          }
          void append(receipt('GET', url.pathname, true, true)).then(
            () => request.socket.destroy(),
            () => response.writeHead(503, { connection: 'close' }).end()
          );
          return;
        }
        if (url.pathname === '/healthz' && request.method === 'GET') {
          response.writeHead(receiptFailed ? 503 : 204).end();
          return;
        }
        if (!routes.has(url.pathname) || !['GET', 'POST'].includes(request.method ?? '')) {
          response.writeHead(404, { 'content-type': 'text/plain', connection: 'close' }).end('not found');
          return;
        }
        const body = Buffer.concat(chunks);
        const headerMatches =
          url.pathname !== '/post' || request.headers['x-aster-probe'] === 'bounded-header';
        const bodyMatches =
          url.pathname !== '/post' ||
          createHash('sha256').update(body).digest('hex') ===
            '3920a2e1225ff984975c8a9c4f13a31b60e3ebcedc4b4bb9d440c50568128b8f';
        void append(receipt(request.method ?? '', url.pathname, headerMatches, bodyMatches)).then(
          () => {
            if (url.pathname === '/text') response.writeHead(200).end('bounded-text');
            else if (url.pathname === '/json') {
              response.writeHead(200, { 'content-type': 'application/json' });
              response.end('{"kind":"bounded-json","count":2}');
            } else if (url.pathname === '/post') {
              response.writeHead(201, { 'content-type': 'application/json' });
              response.end('{"method":"POST","header":"bounded-header","body":"bounded-body"}');
            } else if (url.pathname === '/not-found') response.writeHead(404).end('missing');
            else if (url.pathname === '/redirect') {
              response.writeHead(302, { location: '/final' }).end();
            } else response.writeHead(200).end('redirected');
          },
          () => response.writeHead(503, { connection: 'close' }).end()
        );
      });
    });
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        server.off('listening', onListening);
        reject(error);
      };
      const onListening = () => {
        server.off('error', onError);
        resolve();
      };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen(listenPort, address);
    });
    server.on('error', () => { receiptFailed = true; });
    boundPort = server.address().port;
    return server;
  };
  const servers = [];
  try {
    servers.push(await startServer(port));
    if (deniedPort !== undefined) servers.push(await startServer(deniedPort));
  } catch (error) {
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    await receipts.close();
    throw error;
  }
  return Object.freeze({
    address: servers[0].address(),
    ...(servers[1] ? { deniedAddress: servers[1].address() } : {}),
    close: async () => {
      const results = await Promise.allSettled(servers.map((server) => new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve()))
      )));
      try {
        await writeChain;
      } finally {
        await receipts.close();
      }
      const failed = results.find((result) => result.status === 'rejected');
      if (failed) throw failed.reason;
    },
  });
};

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const deniedPort = process.env.ASTER_FETCH_OBSERVER_DENIED_PORT;
  if (deniedPort !== undefined && deniedPort !== '8444') {
    throw new Error('observer denied port invalid');
  }
  await startFetchObserver({
    certificateFile: required('ASTER_FETCH_OBSERVER_CERTIFICATE_FILE'),
    privateKeyFile: required('ASTER_FETCH_OBSERVER_PRIVATE_KEY_FILE'),
    receiptFile: required('ASTER_FETCH_OBSERVER_RECEIPT_FILE'),
    ...(deniedPort ? { deniedPort: 8444 } : {}),
  });
}
