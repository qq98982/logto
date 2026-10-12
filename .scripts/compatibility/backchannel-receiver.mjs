import { constants } from 'node:fs';
import { chmod, lstat, open, readFile, realpath, unlink } from 'node:fs/promises';
import https from 'node:https';
import net from 'node:net';
import { parse } from 'node:querystring';

const MAX_BODY = 16 * 1024;
const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error('fixture configuration invalid');
  return value;
};
const receiptPath = required('ASTER_BACKCHANNEL_RECEIPT_FILE');
if (receiptPath !== await realpath(receiptPath)) throw new Error('receipt path invalid');
const before = await lstat(receiptPath);
const receipt = await open(receiptPath, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
const metadata = await receipt.stat();
if (!before.isFile() || before.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1 ||
    (metadata.mode & 0o777) !== 0o600 || metadata.uid !== process.getuid() || metadata.size !== 0 ||
    metadata.dev !== before.dev || metadata.ino !== before.ino) {
  await receipt.close();
  throw new Error('receipt path invalid');
}
const certificate = await readFile(required('ASTER_BACKCHANNEL_CERTIFICATE_FILE'));
const privateKey = await readFile(required('ASTER_BACKCHANNEL_PRIVATE_KEY_FILE'));
const responseStatus = Number(process.env.ASTER_BACKCHANNEL_RESPONSE_STATUS ?? '204');
if (responseStatus !== 204 && responseStatus !== 503) throw new Error('fixture configuration invalid');
const socketPath = required('ASTER_BACKCHANNEL_CONSUME_SOCKET');
if (!socketPath.startsWith('/') || Buffer.byteLength(socketPath) > 100) throw new Error('socket path invalid');
await unlink(socketPath).catch((error) => { if (error.code !== 'ENOENT') throw error; });
let token;
let consumed = false;
let receiptCount = 0;
const ipc = net.createServer((connection) => {
  let command = '';
  connection.setEncoding('utf8');
  connection.on('data', (chunk) => {
    command += chunk;
    if (command.length > 16) connection.destroy();
    if (command === 'CONSUME\n') {
      if (typeof token !== 'string' || consumed) connection.end('EMPTY\n');
      else {
        consumed = true;
        const value = token;
        token = undefined;
        connection.end(`${value}\n`);
      }
    }
  });
});
ipc.listen(socketPath, () => { void chmod(socketPath, 0o600); });
const server = https.createServer({ cert: certificate, key: privateKey }, (request, response) => {
  const chunks = [];
  let bytes = 0;
  request.on('data', (chunk) => {
    bytes += chunk.length;
    if (bytes > MAX_BODY) request.destroy();
    else chunks.push(chunk);
  });
  request.on('end', () => {
    if (receiptCount >= 4) {
      response.writeHead(503, { connection: 'close' }).end();
      return;
    }
    receiptCount += 1;
    const body = Buffer.concat(chunks).toString('utf8');
    const contentTypeMatches = request.headers['content-type'] === 'application/x-www-form-urlencoded';
    const originMatches = request.headers.host === 'backchannel.aster.test:8443' &&
      request.socket.servername === 'backchannel.aster.test';
    const parsed = parse(body);
    const exactForm = Object.keys(parsed).length === 1 && Object.hasOwn(parsed, 'logout_token');
    const tokenPresent = typeof parsed.logout_token === 'string' && parsed.logout_token.length > 0 &&
      parsed.logout_token.length <= MAX_BODY;
    const accepted = !token && !consumed && request.method === 'POST' &&
      request.url === '/backchannel-logout' && contentTypeMatches && originMatches && exactForm && tokenPresent;
    if (accepted) token = parsed.logout_token;
    const status = accepted ? responseStatus : 400;
    void receipt.write(`${JSON.stringify({
      methodPost: request.method === 'POST', pathMatches: request.url === '/backchannel-logout',
      contentTypeMatches, originMatches, bodyWithinLimit: bytes <= MAX_BODY, exactForm, tokenPresent,
      configuredResponseStatus: responseStatus, status,
    })}\n`).then(async () => {
      await receipt.sync();
      response.writeHead(status, { connection: 'close' }).end();
    }, () => response.writeHead(503, { connection: 'close' }).end());
  });
});
server.listen(8443, '0.0.0.0');

