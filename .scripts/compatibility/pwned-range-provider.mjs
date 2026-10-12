import { constants } from 'node:fs';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import https from 'node:https';

const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error('fixture configuration invalid');
  return value;
};

const privateAppendFile = async (path) => {
  if (!path.startsWith('/') || path !== await realpath(path)) throw new Error('receipt path invalid');
  const before = await lstat(path);
  const handle = await open(path, constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
  const metadata = await handle.stat();
  if (!before.isFile() || before.isSymbolicLink() || !metadata.isFile() || metadata.nlink !== 1 ||
      (metadata.mode & 0o777) !== 0o600 || metadata.uid !== process.getuid() || metadata.size !== 0 ||
      metadata.dev !== before.dev || metadata.ino !== before.ino) {
    await handle.close();
    throw new Error('receipt path invalid');
  }
  return handle;
};

const configuration = JSON.parse(await readFile(required('ASTER_PWNED_CONFIGURATION_FILE'), 'utf8'));
const responseModes = new Set(['count-zero', 'count-one', 'status-503', 'malformed-body']);
if (!/^[0-9A-F]{5}$/u.test(configuration.prefix) || !/^[0-9A-F]{35}$/u.test(configuration.suffix) ||
    !responseModes.has(configuration.responseMode)) {
  throw new Error('fixture configuration invalid');
}
const receipt = await privateAppendFile(required('ASTER_PWNED_RECEIPT_FILE'));
const certificate = await readFile(required('ASTER_PWNED_CERTIFICATE_FILE'));
const privateKey = await readFile(required('ASTER_PWNED_PRIVATE_KEY_FILE'));
let used = false;
let receiptCount = 0;
const userAgentProduct = (value) => {
  if (value === undefined) return 'absent';
  if (/^Aster\//u.test(value)) return 'aster';
  if (/^Logto\//u.test(value)) return 'logto';
  if (/^undici$/u.test(value)) return 'undici';
  if (/^node$/u.test(value) || /^Node\.js\//u.test(value)) return 'node';
  return 'other';
};
const server = https.createServer({ cert: certificate, key: privateKey }, (request, response) => {
  const target = request.url ?? '';
  const pathMatch = /^\/range\/([0-9A-F]{5})$/u.exec(target);
  const originMatches = request.headers.host === 'api.pwnedpasswords.com' &&
    request.socket.servername === 'api.pwnedpasswords.com';
  const accepted = !used && request.method === 'GET' && originMatches &&
    pathMatch?.[1] === configuration.prefix;
  const status = accepted ? configuration.responseMode === 'status-503' ? 503 : 200 : 400;
  if (receiptCount >= 4) {
    response.writeHead(503, { connection: 'close' }).end();
    return;
  }
  receiptCount += 1;
  void receipt.write(`${JSON.stringify({
    methodGet: request.method === 'GET', originMatches, pathShapeMatches: pathMatch !== null,
    prefixMatches: pathMatch?.[1] === configuration.prefix,
    addPaddingPresent: request.headers['add-padding'] !== undefined,
    userAgentProduct: userAgentProduct(request.headers['user-agent']), status,
  })}\n`).then(async () => {
    await receipt.sync();
    if (accepted) {
      used = true;
      if (configuration.responseMode === 'status-503') {
        response.writeHead(503, { connection: 'close' }).end();
        return;
      }
      response.writeHead(200, { 'content-type': 'text/plain', connection: 'close' });
      if (configuration.responseMode === 'malformed-body') response.end('NOT-A-RANGE-ROW\r\n');
      else response.end(`${configuration.suffix}:${configuration.responseMode === 'count-one' ? 1 : 0}\r\n`);
    } else response.writeHead(status, { connection: 'close' }).end();
  }, () => response.writeHead(503, { connection: 'close' }).end());
});
server.listen(443, '0.0.0.0');

