import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, rm } from 'node:fs/promises';
import path from 'node:path';

const failure = 'Invalid Phase 2 SMS provider runtime';
const fail = () => { throw new TypeError(failure); };
const names = ['configuration.json', 'receipt.json', 'input.json'];
const safeRoot = (root) => typeof root === 'string' &&
  root.startsWith('/var/tmp/henry-build/') && path.normalize(root) === root &&
  !/[\u0000-\u001F\u007F: ,]/u.test(root) && Buffer.byteLength(`${root}/o/s.sock`) <= 100;
const writeNew = async (file, value) => {
  const handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await handle.writeFile(value === undefined ? '' : `${JSON.stringify(value)}\n`); await handle.sync(); }
  finally { await handle.close(); }
};
export const createSmsProviderRuntime = async (root) => {
  if (!safeRoot(root) || await realpath(path.dirname(root)) !== path.dirname(root)) return fail();
  await mkdir(root, { mode: 0o700 });
  const identity = await lstat(root);
  try {
    const roles = {};
    for (const role of ['oracle', 'candidate']) {
      const directory = path.join(root, role === 'oracle' ? 'o' : 'c');
      await mkdir(directory, { mode: 0o700 });
      const configurationFile = path.join(directory, names[0]);
      const receiptFile = path.join(directory, names[1]);
      const inputFile = path.join(directory, names[2]);
      const controlSocket = path.join(directory, 's.sock');
      const templates = Object.fromEntries(['SignIn', 'Register', 'ForgotPassword', 'Generic']
        .map((purpose) => [purpose, `SMS_${randomBytes(8).readBigUInt64BE().toString().padStart(20, '0')}`]));
      await writeNew(configurationFile, { schemaVersion: 1, accessKeyId: randomBytes(16).toString('hex'),
        accessKeySecret: randomBytes(32).toString('hex'), signName: `aster-${role}`, templates,
        controlCapability: randomBytes(32).toString('hex') });
      await writeNew(receiptFile);
      await writeNew(inputFile, { schemaVersion: 1, configurationFile, controlSocket });
      roles[role] = Object.freeze({ configurationFile, receiptFile, inputFile, controlDirectory: directory, controlSocket });
    }
    return Object.freeze(roles);
  } catch {
    const current = await lstat(root);
    if (current.dev === identity.dev && current.ino === identity.ino) await rm(root, { recursive: true });
    return fail();
  }
};

// Call only after the owned provider processes are stopped and their sockets are absent.
export const clearSmsProviderRuntime = async (root) => {
  if (!safeRoot(root)) return fail();
  const directory = await lstat(root);
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== process.getuid() ||
    (directory.mode & 0o777) !== 0o700 || await realpath(root) !== root) return fail();
  const files = [];
  for (const role of ['o', 'c']) {
    const parent = path.join(root, role), state = await lstat(parent);
    if (!state.isDirectory() || state.isSymbolicLink() || state.uid !== process.getuid() ||
        (state.mode & 0o777) !== 0o700 || await realpath(parent) !== parent) return fail();
    try { await lstat(path.join(parent, 's.sock')); return fail(); }
    catch (error) { if (error?.code !== 'ENOENT') return fail(); }
    for (const name of names) {
      const file = path.join(parent, name), before = await lstat(file);
      if (!before.isFile() || before.isSymbolicLink() || before.uid !== process.getuid() ||
          before.nlink !== 1 || (before.mode & 0o777) !== 0o600 || before.size > 65_536 ||
          await realpath(file) !== file) return fail();
      files.push({ file, before });
    }
  }
  for (const { file, before } of files) {
    const handle = await open(file, constants.O_WRONLY | constants.O_NOFOLLOW);
    try {
      const current = await handle.stat();
      if (current.dev !== before.dev || current.ino !== before.ino || current.nlink !== 1 ||
          current.uid !== process.getuid() || (current.mode & 0o777) !== 0o600) return fail();
      await handle.truncate(0); await handle.sync();
    } finally { await handle.close(); }
  }
};
