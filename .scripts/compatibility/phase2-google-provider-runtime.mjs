#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, mkdir, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const failure = 'Invalid Phase 2 Google provider runtime preparation';
const safeName = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/u;
const imageId = /^sha256:[0-9a-f]{64}$/u;
const apiVersionPattern = /^[1-9][0-9]*\.[0-9]+\.[0-9]+$/u;
const maximumInputBytes = 65_536;
const roles = Object.freeze(['oracle', 'candidate']);

const fail = () => {
  throw new TypeError(failure);
};

const exactAbsolutePath = (value) =>
  typeof value === 'string' &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  !/[\u0000-\u001F\u007F]/u.test(value) &&
  Buffer.byteLength(value) <= 4096
    ? value
    : fail();

const currentUid = () => process.getuid?.() ?? fail();

const assertPrivateDirectory = async (directory) => {
  const target = exactAbsolutePath(directory);
  const [state, resolved] = await Promise.all([lstat(target), realpath(target)]);
  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.uid !== currentUid() ||
    (state.mode & 0o777) !== 0o700 ||
    resolved !== target
  ) {
    return fail();
  }
};

const privateFile = (root, role, kind) => {
  const names = {
    configuration: ['configuration', 'configuration.json'],
    receipt: ['receipts', 'observations.json'],
    diagnostic: ['diagnostics', 'health.json'],
    input: ['', 'provider-input.json'],
  };
  const selected = names[kind] ?? fail();
  return path.join(root, role, ...selected.filter(Boolean));
};

const assertEmptyPrivateFile = async (file) => {
  const target = exactAbsolutePath(file);
  const [state, resolved] = await Promise.all([lstat(target), realpath(target)]);
  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.uid !== currentUid() ||
    state.nlink !== 1 ||
    (state.mode & 0o777) !== 0o600 ||
    state.size !== 0 ||
    resolved !== target
  ) {
    return fail();
  }
};

const inspectPrivateMutableFile = async (file, requireEmpty) => {
  const target = exactAbsolutePath(file);
  const [state, resolved] = await Promise.all([lstat(target), realpath(target)]);
  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.uid !== currentUid() ||
    state.nlink !== 1 ||
    (state.mode & 0o777) !== 0o600 ||
    state.size > maximumInputBytes ||
    (requireEmpty && state.size !== 0) ||
    resolved !== target
  ) {
    return fail();
  }
  return Object.freeze({ dev: state.dev, ino: state.ino });
};

const writeExistingJson = async (file, value) => {
  const identity = await inspectPrivateMutableFile(file, true);
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (bytes.byteLength < 2 || bytes.byteLength > maximumInputBytes) {
    return fail();
  }
  const handle = await open(file, constants.O_RDWR | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      before.dev !== identity.dev ||
      before.ino !== identity.ino ||
      before.uid !== currentUid() ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600 ||
      before.size !== 0
    ) {
      return fail();
    }
    await handle.truncate(bytes.byteLength);
    const written = await handle.write(bytes, 0, bytes.byteLength, 0);
    if (written.bytesWritten !== bytes.byteLength) {
      return fail();
    }
    await handle.sync();
    const after = await handle.stat();
    if (
      after.dev !== identity.dev ||
      after.ino !== identity.ino ||
      after.size !== bytes.byteLength
    ) {
      return fail();
    }
  } finally {
    await handle.close();
  }
  const current = await inspectPrivateMutableFile(file, false);
  if (current.dev !== identity.dev || current.ino !== identity.ino) {
    return fail();
  }
};

const clearExistingFile = async (file) => {
  const identity = await inspectPrivateMutableFile(file, false);
  const handle = await open(file, constants.O_RDWR | constants.O_NOFOLLOW);
  try {
    const before = await handle.stat();
    if (
      before.dev !== identity.dev ||
      before.ino !== identity.ino ||
      before.uid !== currentUid() ||
      before.nlink !== 1 ||
      (before.mode & 0o777) !== 0o600
    ) {
      return fail();
    }
    await handle.truncate(0);
    await handle.sync();
    const after = await handle.stat();
    if (after.dev !== identity.dev || after.ino !== identity.ino || after.size !== 0) {
      return fail();
    }
  } finally {
    await handle.close();
  }
  const current = await inspectPrivateMutableFile(file, true);
  if (current.dev !== identity.dev || current.ino !== identity.ino) {
    return fail();
  }
};

const writeExclusiveJson = async (file, value) => {
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  if (bytes.byteLength < 2 || bytes.byteLength > maximumInputBytes) {
    return fail();
  }
  const handle = await open(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    const written = await handle.write(bytes, 0, bytes.byteLength, 0);
    if (written.bytesWritten !== bytes.byteLength) {
      return fail();
    }
    await handle.sync();
    const state = await handle.stat();
    if (
      !state.isFile() ||
      state.uid !== currentUid() ||
      state.nlink !== 1 ||
      (state.mode & 0o777) !== 0o600 ||
      state.size !== bytes.byteLength
    ) {
      return fail();
    }
  } finally {
    await handle.close();
  }
};

export const prepareGoogleProviderRuntimeFiles = async (rawRoot) => {
  const root = exactAbsolutePath(rawRoot);
  await assertPrivateDirectory(path.dirname(root));
  await mkdir(root, { mode: 0o700 });
  await chmod(root, 0o700);
  for (const role of roles) {
    const roleRoot = path.join(root, role);
    await mkdir(roleRoot, { mode: 0o700 });
    for (const directory of ['configuration', 'receipts', 'diagnostics']) {
      await mkdir(path.join(roleRoot, directory), { mode: 0o700 });
    }
    for (const kind of ['configuration', 'receipt', 'diagnostic']) {
      const handle = await open(privateFile(root, role, kind), 'wx', 0o600);
      await handle.close();
    }
  }
  return Object.freeze({
    root,
    oracleInputFile: privateFile(root, 'oracle', 'input'),
    candidateInputFile: privateFile(root, 'candidate', 'input'),
  });
};

const validatedTarget = (value, expectedRole) => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).toSorted().join('\0') !==
      ['container', 'project', 'service', 'image'].toSorted().join('\0') ||
    !safeName.test(value.container) ||
    !safeName.test(value.project) ||
    value.service !== `${expectedRole}-google-provider` ||
    !imageId.test(value.image)
  ) {
    return fail();
  }
  return Object.freeze({
    container: value.container,
    project: value.project,
    service: value.service,
    image: value.image,
  });
};

export const writeGoogleProviderRuntimeInputs = async (rawInput) => {
  if (
    typeof rawInput !== 'object' ||
    rawInput === null ||
    Array.isArray(rawInput) ||
    Object.keys(rawInput).toSorted().join('\0') !==
      ['root', 'oracle', 'candidate', 'dockerHome', 'apiVersion'].toSorted().join('\0')
  ) {
    return fail();
  }
  const root = exactAbsolutePath(rawInput.root);
  const dockerHome = exactAbsolutePath(rawInput.dockerHome);
  if (!apiVersionPattern.test(rawInput.apiVersion)) {
    return fail();
  }
  const oracle = validatedTarget(rawInput.oracle, 'oracle');
  const candidate = validatedTarget(rawInput.candidate, 'candidate');
  if (
    oracle.container === candidate.container ||
    oracle.project === candidate.project ||
    oracle.image !== candidate.image
  ) {
    return fail();
  }
  await Promise.all([
    assertPrivateDirectory(root),
    assertPrivateDirectory(dockerHome),
    ...roles.flatMap((role) => [
      assertPrivateDirectory(path.join(root, role)),
      assertPrivateDirectory(path.join(root, role, 'configuration')),
      assertPrivateDirectory(path.join(root, role, 'receipts')),
      assertPrivateDirectory(path.join(root, role, 'diagnostics')),
      assertEmptyPrivateFile(privateFile(root, role, 'configuration')),
      assertEmptyPrivateFile(privateFile(root, role, 'receipt')),
      assertEmptyPrivateFile(privateFile(root, role, 'diagnostic')),
    ]),
  ]);
  const common = Object.freeze({
    schemaVersion: 1,
    dockerHome,
    apiVersion: rawInput.apiVersion,
    googleSubject: 'common-google-owner',
    originalOwnerEmail: 'owner@example.invalid',
    changedProviderEmail: 'changed@example.invalid',
  });
  const rows = roles.map((role) => {
    const target = role === 'oracle' ? oracle : candidate;
    return Object.freeze({
      ...common,
      ...target,
      configFile: privateFile(root, role, 'configuration'),
      receiptFile: privateFile(root, role, 'receipt'),
      healthDiagnosticFile: privateFile(root, role, 'diagnostic'),
      expectedUserinfoMethod: role === 'oracle' ? 'POST' : 'GET',
      clientId: `google-${role}-${randomBytes(16).toString('hex')}`,
      clientSecret: randomBytes(32).toString('hex'),
    });
  });
  if (rows[0].clientId === rows[1].clientId || rows[0].clientSecret === rows[1].clientSecret) {
    return fail();
  }
  const oracleInputFile = privateFile(root, 'oracle', 'input');
  const candidateInputFile = privateFile(root, 'candidate', 'input');
  await writeExclusiveJson(oracleInputFile, rows[0]);
  try {
    await writeExclusiveJson(candidateInputFile, rows[1]);
  } catch {
    const handle = await open(oracleInputFile, constants.O_WRONLY | constants.O_NOFOLLOW);
    try {
      await handle.truncate(0);
      await handle.sync();
    } finally {
      await handle.close();
    }
    throw new TypeError(failure);
  }
  return Object.freeze({ root, oracleInputFile, candidateInputFile });
};

const probeCase = (subject, email) =>
  Object.freeze({
    code: randomBytes(24).toString('hex'),
    accessToken: randomBytes(24).toString('hex'),
    profile: Object.freeze({ sub: subject, email, emailVerified: true }),
  });

const healthProbeConfiguration = (role) => {
  const subject = 'common-google-health-probe';
  const connectorId = `health-probe-${role}`;
  const targetOrigin = 'https://health-probe.example.invalid';
  return Object.freeze({
    schemaVersion: 1,
    clientId: `health-probe-${role}-${randomBytes(16).toString('hex')}`,
    clientSecret: randomBytes(32).toString('hex'),
    targetOrigin,
    connectorId,
    callbackUri: `${targetOrigin}/callback/${connectorId}`,
    stable: probeCase(subject, 'health-owner@example.invalid'),
    changedEmail: probeCase(subject, 'health-changed@example.invalid'),
    wrongStateControl: probeCase(subject, 'health-changed@example.invalid'),
  });
};

export const writeGoogleProviderHealthProbeConfigurations = async (rawRoot) => {
  const root = exactAbsolutePath(rawRoot);
  await assertPrivateDirectory(root);
  for (const role of roles) {
    await Promise.all([
      assertPrivateDirectory(path.join(root, role)),
      assertPrivateDirectory(path.join(root, role, 'configuration')),
      assertPrivateDirectory(path.join(root, role, 'receipts')),
      assertPrivateDirectory(path.join(root, role, 'diagnostics')),
      assertEmptyPrivateFile(privateFile(root, role, 'configuration')),
      assertEmptyPrivateFile(privateFile(root, role, 'receipt')),
      assertEmptyPrivateFile(privateFile(root, role, 'diagnostic')),
    ]);
  }
  const written = [];
  try {
    for (const role of roles) {
      const file = privateFile(root, role, 'configuration');
      await writeExistingJson(file, healthProbeConfiguration(role));
      written.push(file);
    }
  } catch {
    await Promise.all(written.map(async (file) => clearExistingFile(file)));
    return fail();
  }
  return Object.freeze({
    oracleConfigurationFile: privateFile(root, 'oracle', 'configuration'),
    candidateConfigurationFile: privateFile(root, 'candidate', 'configuration'),
  });
};

export const clearGoogleProviderHealthProbeFiles = async (rawRoot) => {
  const root = exactAbsolutePath(rawRoot);
  await assertPrivateDirectory(root);
  await Promise.all(
    roles.flatMap((role) =>
      ['configuration', 'receipt', 'diagnostic'].map(async (kind) =>
        clearExistingFile(privateFile(root, role, kind))
      )
    )
  );
};

const main = async () => {
  const [operation, ...values] = process.argv.slice(2);
  if (operation === 'prepare' && values.length === 1) {
    await prepareGoogleProviderRuntimeFiles(values[0]);
    return;
  }
  if (operation === 'write' && values.length === 11) {
    const [
      root,
      oracleContainer,
      oracleProject,
      oracleImage,
      candidateContainer,
      candidateProject,
      candidateImage,
      dockerHome,
      apiVersion,
      oracleService,
      candidateService,
    ] = values;
    await writeGoogleProviderRuntimeInputs({
      root,
      oracle: {
        container: oracleContainer,
        project: oracleProject,
        service: oracleService,
        image: oracleImage,
      },
      candidate: {
        container: candidateContainer,
        project: candidateProject,
        service: candidateService,
        image: candidateImage,
      },
      dockerHome,
      apiVersion,
    });
    return;
  }
  if (operation === 'probe' && values.length === 1) {
    await writeGoogleProviderHealthProbeConfigurations(values[0]);
    return;
  }
  if (operation === 'clear-probe' && values.length === 1) {
    await clearGoogleProviderHealthProbeFiles(values[0]);
    return;
  }
  return fail();
};

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  main().catch(() => {
    process.stderr.write(`${failure}\n`);
    process.exitCode = 1;
  });
}
