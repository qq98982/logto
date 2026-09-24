#!/usr/bin/env node
/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The tracked launcher owns bounded child-process capture, recursive stable module hashing, loader generation, and exact process exit propagation. */

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const diagnostic = 'Phase 2 client credentials launcher failed.\n';
const batchFailureModes = new Set(['oracle', 'differential', 'candidate-invariants']);
const closedScenarioIds = new Set([
  'basic-explicit-resource',
  'post-explicit-resource',
  'default-resource',
  'resource-no-scope',
  'resource-partial-scope',
  'organization-empty-scope',
  'organization-scope',
  'organization-resource-scope',
  'unknown-client-basic',
  'unknown-client-post',
  'wrong-secret-basic',
  'wrong-secret-post',
  'mixed-authentication',
  'missing-target',
  'unknown-resource',
  'unassociated-organization',
  'duplicate-resource',
  'duplicate-scope-name',
  'malformed-scope-whitespace',
  'unsupported-parameter',
]);
export const diagnosticForPhase2Child = (stderr) => {
  const match =
    /^Phase 2 client credentials command failed \((oracle|candidate)\/client-credentials\.([a-z-]+)\)\.\n$/u.exec(
      stderr
    );
  if (match && closedScenarioIds.has(match[2])) {
    return stderr;
  }
  if (
    /^Phase 2 client credentials command failed \((oracle|candidate)\/token-status\.public-access-active\)\.\n$/u.test(
      stderr
    )
  ) {
    return stderr;
  }
  return /^Phase 2 client credentials command failed \((oracle|candidate)-(fixture|discovery|controls|comparison|status-(admission|authorization|bootstrap|verification|identification|submit|bridge|consent-read|consent-write|resume|token|introspection))\)\.\n$/u.test(
    stderr
  ) ||
    /^Phase 2 client credentials command failed \(differential-(target-path|target-read|target-pair|target-verify|target-prepare|execution|harness|evidence|publish|cleanup)\)\.\n$/u.test(
      stderr
    )
    ? stderr
    : diagnostic;
};
export const diagnosticForPhase2Batch = (error) =>
  error instanceof Error && batchFailureModes.has(error.message)
    ? `Phase 2 client credentials batch failed (${error.message}).\n`
    : diagnostic;
const maximumModuleBytes = 16 * 1024 * 1024;
const maximumModules = 512;
const commitPattern = /^[0-9a-f]{40}$/u;
const runtimeCapabilitySymbolKey = 'aster.phase2.runtime-capability';

const fail = () => {
  throw new TypeError('Invalid Phase 2 launcher');
};

const run = (command, args, options) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: options.stdio,
    });
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 250).unref();
    }, options.timeoutMs);
    timer.unref();
    child.once('error', reject);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      if (timedOut || signal !== null || !Number.isSafeInteger(code)) {
        reject(new TypeError('Invalid Phase 2 launcher'));
        return;
      }
      resolve(code);
    });
  });

// `spawn` stream capture is kept separate so test dependencies can replace the process runners.
const runCaptured = (command, args, options) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 250).unref();
    }, options.timeoutMs);
    timer.unref();
    const append = (chunks, chunk, kind) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (kind === 'stdout') {
        stdoutBytes += bytes.byteLength;
      } else {
        stderrBytes += bytes.byteLength;
      }
      if (stdoutBytes > 1024 * 1024 || stderrBytes > 1024 * 1024) {
        child.kill('SIGKILL');
        return;
      }
      chunks.push(bytes);
    };
    child.stdout.on('data', (chunk) => append(stdout, chunk, 'stdout'));
    child.stderr.on('data', (chunk) => append(stderr, chunk, 'stderr'));
    child.once('error', reject);
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({
        code,
        signal,
        timedOut,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
  });

const gitText = async (root, args) => {
  const result = await runCaptured('git', args, {
    cwd: root,
    env: {
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_KEY_0: 'credential.helper',
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_CONFIG_VALUE_0: '',
      GIT_TERMINAL_PROMPT: '0',
      LC_ALL: 'C',
      PATH: '/usr/bin:/bin',
    },
    timeoutMs: 10_000,
  }).catch(fail);
  if (result.timedOut || result.code !== 0 || result.signal !== null || result.stderr !== '') {
    return fail();
  }
  return result.stdout.trim();
};

export const inspectCleanHead = async (root) => {
  const top = await gitText(root, ['rev-parse', '--show-toplevel']);
  const [head, tree, status, origin] = await Promise.all([
    gitText(root, ['rev-parse', 'HEAD']),
    gitText(root, ['rev-parse', 'HEAD^{tree}']),
    gitText(root, ['status', '--porcelain=v1', '--untracked-files=all']),
    gitText(root, ['remote', 'get-url', 'origin']),
  ]);
  if (
    top !== root ||
    !commitPattern.test(head) ||
    !commitPattern.test(tree) ||
    status !== '' ||
    !['git@github.com:qq98982/logto.git', 'https://github.com/qq98982/logto.git'].includes(origin)
  ) {
    return fail();
  }
  return Object.freeze({ head, tree });
};

const importsFrom = (source) => {
  const result = [];
  const patterns = [
    /^(?:import|export)\s+(?:(?:[\s\S]*?)\s+from\s+)?["']([^"']+)["'];/gmu,
    /\bimport\(\s*["']([^"']+)["']\s*\)/gu,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      if (match[1]?.startsWith('.')) {
        result.push(match[1]);
      }
    }
  }
  return [...new Set(result)];
};

const readStable = async (filePath) => {
  const before = await lstat(filePath).catch(fail);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.size <= 0 ||
    before.size > maximumModuleBytes ||
    (await realpath(filePath).catch(fail)) !== filePath
  ) {
    return fail();
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const opened = await handle.stat();
    const bytes = await handle.readFile();
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(filePath)]);
    if (
      opened.dev !== before.dev ||
      opened.ino !== before.ino ||
      opened.size !== before.size ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino ||
      after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs ||
      pathAfter.dev !== opened.dev ||
      pathAfter.ino !== opened.ino ||
      pathAfter.size !== opened.size ||
      pathAfter.mtimeMs !== opened.mtimeMs
    ) {
      return fail();
    }
    return bytes;
  } finally {
    await handle.close();
  }
};

export const computeRuntimeBundleManifest = async (entryPath) => {
  const libraryRoot = path.resolve(path.dirname(entryPath), '../..');
  if (!path.isAbsolute(entryPath) || path.basename(libraryRoot) !== 'lib') {
    return fail();
  }
  const pending = [entryPath];
  const modules = new Map();
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || modules.has(current)) {
      continue;
    }
    if (!current.startsWith(`${libraryRoot}${path.sep}`)) {
      return fail();
    }
    const bytes = await readStable(current);
    modules.set(current, bytes);
    if (modules.size > maximumModules) {
      return fail();
    }
    const source = new TextDecoder('utf8', { fatal: true }).decode(bytes);
    for (const specifier of importsFrom(source)) {
      const resolved = path.resolve(path.dirname(current), specifier);
      if (path.extname(resolved) !== '.js') {
        return fail();
      }
      pending.push(resolved);
    }
  }
  const hash = createHash('sha256');
  const sortedModules = [...modules.entries()].sort(([left], [right]) =>
    Buffer.compare(Buffer.from(left), Buffer.from(right))
  );
  for (const [filePath, bytes] of sortedModules) {
    const relative = path.relative(libraryRoot, filePath).split(path.sep).join('/');
    hash.update(`${Buffer.byteLength(relative)}:${relative}:${bytes.byteLength}:`);
    hash.update(bytes);
  }
  return Object.freeze({
    sha256: hash.digest('hex'),
    moduleCount: modules.size,
    entryUrl: pathToFileURL(entryPath).href,
    libraryRootUrl: pathToFileURL(`${libraryRoot}${path.sep}`).href,
    modules: Object.freeze(
      Object.fromEntries(
        sortedModules.map(([filePath, bytes]) => [
          pathToFileURL(filePath).href,
          createHash('sha256').update(bytes).digest('hex'),
        ])
      )
    ),
  });
};

export const computeRuntimeBundleIdentity = async (entryPath) => {
  const manifest = await computeRuntimeBundleManifest(entryPath);
  return Object.freeze({ sha256: manifest.sha256, moduleCount: manifest.moduleCount });
};

const dataUrl = (source) =>
  `data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`;

export const createRuntimeHookImport = (manifest, capability) => {
  const moduleEntries =
    typeof manifest === 'object' && manifest !== null && typeof manifest.modules === 'object'
      ? Object.entries(manifest.modules ?? {})
      : [];
  if (
    !/^[0-9a-f]{64}$/u.test(capability) ||
    typeof manifest !== 'object' ||
    manifest === null ||
    !/^[0-9a-f]{64}$/u.test(manifest.sha256) ||
    !Number.isSafeInteger(manifest.moduleCount) ||
    manifest.moduleCount <= 0 ||
    typeof manifest.entryUrl !== 'string' ||
    typeof manifest.libraryRootUrl !== 'string' ||
    !manifest.libraryRootUrl.endsWith('/') ||
    !manifest.entryUrl.startsWith(manifest.libraryRootUrl) ||
    typeof manifest.modules !== 'object' ||
    manifest.modules === null ||
    moduleEntries.length !== manifest.moduleCount ||
    !Object.hasOwn(manifest.modules, manifest.entryUrl) ||
    moduleEntries.some(
      ([url, sha256]) =>
        !url.startsWith(manifest.libraryRootUrl) ||
        typeof sha256 !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(sha256)
    )
  ) {
    return fail();
  }
  const hookSource = `
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
const expected = new Map(${JSON.stringify(moduleEntries)});
const libraryRoot = ${JSON.stringify(manifest.libraryRootUrl)};
const entry = ${JSON.stringify(manifest.entryUrl)};
const capability = ${JSON.stringify(capability)};
const capabilityKey = ${JSON.stringify(runtimeCapabilitySymbolKey)};
const fail = () => { throw new Error('Phase 2 runtime module rejected'); };
const bytesFor = (source) => {
  if (typeof source === 'string') return Buffer.from(source, 'utf8');
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  return fail();
};
export async function load(url, context, nextLoad) {
  const loaded = await nextLoad(url, context);
  if (!url.startsWith(libraryRoot)) return loaded;
  const expectedHash = expected.get(url);
  if (expectedHash === undefined || loaded.source === null || loaded.source === undefined) fail();
  const bytes = bytesFor(loaded.source);
  if (createHash('sha256').update(bytes).digest('hex') !== expectedHash) fail();
  if (url !== entry) return loaded;
  const source = typeof loaded.source === 'string'
    ? loaded.source
    : new TextDecoder('utf8', { fatal: true }).decode(bytes);
  const capabilitySource = 'Object.defineProperty(globalThis, Symbol.for(' +
    JSON.stringify(capabilityKey) +
    '), { configurable: true, enumerable: false, value: ' +
    JSON.stringify(capability) +
    ', writable: false });\\n';
  return { ...loaded, source: capabilitySource + source };
}
`;
  const hookUrl = dataUrl(hookSource);
  return dataUrl(
    `import { register } from 'node:module';\nregister(${JSON.stringify(
      hookUrl
    )}, import.meta.url);\n`
  );
};

export const createRuntimeBootstrap = (entryUrl, capability) => {
  if (
    typeof entryUrl !== 'string' ||
    !entryUrl.startsWith('file:') ||
    !/^[0-9a-f]{64}$/u.test(capability)
  ) {
    return fail();
  }
  return dataUrl(`
const fail = () => { throw new Error('Phase 2 runtime bootstrap rejected'); };
const entry = ${JSON.stringify(entryUrl)};
const capability = ${JSON.stringify(capability)};
const cli = await import(entry);
if (typeof cli.runPhase2CliMain !== 'function') fail();
const code = await cli.runPhase2CliMain(Object.freeze(process.argv.slice(1)), capability);
if (code !== 0 && code !== 1) fail();
process.exitCode = code;
`);
};

export const executeVerifiedPhase2Entry = async (
  entryPath,
  args,
  environment,
  manifest,
  capability
) => {
  const registerImport = createRuntimeHookImport(manifest, capability);
  const bootstrap = createRuntimeBootstrap(manifest.entryUrl, capability);
  return runCaptured(
    process.execPath,
    [
      '--import',
      registerImport,
      '--input-type=module',
      '--eval',
      `await import(${JSON.stringify(bootstrap)})`,
      '--',
      ...args,
    ],
    {
      cwd: path.resolve(path.dirname(entryPath), '../../..'),
      env: environment,
      timeoutMs: 30 * 60_000,
    }
  );
};

const defaultDependencies = Object.freeze({
  inspect: inspectCleanHead,
  async build(root) {
    const code = await run('pnpm', ['--filter', '@logto/integration-tests', 'build'], {
      cwd: root,
      env: {
        HOME: process.env.HOME ?? fail(),
        LC_ALL: 'C',
        PATH: process.env.PATH ?? fail(),
      },
      stdio: 'ignore',
      timeoutMs: 5 * 60_000,
    });
    if (code !== 0) {
      return fail();
    }
  },
  identity: computeRuntimeBundleManifest,
  async execute(entryPath, args, environment, manifest, capability) {
    const result = await executeVerifiedPhase2Entry(
      entryPath,
      args,
      environment,
      manifest,
      capability
    );
    if (result.timedOut || result.code !== 0 || result.signal !== null || result.stderr !== '') {
      if (!result.timedOut && result.code === 1 && result.signal === null) {
        const failure = diagnosticForPhase2Child(result.stderr);
        if (failure !== diagnostic) {
          process.stderr.write(failure);
        }
      }
      return 1;
    }
    process.stdout.write(result.stdout);
    return 0;
  },
});

const preparePhase2Runtime = async (dependencies) => {
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  const repositoryRoot = path.resolve(packageRoot, '../..');
  const entryPath = path.join(packageRoot, 'lib/compatibility/phase-2/cli.js');
  const before = await dependencies.inspect(repositoryRoot);
  await dependencies.build(repositoryRoot);
  const after = await dependencies.inspect(repositoryRoot);
  if (before.head !== after.head || before.tree !== after.tree) {
    return fail();
  }
  const runtime = await dependencies.identity(entryPath);
  const environment = Object.freeze({
    ASTER_PHASE2_HARNESS_HEAD: before.head,
    ASTER_PHASE2_HARNESS_TREE: before.tree,
    ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: runtime.sha256,
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
  });
  return Object.freeze({ entryPath, environment, runtime });
};

const validateBatchCommands = (commands) => {
  if (!Array.isArray(commands) || commands.length === 0 || commands.length > 8) {
    return fail();
  }
  return Object.freeze(
    commands.map((command) => {
      if (
        !Array.isArray(command) ||
        command.length === 0 ||
        command.some(
          (value) =>
            typeof value !== 'string' || /\p{Cc}/u.test(value) || Buffer.byteLength(value) > 4096
        )
      ) {
        return fail();
      }
      return Object.freeze([...command]);
    })
  );
};

export const launchPhase2Batch = async (commands, dependencies = defaultDependencies) => {
  const validated = validateBatchCommands(commands);
  const { entryPath, environment, runtime } = await preparePhase2Runtime(dependencies);
  const capabilities = new Set();
  for (const command of validated) {
    let capability;
    do {
      capability = randomBytes(32).toString('hex');
    } while (capabilities.has(capability));
    capabilities.add(capability);
    const code = await dependencies.execute(entryPath, command, environment, runtime, capability);
    if (code !== 0) {
      throw new Error(batchFailureModes.has(command[0]) ? command[0] : 'unknown');
    }
  }
  return 0;
};

export const launchPhase2 = async (arguments_, dependencies = defaultDependencies) =>
  launchPhase2Batch([arguments_], dependencies);

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) {
  try {
    await launchPhase2(process.argv.slice(2));
  } catch {
    process.exitCode = 1;
    process.stderr.write(diagnostic);
  }
}

/* eslint-enable complexity, max-lines, max-params, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
