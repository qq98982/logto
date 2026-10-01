#!/usr/bin/env node
/* eslint-disable complexity, max-lines, max-params, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The tracked launcher owns bounded child-process capture, recursive stable module hashing, loader generation, and exact process exit propagation. */

import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const diagnostic = 'Phase 2 client credentials launcher failed.\n';
const childDiagnostic = (failureClass) =>
  `Phase 2 client credentials launcher child failed (${failureClass}).\n`;
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
const closedStatusScenarioIds = new Set([
  'public-access-active',
  'public-refresh-active',
  'access-wrong-hint-active',
  'refresh-no-hint-active',
  'resource-jwt-introspection-rejected',
  'resource-jwt-revocation-rejected',
  'consumed-refresh-active',
  'rotated-refresh-active',
  'consumed-refresh-revoked',
  'rotated-refresh-inactive',
  'original-access-inactive',
  'unknown-token-inactive',
  'no-auth-rejected',
  'owner-access-revoked',
  'owner-access-inactive',
  'owner-refresh-inactive',
  'missing-token-rejected',
  'duplicate-token-rejected',
  'dotted-unknown-inactive',
  'unknown-extension-inactive',
  'no-auth-precedes-missing-token',
  'confidential-basic-access-active',
  'confidential-post-access-active',
  'confidential-wrong-secret-rejected',
  'confidential-public-cross-client-inactive',
  'confidential-public-cross-client-revoked',
  'confidential-owner-after-cross-client-active',
]);
const closedLogoutSessionScenarioIds = new Set([
  'anonymous-get',
  'anonymous-post',
  'anonymous-confirmed',
  'duplicate-client',
  'unknown-client',
  'unauthoritative-redirect',
  'unregistered-redirect',
  'success-page',
  'authenticated-get',
  'authenticated-confirmed',
  'offline-refresh-active',
  'authenticated-declined',
  'offline-refresh-active-after-decline',
  'confirm-missing-session',
  'confirm-xsrf-mismatch',
  'confirm-replay',
  'confirm-cross-cookie',
]);
const closedAccountSessionScenarioIds = new Set([
  'missing-verification',
  'wrong-password',
  'password-verification',
  'list-current',
  'delete-current',
  'list-zero-current',
]);
const closedDeviceScenarioIds = new Set([
  'device-authorization.urlencoded-success',
  'device-authorization.json-object-success',
  'device-authorization.missing-client',
  'device-authorization.unknown-client',
  'device-authorization.ineligible-web-client',
  'device-authorization.confidential-client',
  'device-authorization.public-client-basic-rejected',
  'device-authorization.public-client-secret-post-rejected',
  'device-authorization.missing-device-grant',
  'device-authorization.explicit-resource',
  'device-authorization.unknown-resource',
  'device-authorization.organization',
  'device-authorization.unassociated-organization',
  'device-authorization.absent-scope',
  'device-authorization.empty-scope',
  'device-authorization.unknown-scope',
  'device-authorization.duplicate-client',
  'device-authorization.duplicate-resource',
  'device-authorization.duplicate-scope',
  'device-authorization.malformed-form',
  'device-authorization.malformed-json',
  'device-authorization.unsupported-parameter',
  'device-authorization.unknown-extension',
  'device-authorization.ui-locales',
  'device-authorization.json-array-rejected',
  'device-authorization.text-body-rejected',
  'device-authorization.query-only-rejected',
  'device-verification.shortcut-redirect',
  'device-verification.manual-entry',
  'device-verification.complete-url-entry',
  'device-verification.missing-code',
  'device-verification.malformed-code',
  'device-verification.unknown-code',
  'device-verification.expired-code',
  'device-verification.already-used-code',
  'device-verification.invalid-xsrf',
  'device-verification.cross-cookie-xsrf',
  'device-verification.abort',
  'device-verification.confirmation',
  'device-verification.confirmed-sign-in-redirect',
  'device-token.pending-poll',
  'device-token.in-flight-poll',
  'device-consent.first-party-matching-grant-required',
  'device-consent.third-party-redirect-absent',
  'device-token.denied-poll',
  'device-consent.approval',
  'device-verification.success-page',
  'device-verification.completed-cookie-cleanup',
  'device-token.openid-issuance',
  'device-token.id-token-signature-and-claims',
  'device-token.userinfo',
  'device-token.offline-refresh-rotation',
  'device-token.offline-refresh-after-logout',
  'device-token.resource-authority',
  'device-token.organization-authority',
  'device-token.refresh-resource-selection',
  'device-token.refresh-organization-selection',
  'device-token.session-bound-expiry',
  'device-token.client-mismatch',
  'device-token.unknown-code',
  'device-token.expired-code',
  'device-token.consumed-replay',
  'device-token.concurrent-reference-multi-winner',
  'device-token-status.access-introspection',
  'device-token-status.access-revocation',
  'device-token-status.refresh-introspection',
  'device-token-status.refresh-revocation',
  'device-discovery.oidc',
  'device-discovery.oauth',
]);
const closedIdClaimName =
  '(?:iss|aud|sub|iat|exp|nbf|auth_time|sid|jti|client_id|acr|amr|name|picture|username|email|email_verified|phone_number|phone_number_verified|family_name|given_name|middle_name|nickname|preferred_username|profile|website|gender|birthdate|zoneinfo|locale|address|created_at|updated_at|roles|organizations|organization_roles|organization_id|permissions)';
const closedIdClaimSet = `(?:none|${closedIdClaimName}(?:,${closedIdClaimName})*)`;
const deviceIdClaimKeysDifferencePattern = new RegExp(
  `^Phase 2 client credentials command failed \\((oracle|candidate)\\/(device-(?:authorization|verification|consent|token|token-status|discovery)\\.[a-z-]+):projection-id-claimKeys\\)\\.\\nPhase 2 device ID claimKeys differ \\(only on oracle: ${closedIdClaimSet}; only on candidate: ${closedIdClaimSet}\\)\\.\\n$`,
  'u'
);
export const diagnosticForPhase2Child = (stderr) => {
  const match =
    /^Phase 2 client credentials command failed \((oracle|candidate)\/client-credentials\.([a-z-]+)\)\.\n$/u.exec(
      stderr
    );
  if (match && closedScenarioIds.has(match[2])) {
    return stderr;
  }
  const statusMatch =
    /^Phase 2 client credentials command failed \((oracle|candidate)\/token-status\.([a-z-]+)\)\.\n$/u.exec(
      stderr
    );
  if (statusMatch && closedStatusScenarioIds.has(statusMatch[2])) {
    return stderr;
  }
  const logoutMatch =
    /^Phase 2 client credentials command failed \((oracle|candidate)\/logout\.([a-z-]+)\)\.\n$/u.exec(
      stderr
    );
  if (logoutMatch && closedLogoutSessionScenarioIds.has(logoutMatch[2])) return stderr;
  const accountMatch =
    /^Phase 2 client credentials command failed \((oracle|candidate)\/account-sessions\.([a-z-]+)\)\.\n$/u.exec(
      stderr
    );
  if (accountMatch && closedAccountSessionScenarioIds.has(accountMatch[2])) return stderr;
  const deviceIdClaimKeysDifferenceMatch = deviceIdClaimKeysDifferencePattern.exec(stderr);
  if (
    deviceIdClaimKeysDifferenceMatch &&
    closedDeviceScenarioIds.has(deviceIdClaimKeysDifferenceMatch[2])
  ) {
    return stderr;
  }
  const deviceIdMatch =
    /^Phase 2 client credentials command failed \((oracle|candidate)\/(device-(?:authorization|verification|consent|token|token-status|discovery)\.[a-z-]+):projection-id-(?:claimKeys|claimTypes-(?:aud|created_at|email|email_verified|exp|iat|iss|name|picture|preferred_username|sub|updated_at|username|auth_time|acr|amr|sid)|header|signature|format|issuer|audience|subject|issuedAt|lifetimeSeconds|other)\)\.\n$/u.exec(
      stderr
    );
  if (deviceIdMatch && closedDeviceScenarioIds.has(deviceIdMatch[2])) return stderr;
  const deviceMatch =
    /^Phase 2 client credentials command failed \((oracle|candidate)\/(device-(?:authorization|verification|consent|token|token-status|discovery)\.[a-z-]+)(?::(?:lifecycle-request|lifecycle-response|token-response|credential-lease|projection|scenario|approval(?:-(?:authorize|capture|verify|experience-open|password|identification|experience-submit|resume-initial|consent-read|consent-write|resume-final))?|transition|verification-get|verification-post|projection-(?:(?:firstIssued|consent|completion)-(?:status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)|sequence-(?:before|action|after|siblingBefore|siblingAfter)-(?:status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)|status|contentType|headers|keys|cookies|challenge|location|oauthError|userCodeShape|deviceCodeShape|expiresIn|interval|tokenType|verificationUri|verificationUriComplete|experience|kind|facts|access|id|refresh|redirect|terminal|other)))?\)\.\n$/u.exec(
      stderr
    );
  if (deviceMatch && closedDeviceScenarioIds.has(deviceMatch[2])) return stderr;
  if (
    /^Phase 2 client credentials command failed \((oracle|candidate)-sanitizer-(target|discovery|controls|ids|(?:client|device)-(?:[0-9]|[1-9][0-9]|1[0-5][0-9]|16[0-7]))\)\.\n$/u.test(
      stderr
    )
  ) {
    return stderr;
  }
  if (
    /^Phase 2 client credentials command failed \(candidate-invariant-device-(?:[0-7]|1-(?:private-code-extraction|row-sql|row-missing|row-facts|schema-query|schema-clear-columns)|2-(?:arm|abort|foreign-poll-(?:error|invalid-client|authorization-pending|status)|response|finish)|7-(?:prepare|approval|issuance|evidence-(?:open|values|validation|lease)|driver-unclassified|private-extraction|row-sql|row-facts|schema-query|schema-clear-columns|scan-(?:input|query|match)|normalized-(?:input|query|match)))\)\.\n$/u.test(
      stderr
    )
  ) {
    return stderr;
  }
  return /^Phase 2 client credentials command failed \((oracle|candidate)-(fixture|discovery|controls|sanitizer|comparison|logout-session|status-(admission|authorization|bootstrap|verification|identification|submit|bridge-(url|send|http-([1-5][0-9]{2}|other))|consent-read|consent-write|resume|token-(http|body|type|access|refresh)|introspection)|status-comparison-(kind|status|headers|body(-(sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-case-([0-9]|1[0-9]|2[0-6])-(kind|status|headers|body(-(sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-scope-([0-9]|1[0-9]|2[0-6])-(short|full|resource|offline|other)-(short|full|resource|offline|other))\)\.\n$/u.test(
    stderr
  ) ||
    /^Phase 2 client credentials command failed \((oracle|candidate|differential)-(target-path|target-read|target-pair|target-verify|target-prepare|execution|harness|evidence|publish|cleanup)\)\.\n$/u.test(
      stderr
    )
    ? stderr
    : diagnostic;
};
export const diagnosticForPhase2ChildResult = (result) => {
  if (result.timedOut) return childDiagnostic('timeout');
  if (result.signal !== null) return childDiagnostic('signal');
  if (result.code === 1) {
    const named = diagnosticForPhase2Child(result.stderr);
    if (named !== diagnostic) return named;
  }
  if (result.stderr !== '') return childDiagnostic('stderr');
  return childDiagnostic('exit-code');
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
      process.stderr.write(diagnosticForPhase2ChildResult(result));
      return 1;
    }
    process.stdout.write(result.stdout);
    return 0;
  },
});

const preparedRuntimes = new WeakMap();
const preparingRuntimes = new WeakMap();

const manifestsEqual = (left, right) => {
  if (
    typeof left !== 'object' ||
    left === null ||
    typeof right !== 'object' ||
    right === null ||
    typeof left.modules !== 'object' ||
    left.modules === null ||
    typeof right.modules !== 'object' ||
    right.modules === null ||
    left.sha256 !== right.sha256 ||
    left.moduleCount !== right.moduleCount ||
    left.entryUrl !== right.entryUrl ||
    left.libraryRootUrl !== right.libraryRootUrl
  ) {
    return false;
  }
  const leftEntries = Object.entries(left.modules);
  const rightEntries = Object.entries(right.modules);
  return (
    leftEntries.length === rightEntries.length &&
    leftEntries.every(([url, sha256]) => right.modules[url] === sha256)
  );
};

const prepareNewPhase2Runtime = async (dependencies, repositoryRoot, entryPath) => {
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
  const value = Object.freeze({ entryPath, environment, runtime });
  preparedRuntimes.set(dependencies, Object.freeze({ source: before, runtime, value }));
  return value;
};

const preparePhase2Runtime = async (dependencies) => {
  const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  const repositoryRoot = path.resolve(packageRoot, '../..');
  const entryPath = path.join(packageRoot, 'lib/compatibility/phase-2/cli.js');
  const prepared = preparedRuntimes.get(dependencies);
  if (prepared !== undefined) {
    const [source, runtime] = await Promise.all([
      dependencies.inspect(repositoryRoot),
      dependencies.identity(entryPath),
    ]);
    if (
      source.head !== prepared.source.head ||
      source.tree !== prepared.source.tree ||
      !manifestsEqual(runtime, prepared.runtime)
    ) {
      return fail();
    }
    return prepared.value;
  }
  const pending = preparingRuntimes.get(dependencies);
  if (pending !== undefined) {
    return pending;
  }
  const preparation = prepareNewPhase2Runtime(dependencies, repositoryRoot, entryPath);
  preparingRuntimes.set(dependencies, preparation);
  try {
    return await preparation;
  } finally {
    if (preparingRuntimes.get(dependencies) === preparation) {
      preparingRuntimes.delete(dependencies);
    }
  }
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
