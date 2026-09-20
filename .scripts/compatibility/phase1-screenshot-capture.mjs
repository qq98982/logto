#!/usr/bin/env node
import crypto, { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import tls from 'node:tls';

const suiteCommit = '0dc0e3a21ec411e92c808e5b2e2258592c22b594';
const planName = 'oidcc-basic-certification-test-plan';
const maximumJsonBytes = 131_072;
const maximumAuditBytes = 16_777_216;
const maximumImageBytes = 512_000;
const pollIntervalMs = 200;
const captureRequestName = 'capture-request.json';
const captureResponseName = 'capture-response.json';
const imageName = 'capture.png';
const moduleAuditName = 'module-audit.json';
const planIdPattern = /^[A-Za-z0-9]{13}$/u;
const testIdPattern = /^[A-Za-z0-9]{15}$/u;
const placeholderPattern = /^[A-Za-z0-9]{10}$/u;
const captureIdPattern = /^[a-f0-9]{32}$/u;
const modulePattern = /^[a-z0-9][a-z0-9-]{0,127}$/u;
const conditionPattern = /^[A-Za-z][A-Za-z0-9]{0,127}$/u;
const cookieNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const commonBindingKeys = Object.freeze([
  'schemaVersion',
  'suiteCommit',
  'planName',
  'planInstanceId',
  'moduleName',
  'testId',
  'placeholderId',
  'conditionId',
  'captureId',
  'captureKind',
  'createdAt',
  'deadline',
]);
const cookieKeys = Object.freeze([
  'name',
  'value',
  'domain',
  'path',
  'expires',
  'httpOnly',
  'secure',
  'sameSite',
]);
const requestKeys = Object.freeze([
  ...commonBindingKeys,
  'url',
  'issuerOrigin',
  'cookies',
]);
const responseKeys = Object.freeze([
  ...commonBindingKeys,
  'result',
  'renderedUrl',
  'imageFile',
  'imageSha256',
  'imageBytes',
  'observedCondition',
  'cookies',
]);
const errorConditions = Object.freeze({
  ExpectResponseTypeMissingErrorPage:
    /(?:response[_ ]type|missing required parameter|request is invalid)/iu,
  ExpectRedirectUriErrorPage:
    /(?:redirect[_ ]uri.{0,160}(?:did not match|invalid)|invalid.{0,80}redirect)/iu,
});
const requireFromHere = createRequire(import.meta.url);

const fail = () => {
  throw new TypeError('Invalid phase 1 screenshot capture');
};

const isRecord = (value) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const hasExactKeys = (value, expected) => {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
};

const requireSafeInteger = (value) => {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
};

const requireAbsoluteCanonicalPath = (value) => {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.normalize(value) !== value) {
    fail();
  }
  let canonical;
  try {
    canonical = fs.realpathSync(value);
  } catch {
    fail();
  }
  if (canonical !== value) fail();
  return value;
};

const requireOwnedDirectory = (directory, mode = 0o700) => {
  const canonical = requireAbsoluteCanonicalPath(directory);
  let metadata;
  try {
    metadata = fs.lstatSync(canonical);
  } catch {
    fail();
  }
  const uid = process.getuid?.();
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    (metadata.mode & 0o777) !== mode ||
    (uid !== undefined && metadata.uid !== uid)
  ) {
    fail();
  }
  return canonical;
};

const requireOwnedFile = (file, maximumBytes, allowedModes) => {
  const canonical = requireAbsoluteCanonicalPath(file);
  let metadata;
  try {
    metadata = fs.lstatSync(canonical);
  } catch {
    fail();
  }
  const uid = process.getuid?.();
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size < 1 ||
    metadata.size > maximumBytes ||
    !allowedModes.includes(metadata.mode & 0o777) ||
    (uid !== undefined && metadata.uid !== uid)
  ) {
    fail();
  }
  return Object.freeze({ path: canonical, size: metadata.size });
};

const readOwnedFile = (file, maximumBytes, allowedModes) => {
  const expected = requireOwnedFile(file, maximumBytes, allowedModes);
  let bytes;
  try {
    bytes = fs.readFileSync(expected.path);
  } catch {
    fail();
  }
  if (bytes.byteLength !== expected.size) fail();
  return bytes;
};

const parseJson = (bytes) => {
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail();
  }
  if (!isRecord(value)) fail();
  return value;
};

const requireHttpsOrigin = (value) => {
  if (typeof value !== 'string' || value.length > 2048) fail();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail();
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== '' ||
    parsed.hostname === '' ||
    parsed.port === ''
  ) {
    fail();
  }
  return parsed;
};

const requireCaptureUrl = (value, issuer) => {
  if (typeof value !== 'string' || value.length > 2048) fail();
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail();
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.hash !== '' ||
    parsed.origin !== issuer.origin
  ) {
    fail();
  }
  return parsed;
};

const requireBinding = (value) => {
  if (
    value.schemaVersion !== 1 ||
    value.suiteCommit !== suiteCommit ||
    value.planName !== planName ||
    typeof value.planInstanceId !== 'string' ||
    !planIdPattern.test(value.planInstanceId) ||
    typeof value.moduleName !== 'string' ||
    !modulePattern.test(value.moduleName) ||
    typeof value.testId !== 'string' ||
    !testIdPattern.test(value.testId) ||
    typeof value.placeholderId !== 'string' ||
    !placeholderPattern.test(value.placeholderId) ||
    typeof value.conditionId !== 'string' ||
    !conditionPattern.test(value.conditionId) ||
    typeof value.captureId !== 'string' ||
    !captureIdPattern.test(value.captureId) ||
    !['second-sign-in', 'ui-error'].includes(value.captureKind)
  ) {
    fail();
  }
  const createdAt = requireSafeInteger(value.createdAt);
  const deadline = requireSafeInteger(value.deadline);
  if (deadline <= createdAt || deadline <= Date.now()) fail();
  return Object.freeze(
    Object.fromEntries(commonBindingKeys.map((key) => [key, value[key]]))
  );
};

const requireCookie = (value, issuerHost) => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, cookieKeys) ||
    typeof value.name !== 'string' ||
    !cookieNamePattern.test(value.name) ||
    typeof value.value !== 'string' ||
    value.value.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(value.value) ||
    typeof value.domain !== 'string' ||
    ![issuerHost, `.${issuerHost}`].includes(value.domain) ||
    typeof value.path !== 'string' ||
    !value.path.startsWith('/') ||
    value.path.length > 2048 ||
    (!Number.isSafeInteger(value.expires) || value.expires < -1) ||
    typeof value.httpOnly !== 'boolean' ||
    typeof value.secure !== 'boolean' ||
    !['Strict', 'Lax', 'None'].includes(value.sameSite)
  ) {
    fail();
  }
  return Object.freeze({ ...value });
};

const requireCookies = (value, issuerHost) => {
  if (!Array.isArray(value) || value.length > 128) fail();
  const cookies = value.map((cookie) => requireCookie(cookie, issuerHost));
  const identities = cookies.map(({ domain, path: cookiePath, name }) =>
    `${domain}\u0000${cookiePath}\u0000${name}`
  );
  if (new Set(identities).size !== identities.length) fail();
  return Object.freeze(cookies);
};

const requireRequest = (file, directory, issuer) => {
  const request = parseJson(readOwnedFile(file, maximumJsonBytes, [0o600]));
  if (!hasExactKeys(request, requestKeys)) fail();
  const binding = requireBinding(request);
  if (
    path.basename(path.dirname(path.dirname(directory))) !== binding.planInstanceId ||
    path.basename(path.dirname(directory)) !== binding.testId ||
    path.basename(directory) !== binding.placeholderId ||
    request.issuerOrigin !== issuer.origin
  ) {
    fail();
  }
  const url = requireCaptureUrl(request.url, issuer);
  if (binding.captureKind === 'second-sign-in' && url.pathname !== '/sign-in') fail();
  if (binding.captureKind === 'ui-error' && url.pathname === '/oidc/auth') fail();
  if (
    binding.captureKind === 'ui-error' &&
    !Object.hasOwn(errorConditions, binding.conditionId)
  ) {
    fail();
  }
  const cookies = requireCookies(request.cookies, issuer.hostname);
  return Object.freeze({ binding, url, cookies });
};

const writePrivateAtomic = (directory, name, bytes) => {
  const target = path.join(directory, name);
  const temporary = `${target}.tmp`;
  let descriptor;
  try {
    if (fs.existsSync(target) || fs.existsSync(temporary)) fail();
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, target);
    requireOwnedFile(target, name === imageName ? maximumImageBytes : maximumJsonBytes, [0o600]);
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Preserve the fixed outer failure.
      }
    }
    try {
      fs.unlinkSync(temporary);
    } catch {
      // The temporary file may not exist.
    }
    if (error instanceof TypeError && error.message === 'Invalid phase 1 screenshot capture') {
      throw error;
    }
    fail();
  }
  return target;
};

const remainingTimeout = (deadline, maximum = 30_000) => {
  const remaining = deadline - Date.now();
  if (!Number.isSafeInteger(remaining) || remaining <= 0) fail();
  return Math.min(remaining, maximum);
};

const verifyCertificate = async ({ issuer, rootCaFile, certificateFile, deadline }) => {
  const rootBytes = readOwnedFile(rootCaFile, 1_048_576, [0o400, 0o440, 0o444, 0o600]);
  const certificateBytes = readOwnedFile(certificateFile, 1_048_576, [0o400, 0o440, 0o444, 0o600]);
  let certificate;
  try {
    certificate = new X509Certificate(certificateBytes);
  } catch {
    fail();
  }
  const now = Date.now();
  if (
    certificate.checkHost(issuer.hostname) !== issuer.hostname ||
    !Number.isFinite(Date.parse(certificate.validFrom)) ||
    !Number.isFinite(Date.parse(certificate.validTo)) ||
    now < Date.parse(certificate.validFrom) ||
    now > Date.parse(certificate.validTo)
  ) {
    fail();
  }
  const pin = crypto
    .createHash('sha256')
    .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64');
  await new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: '127.0.0.1',
      port: Number(issuer.port),
      servername: issuer.hostname,
      ca: rootBytes,
      rejectUnauthorized: true,
    });
    const rejectFixed = () => reject(new TypeError('Invalid phase 1 screenshot capture'));
    const timer = setTimeout(() => {
      socket.destroy();
      rejectFixed();
    }, remainingTimeout(deadline, 10_000));
    socket.once('error', rejectFixed);
    socket.once('secureConnect', () => {
      try {
        const peer = socket.getPeerCertificate(true);
        if (!socket.authorized || !peer.raw) fail();
        const peerCertificate = new X509Certificate(peer.raw);
        if (peerCertificate.fingerprint256 !== certificate.fingerprint256) fail();
        clearTimeout(timer);
        socket.end();
        resolve();
      } catch {
        socket.destroy();
        rejectFixed();
      }
    });
  });
  return pin;
};

const requirePlaywright = (moduleFile) => {
  const file = requireOwnedFile(moduleFile, 1_048_576, [0o444, 0o644, 0o664]);
  const manifestFile = path.join(path.dirname(file.path), 'package.json');
  const manifest = parseJson(
    readOwnedFile(manifestFile, maximumJsonBytes, [0o444, 0o644, 0o664])
  );
  if (manifest.name !== '@playwright/test' || manifest.version !== '1.62.1') fail();
  let loaded;
  try {
    loaded = requireFromHere(file.path);
  } catch {
    fail();
  }
  if (!loaded?.chromium || typeof loaded.chromium.launch !== 'function') fail();
  return loaded.chromium;
};

const requireBrowserCookies = (cookies, issuerHost) => {
  if (!Array.isArray(cookies) || cookies.length > 128) fail();
  return Object.freeze(
    cookies.map((cookie) => {
      if (!isRecord(cookie) || !hasExactKeys(cookie, cookieKeys)) fail();
      return requireCookie(cookie, issuerHost);
    })
  );
};

const observeCondition = async (page, request) => {
  const hasAsterMarker = await page.evaluate(
    () => Object.hasOwn(globalThis, 'asterSsr') && !Object.hasOwn(globalThis, 'logtoSsr')
  );
  if (hasAsterMarker !== true) fail();
  if (request.binding.captureKind === 'second-sign-in') {
    const current = new URL(page.url());
    if (current.pathname !== '/sign-in') fail();
    const identifier = page.locator('form input[name="identifier"]:visible');
    const password = page.locator('form input[name="password"]:visible');
    const identifierCount = await identifier.count();
    const passwordCount = await password.count();
    if (
      identifierCount > 1 ||
      passwordCount > 1 ||
      identifierCount + passwordCount < 1
    ) {
      fail();
    }
    if (identifierCount === 1 && (await identifier.inputValue()) !== '') fail();
    for (let index = 0; index < passwordCount; index += 1) {
      if ((await password.nth(index).inputValue()) !== '') fail();
    }
    return;
  }
  if ((await page.locator('form input:visible').count()) !== 0) fail();
  const text = (await page.locator('body').innerText()).slice(0, 8192);
  const expected = errorConditions[request.binding.conditionId];
  if (!(expected instanceof RegExp) || !expected.test(text)) fail();
};

const captureRequest = async ({ browser, directory, request, issuer }) => {
  let context;
  let imageFile;
  try {
    context = await browser.newContext({
      acceptDownloads: false,
      colorScheme: 'light',
      deviceScaleFactor: 1,
      locale: 'en-US',
      reducedMotion: 'reduce',
      serviceWorkers: 'block',
      viewport: { width: 1280, height: 960 },
    });
    context.setDefaultNavigationTimeout(remainingTimeout(request.binding.deadline));
    context.setDefaultTimeout(remainingTimeout(request.binding.deadline));
    await context.addCookies(request.cookies);
    let networkViolation = false;
    await context.route('**/*', async (route) => {
      try {
        const target = new URL(route.request().url());
        if (target.origin !== issuer.origin) {
          networkViolation = true;
          await route.abort('blockedbyclient');
          return;
        }
        await route.continue();
      } catch {
        networkViolation = true;
        await route.abort('blockedbyclient');
      }
    });
    const page = await context.newPage();
    await page.goto(request.url.href, {
      waitUntil: 'networkidle',
      timeout: remainingTimeout(request.binding.deadline),
    });
    if (networkViolation || new URL(page.url()).origin !== issuer.origin) fail();
    await observeCondition(page, request);
    const image = await page.screenshot({
      animations: 'disabled',
      caret: 'hide',
      fullPage: true,
      scale: 'css',
      type: 'png',
    });
    if (!(image instanceof Buffer) || image.byteLength < 1 || image.byteLength > maximumImageBytes) {
      fail();
    }
    const browserCookies = requireBrowserCookies(
      await context.cookies(),
      issuer.hostname
    );
    imageFile = writePrivateAtomic(directory, imageName, image);
    const response = Object.freeze({
      ...request.binding,
      result: 'CAPTURED',
      renderedUrl: page.url(),
      imageFile: imageName,
      imageSha256: crypto.createHash('sha256').update(image).digest('hex'),
      imageBytes: image.byteLength,
      observedCondition: true,
      cookies: browserCookies,
    });
    if (!hasExactKeys(response, responseKeys)) fail();
    writePrivateAtomic(directory, captureResponseName, Buffer.from(JSON.stringify(response)));
  } catch (error) {
    if (imageFile) {
      try {
        fs.unlinkSync(imageFile);
      } catch {
        // The fixed process failure remains authoritative.
      }
    }
    throw error;
  } finally {
    if (context) {
      try {
        await context.close();
      } catch {
        fail();
      }
    }
  }
};

const requestDirectories = (root) => {
  const result = [];
  const directoryPatterns = [planIdPattern, testIdPattern, placeholderPattern];
  const captureFiles = new Set([
    captureRequestName,
    captureResponseName,
    imageName,
    'review-request.json',
    'manual-review.json',
  ]);
  const walk = (directory, depth) => {
    requireOwnedDirectory(directory);
    let entries;
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true });
    } catch {
      fail();
    }
    for (const entry of entries) {
      const child = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) fail();
      if (entry.isDirectory()) {
        if (depth >= directoryPatterns.length || !directoryPatterns[depth].test(entry.name)) fail();
        walk(child, depth + 1);
      } else if (entry.isFile()) {
        if (depth === 2 && entry.name === `${moduleAuditName}.tmp`) {
          // The handoff publishes the audit atomically.
        } else if (depth === 2 && entry.name === moduleAuditName) {
          requireOwnedFile(child, maximumAuditBytes, [0o600]);
        } else if (
          depth === 3 &&
          (captureFiles.has(entry.name) ||
            [...captureFiles].some((name) => entry.name === `${name}.tmp`))
        ) {
          if (entry.name === captureRequestName) result.push(directory);
        } else {
          fail();
        }
      } else {
        fail();
      }
    }
  };
  walk(root, 0);
  return result.sort();
};

const parseArguments = (arguments_) => {
  const expected = [
    '--issuer-origin',
    '--root-ca-file',
    '--certificate-file',
    '--playwright-module',
    '--deadline',
  ];
  if (arguments_.length !== expected.length * 2) fail();
  const values = {};
  for (let index = 0; index < expected.length; index += 1) {
    if (arguments_[index * 2] !== expected[index]) fail();
    values[expected[index]] = arguments_[index * 2 + 1];
  }
  return Object.freeze(values);
};

export const runCaptureHelper = async ({
  ipcRoot,
  issuerOrigin,
  rootCaFile,
  certificateFile,
  playwrightModule,
  deadline,
}) => {
  const root = requireOwnedDirectory(ipcRoot);
  const issuer = requireHttpsOrigin(issuerOrigin);
  const helperDeadline = requireSafeInteger(deadline);
  if (helperDeadline <= Date.now() || helperDeadline - Date.now() > 14_400_000) fail();
  const chromium = requirePlaywright(playwrightModule);
  const spki = await verifyCertificate({
    issuer,
    rootCaFile,
    certificateFile,
    deadline: helperDeadline,
  });
  let stopping = false;
  const stop = () => {
    stopping = true;
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let browser;
  try {
    browser = await chromium.launch({
      args: [
        '--disable-background-networking',
        '--disable-breakpad',
        '--disable-component-update',
        '--disable-default-apps',
        '--disable-sync',
        `--host-resolver-rules=MAP ${issuer.hostname} 127.0.0.1,EXCLUDE localhost`,
        `--ignore-certificate-errors-spki-list=${spki}`,
        '--metrics-recording-only',
        '--no-first-run',
      ],
      env: Object.fromEntries(
        ['HOME', 'LANG', 'PATH', 'PLAYWRIGHT_BROWSERS_PATH', 'TMPDIR', 'XDG_RUNTIME_DIR'].flatMap(
          (key) => (process.env[key] === undefined ? [] : [[key, process.env[key]]])
        )
      ),
      headless: true,
    });
    process.stderr.write(`phase 1 screenshot capture ready: ${root}\n`);
    const processed = new Set();
    while (!stopping) {
      if (Date.now() >= helperDeadline) fail();
      for (const directory of requestDirectories(root)) {
        if (processed.has(directory) || fs.existsSync(path.join(directory, captureResponseName))) {
          continue;
        }
        const request = requireRequest(
          path.join(directory, captureRequestName),
          directory,
          issuer
        );
        await captureRequest({ browser, directory, request, issuer });
        processed.add(directory);
      }
      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
    }
  } finally {
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    if (browser) {
      try {
        await browser.close();
      } catch {
        fail();
      }
    }
  }
};

const main = async () => {
  const options = parseArguments(process.argv.slice(2));
  const ipcRoot = process.env.ASTER_PHASE1_SCREENSHOT_IPC_ROOT;
  if (typeof ipcRoot !== 'string') fail();
  await runCaptureHelper({
    ipcRoot,
    issuerOrigin: options['--issuer-origin'],
    rootCaFile: options['--root-ca-file'],
    certificateFile: options['--certificate-file'],
    playwrightModule: options['--playwright-module'],
    deadline: Number(options['--deadline']),
  });
};

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(new URL(import.meta.url).pathname)) {
  main().catch(() => {
    process.stderr.write('phase 1 screenshot capture failed\n');
    process.exitCode = 1;
  });
}
