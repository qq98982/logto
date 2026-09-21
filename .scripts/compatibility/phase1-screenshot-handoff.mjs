import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const suiteCommit = '0dc0e3a21ec411e92c808e5b2e2258592c22b594';
const planName = 'oidcc-basic-certification-test-plan';
const maximumJsonBytes = 131_072;
const maximumAuditBytes = 16_777_216;
const moduleAuditName = 'module-audit.json';
const maximumImageBytes = 512_000;
const pollIntervalMs = 500;
const captureRequestName = 'capture-request.json';
const captureResponseName = 'capture-response.json';
const imageName = 'capture.png';
const reviewRequestName = 'review-request.json';
const manualReviewName = 'manual-review.json';
const planIdPattern = /^[A-Za-z0-9]{13}$/u;
const testIdPattern = /^[A-Za-z0-9]{15}$/u;
const placeholderPattern = /^[A-Za-z0-9]{10}$/u;
const captureIdPattern = /^[a-f0-9]{32}$/u;
const digestPattern = /^[a-f0-9]{64}$/u;
const modulePattern = /^[a-z0-9][a-z0-9-]{0,127}$/u;
const conditionPattern = /^[A-Za-z][A-Za-z0-9]{0,127}$/u;
const reviewerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const rootPattern = /^\/var\/tmp\/henry-build\/aster-phase1-screenshot-evidence\/run\.[A-Za-z0-9_-]{6,64}$/u;
const cookieNamePattern = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/u;
const domainPattern = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/u;
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

export const screenshotConditionMappings = Object.freeze({
  'oidcc-response-type-missing': Object.freeze({
    conditionId: 'ExpectResponseTypeMissingErrorPage',
    message: 'Upload a screenshot of the error page showing a missing response type error.',
    captureKind: 'ui-error',
  }),
  'oidcc-prompt-login': Object.freeze({
    conditionId: 'ExpectSecondLoginPage',
    message:
      'The server must ask the user to login for a second time; a screenshot of this must be uploaded.',
    captureKind: 'second-sign-in',
  }),
  'oidcc-max-age-1': Object.freeze({
    conditionId: 'ExpectSecondLoginPage',
    message:
      'The server must ask the user to login for a second time; a screenshot of this must be uploaded.',
    captureKind: 'second-sign-in',
  }),
  'oidcc-ensure-registered-redirect-uri': Object.freeze({
    conditionId: 'ExpectRedirectUriErrorPage',
    message: 'Show redirect URI error page',
    captureKind: 'ui-error',
  }),
  'oidcc-ensure-request-object-with-redirect-uri': Object.freeze({
    conditionId: 'ExpectRedirectUriErrorPage',
    message: 'Show redirect URI error page',
    captureKind: 'ui-error',
  }),
});

const fail = () => {
  throw new TypeError('Invalid phase 1 screenshot handoff');
};

const isRecord = (value) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const hasExactKeys = (value, expected) => {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key) => expected.includes(key));
};

const requireSafeInteger = (value) => {
  if (!Number.isSafeInteger(value) || value < 0) fail();
  return value;
};

const requirePrivateDirectory = (directory) => {
  let stat;
  try {
    stat = fs.lstatSync(directory);
  } catch {
    fail();
  }
  const uid = process.getuid?.();
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== 0o700 ||
    (uid !== undefined && stat.uid !== uid)
  ) {
    fail();
  }
};

const requirePrivateRoot = (root) => {
  if (
    typeof root !== 'string' ||
    !rootPattern.test(root) ||
    !path.isAbsolute(root) ||
    path.normalize(root) !== root
  ) {
    fail();
  }
  requirePrivateDirectory(root);
  let real;
  try {
    real = fs.realpathSync(root);
  } catch {
    fail();
  }
  if (real !== root) fail();
  return root;
};

const ensurePrivateDirectory = (directory) => {
  try {
    fs.mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') fail();
  }
  requirePrivateDirectory(directory);
};

const requirePrivateFile = (file, maximumBytes) => {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch {
    fail();
  }
  const uid = process.getuid?.();
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    (stat.mode & 0o777) !== 0o600 ||
    (uid !== undefined && stat.uid !== uid) ||
    stat.size < 1 ||
    stat.size > maximumBytes
  ) {
    fail();
  }
  return stat.size;
};

const readPrivateFile = (file, maximumBytes) => {
  const expectedBytes = requirePrivateFile(file, maximumBytes);
  let bytes;
  try {
    bytes = fs.readFileSync(file);
  } catch {
    fail();
  }
  if (bytes.byteLength !== expectedBytes) fail();
  return bytes;
};

const parsePrivateJson = (bytes) => {
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    fail();
  }
  if (!isRecord(value)) fail();
  return value;
};

const readPrivateJson = (file) => {
  const bytes = readPrivateFile(file, maximumJsonBytes);
  return Object.freeze({ bytes, value: parsePrivateJson(bytes) });
};

const writePrivateJsonAtomic = (directory, targetName, value, maximumBytes = maximumJsonBytes) => {
  const target = path.join(directory, targetName);
  const temporary = `${target}.tmp`;
  const bytes = Buffer.from(JSON.stringify(value));
  if (bytes.byteLength < 1 || bytes.byteLength > maximumBytes) fail();
  let descriptor;
  try {
    if (fs.existsSync(target) || fs.existsSync(temporary)) fail();
    descriptor = fs.openSync(temporary, 'wx', 0o600);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, target);
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Preserve the original handoff failure.
      }
    }
    try {
      fs.unlinkSync(temporary);
    } catch {
      // The temporary file may not have been created.
    }
    if (error instanceof TypeError && error.message === 'Invalid phase 1 screenshot handoff') {
      throw error;
    }
    fail();
  }
  requirePrivateFile(target, maximumBytes);
  return target;
};

const auditDirectory = (root, planInstanceId, testId, create) => {
  requirePrivateRoot(root);
  if (
    typeof planInstanceId !== 'string' || !planIdPattern.test(planInstanceId) ||
    typeof testId !== 'string' || !testIdPattern.test(testId)
  ) fail();
  const planDirectory = path.join(root, planInstanceId);
  const directory = path.join(planDirectory, testId);
  const check = create ? ensurePrivateDirectory : requirePrivateDirectory;
  check(planDirectory);
  check(directory);
  return directory;
};

export const writeModuleAudit = (root, audit) => {
  if (
    !isRecord(audit) ||
    !hasExactKeys(audit, [
      'schemaVersion', 'kind', 'suiteCommit', 'planName', 'planInstanceId', 'moduleName',
      'testId', 'info', 'infoSha256', 'conditionLogSha256', 'conditionCount', 'conditions',
      'captureId', 'review', 'accepted', 'failureCategory', 'exception',
    ]) ||
    audit.schemaVersion !== 1 || audit.kind !== 'phase1-conformance-module-audit' ||
    audit.suiteCommit !== suiteCommit || audit.planName !== planName
  ) fail();
  const directory = auditDirectory(root, audit.planInstanceId, audit.testId, true);
  const file = writePrivateJsonAtomic(directory, moduleAuditName, audit, maximumAuditBytes);
  return Object.freeze({
    testId: audit.testId,
    sha256: crypto.createHash('sha256').update(readPrivateFile(file, maximumAuditBytes)).digest('hex'),
  });
};

export const verifyModuleAudits = (root, planInstanceId, audits) => {
  if (!Array.isArray(audits) || audits.length !== 35) fail();
  const testIds = new Set();
  for (const audit of audits) {
    if (
      !isRecord(audit) || !hasExactKeys(audit, ['testId', 'sha256']) ||
      typeof audit.sha256 !== 'string' || !digestPattern.test(audit.sha256) ||
      testIds.has(audit.testId)
    ) fail();
    testIds.add(audit.testId);
    const directory = auditDirectory(root, planInstanceId, audit.testId, false);
    const bytes = readPrivateFile(path.join(directory, moduleAuditName), maximumAuditBytes);
    if (crypto.createHash('sha256').update(bytes).digest('hex') !== audit.sha256) fail();
  }
};

const requireCookie = (value) => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, cookieKeys) ||
    typeof value.name !== 'string' ||
    !cookieNamePattern.test(value.name) ||
    typeof value.value !== 'string' ||
    value.value.length > 4096 ||
    /[\u0000-\u001f\u007f]/u.test(value.value) ||
    typeof value.domain !== 'string' ||
    value.domain.length > 254 ||
    !domainPattern.test(value.domain.replace(/^\./u, '')) ||
    value.domain === '.' ||
    typeof value.path !== 'string' ||
    !value.path.startsWith('/') ||
    value.path.length > 2048 ||
    (value.expires !== -1 &&
      (typeof value.expires !== 'number' ||
        !Number.isFinite(value.expires) ||
        value.expires < 0)) ||
    typeof value.httpOnly !== 'boolean' ||
    typeof value.secure !== 'boolean' ||
    !['Strict', 'Lax', 'None'].includes(value.sameSite)
  ) {
    fail();
  }
  return Object.freeze({ ...value });
};

export const requireScreenshotCookies = (value) => {
  if (!Array.isArray(value) || value.length > 128) fail();
  const cookies = value.map(requireCookie);
  const identities = cookies.map(({ domain, path: cookiePath, name }) =>
    `${domain}\u0000${cookiePath}\u0000${name}`
  );
  if (new Set(identities).size !== identities.length) fail();
  return Object.freeze(cookies);
};

const requireCommonBinding = (value) => {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, commonBindingKeys) ||
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
  if (deadline <= createdAt) fail();
  return Object.freeze({ ...value });
};

const requireBindingMatch = (value, expected) => {
  const actual = requireCommonBinding(value);
  for (const key of commonBindingKeys) {
    if (actual[key] !== expected[key]) fail();
  }
  return actual;
};

const commonBindingFrom = (value) =>
  Object.freeze(Object.fromEntries(commonBindingKeys.map((key) => [key, value[key]])));

const waitForFile = async (file, deadline) => {
  for (;;) {
    if (fs.existsSync(file)) return;
    const remaining = deadline - Date.now();
    if (!Number.isFinite(remaining) || remaining <= 0) fail();
    await new Promise((resolve) => setTimeout(resolve, Math.min(pollIntervalMs, remaining)));
  }
};

const requireHttpsUrl = (value) => {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048) fail();
  let url;
  try {
    url = new URL(value);
  } catch {
    fail();
  }
  if (
    url.protocol !== 'https:' ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== ''
  ) {
    fail();
  }
  return url;
};

const requirePng = (bytes) => {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  if (bytes.byteLength < 45 || !bytes.subarray(0, 8).equals(signature)) fail();
  let offset = 8;
  let chunks = 0;
  let sawHeader = false;
  let sawEnd = false;
  while (offset < bytes.byteLength) {
    if (offset + 12 > bytes.byteLength) fail();
    const length = bytes.readUInt32BE(offset);
    const type = bytes.subarray(offset + 4, offset + 8).toString('ascii');
    const next = offset + 12 + length;
    if (next > bytes.byteLength) fail();
    if (chunks === 0) {
      if (type !== 'IHDR' || length !== 13) fail();
      const width = bytes.readUInt32BE(offset + 8);
      const height = bytes.readUInt32BE(offset + 12);
      if (width < 1 || height < 1 || width > 16_384 || height > 16_384) fail();
      sawHeader = true;
    }
    if (type === 'IEND') {
      if (length !== 0 || next !== bytes.byteLength) fail();
      sawEnd = true;
    }
    chunks += 1;
    offset = next;
  }
  if (!sawHeader || !sawEnd || chunks < 3) fail();
};

const removePrivateFile = (file) => {
  requirePrivateFile(file, maximumJsonBytes);
  try {
    fs.unlinkSync(file);
  } catch {
    fail();
  }
};

const removePrivateFileIfPresent = (file) => {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    fail();
  }
  const uid = process.getuid?.();
  if (stat.isDirectory() || (uid !== undefined && stat.uid !== uid)) fail();
  try {
    fs.unlinkSync(file);
  } catch {
    fail();
  }
};

export const createScreenshotBinding = (value) => requireCommonBinding(value);

export const beginScreenshotHandoff = async ({
  root,
  binding,
  url,
  issuerOrigin,
  cookies,
}) => {
  const privateRoot = requirePrivateRoot(root);
  const common = requireCommonBinding(binding);
  const captureUrl = requireHttpsUrl(url);
  const issuer = requireHttpsUrl(issuerOrigin);
  if (issuer.pathname !== '/' || issuer.search !== '' || captureUrl.origin !== issuer.origin) fail();
  const privateCookies = requireScreenshotCookies(cookies);
  const planDirectory = path.join(privateRoot, common.planInstanceId);
  const testDirectory = path.join(planDirectory, common.testId);
  const captureDirectory = path.join(testDirectory, common.placeholderId);
  ensurePrivateDirectory(planDirectory);
  ensurePrivateDirectory(testDirectory);
  if (fs.existsSync(captureDirectory)) fail();
  ensurePrivateDirectory(captureDirectory);
  const request = Object.freeze({
    ...common,
    url: captureUrl.href,
    issuerOrigin: issuer.origin,
    cookies: privateCookies,
  });
  const requestFile = writePrivateJsonAtomic(captureDirectory, captureRequestName, request);
  const responseFile = path.join(captureDirectory, captureResponseName);
  const imageFile = path.join(captureDirectory, imageName);
  try {
    await waitForFile(responseFile, common.deadline);
    const { value: response } = readPrivateJson(responseFile);
    if (
      !hasExactKeys(response, [
        ...commonBindingKeys,
        'result',
        'renderedUrl',
        'imageFile',
        'imageSha256',
        'imageBytes',
        'observedCondition',
        'cookies',
      ]) ||
      response.result !== 'CAPTURED' ||
      response.imageFile !== imageName ||
      typeof response.imageSha256 !== 'string' ||
      !digestPattern.test(response.imageSha256) ||
      !Number.isSafeInteger(response.imageBytes) ||
      response.imageBytes < 1 ||
      response.imageBytes > maximumImageBytes ||
      response.observedCondition !== true
    ) {
      fail();
    }
    requireBindingMatch(commonBindingFrom(response), common);
    const renderedUrl = requireHttpsUrl(response.renderedUrl);
    if (renderedUrl.origin !== issuer.origin) fail();
    const responseCookies = requireScreenshotCookies(response.cookies);
    const imageBytes = readPrivateFile(imageFile, maximumImageBytes);
    if (imageBytes.byteLength !== response.imageBytes) fail();
    requirePng(imageBytes);
    const imageSha256 = crypto.createHash('sha256').update(imageBytes).digest('hex');
    if (imageSha256 !== response.imageSha256) fail();
    removePrivateFile(requestFile);
    return Object.freeze({
      binding: common,
      captureDirectory,
      responseFile,
      imageBytes,
      imageSha256,
      imageBytesLength: imageBytes.byteLength,
      renderedUrl: renderedUrl.href,
      cookies: responseCookies,
    });
  } catch (error) {
    removePrivateFileIfPresent(requestFile);
    removePrivateFileIfPresent(responseFile);
    throw error;
  }
};

export const consumeScreenshotResponse = (handoff) => {
  if (!isRecord(handoff) || typeof handoff.responseFile !== 'string') fail();
  removePrivateFile(handoff.responseFile);
};

export const awaitScreenshotReview = async (handoff) => {
  if (
    !isRecord(handoff) ||
    !isRecord(handoff.binding) ||
    typeof handoff.captureDirectory !== 'string' ||
    typeof handoff.imageSha256 !== 'string' ||
    !digestPattern.test(handoff.imageSha256) ||
    !Number.isSafeInteger(handoff.imageBytesLength) ||
    handoff.imageBytesLength < 1 ||
    handoff.imageBytesLength > maximumImageBytes
  ) {
    fail();
  }
  const common = requireCommonBinding(handoff.binding);
  writePrivateJsonAtomic(handoff.captureDirectory, reviewRequestName, {
    ...common,
    imageFile: imageName,
    imageSha256: handoff.imageSha256,
    imageBytes: handoff.imageBytesLength,
  });
  const reviewFile = path.join(handoff.captureDirectory, manualReviewName);
  await waitForFile(reviewFile, common.deadline);
  const { bytes, value: review } = readPrivateJson(reviewFile);
  if (
    !hasExactKeys(review, [
      ...commonBindingKeys,
      'imageSha256',
      'reviewer',
      'review',
      'reviewedAt',
    ]) ||
    review.imageSha256 !== handoff.imageSha256 ||
    typeof review.reviewer !== 'string' ||
    !reviewerPattern.test(review.reviewer) ||
    review.review !== 'APPROVE' ||
    !Number.isSafeInteger(review.reviewedAt) ||
    review.reviewedAt < common.createdAt ||
    review.reviewedAt > common.deadline
  ) {
    fail();
  }
  requireBindingMatch(commonBindingFrom(review), common);
  return Object.freeze({
    reviewer: review.reviewer,
    reviewRecordSha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  });
};
