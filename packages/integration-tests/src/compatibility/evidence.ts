/* eslint-disable max-lines -- Secret policy and atomic writer helpers are reviewed as one boundary. */
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises';
import path from 'node:path';

import { decodeProtectedHeader } from 'jose';

import {
  jsonValueGuard,
  runEvidenceGuard,
  scenarioEvidenceGuard,
  type RunEvidence,
  type ScenarioEvidence,
} from './model.js';

const destinationEnvironmentVariable = 'ASTER_EVIDENCE_DIR';
const defaultBuildRoot = '/var/tmp/henry-build';
const defaultEvidenceDirectory = '/var/tmp/henry-build/aster-compatibility/direct';
// Keep this explicit: it documents the exact writer-boundary filename alphabet.
// eslint-disable-next-line unicorn/better-regex
const safeScenarioId = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const safeMetadataKeys = new Set([
  'passwordalgorithm',
  'haspassword',
  'tokenlifetimeseconds',
  'tokentype',
]);
const reviewedPublicProtocolMetadataKeys = new Set([
  'authorizationendpoint',
  'authorizationresponseissparametersupported',
  'deviceauthorizationendpoint',
  'idtokensigningalgvaluessupported',
  'pushedauthorizationrequestendpoint',
  'tokenendpoint',
  'tokenendpointauthmethodssupported',
  'tokenendpointauthsigningalgvaluessupported',
]);
const forbiddenWrapperKeyFragments = [
  'token',
  'authorization',
  'xfunctionskey',
  'jwt',
  'authheader',
  'authenticationheader',
];
const forbiddenKeyFragments = [
  'secret',
  'password',
  'apikey',
  'privatekey',
  'credential',
  'cookie',
];
const bearerPrefixPattern = /\bbearer\s+/giu;
const createCompactJoseRunMatcher = () =>
  /(?<![A-Za-z0-9_-])(?:[A-Za-z0-9_-]*\.){2,}[A-Za-z0-9_-]*(?![A-Za-z0-9_-])/gu;
const privateKeyPattern = /-----BEGIN (?:[A-Z0-9-]+ )*PRIVATE KEY(?: [A-Z0-9-]+)*-----/iu;
const cookieHeaderPattern = /\b(?:set-cookie|cookie)\s*:/iu;
const setCookieValuePattern =
  /^[^;\s=]+=[^;\r\n]*;[^\r\n]*(?:secure|httponly|samesite\s*=|domain\s*=|path\s*=|expires\s*=|max-age\s*=)/iu;

type OpenedEvidenceFile = {
  writeFile: (data: string, encoding: 'utf8') => Promise<void>;
  close: () => Promise<void>;
};

type EvidencePathState = {
  mode: number;
  uid: number;
  isDirectory: () => boolean;
  isFile: () => boolean;
  isSymbolicLink: () => boolean;
};

type EvidenceFileSystemOverrides = {
  chmodPath?: (filePath: string, mode: number) => Promise<void>;
  getCurrentUserId?: () => number | undefined;
  getPathState?: (filePath: string) => Promise<EvidencePathState>;
  getRealPath?: (filePath: string) => Promise<string>;
  makeDirectory?: (
    directoryPath: string,
    options: { recursive: boolean; mode: number }
  ) => Promise<string | undefined | void>;
  openFile?: (filePath: string, flags: 'wx', mode: number) => Promise<OpenedEvidenceFile>;
  renameFile?: (oldPath: string, newPath: string) => Promise<void>;
  unlinkFile?: (filePath: string) => Promise<void>;
};

export type EvidenceWriterOptions = {
  /** A custom ASTER_EVIDENCE_DIR parent must already be lifecycle-owned, trusted, and private. */
  env?: Readonly<Record<string, string | undefined>>;
  fileSystem?: EvidenceFileSystemOverrides;
};

const normalizeEvidenceKey = (key: string) => key.replaceAll(/[_\s-]/gu, '').toLowerCase();

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isForbiddenKey = (key: string) => {
  const normalizedKey = normalizeEvidenceKey(key);

  if (
    safeMetadataKeys.has(normalizedKey) ||
    reviewedPublicProtocolMetadataKeys.has(normalizedKey)
  ) {
    return false;
  }

  return (
    forbiddenWrapperKeyFragments.some((fragment) => normalizedKey.includes(fragment)) ||
    normalizedKey.startsWith('script') ||
    normalizedKey.endsWith('script') ||
    normalizedKey.includes('environmentvariables') ||
    forbiddenKeyFragments.some((fragment) => normalizedKey.includes(fragment))
  );
};

const containsBearerCredential = (value: string) =>
  [...value.matchAll(bearerPrefixPattern)].some((match) => {
    const remainder = value.slice(match.index + match[0].length);

    return remainder.length > 0;
  });

const containsCompactJoseCredential = (value: string) => {
  for (const run of value.matchAll(createCompactJoseRunMatcher())) {
    const segments = run[0].split('.');
    const containsMarkedHeader = segments.slice(0, -2).some((_segment, index) => {
      const [headerSegment = '', payloadSegment = '', signatureSegment = ''] = segments.slice(
        index,
        index + 3
      );

      if (headerSegment.length === 0 || signatureSegment.length % 4 === 1) {
        return false;
      }

      try {
        const protectedHeader = decodeProtectedHeader(
          [headerSegment, payloadSegment, signatureSegment].join('.')
        );

        if (
          isRecord(protectedHeader) &&
          (typeof protectedHeader.alg === 'string' || typeof protectedHeader.enc === 'string')
        ) {
          return true;
        }
      } catch {
        // Invalid protected headers are ordinary dotted text; keep scanning later windows.
      }

      return false;
    });

    if (containsMarkedHeader) {
      return true;
    }
  }

  return false;
};

const containsCredentialMaterial = (value: string) =>
  containsBearerCredential(value) ||
  containsCompactJoseCredential(value) ||
  privateKeyPattern.test(value) ||
  cookieHeaderPattern.test(value) ||
  setCookieValuePattern.test(value);

const inspectEvidenceValue = (value: unknown): void => {
  if (typeof value === 'string') {
    if (containsCredentialMaterial(value)) {
      throw new Error('Evidence contains forbidden credential material');
    }

    return;
  }

  if (Array.isArray(value)) {
    for (const element of value) {
      inspectEvidenceValue(element);
    }

    return;
  }

  if (isRecord(value)) {
    for (const key of Object.keys(value)) {
      if (containsCredentialMaterial(key)) {
        throw new Error('Evidence contains forbidden credential material');
      }

      if (isForbiddenKey(key)) {
        throw new Error(`Evidence contains forbidden key: ${key}`);
      }

      if (Object.hasOwn(value, key)) {
        inspectEvidenceValue(value[key]);
      }
    }
  }
};

export const assertEvidenceIsSanitized = (value: unknown): void => {
  if (!jsonValueGuard.safeParse(value).success) {
    throw new Error('Evidence must be faithful JSON');
  }

  inspectEvidenceValue(value);
};

const requireSafeScenarioId = (scenarioId: string) => {
  if (
    !safeScenarioId.test(scenarioId) ||
    scenarioId === '.' ||
    scenarioId === '..' ||
    scenarioId.toLowerCase() === 'run'
  ) {
    throw new Error('Scenario ID is not a safe evidence filename');
  }
};

const getEvidenceDirectory = (options: EvidenceWriterOptions) => {
  const configuredDirectory = (options.env ?? process.env)[destinationEnvironmentVariable];
  const evidenceDirectory = configuredDirectory ?? defaultEvidenceDirectory;

  if (!path.isAbsolute(evidenceDirectory)) {
    throw new Error('Evidence directory must be an absolute private disk path');
  }

  const normalizedDirectory = path.resolve(evidenceDirectory);
  const sharedMemoryRoot = `${path.sep}dev${path.sep}shm`;

  if (
    normalizedDirectory === sharedMemoryRoot ||
    normalizedDirectory.startsWith(`${sharedMemoryRoot}${path.sep}`)
  ) {
    throw new Error('Evidence directory must be an absolute private disk path');
  }

  const relativeToDefaultBuildRoot = path.relative(defaultBuildRoot, normalizedDirectory);
  const usesSecureBuildPath =
    relativeToDefaultBuildRoot === '' ||
    (relativeToDefaultBuildRoot !== '..' &&
      !relativeToDefaultBuildRoot.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relativeToDefaultBuildRoot));

  return { evidenceDirectory: normalizedDirectory, usesSecureBuildPath };
};

const getDirectoryState = async (
  evidenceDirectory: string,
  overrides: EvidenceFileSystemOverrides
) => {
  const getPathState = overrides.getPathState ?? lstat;

  try {
    return await getPathState(evidenceDirectory);
  } catch {
    throw new Error('Evidence directory must be a real directory');
  }
};

const getRealDirectoryPath = async (
  evidenceDirectory: string,
  overrides: EvidenceFileSystemOverrides
) => {
  const getRealPath = overrides.getRealPath ?? realpath;

  try {
    return await getRealPath(evidenceDirectory);
  } catch {
    throw new Error('Evidence directory must be a real directory');
  }
};

const verifyRealDirectory = async (
  evidenceDirectory: string,
  overrides: EvidenceFileSystemOverrides
) => {
  const directoryState = await getDirectoryState(evidenceDirectory, overrides);

  if (!directoryState.isDirectory() || directoryState.isSymbolicLink()) {
    throw new Error('Evidence directory must be a real directory');
  }

  const resolvedDirectory = await getRealDirectoryPath(evidenceDirectory, overrides);

  if (resolvedDirectory !== evidenceDirectory) {
    throw new Error('Evidence directory must be a real directory');
  }
};

const prepareEvidenceDirectory = async (
  evidenceDirectory: string,
  overrides: EvidenceFileSystemOverrides
) => {
  const makeDirectory = overrides.makeDirectory ?? mkdir;
  const chmodPath = overrides.chmodPath ?? chmod;

  try {
    await makeDirectory(evidenceDirectory, { recursive: true, mode: 0o700 });
  } catch {
    throw new Error('Evidence directory must be a real directory');
  }

  await verifyRealDirectory(evidenceDirectory, overrides);
  await chmodPath(evidenceDirectory, 0o700);
};

const isMissingPathError = (error: unknown) =>
  typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';

const getSecureBuildSegments = (evidenceDirectory: string) => {
  const relativeDirectory = path.relative(defaultBuildRoot, evidenceDirectory);
  const childSegments = relativeDirectory === '' ? [] : relativeDirectory.split(path.sep);

  return [
    defaultBuildRoot,
    ...childSegments.map((_segment, index) =>
      path.join(defaultBuildRoot, ...childSegments.slice(0, index + 1))
    ),
  ];
};

const prepareSecureDirectorySegment = async (
  directorySegment: string,
  currentUserId: number,
  overrides: EvidenceFileSystemOverrides
) => {
  const makeDirectory = overrides.makeDirectory ?? mkdir;
  const chmodPath = overrides.chmodPath ?? chmod;
  const getPathState = overrides.getPathState ?? lstat;

  try {
    await getPathState(directorySegment);
  } catch (error: unknown) {
    if (!isMissingPathError(error)) {
      throw error;
    }

    await makeDirectory(directorySegment, { recursive: false, mode: 0o700 });
  }

  await verifyRealDirectory(directorySegment, overrides);
  const stateBeforeHardening = await getDirectoryState(directorySegment, overrides);

  if (stateBeforeHardening.uid !== currentUserId) {
    throw new Error('Unsafe owner');
  }

  await chmodPath(directorySegment, 0o700);
  await verifyRealDirectory(directorySegment, overrides);
  const hardenedState = await getDirectoryState(directorySegment, overrides);

  if (hardenedState.uid !== currentUserId || hardenedState.mode % 0o100 !== 0) {
    throw new Error('Unsafe permissions');
  }
};

const prepareSecureBuildPath = async (
  evidenceDirectory: string,
  overrides: EvidenceFileSystemOverrides
) => {
  const getCurrentUserId = overrides.getCurrentUserId ?? (() => process.getuid?.());
  const currentUserId = getCurrentUserId();

  if (currentUserId === undefined) {
    throw new Error('Default evidence path must contain private owned directories');
  }

  try {
    /* eslint-disable no-await-in-loop -- Each segment must be created and verified before its child. */
    for (const directorySegment of getSecureBuildSegments(evidenceDirectory)) {
      await prepareSecureDirectorySegment(directorySegment, currentUserId, overrides);
    }
    /* eslint-enable no-await-in-loop */
  } catch {
    throw new Error('Default evidence path must contain private owned directories');
  }
};

const getFinalPath = (evidenceDirectory: string, filename: string) => {
  const finalPath = path.resolve(evidenceDirectory, filename);

  if (
    path.dirname(finalPath) !== evidenceDirectory ||
    finalPath !== path.join(evidenceDirectory, filename)
  ) {
    throw new Error('Evidence filename resolves outside its directory');
  }

  return finalPath;
};

const ignoreCleanupFailure = async (operation: () => Promise<unknown>) => {
  try {
    await operation();
  } catch {
    // Cleanup must not replace the original write or rename error.
  }
};

type EvidenceFileWrite = {
  evidenceDirectory: string;
  usesSecureBuildPath: boolean;
  filename: string;
  value: ScenarioEvidence | RunEvidence;
  overrides?: EvidenceFileSystemOverrides;
};

const writeEvidenceFile = async ({
  evidenceDirectory,
  usesSecureBuildPath,
  filename,
  value,
  overrides = {},
}: EvidenceFileWrite) => {
  await (usesSecureBuildPath
    ? prepareSecureBuildPath(evidenceDirectory, overrides)
    : prepareEvidenceDirectory(evidenceDirectory, overrides));

  await verifyRealDirectory(evidenceDirectory, overrides);

  const finalPath = getFinalPath(evidenceDirectory, filename);
  const temporaryPath = path.join(
    evidenceDirectory,
    `.${filename}.${randomBytes(18).toString('hex')}.tmp`
  );
  const openFile = overrides.openFile ?? open;
  const renameFile = overrides.renameFile ?? rename;
  const unlinkFile = overrides.unlinkFile ?? unlink;
  const temporaryFile = await openFile(temporaryPath, 'wx', 0o600);

  try {
    await temporaryFile.writeFile(`${JSON.stringify(value, undefined, 2)}\n`, 'utf8');
    await temporaryFile.close();
  } catch (error: unknown) {
    await ignoreCleanupFailure(async () => temporaryFile.close());
    await ignoreCleanupFailure(async () => unlinkFile(temporaryPath));
    throw error;
  }

  try {
    await verifyRealDirectory(evidenceDirectory, overrides);
    await renameFile(temporaryPath, finalPath);
  } catch (error: unknown) {
    await ignoreCleanupFailure(async () => unlinkFile(temporaryPath));

    throw error;
  }

  const getPathState = overrides.getPathState ?? lstat;
  const chmodPath = overrides.chmodPath ?? chmod;
  const finalState = await getPathState(finalPath);

  if (!finalState.isFile() || finalState.isSymbolicLink()) {
    throw new Error('Evidence destination is not a regular file');
  }

  await chmodPath(finalPath, 0o600);

  return finalPath;
};

export const writeScenarioEvidence = async (
  input: unknown,
  options: EvidenceWriterOptions = {}
): Promise<string> => {
  assertEvidenceIsSanitized(input);
  const result = scenarioEvidenceGuard.safeParse(input);

  if (!result.success) {
    throw new Error('Invalid scenario evidence');
  }

  const evidence = result.data;
  assertEvidenceIsSanitized(evidence);
  requireSafeScenarioId(evidence.scenarioId);
  const { evidenceDirectory, usesSecureBuildPath } = getEvidenceDirectory(options);

  return writeEvidenceFile({
    evidenceDirectory,
    usesSecureBuildPath,
    filename: `${evidence.scenarioId}.json`,
    value: evidence,
    overrides: options.fileSystem,
  });
};

export const writeRunEvidence = async (
  input: unknown,
  options: EvidenceWriterOptions = {}
): Promise<string> => {
  assertEvidenceIsSanitized(input);
  const result = runEvidenceGuard.safeParse(input);

  if (!result.success) {
    throw new Error('Invalid run evidence');
  }

  const evidence = result.data;
  assertEvidenceIsSanitized(evidence);
  const { evidenceDirectory, usesSecureBuildPath } = getEvidenceDirectory(options);

  return writeEvidenceFile({
    evidenceDirectory,
    usesSecureBuildPath,
    filename: 'run.json',
    value: evidence,
    overrides: options.fileSystem,
  });
};
/* eslint-enable max-lines */
