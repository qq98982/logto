import { randomUUID } from 'node:crypto';
import {
  readFile as readFileFromDisk,
  rename as renameFileOnDisk,
  unlink as unlinkFileOnDisk,
  writeFile as writeFileToDisk,
} from 'node:fs/promises';

import { z } from 'zod';

import { capabilityManifestGuard, targetConfigGuard } from '../model.js';
import type { CapabilityManifest, TargetConfig } from '../model.js';

import { collectCapabilityManifest, mergeCapabilities } from './collect.js';
import { resolveCompatibilityPaths } from './paths.js';
import type { CompatibilityPaths } from './paths.js';

type TargetLabel = TargetConfig['label'];
type InventoryMode = 'check' | 'write';

export type InventoryArguments = {
  target: TargetLabel;
  mode: InventoryMode;
};

type ManifestWriteOptions = {
  encoding: 'utf8';
  flag: 'wx';
};

export type InventoryCliDependencies = {
  resolvePaths: (options: { env: NodeJS.ProcessEnv }) => Promise<CompatibilityPaths>;
  collectManifest: typeof collectCapabilityManifest;
  readManifestFile: (filePath: string) => Promise<string>;
  writeManifestFile: (
    filePath: string,
    contents: string,
    options: ManifestWriteOptions
  ) => Promise<void>;
  renameFile: (oldPath: string, newPath: string) => Promise<void>;
  unlinkFile: (filePath: string) => Promise<void>;
  randomId: () => string;
  writeOutput: (message: string) => Promise<void>;
  writeError: (message: string) => Promise<void>;
};

const usage = 'Usage: compatibility:inventory --target <oracle|candidate> <--check|--write>';

function argumentError(message: string): never {
  throw new Error(`${message}\n${usage}`);
}

export const parseInventoryArguments = (arguments_: readonly string[]): InventoryArguments => {
  if (arguments_.length !== 3) {
    argumentError('Expected exactly one target and one mode');
  }

  const targetFlags = arguments_.filter((argument) => argument === '--target');
  const targetIndex = arguments_.indexOf('--target');
  const target = arguments_[targetIndex + 1];
  const modes = arguments_.filter(
    (argument): argument is '--check' | '--write' =>
      argument === '--check' || argument === '--write'
  );

  if (targetFlags.length !== 1 || (target !== 'oracle' && target !== 'candidate')) {
    argumentError('--target must be specified exactly once as oracle or candidate');
  }

  if (modes.length !== 1) {
    argumentError('Specify exactly one of --check or --write');
  }

  return { target, mode: modes[0] === '--check' ? 'check' : 'write' };
};

const parseHttpUrl = (variableName: string, value: string | undefined) => {
  if (!value) {
    throw new Error(`${variableName} is required and must be an HTTP(S) URL`);
  }

  try {
    const url = new URL(value);

    if (
      (url.protocol !== 'http:' && url.protocol !== 'https:') ||
      url.username.length > 0 ||
      url.password.length > 0
    ) {
      throw new TypeError('Unsupported URL');
    }

    if (url.pathname !== '/' || url.href.includes('?') || url.href.includes('#')) {
      throw new RangeError(`${variableName} must not contain a path, query, or fragment`);
    }

    return url.href;
  } catch (error: unknown) {
    if (error instanceof RangeError) {
      throw error;
    }

    throw new Error(`${variableName} must be an HTTP(S) URL`);
  }
};

export const resolveTargetConfig = (
  label: TargetLabel,
  env: NodeJS.ProcessEnv = process.env
): TargetConfig => {
  const variablePrefix = label === 'oracle' ? 'ASTER_ORACLE' : 'ASTER_CANDIDATE';
  const coreVariable = `${variablePrefix}_URL`;
  const adminVariable = `${variablePrefix}_ADMIN_URL`;

  return targetConfigGuard.parse({
    label,
    coreUrl: parseHttpUrl(coreVariable, env[coreVariable]),
    adminUrl: parseHttpUrl(adminVariable, env[adminVariable]),
  });
};

const normalizeManifest = (document: unknown): CapabilityManifest => {
  const parsed = capabilityManifestGuard.parse(document);

  return {
    ...parsed,
    capabilities: mergeCapabilities(parsed.capabilities),
  };
};

const getErrorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error);
const hasErrorCode = (error: unknown, code: string) =>
  typeof error === 'object' && error !== null && 'code' in error && error.code === code;

const readManifest = async (
  manifestPath: string,
  readManifestFile: InventoryCliDependencies['readManifestFile']
) => {
  const source = await (async () => {
    try {
      return await readManifestFile(manifestPath);
    } catch (error: unknown) {
      throw new Error(`Unable to read committed capability manifest: ${getErrorMessage(error)}`);
    }
  })();
  const document = (() => {
    try {
      return z.unknown().parse(JSON.parse(source));
    } catch (error: unknown) {
      throw new Error(`Invalid committed capability manifest JSON: ${getErrorMessage(error)}`);
    }
  })();

  try {
    return normalizeManifest(document);
  } catch (error: unknown) {
    throw new Error(`Invalid committed capability manifest: ${getErrorMessage(error)}`);
  }
};

const writeManifestAtomically = async (
  manifestPath: string,
  manifest: CapabilityManifest,
  dependencies: InventoryCliDependencies
): Promise<void> => {
  const temporaryPath = `${manifestPath}.${process.pid}.${dependencies.randomId()}.tmp`;

  try {
    await dependencies.writeManifestFile(
      temporaryPath,
      `${JSON.stringify(manifest, undefined, 2)}\n`,
      {
        encoding: 'utf8',
        flag: 'wx',
      }
    );
    await dependencies.renameFile(temporaryPath, manifestPath);
  } catch (error: unknown) {
    try {
      await dependencies.unlinkFile(temporaryPath);
    } catch (unlinkError: unknown) {
      if (!hasErrorCode(unlinkError, 'ENOENT')) {
        throw unlinkError;
      }
    }
    throw error;
  }
};

const getCapabilityIdDiff = (
  committedManifest: CapabilityManifest,
  collectedManifest: CapabilityManifest
) => {
  const committedIds = new Set(committedManifest.capabilities.map(({ id }) => id));
  const collectedIds = new Set(collectedManifest.capabilities.map(({ id }) => id));
  const added = [...collectedIds].filter((id) => !committedIds.has(id)).toSorted();
  const removed = [...committedIds].filter((id) => !collectedIds.has(id)).toSorted();

  return { added, removed };
};

const defaultDependencies: InventoryCliDependencies = {
  resolvePaths: resolveCompatibilityPaths,
  collectManifest: collectCapabilityManifest,
  readManifestFile: async (filePath) => readFileFromDisk(filePath, 'utf8'),
  writeManifestFile: async (filePath, contents, options) =>
    writeFileToDisk(filePath, contents, options),
  renameFile: async (oldPath, newPath) => renameFileOnDisk(oldPath, newPath),
  unlinkFile: async (filePath) => unlinkFileOnDisk(filePath),
  randomId: randomUUID,
  writeOutput: async (message) => {
    console.log(message);
  },
  writeError: async (message) => {
    console.error(message);
  },
};

export const runInventoryCli = async (
  arguments_: readonly string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env,
  injectedDependencies: Partial<InventoryCliDependencies> = {}
): Promise<number> => {
  const { target, mode } = parseInventoryArguments(arguments_);

  if (mode === 'write' && (target !== 'oracle' || env.ASTER_ALLOW_MANIFEST_WRITE !== '1')) {
    throw new Error('--write requires --target oracle and ASTER_ALLOW_MANIFEST_WRITE=1');
  }

  const dependencies = { ...defaultDependencies, ...injectedDependencies };
  const paths = await dependencies.resolvePaths({ env });
  const collectedManifest = normalizeManifest(
    await dependencies.collectManifest(resolveTargetConfig(target, env), {
      testRoot: paths.integrationTestRoot,
      manualCapabilitiesPath: paths.manualCapabilitiesPath,
    })
  );

  if (mode === 'write') {
    await writeManifestAtomically(paths.manifestPath, collectedManifest, dependencies);
    await dependencies.writeOutput(`Wrote ${collectedManifest.capabilities.length} capabilities.`);
    return 0;
  }

  const committedManifest = await readManifest(paths.manifestPath, dependencies.readManifestFile);

  if (JSON.stringify(committedManifest) !== JSON.stringify(collectedManifest)) {
    const { added, removed } = getCapabilityIdDiff(committedManifest, collectedManifest);

    await dependencies.writeError(
      `Added capability IDs: ${added.length === 0 ? '(none)' : added.join(', ')}`
    );
    await dependencies.writeError(
      `Removed capability IDs: ${removed.length === 0 ? '(none)' : removed.join(', ')}`
    );
    return 1;
  }

  await dependencies.writeOutput(
    `Capability inventory matches (${collectedManifest.capabilities.length} capabilities).`
  );
  return 0;
};

const isMainModule =
  process.argv[1]?.replaceAll('\\', '/').endsWith('/compatibility/inventory/cli.js') === true;

if (isMainModule) {
  try {
    const exitCode = await runInventoryCli();

    if (exitCode !== 0) {
      // eslint-disable-next-line @silverhand/fp/no-mutation
      process.exitCode = exitCode;
    }
  } catch (error: unknown) {
    console.error(getErrorMessage(error));
    // eslint-disable-next-line @silverhand/fp/no-mutation
    process.exitCode = 1;
  }
}
