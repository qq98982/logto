import { randomUUID } from 'node:crypto';
import { readFile, rename, unlink, writeFile } from 'node:fs/promises';

import { capabilityManifestGuard, targetConfigGuard } from '../model.js';
import type { CapabilityManifest, TargetConfig } from '../model.js';

import { collectCapabilityManifest, mergeCapabilities } from './collect.js';
import { resolveCompatibilityPaths } from './paths.js';

type TargetLabel = TargetConfig['label'];
type InventoryMode = 'check' | 'write';

export type InventoryArguments = {
  target: TargetLabel;
  mode: InventoryMode;
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

    return url.href;
  } catch {
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

const readManifest = async (manifestPath: string) => {
  const source = await readFile(manifestPath, 'utf8');

  return normalizeManifest(JSON.parse(source));
};

const writeManifestAtomically = async (
  manifestPath: string,
  manifest: CapabilityManifest
): Promise<void> => {
  const temporaryPath = `${manifestPath}.${process.pid}.${randomUUID()}.tmp`;

  try {
    await writeFile(temporaryPath, `${JSON.stringify(manifest, undefined, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
    });
    await rename(temporaryPath, manifestPath);
  } catch (error: unknown) {
    try {
      await unlink(temporaryPath);
    } catch (unlinkError: unknown) {
      if (
        !(unlinkError instanceof Error && 'code' in unlinkError && unlinkError.code === 'ENOENT')
      ) {
        throw unlinkError;
      }
    }
    throw error;
  }
};

const printCapabilityIdDiff = (
  committedManifest: CapabilityManifest,
  collectedManifest: CapabilityManifest
) => {
  const committedIds = new Set(committedManifest.capabilities.map(({ id }) => id));
  const collectedIds = new Set(collectedManifest.capabilities.map(({ id }) => id));
  const added = [...collectedIds].filter((id) => !committedIds.has(id)).toSorted();
  const removed = [...committedIds].filter((id) => !collectedIds.has(id)).toSorted();

  console.error(`Added capability IDs: ${added.length === 0 ? '(none)' : added.join(', ')}`);
  console.error(`Removed capability IDs: ${removed.length === 0 ? '(none)' : removed.join(', ')}`);
};

export const runInventoryCli = async (
  arguments_: readonly string[] = process.argv.slice(2),
  env: NodeJS.ProcessEnv = process.env
) => {
  const { target, mode } = parseInventoryArguments(arguments_);

  if (mode === 'write' && (target !== 'oracle' || env.ASTER_ALLOW_MANIFEST_WRITE !== '1')) {
    throw new Error('--write requires --target oracle and ASTER_ALLOW_MANIFEST_WRITE=1');
  }

  const paths = await resolveCompatibilityPaths({ env });
  const collectedManifest = normalizeManifest(
    await collectCapabilityManifest(resolveTargetConfig(target, env), {
      testRoot: paths.integrationTestRoot,
      manualCapabilitiesPath: paths.manualCapabilitiesPath,
    })
  );

  if (mode === 'write') {
    await writeManifestAtomically(paths.manifestPath, collectedManifest);
    console.log(`Wrote ${collectedManifest.capabilities.length} capabilities.`);
    return;
  }

  const committedManifest = await readManifest(paths.manifestPath);

  if (JSON.stringify(committedManifest) !== JSON.stringify(collectedManifest)) {
    printCapabilityIdDiff(committedManifest, collectedManifest);
    // eslint-disable-next-line @silverhand/fp/no-mutation
    process.exitCode = 1;
    return;
  }

  console.log(
    `Capability inventory matches (${collectedManifest.capabilities.length} capabilities).`
  );
};

const isMainModule =
  process.argv[1]?.replaceAll('\\', '/').endsWith('/compatibility/inventory/cli.js') === true;

if (isMainModule) {
  try {
    await runInventoryCli();
  } catch (error: unknown) {
    console.error(error instanceof Error ? error.message : String(error));
    // eslint-disable-next-line @silverhand/fp/no-mutation
    process.exitCode = 1;
  }
}
