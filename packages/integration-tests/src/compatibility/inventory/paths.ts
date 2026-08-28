import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export type CompatibilityPaths = {
  repoRoot: string;
  manifestPath: string;
  manualCapabilitiesPath: string;
  integrationTestRoot: string;
};

type ResolveCompatibilityPathsOptions = {
  env?: NodeJS.ProcessEnv;
  moduleUrl?: string | URL;
};

const workspaceMarkerName = 'pnpm-workspace.yaml';

const isRegularFile = async (filePath: string) => {
  try {
    const fileStat = await stat(filePath);

    return fileStat.isFile();
  } catch (error: unknown) {
    if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT') {
      return false;
    }

    throw error;
  }
};

const resolveConfiguredRepoRoot = async (configuredRoot: string) => {
  if (!path.isAbsolute(configuredRoot)) {
    throw new Error('ASTER_REPO_ROOT must be an absolute path');
  }

  const repoRoot = await (async () => {
    try {
      return await realpath(configuredRoot);
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : String(error);

      throw new Error(`ASTER_REPO_ROOT could not be resolved: ${reason}`);
    }
  })();

  const markerPath = path.join(repoRoot, workspaceMarkerName);

  if (!(await isRegularFile(markerPath))) {
    throw new Error(
      `ASTER_REPO_ROOT must contain a regular ${workspaceMarkerName} file: ${repoRoot}`
    );
  }

  return repoRoot;
};

const discoverFromDirectory = async (directory: string, startingPath: string): Promise<string> => {
  if (await isRegularFile(path.join(directory, workspaceMarkerName))) {
    return realpath(directory);
  }

  const parent = path.dirname(directory);

  if (parent === directory) {
    throw new Error(
      `Unable to find a regular ${workspaceMarkerName} while walking upward from ${startingPath}`
    );
  }

  return discoverFromDirectory(parent, startingPath);
};

const discoverRepoRoot = async (moduleUrl: string | URL) => {
  const startingPath = fileURLToPath(moduleUrl);

  return discoverFromDirectory(path.dirname(startingPath), startingPath);
};

export const resolveCompatibilityPaths = async ({
  env = process.env,
  moduleUrl = import.meta.url,
}: ResolveCompatibilityPathsOptions = {}): Promise<CompatibilityPaths> => {
  const configuredRoot = env.ASTER_REPO_ROOT;
  const repoRoot =
    configuredRoot === undefined
      ? await discoverRepoRoot(moduleUrl)
      : await resolveConfiguredRepoRoot(configuredRoot);

  return {
    repoRoot,
    manifestPath: path.join(repoRoot, 'compatibility/baseline-manifest.json'),
    manualCapabilitiesPath: path.join(repoRoot, 'compatibility/manual-capabilities.json'),
    integrationTestRoot: path.join(repoRoot, 'packages/integration-tests/src/tests'),
  };
};
