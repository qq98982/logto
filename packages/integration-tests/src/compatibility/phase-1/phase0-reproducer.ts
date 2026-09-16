/* eslint-disable @typescript-eslint/no-unnecessary-condition -- Reproduction rechecks compile-time literal fields at the untrusted runtime boundary and runs the three fixed CLI stages in order. */
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import path from 'node:path';

import { runCompatibilityCli } from '../cli.js';

import {
  type AsterPhase1BuildRootEnvironment,
  withTrustedAsterPhase1BuildDirectory,
} from './build-root.js';
import { phase0HarnessCommit, snapshotClosedDataGraph } from './model.js';
import {
  type Phase0EvidenceFileName,
  type Phase0EvidenceReproducer,
  type Phase0EvidenceReproduction,
  type Phase0EvidenceReproductionRequest,
} from './profile-semantics.js';

type RuntimeEnvironment = AsterPhase1BuildRootEnvironment;
type Phase0Cli = typeof runCompatibilityCli;

export type Phase0ReproducerDependencies = Readonly<{
  runCli: Phase0Cli;
}>;

const diagnostic = 'Phase 0 reproduction failed.';
const expectedFiles = Object.freeze([
  'discovery.json',
  'negative-control.json',
  'password-code.json',
  'run.json',
] as const);
const digestPattern = /^sha256:[0-9a-f]{64}$/u;

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const requiredEnvironmentValue = (environment: RuntimeEnvironment, name: string): string => {
  const value = environment[name];

  return typeof value === 'string' && value.length > 0 ? value : fail();
};

const assertRequest = (
  request: Phase0EvidenceReproductionRequest
): Phase0EvidenceReproductionRequest => {
  const snapshot = snapshotClosedDataGraph<Phase0EvidenceReproductionRequest>(request) ?? fail();

  if (
    Object.keys(snapshot).toSorted().join(',') !== 'commit,files,lifecyclePath,repository' ||
    snapshot.commit !== phase0HarnessCommit ||
    snapshot.lifecyclePath !== '.scripts/compatibility/run.sh' ||
    snapshot.repository !== 'https://github.com/qq98982/logto.git' ||
    JSON.stringify(snapshot.files) !== JSON.stringify(expectedFiles)
  ) {
    return fail();
  }

  return snapshot;
};

const localHttpEndpointPattern = /^http:\/\/localhost:[0-9]{1,5}\/?$/iu;

const isLocalHttpRootEndpoint = (endpoint: URL): boolean =>
  endpoint.protocol === 'http:' &&
  endpoint.hostname === 'localhost' &&
  endpoint.username.length === 0 &&
  endpoint.password.length === 0 &&
  endpoint.pathname === '/' &&
  endpoint.search.length === 0 &&
  endpoint.hash.length === 0;

const hasValidExplicitPort = (endpoint: URL): boolean => {
  const port = Number(endpoint.port);

  return endpoint.port.length > 0 && Number.isSafeInteger(port) && port >= 1 && port <= 65_535;
};

const canonicalLocalHttpOrigin = (value: string): string => {
  if (!localHttpEndpointPattern.test(value)) {
    return fail();
  }

  try {
    const endpoint = new URL(value);

    if (!isLocalHttpRootEndpoint(endpoint) || !hasValidExplicitPort(endpoint)) {
      return fail();
    }

    return endpoint.origin;
  } catch {
    return fail();
  }
};

const loadDedicatedTargets = (environment: RuntimeEnvironment) => {
  const targets = Object.freeze({
    oracleUrl: canonicalLocalHttpOrigin(
      requiredEnvironmentValue(environment, 'ASTER_PHASE1_PHASE0_ORACLE_URL')
    ),
    oracleAdminUrl: canonicalLocalHttpOrigin(
      requiredEnvironmentValue(environment, 'ASTER_PHASE1_PHASE0_ORACLE_ADMIN_URL')
    ),
    candidateUrl: canonicalLocalHttpOrigin(
      requiredEnvironmentValue(environment, 'ASTER_PHASE1_PHASE0_CANDIDATE_URL')
    ),
    candidateAdminUrl: canonicalLocalHttpOrigin(
      requiredEnvironmentValue(environment, 'ASTER_PHASE1_PHASE0_CANDIDATE_ADMIN_URL')
    ),
  });
  const measuredTargets = [
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_ORACLE_URL'),
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_ORACLE_ADMIN_URL'),
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_ORACLE_FOREIGN_URL'),
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_ORACLE_FOREIGN_ADMIN_URL'),
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_CANDIDATE_URL'),
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_CANDIDATE_ADMIN_URL'),
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_CANDIDATE_FOREIGN_URL'),
    requiredEnvironmentValue(environment, 'ASTER_PHASE1_CANDIDATE_FOREIGN_ADMIN_URL'),
  ].map((target) => canonicalLocalHttpOrigin(target));
  const allTargets = [...Object.values(targets), ...measuredTargets];

  if (new Set(allTargets).size !== allTargets.length) {
    return fail();
  }

  return targets;
};

const readEvidenceFile = async (
  directory: string,
  name: Phase0EvidenceFileName
): Promise<Uint8Array> => {
  const filePath = path.join(directory, name);
  const state = await lstat(filePath);

  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.nlink !== 1 ||
    state.mode % 0o1000 !== 0o600 ||
    state.size === 0 ||
    state.size > 1024 * 1024 ||
    (typeof process.getuid === 'function' && state.uid !== process.getuid())
  ) {
    return fail();
  }

  return readFile(filePath);
};

const reproduce = async (
  request: Phase0EvidenceReproductionRequest,
  environment: RuntimeEnvironment,
  dependencies: Phase0ReproducerDependencies
): Promise<Phase0EvidenceReproduction> => {
  assertRequest(request);
  const root = requiredEnvironmentValue(environment, 'ASTER_PHASE1_CONFORMANCE_ROOT');

  try {
    return await withTrustedAsterPhase1BuildDirectory(root, environment, async (trustedRoot) => {
      const workspace = await mkdtemp(path.join(trustedRoot, 'phase0-reproduction.'));
      await chmod(workspace, 0o700);
      const visibleWorkspace = path.join(root, path.basename(workspace));
      const evidenceDirectory = path.join(workspace, 'evidence');
      const oracleMessages = path.join(workspace, 'oracle-messages');
      const candidateMessages = path.join(workspace, 'candidate-messages');
      const visibleEvidenceDirectory = path.join(visibleWorkspace, 'evidence');
      const visibleOracleMessages = path.join(visibleWorkspace, 'oracle-messages');
      const visibleCandidateMessages = path.join(visibleWorkspace, 'candidate-messages');

      try {
        await Promise.all(
          [evidenceDirectory, oracleMessages, candidateMessages].map(async (directory) => {
            await mkdir(directory, { mode: 0o700 });
            await chmod(directory, 0o700);
          })
        );
        const oracleImageDigest = requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_ORACLE_IMAGE_DIGEST'
        );
        const runtimeCandidateImageDigest = requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST'
        );
        const candidateImageDigest = requiredEnvironmentValue(
          environment,
          'ASTER_PHASE1_PHASE0_CANDIDATE_IMAGE_DIGEST'
        );

        if (
          !digestPattern.test(oracleImageDigest) ||
          !digestPattern.test(runtimeCandidateImageDigest) ||
          !digestPattern.test(candidateImageDigest) ||
          candidateImageDigest !== oracleImageDigest
        ) {
          return fail();
        }
        const targets = loadDedicatedTargets(environment);
        const cliEnvironment = Object.freeze({
          ASTER_ORACLE_URL: targets.oracleUrl,
          ASTER_ORACLE_ADMIN_URL: targets.oracleAdminUrl,
          ASTER_CANDIDATE_URL: targets.candidateUrl,
          ASTER_CANDIDATE_ADMIN_URL: targets.candidateAdminUrl,
          ASTER_ORACLE_IMAGE_DIGEST: oracleImageDigest,
          ASTER_CANDIDATE_IMAGE_DIGEST: candidateImageDigest,
          ASTER_ORACLE_MESSAGE_DIR: visibleOracleMessages,
          ASTER_CANDIDATE_MESSAGE_DIR: visibleCandidateMessages,
          ASTER_EVIDENCE_DIR: visibleEvidenceDirectory,
        });
        const quiet = Object.freeze({
          stdout: async (_message: string) => {
            await Promise.resolve();
          },
          stderr: async (_message: string) => {
            await Promise.resolve();
          },
        });
        const positive = await dependencies.runCli([], cliEnvironment, quiet);
        const negative = await dependencies.runCli(
          ['--fault-injection', 'discovery-issuer'],
          cliEnvironment,
          quiet
        );
        const finalized = await dependencies.runCli(
          ['--finalize-run', '--negative-control-path', '/observations/0/value/issuer'],
          cliEnvironment,
          quiet
        );

        if (positive !== 0 || negative !== 2 || finalized !== 0) {
          return fail();
        }
        const directoryEntries = await readdir(evidenceDirectory);
        const entries = directoryEntries.toSorted();

        if (JSON.stringify(entries) !== JSON.stringify(expectedFiles)) {
          return fail();
        }
        const files = await Promise.all(
          expectedFiles.map(async (name) =>
            Object.freeze({ name, bytes: await readEvidenceFile(evidenceDirectory, name) })
          )
        );

        return Object.freeze({ commit: phase0HarnessCommit, files: Object.freeze(files) });
      } finally {
        await rm(workspace, { recursive: true, force: true }).catch(() => false);
      }
    });
  } catch {
    return fail();
  }
};

export const reproducePhase0Evidence: Phase0EvidenceReproducer = async (request) =>
  reproduce(request, process.env, { runCli: runCompatibilityCli });

export const reproducePhase0EvidenceForTesting = async (
  request: Phase0EvidenceReproductionRequest,
  environment: RuntimeEnvironment,
  dependencies: Phase0ReproducerDependencies
): Promise<Phase0EvidenceReproduction> => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return reproduce(request, environment, dependencies);
};

/* eslint-enable @typescript-eslint/no-unnecessary-condition */
