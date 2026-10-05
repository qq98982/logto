/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/member-ordering, @typescript-eslint/no-empty-function -- The separate CLI owns strict control-character grammar, sequential stable-path validation, Linux mode checks, accepted authorization bridging, and fixed no-op reporting ports. */
import { lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

import type { JsonValue } from '../../normalize.js';
import { runPhase1Cli, type Phase1CliDependencies } from '../../phase-1/cli.js';
import { assertPhase1EvidenceIsSanitized } from '../../phase-1/evidence.js';
import { writeSecureJsonArtifact } from '../../phase-1/secure-evidence-sink.js';
import { loadPhase1RuntimeIsolationAttestations } from '../../phase-1/snapshots/execution-coordinator.js';
import {
  createPhase1EvidenceRuntimeContext,
  type Phase1EvidenceRuntimeContext,
} from '../../phase-1/snapshots/runtime-context.js';
import {
  loadPhase2Profile,
  type Phase2ProfilePaths,
  type Phase2ProfileRegistries,
} from '../profile.js';
import {
  inspectLaunchedPhase2HarnessSource,
  phase2OracleImageDigest,
  phase2OracleSourceCommit,
  recheckCleanPhase2HarnessSource,
  type Phase2SourceIdentity,
} from '../provenance.js';

import {
  isPhase2BaseScenarioFailure,
  runPhase2BasePreservationRuntime,
  type Phase2BasePreservationRuntimeResult,
} from './runtime.js';
import {
  createAcceptedPhase1SourceClosureManifest,
  type AcceptedPhase1SourceClosureManifest,
} from './source-closure.js';

export type Phase2BasePreservationCommand = Readonly<{
  phase1ProfilePath: string;
  phase1SchemaPath: string;
  phase2ProfilePath: string;
  phase2SchemaPath: string;
  outputPath: string;
  tempRoot: string;
}>;

export type Phase2BasePreservationCliDependencies = Readonly<{
  loadPhase2Profile(paths: Phase2ProfilePaths): Promise<Phase2ProfileRegistries>;
  runPhase1Cli(args: readonly string[], injected: Partial<Phase1CliDependencies>): Promise<number>;
  createContext(
    authorization: Parameters<NonNullable<Phase1CliDependencies['executeDifferential']>>[0]
  ): Phase1EvidenceRuntimeContext;
  createSourceClosure(repositoryRoot: string): Promise<AcceptedPhase1SourceClosureManifest>;
  runRuntime(
    context: Phase1EvidenceRuntimeContext,
    profile: Phase2ProfileRegistries,
    sourceClosure: AcceptedPhase1SourceClosureManifest
  ): Promise<Phase2BasePreservationRuntimeResult>;
  inspectHarness(runtimeCapability: string | undefined): Promise<Phase2SourceIdentity>;
  recheckHarness(capability: Phase2SourceIdentity): Promise<void>;
  publish(outputPath: string, value: JsonValue): Promise<void>;
  validatePaths(command: Phase2BasePreservationCommand): Promise<void>;
  stdout(message: string): void | Promise<void>;
  stderr(message: string): void | Promise<void>;
  environment: Readonly<Record<string, string | undefined>>;
}>;

const invalidArguments = 'Invalid Phase 2 base-preservation arguments';
const runFailure = 'Phase 2 base-preservation failed.\n';
type BaseFailureStage =
  | 'arguments'
  | 'paths'
  | 'profile'
  | 'harness'
  | 'closure'
  | 'phase1'
  | 'runtime'
  | `runtime-scenario-${number}-${'oracle' | 'candidate' | 'artifact' | 'projection' | 'compare'}`
  | `runtime-scenario-1-compare-step-${number}`
  | `runtime-scenario-1-compare-step-5-field-${number}`
  | 'harness-recheck'
  | 'publish';
const success = 'Phase 2 base-preservation completed.\n';
const outputName = 'phase-2-base-preservation.json';
const maximumInputBytes = 1024 * 1024;
const commitPattern = /^[0-9a-f]{40}$/u;
const imagePattern = /^sha256:[0-9a-f]{64}$/u;

const failArguments = (): never => {
  throw new TypeError(invalidArguments);
};

const fail = (): never => {
  throw new TypeError(runFailure.trim());
};

const packageRoot = path.resolve(process.cwd());
const repositoryRoot = path.resolve(packageRoot, '../..');
export const phase2BasePreservationRuntimeEntryPath = path.join(
  packageRoot,
  'lib/compatibility/phase-2/base-preservation-entry.js'
);

const parseFlags = (values: readonly string[]) => {
  const result = new Map<string, string>();

  for (let index = 0; index < values.length; index += 2) {
    const flag = values[index];
    const value = values[index + 1];

    if (
      !flag ||
      !value ||
      ![
        '--phase1-profile',
        '--phase1-schema',
        '--phase2-profile',
        '--phase2-schema',
        '--output',
        '--temp-root',
      ].includes(flag) ||
      result.has(flag) ||
      /[\u0000-\u001F\u007F]/u.test(value)
    ) {
      return failArguments();
    }
    result.set(flag, value);
  }

  return result;
};

export const parsePhase2BasePreservationArguments = (
  arguments_: readonly string[]
): Phase2BasePreservationCommand => {
  const [subcommand, ...rest] = arguments_;

  if (subcommand !== 'run' || rest.length !== 12) {
    return failArguments();
  }
  const values = parseFlags(rest);
  const phase1ProfilePath = values.get('--phase1-profile') ?? failArguments();
  const phase1SchemaPath = values.get('--phase1-schema') ?? failArguments();
  const phase2ProfilePath = values.get('--phase2-profile') ?? failArguments();
  const phase2SchemaPath = values.get('--phase2-schema') ?? failArguments();
  const outputPath = values.get('--output') ?? failArguments();
  const temporaryRoot = values.get('--temp-root') ?? failArguments();
  const paths = [
    phase1ProfilePath,
    phase1SchemaPath,
    phase2ProfilePath,
    phase2SchemaPath,
    outputPath,
    temporaryRoot,
  ];

  if (
    values.size !== 6 ||
    paths.some((value) => !path.isAbsolute(value) || path.normalize(value) !== value) ||
    new Set(paths.slice(0, 4)).size !== 4 ||
    path.dirname(outputPath) !== temporaryRoot ||
    path.basename(outputPath) !== outputName
  ) {
    return failArguments();
  }

  return Object.freeze({
    phase1ProfilePath,
    phase1SchemaPath,
    phase2ProfilePath,
    phase2SchemaPath,
    outputPath,
    tempRoot: temporaryRoot,
  });
};

const validatePaths = async (command: Phase2BasePreservationCommand): Promise<void> => {
  const root = await lstat(command.tempRoot).catch(fail);

  if (
    root.isSymbolicLink() ||
    !root.isDirectory() ||
    root.uid !== process.getuid?.() ||
    (root.mode & 0o777) !== 0o700 ||
    (await realpath(command.tempRoot).catch(fail)) !== command.tempRoot
  ) {
    return fail();
  }
  for (const inputPath of [
    command.phase1ProfilePath,
    command.phase1SchemaPath,
    command.phase2ProfilePath,
    command.phase2SchemaPath,
  ]) {
    const state = await lstat(inputPath).catch(fail);

    if (
      state.isSymbolicLink() ||
      !state.isFile() ||
      state.size <= 0 ||
      state.size > maximumInputBytes ||
      (await realpath(inputPath).catch(fail)) !== inputPath
    ) {
      return fail();
    }
  }
  try {
    await lstat(command.outputPath);
    return fail();
  } catch (error: unknown) {
    if (
      typeof error !== 'object' ||
      error === null ||
      Object.getOwnPropertyDescriptor(error, 'code')?.value !== 'ENOENT'
    ) {
      return fail();
    }
  }
};

const requiredEnvironment = (
  environment: Readonly<Record<string, string | undefined>>,
  name: string
): string => {
  const value = environment[name];

  return typeof value === 'string' && value.length > 0 ? value : fail();
};

const createContext = (
  authorization: Parameters<NonNullable<Phase1CliDependencies['executeDifferential']>>[0],
  environment: Readonly<Record<string, string | undefined>>
): Phase1EvidenceRuntimeContext =>
  createPhase1EvidenceRuntimeContext(
    {
      authorization,
      oracleImageDigest: requiredEnvironment(environment, 'ASTER_PHASE1_ORACLE_IMAGE_DIGEST'),
      candidateImageDigest: requiredEnvironment(environment, 'ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST'),
      evidenceDirectory: requiredEnvironment(environment, 'ASTER_PHASE1_EVIDENCE_DIR'),
      oracleSnapshotPath: requiredEnvironment(environment, 'ASTER_PHASE1_ORACLE_SNAPSHOT_PATH'),
      repositoryRoot,
      conformanceRoot: requiredEnvironment(environment, 'ASTER_PHASE1_CONFORMANCE_ROOT'),
      isolationAttestations: loadPhase1RuntimeIsolationAttestations(environment),
    },
    environment
  );

export const projectPhase2BasePreservationHarnessEnvironment = (
  environment: Readonly<Record<string, string | undefined>>
): Readonly<Record<string, string | undefined>> =>
  Object.freeze({
    ASTER_PHASE2_HARNESS_HEAD: environment.ASTER_PHASE2_HARNESS_HEAD,
    ASTER_PHASE2_HARNESS_TREE: environment.ASTER_PHASE2_HARNESS_TREE,
    ASTER_PHASE2_RUNTIME_BUNDLE_SHA256: environment.ASTER_PHASE2_RUNTIME_BUNDLE_SHA256,
    HOME: environment.HOME,
    LC_ALL: environment.LC_ALL,
    PATH: environment.PATH,
    PLAYWRIGHT_BROWSERS_PATH: environment.PLAYWRIGHT_BROWSERS_PATH,
    TMPDIR: environment.TMPDIR,
    XDG_RUNTIME_DIR: environment.XDG_RUNTIME_DIR,
  });

const defaultDependencies: Phase2BasePreservationCliDependencies = {
  loadPhase2Profile,
  runPhase1Cli,
  createContext: (authorization) => createContext(authorization, process.env),
  createSourceClosure: createAcceptedPhase1SourceClosureManifest,
  runRuntime: runPhase2BasePreservationRuntime,
  inspectHarness: async (runtimeCapability) =>
    inspectLaunchedPhase2HarnessSource(
      repositoryRoot,
      phase2BasePreservationRuntimeEntryPath,
      runtimeCapability,
      projectPhase2BasePreservationHarnessEnvironment(process.env)
    ),
  recheckHarness: recheckCleanPhase2HarnessSource,
  publish: async (outputPath, value) => {
    await writeSecureJsonArtifact(outputPath, value);
  },
  validatePaths,
  stdout: (message) => {
    process.stdout.write(message);
  },
  stderr: (message) => {
    process.stderr.write(message);
  },
  environment: process.env,
};

const safeWrite = async (
  writer: (message: string) => void | Promise<void>,
  message: string
): Promise<void> => {
  try {
    await writer(message);
  } catch {
    // Fixed diagnostics must not be replaced by reporting failures.
  }
};

export const runPhase2BasePreservationCli = async (
  arguments_: readonly string[] = process.argv.slice(2),
  runtimeCapability?: string,
  dependencies: Phase2BasePreservationCliDependencies = defaultDependencies
): Promise<number> => {
  let failureStage: BaseFailureStage = 'arguments';
  try {
    const command = parsePhase2BasePreservationArguments(arguments_);
    failureStage = 'paths';
    await dependencies.validatePaths(command);
    failureStage = 'profile';
    const profile = await dependencies.loadPhase2Profile({
      profilePath: command.phase2ProfilePath,
      schemaPath: command.phase2SchemaPath,
    });
    failureStage = 'harness';
    const harness = await dependencies.inspectHarness(runtimeCapability);
    failureStage = 'closure';
    const closure = await dependencies.createSourceClosure(harness.repositoryRoot);
    let artifact: JsonValue | undefined;
    failureStage = 'phase1';
    const phase1Code = await dependencies.runPhase1Cli(
      [
        'run-differential',
        '--mode',
        'runtime-candidate',
        '--profile',
        command.phase1ProfilePath,
        '--schema',
        command.phase1SchemaPath,
        '--observation-controls',
        '--discovery-extra-control',
        '--candidate-invariant-controls',
      ],
      {
        verifyRunProvenance: async (phase1Command, bundle) => {
          const harnessCommit = bundle.profile.phase1Harness.commit;

          if (
            phase1Command.command !== 'run-differential' ||
            phase1Command.mode !== 'runtime-candidate' ||
            phase1Command.profilePath !== command.phase1ProfilePath ||
            phase1Command.schemaPath !== command.phase1SchemaPath ||
            phase1Command.controls.recordOracle ||
            !phase1Command.controls.observationControls ||
            !phase1Command.controls.discoveryExtraControl ||
            !phase1Command.controls.candidateInvariantControls ||
            !commitPattern.test(harnessCommit ?? '') ||
            harnessCommit !== harness.public.headCommit ||
            profile.baseAcceptance.harnessCommit !== closure.acceptedCommit
          ) {
            return fail();
          }

          return Object.freeze({
            kind: 'review-candidate' as const,
            harnessCommit,
            publishable: false as const,
          });
        },
        executeDifferential: async (authorization) => {
          const context = dependencies.createContext(authorization);

          if (context.repositoryRoot !== harness.repositoryRoot) {
            return fail();
          }
          failureStage = 'runtime';
          const runtime = await dependencies
            .runRuntime(context, profile, closure)
            .catch((error: unknown) => {
              if (isPhase2BaseScenarioFailure(error)) {
                failureStage =
                  error.scenarioIndex === 1 &&
                  error.stage === 'compare' &&
                  error.stepIndex !== undefined
                    ? error.stepIndex === 5 && error.fieldIndex !== undefined
                      ? `runtime-scenario-1-compare-step-5-field-${error.fieldIndex}`
                      : `runtime-scenario-1-compare-step-${error.stepIndex}`
                    : `runtime-scenario-${error.scenarioIndex}-${error.stage}`;
              }

              throw error;
            });
          const candidateSourceCommit = requiredEnvironment(
            dependencies.environment,
            'ASTER_PHASE2_CANDIDATE_SOURCE_COMMIT'
          );
          const candidateImageDigest = requiredEnvironment(
            dependencies.environment,
            'ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST'
          );
          const oracleImageDigest = requiredEnvironment(
            dependencies.environment,
            'ASTER_PHASE1_ORACLE_IMAGE_DIGEST'
          );

          if (
            !commitPattern.test(candidateSourceCommit) ||
            !imagePattern.test(candidateImageDigest) ||
            oracleImageDigest !== phase2OracleImageDigest ||
            runtime.scenarios.length !== 22 ||
            runtime.scenarios.some(({ differences }) => differences.length > 0) ||
            !isDeepStrictEqual(runtime.sourceClosure, closure)
          ) {
            return fail();
          }
          const value = Object.freeze({
            schemaVersion: 1 as const,
            mode: 'phase-2-base-preservation' as const,
            provenance: Object.freeze({
              profileSha256: profile.profileSha256,
              schemaSha256: profile.schemaSha256,
              baseAcceptance: profile.baseAcceptance,
              harness: harness.public,
              sourceClosure: closure,
              phase1: runtime.phase1Provenance,
              oracle: Object.freeze({
                sourceCommit: phase2OracleSourceCommit,
                imageDigest: oracleImageDigest,
              }),
              candidate: Object.freeze({
                sourceCommit: candidateSourceCommit,
                imageDigest: candidateImageDigest,
              }),
            }),
            sanitizerSuccess: true as const,
            rawPhase1NegativeControl: runtime.rawPhase1NegativeControl,
            discoveryAppendProofs: runtime.discoveryAppendProofs,
            scenarios: runtime.scenarios,
          });
          assertPhase1EvidenceIsSanitized(value);
          failureStage = 'harness-recheck';
          await dependencies.recheckHarness(harness);
          artifact = value as unknown as JsonValue;
        },
        stdout: () => {},
        stderr: () => {},
      }
    );

    if (artifact !== undefined) {
      failureStage = 'phase1';
    }
    if (phase1Code !== 0 || artifact === undefined) {
      return fail();
    }
    failureStage = 'publish';
    await dependencies.publish(command.outputPath, artifact);
    await safeWrite(dependencies.stdout, success);

    return 0;
  } catch {
    await safeWrite(dependencies.stderr, `Phase 2 base-preservation failed (${failureStage}).\n`);

    return 1;
  }
};

export const runPhase2CliMain = runPhase2BasePreservationCli;

const directEntry = path.resolve(process.argv[1] ?? '');

if (
  directEntry === fileURLToPath(import.meta.url) ||
  directEntry === phase2BasePreservationRuntimeEntryPath
) {
  process.exitCode = await runPhase2BasePreservationCli();
}

/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, no-control-regex, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/member-ordering, @typescript-eslint/no-empty-function */
