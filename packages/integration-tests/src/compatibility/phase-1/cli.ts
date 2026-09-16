/* eslint-disable max-lines, complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-assign, no-restricted-syntax, @typescript-eslint/no-empty-function, @typescript-eslint/no-unnecessary-condition -- The closed CLI grammar, review-profile preparation, and authorization composition form one auditable command boundary. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import type { CapabilityManifest } from '../model.js';

import { canonicalBrowserSourcePaths } from './browser/index.js';
import { candidateInvariantRegistryIds } from './candidate-invariants/index.js';
import { assertPhase1CapabilityDocument, parsePhase1CapabilityDocument } from './capabilities.js';
import { createProductionPhase1GithubReader } from './github-reader.js';
import { differentialScenarioIds, oracleCommit, snapshotClosedDataGraph } from './model.js';
import { reproducePhase0Evidence } from './phase0-reproducer.js';
import { phase1ProfileSchemaLock } from './profile-lock.js';
import { createProductionPhase1GitReader } from './profile-semantics/provenance.js';
import {
  assertPhase1ProfileSemantics,
  authorizePhase1ProtectedExecution,
  verifyPhase1ProfileProvenance,
  type Phase1ProvenanceResult,
} from './profile-semantics.js';
import type { Phase1Profile } from './profile-types.js';
import {
  createPhase1DesignProfileBundleFromBytes,
  createPhase1ProfileBundleFromBytes,
  createPhase1ProfileBundleLoader,
  phase1SchemaLockDocument,
  type Phase1ProfileBundle,
} from './profile.js';
import {
  mintPhase1RunAuthorization,
  type Phase1RunAuthorization,
  type Phase1RunControls,
  type Phase1RunMode,
} from './run-authorization.js';
import { phase1DifferentialScenarios } from './scenarios/index.js';
import {
  rollbackSecureJsonArtifact,
  writeSecureJsonArtifact,
  type SecureJsonPublication,
} from './secure-evidence-sink.js';
import {
  executeAuthorizedPhase1DifferentialGate,
  executeAuthorizedPhase1Run,
} from './snapshots/execution-coordinator.js';

export { assertAuthorizedPhase1Run, authorizePhase1RunForTesting } from './run-authorization.js';
export type {
  Phase1RunAuthorization,
  Phase1RunControls,
  Phase1RunMode,
} from './run-authorization.js';

export type Phase1RunCommand = Readonly<{
  command: 'run' | 'run-differential';
  mode: Phase1RunMode;
  profilePath: string;
  schemaPath: string;
  controls: Phase1RunControls;
}>;

export type Phase1PrepareReviewProfileCommand = Readonly<{
  command: 'prepare-review-profile';
  sourceProfilePath: string;
  schemaPath: string;
  harnessCommit: string;
  outputPath: string;
}>;

export type Phase1CliCommand = Phase1RunCommand | Phase1PrepareReviewProfileCommand;

type OutputWriter = (message: string) => void | Promise<void>;

export type Phase1CliDependencies = Readonly<{
  loadRunBundle: (command: Phase1RunCommand) => Promise<
    Readonly<{
      bundle: Phase1ProfileBundle;
      baselineCapabilityIds: ReadonlySet<string>;
    }>
  >;
  verifyRunProvenance: (
    command: Phase1RunCommand,
    bundle: Phase1ProfileBundle,
    baselineCapabilityIds: ReadonlySet<string>
  ) => Promise<Phase1ProvenanceResult>;
  authorizeProtectedExecution: typeof authorizePhase1ProtectedExecution;
  executeRun: (authorization: Phase1RunAuthorization, command: Phase1RunCommand) => Promise<void>;
  executeDifferential: (
    authorization: Phase1RunAuthorization,
    command: Phase1RunCommand
  ) => Promise<void>;
  prepareReviewProfile: (command: Phase1PrepareReviewProfileCommand) => Promise<void>;
  stdout: OutputWriter;
  stderr: OutputWriter;
}>;

type GitFileAuthority = Readonly<{
  root: string;
  relativePath: string;
  originUrl: string;
  head: string;
  blobId: string;
  clean: boolean;
  bytes: Uint8Array;
}>;

const preparedReviewCapabilityBrand: unique symbol = Symbol('prepared-review-profile');
type PreparedReviewProfileCapability = Readonly<{
  [preparedReviewCapabilityBrand]: true;
  bundle: Phase1ProfileBundle;
}>;
const preparedReviewCapabilities = new WeakSet<Record<PropertyKey, unknown>>();

export type Phase1ReviewPreparationDependencies = Readonly<{
  inspectGitFile: (filePath: string) => Promise<GitFileAuthority>;
  logtoRoot: string;
  loadDesignBundle: (
    profileBytes: Uint8Array,
    schemaBytes: Uint8Array
  ) => Promise<Phase1ProfileBundle>;
  loadBaselineCapabilityIds: (profile: Readonly<Phase1Profile>) => Promise<ReadonlySet<string>>;
  assertSemantics: (
    profile: Readonly<Phase1Profile>,
    baselineCapabilityIds: ReadonlySet<string>
  ) => void;
  validatePreparedBytes: (
    profileBytes: Uint8Array,
    schemaBytes: Uint8Array,
    baselineCapabilityIds: ReadonlySet<string>
  ) => Promise<Phase1ProfileBundle>;
  publish: (
    outputPath: string,
    capability: PreparedReviewProfileCapability
  ) => Promise<SecureJsonPublication>;
  rollback: (publication: SecureJsonPublication) => Promise<void>;
  loadPublishedBundle: (
    profilePath: string,
    schemaBytes: Uint8Array,
    baselineCapabilityIds: ReadonlySet<string>
  ) => Promise<Phase1ProfileBundle>;
}>;

const invalidArgumentsDiagnostic = 'Invalid Phase 1 arguments.';
const runFailureDiagnostic = 'Phase 1 run failed.';
const preparationFailureDiagnostic = 'Phase 1 review profile preparation failed.';
const commitPattern = /^[\da-f]{40}$/u;
const profileSchemaLockState =
  'locked; sourceCommit and sha256 pin the sole canonical Phase 1 profile schema';
const harnessLockState = 'locked; commit pins the reviewed Phase 1 harness descendant';
const designSchemaLockState =
  'design-unlocked; the canonical schema source commit and SHA-256 must be pinned before the Phase 1 harness is pinned';
const designHarnessLockState =
  'design-unlocked; a reviewed descendant commit must be pinned before Rust behavior implementation';
const sourceProfileRelativePath = 'compatibility/phase-1-profile.json';
const sourceSchemaRelativePath = 'compatibility/phase-1-profile.schema.json';
export const phase1ReviewSourceCommit = '8ddefcfa377b85871734ab2700da13d9d4f372ef';
const canonicalAsterOrigins = new Set([
  'https://github.com/qq98982/aster.git',
  'git@github.com:qq98982/aster.git',
]);
const executeFile = promisify(execFile);

const findIntegrationTestsPackageRoot = () => {
  let current = path.dirname(fileURLToPath(import.meta.url));

  for (let remaining = 8; remaining > 0; remaining -= 1) {
    if (
      path.basename(current) === 'integration-tests' &&
      path.basename(path.dirname(current)) === 'packages'
    ) {
      return current;
    }

    current = path.dirname(current);
  }

  throw new Error(runFailureDiagnostic);
};

const packageRoot = findIntegrationTestsPackageRoot();
const defaultLogtoRoot = path.resolve(packageRoot, '../..');

const writeStatus = async (writer: OutputWriter, message: string): Promise<void> => {
  try {
    await writer(message);
  } catch {
    // Reporting failures must not replace or disclose the fixed CLI outcome.
  }
};

const parseFlagMap = (
  arguments_: readonly string[],
  valueFlags: ReadonlySet<string>,
  booleanFlags: ReadonlySet<string>
) => {
  const values = new Map<string, string>();
  const booleans = new Set<string>();

  for (let index = 0; index < arguments_.length; index += 1) {
    const flag = arguments_[index];

    if (!flag || !flag.startsWith('--') || flag.includes('=')) {
      throw new TypeError(invalidArgumentsDiagnostic);
    }
    if (valueFlags.has(flag)) {
      if (values.has(flag) || booleans.has(flag)) {
        throw new TypeError(invalidArgumentsDiagnostic);
      }
      const value = arguments_[index + 1];

      if (!value || value.startsWith('--')) {
        throw new TypeError(invalidArgumentsDiagnostic);
      }
      values.set(flag, value);
      index += 1;
      continue;
    }
    if (booleanFlags.has(flag)) {
      if (values.has(flag) || booleans.has(flag)) {
        throw new TypeError(invalidArgumentsDiagnostic);
      }
      booleans.add(flag);
      continue;
    }

    throw new TypeError(invalidArgumentsDiagnostic);
  }

  return { values, booleans };
};

export const parsePhase1Arguments = (arguments_: readonly string[]): Phase1CliCommand => {
  const [subcommand, ...rest] = arguments_;

  if (subcommand === 'run' || subcommand === 'run-differential') {
    const { values, booleans } = parseFlagMap(
      rest,
      new Set(['--mode', '--profile', '--schema']),
      new Set([
        '--record-oracle',
        '--observation-controls',
        '--discovery-extra-control',
        '--candidate-invariant-controls',
      ])
    );
    const mode = values.get('--mode');
    const profilePath = values.get('--profile');
    const schemaPath = values.get('--schema');

    if (
      values.size !== 3 ||
      (mode !== 'review-candidate' && mode !== 'mirror-control' && mode !== 'runtime-candidate') ||
      !profilePath ||
      !schemaPath ||
      (booleans.has('--record-oracle') && mode !== 'review-candidate') ||
      (subcommand === 'run-differential' &&
        (mode !== 'runtime-candidate' ||
          booleans.has('--record-oracle') ||
          !booleans.has('--observation-controls') ||
          !booleans.has('--discovery-extra-control') ||
          !booleans.has('--candidate-invariant-controls')))
    ) {
      throw new TypeError(invalidArgumentsDiagnostic);
    }

    return Object.freeze({
      command: subcommand,
      mode,
      profilePath,
      schemaPath,
      controls: Object.freeze({
        recordOracle: booleans.has('--record-oracle'),
        observationControls: booleans.has('--observation-controls'),
        discoveryExtraControl: booleans.has('--discovery-extra-control'),
        candidateInvariantControls: booleans.has('--candidate-invariant-controls'),
      }),
    });
  }

  if (subcommand === 'prepare-review-profile') {
    const { values, booleans } = parseFlagMap(
      rest,
      new Set(['--source-profile', '--schema', '--harness-commit', '--output']),
      new Set()
    );
    const sourceProfilePath = values.get('--source-profile');
    const schemaPath = values.get('--schema');
    const harnessCommit = values.get('--harness-commit');
    const outputPath = values.get('--output');

    if (
      values.size !== 4 ||
      booleans.size > 0 ||
      !sourceProfilePath ||
      !schemaPath ||
      !harnessCommit ||
      !outputPath ||
      !commitPattern.test(harnessCommit)
    ) {
      throw new TypeError(invalidArgumentsDiagnostic);
    }

    return Object.freeze({
      command: 'prepare-review-profile',
      sourceProfilePath,
      schemaPath,
      harnessCommit,
      outputPath,
    });
  }

  throw new TypeError(invalidArgumentsDiagnostic);
};

const gitEnvironment = Object.freeze({
  PATH: process.env.PATH,
  GIT_ASKPASS: '/bin/false',
  GIT_CONFIG_COUNT: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_KEY_0: 'credential.helper',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_CONFIG_VALUE_0: '',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_TERMINAL_PROMPT: '0',
  LC_ALL: 'C',
  SSH_ASKPASS: '/bin/false',
});

const runGit = async (cwd: string, args: readonly string[], maximumBytes = 1024 * 1024) => {
  const { stdout } = await executeFile('git', ['--no-replace-objects', ...args], {
    cwd,
    encoding: 'utf8',
    env: gitEnvironment,
    maxBuffer: maximumBytes,
    timeout: 30_000,
  });

  return stdout.trim();
};

const inspectGitFile = async (filePath: string): Promise<GitFileAuthority> => {
  const resolvedPath = path.resolve(filePath);
  await assertStableOwnedInput(resolvedPath);
  const root = await runGit(path.dirname(resolvedPath), ['rev-parse', '--show-toplevel'], 4096);
  const relativePath = path.relative(root, resolvedPath).replaceAll('\\', '/');

  if (
    !path.isAbsolute(filePath) ||
    resolvedPath !== filePath ||
    relativePath.length === 0 ||
    relativePath.startsWith('../') ||
    path.isAbsolute(relativePath)
  ) {
    throw new Error(preparationFailureDiagnostic);
  }
  await runGit(root, ['ls-files', '--error-unmatch', '--', relativePath], 4096);
  const [originUrl, head, status] = await Promise.all([
    runGit(root, ['remote', 'get-url', 'origin'], 4096),
    runGit(root, ['rev-parse', 'HEAD'], 128),
    runGit(root, ['status', '--porcelain=v1', '--untracked-files=all']),
  ]);

  if (!commitPattern.test(head)) {
    throw new Error(preparationFailureDiagnostic);
  }

  const blobId = await runGit(root, ['rev-parse', `${head}:${relativePath}`], 128);
  const { stdout } = await executeFile(
    'git',
    ['--no-replace-objects', 'cat-file', 'blob', `${head}:${relativePath}`],
    {
      cwd: root,
      encoding: 'buffer',
      env: gitEnvironment,
      maxBuffer: 1024 * 1024,
      timeout: 30_000,
    }
  );

  return Object.freeze({
    root,
    relativePath,
    originUrl,
    head,
    blobId,
    clean: status.length === 0,
    bytes: Buffer.from(stdout),
  });
};

export const inspectGitFileForTesting = async (filePath: string): Promise<GitFileAuthority> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(preparationFailureDiagnostic);
  }

  return inspectGitFile(filePath);
};

const assertStableOwnedInput = async (filePath: string): Promise<void> => {
  const state = await lstat(filePath);

  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.nlink !== 1 ||
    (typeof process.getuid === 'function' && state.uid !== process.getuid()) ||
    (await realpath(filePath)) !== filePath
  ) {
    throw new Error(preparationFailureDiagnostic);
  }
};

const pathIsInside = (root: string, candidate: string) => {
  const relative = path.relative(root, candidate);

  return relative === '' || (!relative.startsWith('../') && !path.isAbsolute(relative));
};

const assertReviewSource = (profile: Readonly<Phase1Profile>): void => {
  const designSource =
    profile.profileSchema.sourceCommit === null &&
    profile.profileSchema.sha256 === null &&
    profile.profileSchema.lockState === designSchemaLockState &&
    profile.phase1Harness.commit === null &&
    profile.phase1Harness.lockState === designHarnessLockState;
  const lockedSource =
    profile.profileSchema.sourceCommit === phase1ProfileSchemaLock.sourceCommit &&
    profile.profileSchema.sha256 === phase1ProfileSchemaLock.sha256 &&
    profile.profileSchema.lockState === profileSchemaLockState &&
    typeof profile.phase1Harness.commit === 'string' &&
    commitPattern.test(profile.phase1Harness.commit) &&
    profile.phase1Harness.lockState === harnessLockState;

  if (
    profile.schemaVersion !== 2 ||
    profile.profileId !== 'aster.phase-1.password-pkce' ||
    profile.reference.oracleCommit !== oracleCommit ||
    profile.profileSchema.repository !== 'aster' ||
    profile.profileSchema.path !== sourceSchemaRelativePath ||
    profile.phase1Harness.repository !== profile.reference.oracleRepository ||
    profile.phase1Harness.baseCommit !== profile.reference.phase0HarnessCommit ||
    (!designSource && !lockedSource)
  ) {
    throw new Error(preparationFailureDiagnostic);
  }
};

const sameGitAuthority = (left: GitFileAuthority, right: GitFileAuthority): boolean =>
  left.root === right.root &&
  left.relativePath === right.relativePath &&
  left.originUrl === right.originUrl &&
  left.head === right.head &&
  left.blobId === right.blobId &&
  left.clean &&
  right.clean;

const mintPreparedReviewCapability = (
  bundle: Phase1ProfileBundle
): PreparedReviewProfileCapability => {
  const capability = Object.freeze({ [preparedReviewCapabilityBrand]: true as const, bundle });
  preparedReviewCapabilities.add(capability);
  return capability;
};

const consumePreparedReviewCapability = (
  capability: PreparedReviewProfileCapability
): Phase1ProfileBundle => {
  if (!preparedReviewCapabilities.delete(capability)) {
    throw new Error(preparationFailureDiagnostic);
  }
  return capability.bundle;
};

export const consumePreparedReviewCapabilityForTesting = (
  capability: unknown
): Phase1ProfileBundle => {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(preparationFailureDiagnostic);
  }

  return consumePreparedReviewCapability(capability as PreparedReviewProfileCapability);
};

const semanticContext = (baselineCapabilityIds: ReadonlySet<string>) => ({
  baselineCapabilityIds,
  differentialRegistryIds: differentialScenarioIds,
  candidateInvariantRegistryIds,
});

const parseStrictAuthorityJson = (source: string): unknown => {
  const errors: ParseError[] = [];
  const root = parseTree(source, errors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });
  const visit = (node: JsonNode | undefined): void => {
    if (!node) {
      throw new Error(runFailureDiagnostic);
    }
    if (node.type === 'object') {
      const names = new Set<string>();

      for (const property of node.children ?? []) {
        const [nameNode, valueNode] = property.children ?? [];
        const name: unknown = nameNode?.value;

        if (typeof name !== 'string' || names.has(name)) {
          throw new Error(runFailureDiagnostic);
        }
        names.add(name);
        visit(valueNode);
      }
    } else if (node.type === 'array') {
      for (const child of node.children ?? []) {
        visit(child);
      }
    }
  };

  if (!root || errors.length > 0) {
    throw new Error(runFailureDiagnostic);
  }
  visit(root);

  try {
    return JSON.parse(source) as unknown;
  } catch {
    throw new Error(runFailureDiagnostic);
  }
};

export const parseStrictAuthorityJsonForTesting = (source: string): unknown => {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(runFailureDiagnostic);
  }

  return parseStrictAuthorityJson(source);
};

const readCapabilityAuthority = async (profile: Readonly<Phase1Profile>) => {
  const [documentSource, manifestSource] = await Promise.all([
    readFile(path.join(defaultLogtoRoot, 'compatibility/phases/phase-1-capabilities.json'), 'utf8'),
    readFile(path.join(defaultLogtoRoot, 'compatibility/baseline-manifest.json'), 'utf8'),
  ]);
  const document = parseStrictAuthorityJson(documentSource);
  const manifest = parseStrictAuthorityJson(manifestSource) as CapabilityManifest;
  assertPhase1CapabilityDocument(document, profile, manifest);
  const parsed = parsePhase1CapabilityDocument(document, profile, manifest);

  return new Set(parsed.baselineCapabilityIds);
};

const defaultPrepareDependencies = (): Phase1ReviewPreparationDependencies => {
  return {
    inspectGitFile,
    logtoRoot: defaultLogtoRoot,
    loadDesignBundle: async (profileBytes, schemaBytes) =>
      createPhase1DesignProfileBundleFromBytes(profileBytes, schemaBytes, phase1ProfileSchemaLock),
    loadBaselineCapabilityIds: readCapabilityAuthority,
    assertSemantics: (profile, baselineCapabilityIds) => {
      assertPhase1ProfileSemantics(profile, semanticContext(baselineCapabilityIds));
    },
    validatePreparedBytes: async (profileBytes, schemaBytes, baselineCapabilityIds) =>
      createPhase1ProfileBundleFromBytes(profileBytes, schemaBytes, phase1ProfileSchemaLock, {
        assertSemantics: (profile) => {
          assertPhase1ProfileSemantics(profile, semanticContext(baselineCapabilityIds));
        },
      }),
    publish: async (outputPath, capability) => {
      const bundle = consumePreparedReviewCapability(capability);
      const value = snapshotClosedDataGraph<unknown>(bundle.profile);

      if (value === undefined) {
        throw new Error(preparationFailureDiagnostic);
      }
      return writeSecureJsonArtifact(outputPath, value as never);
    },
    rollback: rollbackSecureJsonArtifact,
    loadPublishedBundle: async (profilePath, schemaBytes, baselineCapabilityIds) =>
      createPhase1ProfileBundleFromBytes(
        await readFile(profilePath),
        schemaBytes,
        phase1ProfileSchemaLock,
        {
          assertSemantics: (profile) => {
            assertPhase1ProfileSemantics(profile, semanticContext(baselineCapabilityIds));
          },
        }
      ),
  };
};

const preparePhase1ReviewProfileWithDependencies = async (
  command: Phase1PrepareReviewProfileCommand,
  dependencies: Phase1ReviewPreparationDependencies
): Promise<void> => {
  let publication: SecureJsonPublication | undefined;

  try {
    const [profileAuthority, schemaAuthority] = await Promise.all([
      dependencies.inspectGitFile(command.sourceProfilePath),
      dependencies.inspectGitFile(command.schemaPath),
    ]);
    const logtoRoot = await realpath(dependencies.logtoRoot);

    if (
      profileAuthority.root !== schemaAuthority.root ||
      profileAuthority.root === logtoRoot ||
      profileAuthority.head !== schemaAuthority.head ||
      profileAuthority.head !== phase1ReviewSourceCommit ||
      profileAuthority.originUrl !== schemaAuthority.originUrl ||
      !canonicalAsterOrigins.has(profileAuthority.originUrl) ||
      !commitPattern.test(profileAuthority.blobId) ||
      !commitPattern.test(schemaAuthority.blobId) ||
      profileAuthority.bytes.length === 0 ||
      schemaAuthority.bytes.length === 0 ||
      profileAuthority.relativePath !== sourceProfileRelativePath ||
      schemaAuthority.relativePath !== sourceSchemaRelativePath ||
      !profileAuthority.clean ||
      !schemaAuthority.clean
    ) {
      throw new Error(preparationFailureDiagnostic);
    }
    await Promise.all([
      assertStableOwnedInput(command.sourceProfilePath),
      assertStableOwnedInput(command.schemaPath),
    ]);
    const outputParent = path.dirname(command.outputPath);
    const outputParentState = await lstat(outputParent);
    const outputParentReal = await realpath(outputParent);

    if (
      !path.isAbsolute(command.outputPath) ||
      path.resolve(command.outputPath) !== command.outputPath ||
      outputParentReal !== outputParent ||
      outputParentState.isSymbolicLink() ||
      !outputParentState.isDirectory() ||
      outputParentState.mode % 0o1000 !== 0o700 ||
      (typeof process.getuid === 'function' && outputParentState.uid !== process.getuid()) ||
      pathIsInside(profileAuthority.root, command.outputPath) ||
      pathIsInside(logtoRoot, command.outputPath)
    ) {
      throw new Error(preparationFailureDiagnostic);
    }
    const logtoAuthority = await dependencies.inspectGitFile(
      path.join(logtoRoot, 'packages/integration-tests/package.json')
    );

    if (!logtoAuthority.clean || logtoAuthority.head !== command.harnessCommit) {
      throw new Error(preparationFailureDiagnostic);
    }
    const source = await dependencies.loadDesignBundle(
      profileAuthority.bytes,
      schemaAuthority.bytes
    );
    assertReviewSource(source.profile);
    const baselineCapabilityIds = await dependencies.loadBaselineCapabilityIds(source.profile);
    dependencies.assertSemantics(source.profile, baselineCapabilityIds);
    if (
      source.schemaSha256 !== phase1ProfileSchemaLock.sha256 ||
      source.schemaSha256 !== phase1SchemaLockDocument.schemaSha256 ||
      phase1ProfileSchemaLock.sourceCommit !== phase1SchemaLockDocument.schemaSourceCommit
    ) {
      throw new Error(preparationFailureDiagnostic);
    }
    const prepared = structuredClone(source.profile) as Phase1Profile;
    Object.assign(prepared.profileSchema, {
      sourceCommit: phase1ProfileSchemaLock.sourceCommit,
      sha256: source.schemaSha256,
      lockState: profileSchemaLockState,
    });
    Object.assign(prepared.phase1Harness, {
      commit: command.harnessCommit,
      lockState: harnessLockState,
    });
    const preparedBytes = Buffer.from(`${JSON.stringify(prepared)}\n`, 'utf8');
    const validated = await dependencies.validatePreparedBytes(
      preparedBytes,
      source.readSchemaBytes(),
      baselineCapabilityIds
    );
    const [profileAfter, schemaAfter, logtoAfter] = await Promise.all([
      dependencies.inspectGitFile(command.sourceProfilePath),
      dependencies.inspectGitFile(command.schemaPath),
      dependencies.inspectGitFile(path.join(logtoRoot, 'packages/integration-tests/package.json')),
    ]);

    if (
      !sameGitAuthority(profileAuthority, profileAfter) ||
      !sameGitAuthority(schemaAuthority, schemaAfter) ||
      !sameGitAuthority(logtoAuthority, logtoAfter)
    ) {
      throw new Error(preparationFailureDiagnostic);
    }
    publication = await dependencies.publish(
      command.outputPath,
      mintPreparedReviewCapability(validated)
    );
    const written = await dependencies.loadPublishedBundle(
      command.outputPath,
      schemaAuthority.bytes,
      baselineCapabilityIds
    );

    if (
      written.profileSha256 !== createHash('sha256').update(preparedBytes).digest('hex') ||
      written.schemaSha256 !== source.schemaSha256 ||
      written.profile.phase1Harness.commit !== command.harnessCommit
    ) {
      throw new Error(preparationFailureDiagnostic);
    }
  } catch {
    if (publication) {
      await dependencies.rollback(publication).catch(() => {});
    }
    throw new Error(preparationFailureDiagnostic);
  }
};

export const preparePhase1ReviewProfile = async (
  command: Phase1PrepareReviewProfileCommand
): Promise<void> =>
  preparePhase1ReviewProfileWithDependencies(command, defaultPrepareDependencies());

export const preparePhase1ReviewProfileForTesting = async (
  command: Phase1PrepareReviewProfileCommand,
  dependencies: Phase1ReviewPreparationDependencies
): Promise<void> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new Error(preparationFailureDiagnostic);
  }

  return preparePhase1ReviewProfileWithDependencies(command, dependencies);
};

const closeReviewProvenance = (
  provenance: Phase1ProvenanceResult,
  harnessCommit: string | undefined
): Phase1ProvenanceResult => {
  const snapshot = snapshotClosedDataGraph<Phase1ProvenanceResult>(provenance);

  if (
    !snapshot ||
    snapshot.kind !== 'review-candidate' ||
    snapshot.harnessCommit !== harnessCommit ||
    Reflect.ownKeys(snapshot).length !== 3
  ) {
    throw new Error(runFailureDiagnostic);
  }

  return snapshot;
};

const loadRunBundle = async (command: Phase1RunCommand) => {
  const bundle = await createPhase1ProfileBundleLoader(phase1ProfileSchemaLock)({
    profilePath: command.profilePath,
    schemaPath: command.schemaPath,
  });
  const baselineCapabilityIds = await readCapabilityAuthority(bundle.profile);
  assertPhase1ProfileSemantics(bundle.profile, semanticContext(baselineCapabilityIds));

  return Object.freeze({ bundle, baselineCapabilityIds });
};

export const phase1BrowserSourceEvidence = Object.freeze(
  canonicalBrowserSourcePaths.map((sourcePath) =>
    Object.freeze({ commit: oracleCommit, path: sourcePath })
  )
);
export const phase1RegistrySourceEvidence = Object.freeze([
  ...new Map(
    [
      ...phase1DifferentialScenarios.flatMap(({ sourceEvidence }) => sourceEvidence),
      ...phase1BrowserSourceEvidence,
    ].map((source) => [
      `${source.commit}\u0000${source.path}`,
      Object.freeze({ commit: source.commit, path: source.path }),
    ])
  ).values(),
]);

const verifyRunProvenance = async (
  command: Phase1RunCommand,
  bundle: Phase1ProfileBundle,
  baselineCapabilityIds: ReadonlySet<string>
) => {
  const gitReader = createProductionPhase1GitReader({
    [bundle.profile.phase1Harness.repository]: defaultLogtoRoot,
  });

  return verifyPhase1ProfileProvenance(bundle.profile, {
    mode:
      command.command === 'run-differential' || command.mode === 'review-candidate'
        ? 'review-candidate'
        : 'accepted-harness',
    schemaBytes: bundle.readSchemaBytes(),
    profileLock: phase1ProfileSchemaLock,
    schemaLockDocument: phase1SchemaLockDocument,
    baselineCapabilityIds,
    browserSourceEvidence: phase1BrowserSourceEvidence,
    registrySourceEvidence: phase1RegistrySourceEvidence,
    phase0EvidenceReproducer: reproducePhase0Evidence,
    gitReader,
    githubReader: createProductionPhase1GithubReader(),
  });
};

const defaultDependencies: Phase1CliDependencies = {
  loadRunBundle,
  verifyRunProvenance,
  authorizeProtectedExecution: authorizePhase1ProtectedExecution,
  executeRun: async (authorization) => {
    await executeAuthorizedPhase1Run(authorization, defaultLogtoRoot);
  },
  executeDifferential: async (authorization) => {
    await executeAuthorizedPhase1DifferentialGate(authorization, defaultLogtoRoot);
  },
  prepareReviewProfile: preparePhase1ReviewProfile,
  stdout: (message) => {
    console.log(message);
  },
  stderr: (message) => {
    console.error(message);
  },
};

export const runPhase1Cli = async (
  arguments_: readonly string[] = process.argv.slice(2),
  injectedDependencies: Partial<Phase1CliDependencies> = {}
): Promise<number> => {
  let command: Phase1CliCommand;

  try {
    command = parsePhase1Arguments(arguments_[0] === '--' ? arguments_.slice(1) : arguments_);
  } catch {
    await writeStatus(
      injectedDependencies.stderr ?? defaultDependencies.stderr,
      invalidArgumentsDiagnostic
    );
    return 1;
  }
  const dependencies = { ...defaultDependencies, ...injectedDependencies };

  if (command.command === 'prepare-review-profile') {
    try {
      await dependencies.prepareReviewProfile(command);
      await writeStatus(dependencies.stdout, 'Phase 1 review profile prepared.');
      return 0;
    } catch {
      await writeStatus(dependencies.stderr, preparationFailureDiagnostic);
      return 1;
    }
  }

  try {
    const { bundle, baselineCapabilityIds } = await dependencies.loadRunBundle(command);
    const provenance = await dependencies.verifyRunProvenance(
      command,
      bundle,
      baselineCapabilityIds
    );
    const closedProvenance =
      command.command === 'run-differential' || command.mode === 'review-candidate'
        ? closeReviewProvenance(provenance, bundle.profile.phase1Harness.commit ?? undefined)
        : provenance;
    const protectedExecution =
      command.command === 'run-differential' || command.mode === 'review-candidate'
        ? undefined
        : dependencies.authorizeProtectedExecution(command.mode, closedProvenance);
    const authorization = mintPhase1RunAuthorization(
      Object.freeze({
        mode: command.mode,
        profile: bundle.profile,
        profileSha256: bundle.profileSha256,
        schemaSha256: bundle.schemaSha256,
        provenance: closedProvenance,
        protectedExecution,
        controls: command.controls,
        ...(command.command === 'run-differential' && { differentialGate: true as const }),
      } satisfies Phase1RunAuthorization)
    );
    if (command.command === 'run-differential') {
      await dependencies.executeDifferential(authorization, command);
      await writeStatus(dependencies.stdout, 'Phase 1 differential gate authorized.');
    } else {
      await dependencies.executeRun(authorization, command);
      await writeStatus(dependencies.stdout, 'Phase 1 run authorized.');
    }
    return 0;
  } catch {
    await writeStatus(dependencies.stderr, runFailureDiagnostic);
    return 1;
  }
};

const isMainModule =
  process.argv[1]?.replaceAll('\\', '/').endsWith('/compatibility/phase-1/cli.js') === true;

if (isMainModule) {
  const exitCode = await runPhase1Cli();

  if (exitCode !== 0) {
    process.exitCode = exitCode;
  }
}

/* eslint-enable max-lines, complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-assign, no-restricted-syntax, @typescript-eslint/no-empty-function, @typescript-eslint/no-unnecessary-condition */
