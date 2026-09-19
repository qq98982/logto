/* eslint-disable max-lines, complexity, no-control-regex, no-restricted-syntax, no-await-in-loop, unicorn/prevent-abbreviations, unicorn/no-array-for-each, unicorn/escape-case, @typescript-eslint/consistent-type-definitions, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/promise-function-async, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This is the closed bounded provenance boundary; sequential Git object checks and exact external field names are part of the audited contract. */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual, promisify } from 'node:util';

import { getNodeValue, parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import { compareJson } from '../../compare.js';
import { assertEvidenceIsSanitized, negativeControlEvidenceGuard } from '../../evidence.js';
import { runEvidenceGuard, scenarioEvidenceGuard } from '../../model.js';
import {
  assertPhase1IntegrationLockAuthority,
  assertPhase1IntegrationManifestDelta,
  Phase1PackageAuthorityError,
} from '../package-authority.js';
import type {
  Phase1Profile,
  Phase1ProfileSchemaLock,
  Phase1ProvenanceMode,
} from '../profile-types.js';
import { Phase1ProfileValidationError, type Phase1SchemaLockDocument } from '../profile.js';
import { evaluatePhase1WorkflowPolicy, Phase1WorkflowPolicyError } from '../workflow-policy.js';

const oracleCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const phase0HarnessCommit = '40135e37201f36ac05ece1eff82e37bb6d9649f1';
const maximumReaderBytes = 1024 * 1024;
const maximumAuthorityItems = 1000;
const maximumGitDeltaItems = 4096;
// Canonical Phase 0-to-combined-harness/client status, path, and mode set.
const reviewedCombinedDeltaSha256 =
  '13a2c534e95d958563a61b312205b6b59012e354f4b6474e3c54348ab46136d2';
const commitPattern = /^[\da-f]{40}$/u;
const sha256Pattern = /^[\da-f]{64}$/u;
const repositoryPathPattern = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*[\u0000-\u001f\u007f]).+$/u;
const privatePhase0EvidencePath = 'compatibility/phase-0-evidence';
const regularFileMode = '100644';
const executableFileMode = '100755';
const missingFileMode = '000000';
const integrationManifestPath = 'packages/integration-tests/package.json';
const integrationLockPath = 'pnpm-lock.yaml';
const compatibilityWorkflowPath = '.github/workflows/compatibility-test.yml';
const phase1WorkflowPath = '.github/workflows/phase1-compatibility-test.yml';

const governanceDeltaPaths = Object.freeze([
  '.github/CODEOWNERS',
  '.github/workflows/alteration-compatibility-integration-test.yml',
  '.github/workflows/changesets.yml',
  '.github/workflows/close-stale.yml',
  '.github/workflows/codeql-analysis.yml',
  '.github/workflows/commitlint.yml',
  '.github/workflows/compatibility-test.yml',
  '.github/workflows/integration-test.yml',
  '.github/workflows/main.yml',
  '.github/workflows/master-codecov-report.yml',
  '.github/workflows/pen-tests.yml',
  '.github/workflows/release.yml',
  '.github/workflows/repository-dispatch.yml',
  '.github/workflows/rerun.yml',
  '.github/workflows/update-pr-metadata.yml',
] as const);
const deletedGovernanceWorkflowPaths: ReadonlySet<string> = new Set(
  governanceDeltaPaths
    .slice(1)
    .filter((path) => path !== '.github/workflows/compatibility-test.yml')
);
const governanceDeltaPathSet: ReadonlySet<string> = new Set(governanceDeltaPaths);
const requiredFeaturePaths = Object.freeze({
  '.github/workflows/phase1-compatibility-test.yml': 'regular-added',
  '.scripts/compatibility/phase1-conformance-driver.sh': 'executable-added',
  '.scripts/compatibility/phase1-reference-state-driver.sh': 'executable-added',
  '.scripts/compatibility/run-phase1-conformance.sh': 'executable-added',
  '.scripts/compatibility/run-phase1.sh': 'executable-added',
  'compatibility/phase-1-schema-lock.json': 'regular-added',
  'compatibility/phases/phase-1-capabilities.json': 'regular-added',
  'docker-compose.phase1-compatibility.yml': 'regular-added',
  [integrationManifestPath]: 'regular-modified',
  [integrationLockPath]: 'regular-modified',
} as const);
const featurePrefixes = Object.freeze([
  'compatibility/phase-1-acceptance/',
  'packages/integration-tests/src/compatibility/phase-1/',
]);

export type Phase1SourceEvidenceRef = Readonly<{
  commit: typeof oracleCommit | typeof phase0HarnessCommit;
  path: string;
}>;

export type Phase0EvidenceFileName =
  | 'discovery.json'
  | 'negative-control.json'
  | 'password-code.json'
  | 'run.json';
export type Phase0EvidenceReproductionRequest = Readonly<{
  repository: string;
  commit: typeof phase0HarnessCommit;
  lifecyclePath: '.scripts/compatibility/run.sh';
  files: readonly ['discovery.json', 'negative-control.json', 'password-code.json', 'run.json'];
}>;
export type Phase0EvidenceReproduction = Readonly<{
  commit: typeof phase0HarnessCommit;
  files: ReadonlyArray<Readonly<{ name: Phase0EvidenceFileName; bytes: Uint8Array }>>;
}>;
export type Phase0EvidenceReproducer = (
  request: Phase0EvidenceReproductionRequest
) => Promise<Phase0EvidenceReproduction>;

export type Phase1CommitAvailability = 'complete' | 'shallow' | 'missing';
export type Phase1GitObjectKind = 'blob' | 'tree' | 'missing';
export type Phase1GitDeltaEntry = Readonly<{
  status: 'added' | 'modified' | 'deleted' | 'type-changed';
  path: string;
  oldMode: string;
  newMode: string;
}>;

const expectedGovernanceDelta = Object.freeze(
  governanceDeltaPaths.map(
    (path): Phase1GitDeltaEntry =>
      Object.freeze(
        deletedGovernanceWorkflowPaths.has(path)
          ? {
              status: 'deleted' as const,
              path,
              oldMode: regularFileMode,
              newMode: missingFileMode,
            }
          : {
              status: 'modified' as const,
              path,
              oldMode: regularFileMode,
              newMode: regularFileMode,
            }
      )
  )
);

export interface Phase1GitReader {
  ensureFullCommit: (repository: string, commit: string) => Promise<Phase1CommitAvailability>;
  readBlob: (repository: string, commit: string, path: string) => Promise<Uint8Array>;
  objectId: (repository: string, commit: string, path: string) => Promise<string>;
  objectKind: (repository: string, commit: string, path: string) => Promise<Phase1GitObjectKind>;
  parents: (repository: string, commit: string) => Promise<readonly string[]>;
  isAncestor: (repository: string, ancestor: string, descendant: string) => Promise<boolean>;
  localState: (repository: string) => Promise<Readonly<{ head: string; clean: boolean }>>;
  remoteContains: (repository: string, branch: string, commit: string) => Promise<boolean>;
  diffEntries: (
    repository: string,
    fromCommit: string,
    toCommit: string
  ) => Promise<readonly Phase1GitDeltaEntry[]>;
}

export type Phase1Approval = Readonly<{
  reviewer: string;
  state: 'APPROVED' | 'CHANGES_REQUESTED' | 'DISMISSED';
  commit: string;
}>;

export type Phase1Check = Readonly<{
  name: string;
  conclusion: 'success' | 'neutral' | 'skipped' | 'failure' | 'cancelled' | 'timed_out';
  headSha: string;
}>;

export type Phase1AcceptedHarnessPullRequest = Readonly<{
  number: number;
  state: 'closed';
  author: string;
  mergeCommit: string;
  headCommit: string;
  evaluatedCommit: string;
  baseCommit: string;
  baseBranch: string;
  approvals: readonly Phase1Approval[];
  requiredChecks: readonly string[];
  checks: readonly Phase1Check[];
}>;

export type Phase1AcceptedHarnessAuthority = Readonly<{
  pullRequests: readonly Phase1AcceptedHarnessPullRequest[];
}>;

export interface Phase1GithubReader {
  acceptedHarnessAuthority: (
    repository: string,
    commit: string
  ) => Promise<Phase1AcceptedHarnessAuthority>;
}

export interface Phase1ProvenanceContext {
  mode: Phase1ProvenanceMode;
  schemaBytes: Uint8Array;
  profileLock: Phase1ProfileSchemaLock;
  schemaLockDocument: Phase1SchemaLockDocument;
  baselineCapabilityIds: ReadonlySet<string>;
  browserSourceEvidence: readonly Phase1SourceEvidenceRef[];
  registrySourceEvidence: readonly Phase1SourceEvidenceRef[];
  phase0EvidenceReproducer: Phase0EvidenceReproducer;
  gitReader: Phase1GitReader;
  githubReader: Phase1GithubReader;
}

export type Phase1ReviewCandidateProvenance = Readonly<{
  kind: 'review-candidate';
  harnessCommit: string;
  publishable: false;
}>;

export type Phase1AcceptedHarnessProvenance = Readonly<{
  kind: 'accepted-harness';
  harnessCommit: string;
  protectedBranch: string;
  pullRequestNumber: number;
  publishable: true;
}>;

export type Phase1ProvenanceResult =
  | Phase1ReviewCandidateProvenance
  | Phase1AcceptedHarnessProvenance;

export type Phase1ProtectedExecutionMode = 'mirror-control' | 'runtime-candidate';
export type Phase1ProtectedExecutionAuthorization = Readonly<{
  mode: Phase1ProtectedExecutionMode;
  provenance: Phase1AcceptedHarnessProvenance;
}>;

export type Phase1CommandRequest = Readonly<{
  command: 'git';
  args: readonly string[];
  cwd: string;
  maximumBytes: number;
  environment: Readonly<Record<string, string | undefined>>;
}>;

export type Phase1CommandRunner = (request: Phase1CommandRequest) => Promise<Uint8Array>;

const acceptedProvenanceResults = new WeakSet<object>();
const trustedProvenanceErrors = new WeakSet<object>();
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

const fail = (pointer: string, rule: string): never => {
  const error = new Phase1ProfileValidationError('provenance', [pointer], [rule]);
  trustedProvenanceErrors.add(error);
  Object.freeze(error);
  throw error;
};

const consumeTrustedProvenanceError = (error: unknown): error is Phase1ProfileValidationError =>
  typeof error === 'object' && error !== null && trustedProvenanceErrors.delete(error);

const requireValue = <Value>(value: Value, pointer: string, rule: string): NonNullable<Value> =>
  value === undefined || value === null ? fail(pointer, rule) : (value as NonNullable<Value>);

const escapePointerToken = (value: string) => value.replaceAll('~', '~0').replaceAll('/', '~1');
const hashSha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const exactKeys = (value: object, keys: readonly string[]) => {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();

  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
};

const assertRepositoryPath = (path: string, pointer: string): void => {
  const segments = path.split('/');

  if (
    !repositoryPathPattern.test(path) ||
    segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    fail(pointer, 'repository-path');
  }
};

const assertPublicGitObjectPath = (path: string, pointer: string): void => {
  const policyPath = path
    .split('/')
    .filter((segment) => segment.length > 0 && segment !== '.')
    .join('/');

  if (
    policyPath === privatePhase0EvidencePath ||
    policyPath.startsWith(`${privatePhase0EvidencePath}/`)
  ) {
    fail(pointer, 'phase0-private-evidence-path');
  }

  assertRepositoryPath(path, pointer);
};

const snapshotGitDeltaEntries = (
  value: unknown,
  pointer: string,
  rule: string
): readonly Phase1GitDeltaEntry[] => {
  if (!Array.isArray(value) || value.length > maximumGitDeltaItems) {
    return fail(pointer, rule);
  }
  const entries: Phase1GitDeltaEntry[] = [];
  const paths = new Set<string>();
  const candidates = value as unknown[];

  for (const candidate of candidates) {
    if (
      typeof candidate !== 'object' ||
      candidate === null ||
      Array.isArray(candidate) ||
      !exactKeys(candidate, ['status', 'path', 'oldMode', 'newMode'])
    ) {
      return fail(pointer, rule);
    }
    const entry = candidate as Record<string, unknown>;

    if (
      (entry.status !== 'added' &&
        entry.status !== 'modified' &&
        entry.status !== 'deleted' &&
        entry.status !== 'type-changed') ||
      typeof entry.path !== 'string' ||
      typeof entry.oldMode !== 'string' ||
      typeof entry.newMode !== 'string' ||
      !/^[0-7]{6}$/u.test(entry.oldMode) ||
      !/^[0-7]{6}$/u.test(entry.newMode) ||
      paths.has(entry.path)
    ) {
      return fail(pointer, rule);
    }
    assertRepositoryPath(entry.path, pointer);
    paths.add(entry.path);
    entries.push(
      Object.freeze({
        status: entry.status,
        path: entry.path,
        oldMode: entry.oldMode,
        newMode: entry.newMode,
      })
    );
  }
  entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));

  return Object.freeze(entries);
};

type FeaturePathContract = (typeof requiredFeaturePaths)[keyof typeof requiredFeaturePaths];

const matchesFeaturePathContract = (
  entry: Phase1GitDeltaEntry,
  contract: FeaturePathContract
): boolean =>
  contract === 'executable-added'
    ? entry.status === 'added' &&
      entry.oldMode === missingFileMode &&
      entry.newMode === executableFileMode
    : contract === 'regular-added'
      ? entry.status === 'added' &&
        entry.oldMode === missingFileMode &&
        entry.newMode === regularFileMode
      : entry.status === 'modified' &&
        entry.oldMode === regularFileMode &&
        entry.newMode === regularFileMode;

const featureDeltaIsValid = (entries: readonly Phase1GitDeltaEntry[]): boolean => {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));

  if (
    Object.entries(requiredFeaturePaths).some(([path, contract]) => {
      const entry = byPath.get(path);

      return !entry || !matchesFeaturePathContract(entry, contract);
    })
  ) {
    return false;
  }

  return entries.every((entry) => {
    const contract = requiredFeaturePaths[entry.path as keyof typeof requiredFeaturePaths];

    if (contract !== undefined) {
      return matchesFeaturePathContract(entry, contract);
    }

    return (
      featurePrefixes.some((prefix) => entry.path.startsWith(prefix)) &&
      entry.status === 'added' &&
      entry.oldMode === missingFileMode &&
      entry.newMode === regularFileMode
    );
  });
};

const assertReviewHarnessDelta = (value: unknown): 'prebootstrap' | 'rebased' => {
  const entries = snapshotGitDeltaEntries(value, '/phase1Harness/commit', 'review-harness-delta');
  const governance = entries.filter(({ path }) => governanceDeltaPathSet.has(path));
  const feature = entries.filter(({ path }) => !governanceDeltaPathSet.has(path));
  const pureHarnessDelta =
    featureDeltaIsValid(feature) &&
    governance.every((entry) =>
      expectedGovernanceDelta.some((allowed) => isDeepStrictEqual(entry, allowed))
    );

  if (
    !pureHarnessDelta &&
    hashSha256(Buffer.from(JSON.stringify(entries))) !== reviewedCombinedDeltaSha256
  ) {
    fail('/phase1Harness/commit', 'review-harness-delta');
  }

  return pureHarnessDelta && governance.length === 0 ? 'prebootstrap' : 'rebased';
};

const readBoundedBlob = async ({
  gitReader,
  repository,
  commit,
  path,
  pointer,
}: Readonly<{
  gitReader: Phase1GitReader;
  repository: string;
  commit: string;
  path: string;
  pointer: string;
}>): Promise<Uint8Array> => {
  assertPublicGitObjectPath(path, pointer);
  const bytes = await gitReader.readBlob(repository, commit, path);

  if (!(bytes instanceof Uint8Array) || bytes.byteLength > maximumReaderBytes) {
    fail(pointer, 'git-reader-bound');
  }

  return bytes;
};

type GitObjectRead = Readonly<{
  gitReader: Phase1GitReader;
  repository: string;
  commit: string;
  path: string;
  pointer: string;
}>;

const readObjectId = async ({
  gitReader,
  repository,
  commit,
  path,
  pointer,
}: GitObjectRead): Promise<string> => {
  assertPublicGitObjectPath(path, pointer);

  return gitReader.objectId(repository, commit, path);
};

const readObjectKind = async ({
  gitReader,
  repository,
  commit,
  path,
  pointer,
}: GitObjectRead): Promise<Phase1GitObjectKind> => {
  assertPublicGitObjectPath(path, pointer);

  return gitReader.objectKind(repository, commit, path);
};

type ProfileSource = Readonly<{ path: string; pointer: string }>;

const collectProfileSources = (profile: Phase1Profile): readonly ProfileSource[] => [
  ...profile.browserFlows.flatMap((flow, flowIndex) =>
    flow.sourceEvidence.map((path, sourceIndex) => ({
      path,
      pointer: `/browserFlows/${flowIndex}/sourceEvidence/${sourceIndex}`,
    }))
  ),
  ...profile.consoleOrganizationTokenRequest.sourceEvidence.map((path, sourceIndex) => ({
    path,
    pointer: `/consoleOrganizationTokenRequest/sourceEvidence/${sourceIndex}`,
  })),
  ...profile.interactionOperations.flatMap((operation, operationIndex) =>
    operation.sourceEvidence.map((path, sourceIndex) => ({
      path,
      pointer: `/interactionOperations/${operationIndex}/sourceEvidence/${sourceIndex}`,
    }))
  ),
];

const uniqueProfileSources = (sources: readonly ProfileSource[]): readonly ProfileSource[] => {
  const firstByPath = new Map<string, ProfileSource>();

  for (const source of sources) {
    assertPublicGitObjectPath(source.path, source.pointer);

    if (!firstByPath.has(source.path)) {
      firstByPath.set(source.path, source);
    }
  }

  if (firstByPath.size !== 31) {
    fail(sources.at(-1)?.pointer ?? '/sourceEvidence', 'profile-source-path-count');
  }

  return [...firstByPath.values()];
};

const assertLockRelationships = (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext
): string => {
  const harnessCommit = profile.phase1Harness.commit;

  if (harnessCommit === null || !commitPattern.test(harnessCommit)) {
    fail('/phase1Harness/commit', 'harness-lock');
  }
  const lockedHarnessCommit = requireValue(harnessCommit, '/phase1Harness/commit', 'harness-lock');

  if (profile.reference.oracleCommit !== oracleCommit) {
    fail('/reference/oracleCommit', 'oracle-commit-lock');
  }

  if (profile.reference.oracleCommit !== profile.uiSource.commit) {
    fail('/reference/oracleCommit', 'oracle-ui-lock');
  }

  if (profile.reference.phase0HarnessCommit !== phase0HarnessCommit) {
    fail('/reference/phase0HarnessCommit', 'phase0-commit-lock');
  }

  if (profile.reference.phase0HarnessCommit !== profile.phase1Harness.baseCommit) {
    fail('/reference/phase0HarnessCommit', 'phase0-base-lock');
  }

  if (
    profile.reference.oracleRepository !== profile.uiSource.repository ||
    profile.reference.oracleRepository !== profile.phase1Harness.repository
  ) {
    fail('/uiSource/repository', 'repository-lock');
  }

  if (profile.reference.phase0EvidencePath !== 'compatibility/phase-0-evidence') {
    fail('/reference/phase0EvidencePath', 'phase0-evidence-map');
  }

  if (
    profile.profileSchema.repository !== 'aster' ||
    profile.profileSchema.path !== 'compatibility/phase-1-profile.schema.json'
  ) {
    fail('/profileSchema/path', 'schema-lock');
  }

  if (profile.phase1Harness.plannedBranch !== 'aster-phase1-harness') {
    fail('/phase1Harness/plannedBranch', 'protected-branch-lock');
  }

  const schemaSha256 = hashSha256(context.schemaBytes);
  const schemaCommit = profile.profileSchema.sourceCommit;
  const profileSchemaSha256 = profile.profileSchema.sha256;
  const lockedSchemaCommit = requireValue(
    typeof schemaCommit === 'string' ? schemaCommit : undefined,
    '/profileSchema/sourceCommit',
    'schema-lock'
  );

  if (
    profileSchemaSha256 === null ||
    profileSchemaSha256 !== schemaSha256 ||
    profileSchemaSha256 !== context.profileLock.sha256 ||
    profileSchemaSha256 !== context.schemaLockDocument.schemaSha256
  ) {
    fail('/profileSchema/sha256', 'schema-lock');
  }

  if (
    lockedSchemaCommit !== context.profileLock.sourceCommit ||
    lockedSchemaCommit !== context.schemaLockDocument.schemaSourceCommit
  ) {
    fail('/profileSchema/sourceCommit', 'schema-lock');
  }

  if (
    context.schemaLockDocument.phase0BaseCommit !== profile.phase1Harness.baseCommit ||
    context.schemaLockDocument.schemaVersion !== 1
  ) {
    fail('/phase1Harness/baseCommit', 'schema-lock-document');
  }

  return lockedHarnessCommit;
};

const assertCompleteHistory = async (
  profile: Phase1Profile,
  harnessCommit: string,
  gitReader: Phase1GitReader
): Promise<void> => {
  const commits = [
    {
      repository: profile.reference.oracleRepository,
      commit: profile.reference.oracleCommit,
      pointer: '/reference/oracleCommit',
    },
    {
      repository: profile.phase1Harness.repository,
      commit: profile.phase1Harness.baseCommit,
      pointer: '/phase1Harness/baseCommit',
    },
    {
      repository: profile.phase1Harness.repository,
      commit: harnessCommit,
      pointer: '/phase1Harness/commit',
    },
  ];

  for (const entry of commits) {
    if ((await gitReader.ensureFullCommit(entry.repository, entry.commit)) !== 'complete') {
      fail(entry.pointer, 'complete-history');
    }
  }
};

const assertProfileSources = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext
): Promise<readonly ProfileSource[]> => {
  const allProfileSources = collectProfileSources(profile);
  const browserSources = [...new Set(profile.browserFlows.flatMap((flow) => flow.sourceEvidence))];

  if (browserSources.length !== 25) {
    fail('/browserFlows', 'browser-source-path-count');
  }
  const browserRefs = context.browserSourceEvidence;
  const maximumBrowserLength = Math.max(browserSources.length, browserRefs.length);

  for (let index = 0; index < maximumBrowserLength; index += 1) {
    const ref = browserRefs[index];

    if (ref?.commit !== profile.reference.oracleCommit || ref.path !== browserSources[index]) {
      const source = allProfileSources.find(({ path }) => path === browserSources[index]);
      fail(source?.pointer ?? `/browserSourceEvidence/${index}`, 'browser-source-exact-set');
    }
  }
  const sources = uniqueProfileSources(allProfileSources);

  for (const source of sources) {
    await readBoundedBlob({
      gitReader: context.gitReader,
      repository: profile.reference.oracleRepository,
      commit: profile.reference.oracleCommit,
      path: source.path,
      pointer: source.pointer,
    });
  }

  return sources;
};

const assertRegistrySources = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext,
  profileSources: readonly ProfileSource[]
): Promise<void> => {
  if (context.registrySourceEvidence.length > maximumAuthorityItems) {
    fail('/registrySourceEvidence', 'source-evidence-bound');
  }
  const registryKeys = new Set(
    context.registrySourceEvidence.map(({ commit, path }) => `${commit}\u0000${path}`)
  );

  for (const source of profileSources) {
    if (!registryKeys.has(`${profile.reference.oracleCommit}\u0000${source.path}`)) {
      fail(source.pointer, 'registry-source-coverage');
    }
  }

  const encounteredRegistryKeys = new Set<string>();

  for (const [index, ref] of context.registrySourceEvidence.entries()) {
    assertPublicGitObjectPath(ref.path, `/registrySourceEvidence/${index}/path`);
    const key = `${ref.commit}\u0000${ref.path}`;

    if (ref.commit !== oracleCommit && ref.commit !== phase0HarnessCommit) {
      fail(`/registrySourceEvidence/${index}/commit`, 'source-evidence-commit');
    }

    if (encounteredRegistryKeys.has(key)) {
      fail(`/registrySourceEvidence/${index}/path`, 'registry-source-exact-set');
    }
    encounteredRegistryKeys.add(key);

    const repository = profile.reference.oracleRepository;
    await readBoundedBlob({
      gitReader: context.gitReader,
      repository,
      commit: ref.commit,
      path: ref.path,
      pointer: `/registrySourceEvidence/${index}/path`,
    });
  }
};

const assertHttpCitations = (profile: Phase1Profile, context: Phase1ProvenanceContext): void => {
  const contracts = [
    {
      sourceEvidence: profile.consoleOrganizationTokenRequest.sourceEvidence,
      sourceCapabilities: profile.consoleOrganizationTokenRequest.sourceCapabilities,
      pointer: '/consoleOrganizationTokenRequest',
    },
    ...profile.interactionOperations.map((operation, index) => ({
      sourceEvidence: operation.sourceEvidence,
      sourceCapabilities: operation.sourceCapabilities,
      pointer: `/interactionOperations/${index}`,
    })),
  ];

  for (const contract of contracts) {
    if (contract.sourceEvidence.length === 0) {
      fail(`${contract.pointer}/sourceEvidence`, 'oracle-source-citation');
    }

    if (contract.sourceCapabilities.length === 0) {
      fail(`${contract.pointer}/sourceCapabilities`, 'phase0-capability-citation');
    }

    contract.sourceCapabilities.forEach((capability, index) => {
      if (!context.baselineCapabilityIds.has(capability)) {
        fail(`${contract.pointer}/sourceCapabilities/${index}`, 'phase0-capability-citation');
      }
    });
  }
};

const assertUiObjects = async (
  profile: Phase1Profile,
  gitReader: Phase1GitReader
): Promise<void> => {
  const expectedObjects = [
    ['packages/console', profile.uiSource.consoleTree, '/uiSource/consoleTree'],
    ['packages/experience', profile.uiSource.experienceTree, '/uiSource/experienceTree'],
    ['packages/demo-app', profile.uiSource.demoAppTree, '/uiSource/demoAppTree'],
    ['pnpm-lock.yaml', profile.uiSource.pnpmLockBlob, '/uiSource/pnpmLockBlob'],
  ] as const;

  for (const [path, expected, pointer] of expectedObjects) {
    const actual = await readObjectId({
      gitReader,
      repository: profile.reference.oracleRepository,
      commit: profile.reference.oracleCommit,
      path,
      pointer,
    });

    if (actual !== expected) {
      fail(pointer, 'ui-object-lock');
    }
  }
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const assertExactEvidenceKeys: (
  value: unknown,
  keys: readonly string[],
  pointer: string
) => asserts value is Record<string, unknown> = (value, keys, pointer) => {
  if (!isRecord(value) || !exactKeys(value, keys)) {
    fail(pointer, 'phase0-evidence-keys');
  }
};

const assertNoDuplicateJsonKeys = (node: JsonNode, pointer: string): void => {
  if (node.type === 'object') {
    const names = new Set<string>();

    for (const property of node.children ?? []) {
      const keyNode = property.children?.at(0);
      const valueNode = property.children?.at(1);
      const name: unknown = keyNode?.value;
      const stringName =
        typeof name === 'string' ? name : fail(pointer, 'phase0-strict-json-duplicate-key');

      if (names.has(stringName)) {
        fail(pointer, 'phase0-strict-json-duplicate-key');
      }

      names.add(stringName);

      if (valueNode) {
        assertNoDuplicateJsonKeys(valueNode, pointer);
      }
    }
  } else {
    for (const child of node.children ?? []) {
      assertNoDuplicateJsonKeys(child, pointer);
    }
  }
};

const parseStrictPhase0Json = (bytes: Uint8Array, name: Phase0EvidenceFileName): unknown => {
  const pointer = `/phase0Reproduction/${name}`;

  if (bytes.byteLength === 0 || (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)) {
    fail(pointer, 'phase0-strict-json');
  }
  let source: string;

  try {
    source = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  } catch {
    return fail(pointer, 'phase0-strict-json-utf8');
  }

  const errors: ParseError[] = [];
  const tree = parseTree(source, errors, {
    allowTrailingComma: false,
    disallowComments: true,
  });

  if (errors.length > 0) {
    fail(pointer, 'phase0-strict-json');
  }
  const parsedTree = requireValue(tree, pointer, 'phase0-strict-json');

  assertNoDuplicateJsonKeys(parsedTree, pointer);

  return getNodeValue(parsedTree);
};

const assertSanitizedPhase0Evidence = (value: unknown, pointer: string): void => {
  try {
    assertEvidenceIsSanitized(value);
  } catch {
    fail(pointer, 'phase0-evidence-sanitized');
  }
};

const assertValidTimestampMarkers = (value: unknown, pointer: string): void => {
  if (Array.isArray(value)) {
    value.forEach((element) => {
      assertValidTimestampMarkers(element, pointer);
    });

    return;
  }

  if (!isRecord(value)) {
    return;
  }

  const hasTimestampField = Object.hasOwn(value, '$timestamp');
  const hasToleranceField = Object.hasOwn(value, '$toleranceSeconds');

  if (hasTimestampField || hasToleranceField) {
    if (
      !exactKeys(value, ['$timestamp', '$toleranceSeconds']) ||
      typeof value.$timestamp !== 'number' ||
      !Number.isFinite(value.$timestamp) ||
      typeof value.$toleranceSeconds !== 'number' ||
      !Number.isFinite(value.$toleranceSeconds) ||
      value.$toleranceSeconds < 0
    ) {
      fail(pointer, 'phase0-scenario-timestamp-marker');
    }

    return;
  }

  for (const child of Object.values(value)) {
    assertValidTimestampMarkers(child, pointer);
  }
};

const assertScenarioEvidence = (
  value: unknown,
  name: 'discovery.json' | 'password-code.json',
  scenarioId: 'discovery' | 'password-code'
): void => {
  const pointer = `/phase0Reproduction/${name}`;
  assertExactEvidenceKeys(
    value,
    ['schemaVersion', 'scenarioId', 'oracle', 'candidate', 'differences'],
    pointer
  );
  assertExactEvidenceKeys(value.oracle, ['target', 'observations'], `${pointer}/oracle`);
  assertExactEvidenceKeys(value.candidate, ['target', 'observations'], `${pointer}/candidate`);

  if (value.schemaVersion !== 1) {
    fail(`${pointer}/schemaVersion`, 'phase0-scenario-contract');
  }

  if (value.scenarioId !== scenarioId) {
    fail(`${pointer}/scenarioId`, 'phase0-scenario-contract');
  }

  if (value.oracle.target !== 'oracle') {
    fail(`${pointer}/oracle/target`, 'phase0-scenario-contract');
  }

  if (value.candidate.target !== 'candidate') {
    fail(`${pointer}/candidate/target`, 'phase0-scenario-contract');
  }

  for (const [targetName, target] of [
    ['oracle', value.oracle],
    ['candidate', value.candidate],
  ] as const) {
    const observations = Array.isArray(target.observations)
      ? target.observations
      : fail(`${pointer}/${targetName}/observations`, 'phase0-scenario-observations');

    if (observations.length === 0) {
      fail(`${pointer}/${targetName}/observations`, 'phase0-scenario-observations');
    }

    observations.forEach((observation, index) => {
      assertExactEvidenceKeys(
        observation,
        ['stepId', 'kind', 'value'],
        `${pointer}/${targetName}/observations/${index}`
      );
      assertValidTimestampMarkers(
        observation.value,
        `${pointer}/${targetName}/observations/${index}/value`
      );
    });
  }

  const result = scenarioEvidenceGuard.safeParse(value);

  if (!result.success) {
    return fail(pointer, 'phase0-scenario-contract');
  }
  const evidence = result.data;

  if (evidence.differences.length > 0) {
    fail(`${pointer}/differences`, 'phase0-scenario-differences');
  }

  const maximumObservations = Math.max(
    evidence.oracle.observations.length,
    evidence.candidate.observations.length
  );

  for (const index of Array.from({ length: maximumObservations }, (_, candidate) => candidate)) {
    const oracleObservation = evidence.oracle.observations[index];
    const candidateObservation = evidence.candidate.observations[index];
    const resolvedOracle = requireValue(
      oracleObservation,
      `${pointer}/oracle/observations/${index}`,
      'phase0-scenario-observations'
    );
    const resolvedCandidate = requireValue(
      candidateObservation,
      `${pointer}/candidate/observations/${index}`,
      'phase0-scenario-observations'
    );

    if (
      resolvedOracle.stepId !== resolvedCandidate.stepId ||
      resolvedOracle.kind !== resolvedCandidate.kind
    ) {
      fail(`${pointer}/candidate/observations/${index}`, 'phase0-scenario-observations');
    }
  }

  const computedDifferences = compareJson(
    evidence.oracle.observations,
    evidence.candidate.observations
  );

  if (computedDifferences.length > 0) {
    fail(`${pointer}/candidate/observations`, 'phase0-scenario-comparison');
  }
};

const assertNegativeControlEvidence = (value: unknown): void => {
  const pointer = '/phase0Reproduction/negative-control.json';
  assertExactEvidenceKeys(value, ['schemaVersion', 'faultInjection', 'differencePaths'], pointer);
  if (value.schemaVersion !== 1) {
    fail(`${pointer}/schemaVersion`, 'phase0-negative-control-contract');
  }

  if (value.faultInjection !== 'discovery-issuer') {
    fail(`${pointer}/faultInjection`, 'phase0-negative-control-contract');
  }

  if (
    !Array.isArray(value.differencePaths) ||
    value.differencePaths.length !== 1 ||
    value.differencePaths[0] !== '/observations/0/value/issuer'
  ) {
    fail(`${pointer}/differencePaths`, 'phase0-negative-control-contract');
  }
  const result = negativeControlEvidenceGuard.safeParse(value);

  if (!result.success) {
    fail(pointer, 'phase0-negative-control-contract');
  }
};

const assertRunEvidence = (value: unknown): void => {
  const pointer = '/phase0Reproduction/run.json';
  assertExactEvidenceKeys(
    value,
    [
      'schemaVersion',
      'referenceCommit',
      'oracleImageDigest',
      'candidateImageDigest',
      'scenarios',
      'negativeControl',
    ],
    pointer
  );
  assertExactEvidenceKeys(value.negativeControl, ['differencePath'], `${pointer}/negativeControl`);

  if (value.schemaVersion !== 1) {
    fail(`${pointer}/schemaVersion`, 'phase0-run-contract');
  }

  if (value.referenceCommit !== oracleCommit) {
    fail(`${pointer}/referenceCommit`, 'phase0-run-contract');
  }

  if (
    typeof value.oracleImageDigest !== 'string' ||
    !/^sha256:[\da-f]{64}$/u.test(value.oracleImageDigest)
  ) {
    fail(`${pointer}/oracleImageDigest`, 'phase0-run-contract');
  }

  if (
    typeof value.candidateImageDigest !== 'string' ||
    !/^sha256:[\da-f]{64}$/u.test(value.candidateImageDigest)
  ) {
    fail(`${pointer}/candidateImageDigest`, 'phase0-run-contract');
  }

  if (Array.isArray(value.scenarios)) {
    value.scenarios.forEach((scenario, index) => {
      assertExactEvidenceKeys(
        scenario,
        ['scenarioId', 'differenceCount'],
        `${pointer}/scenarios/${index}`
      );
    });
  }

  const result = runEvidenceGuard.safeParse(value);

  if (!result.success) {
    return fail(pointer, 'phase0-run-contract');
  }
  const evidence = result.data;

  if (evidence.oracleImageDigest !== evidence.candidateImageDigest) {
    fail(`${pointer}/candidateImageDigest`, 'phase0-run-mirror-digest');
  }

  const expectedScenarios = ['discovery', 'password-code'] as const;

  if (evidence.scenarios.length !== expectedScenarios.length) {
    fail(`${pointer}/scenarios`, 'phase0-run-scenarios');
  }

  evidence.scenarios.forEach((scenario, index) => {
    if (scenario.scenarioId !== expectedScenarios[index]) {
      fail(`${pointer}/scenarios/${index}/scenarioId`, 'phase0-run-scenarios');
    }

    if (scenario.differenceCount !== 0) {
      fail(`${pointer}/scenarios/${index}/differenceCount`, 'phase0-run-scenarios');
    }
  });

  if (evidence.negativeControl.differencePath !== '/observations/0/value/issuer') {
    fail(`${pointer}/negativeControl/differencePath`, 'phase0-run-negative-control');
  }
};

const assertReproducedEvidence = (name: Phase0EvidenceFileName, bytes: Uint8Array): void => {
  const pointer = `/phase0Reproduction/${name}`;
  const value = parseStrictPhase0Json(bytes, name);
  assertSanitizedPhase0Evidence(value, pointer);

  switch (name) {
    case 'discovery.json': {
      assertScenarioEvidence(value, name, 'discovery');
      break;
    }
    case 'password-code.json': {
      assertScenarioEvidence(value, name, 'password-code');
      break;
    }
    case 'negative-control.json': {
      assertNegativeControlEvidence(value);
      break;
    }
    case 'run.json': {
      assertRunEvidence(value);
    }
  }
};

const assertPhase0Evidence = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext
): Promise<void> => {
  const expectedNames = [
    'discovery.json',
    'negative-control.json',
    'password-code.json',
    'run.json',
  ] as const;
  const hashes = profile.reference.phase0ArtifactSha256;

  if (!exactKeys(hashes, expectedNames)) {
    fail('/reference/phase0ArtifactSha256', 'phase0-evidence-map');
  }

  for (const name of expectedNames) {
    if (!sha256Pattern.test(hashes[name])) {
      fail(`/reference/phase0ArtifactSha256/${name}`, 'phase0-evidence-map');
    }
  }
  const reproduction = await context.phase0EvidenceReproducer(
    Object.freeze({
      repository: profile.reference.oracleRepository,
      commit: phase0HarnessCommit,
      lifecyclePath: '.scripts/compatibility/run.sh',
      files: Object.freeze([
        ...expectedNames,
      ]) as unknown as Phase0EvidenceReproductionRequest['files'],
    })
  );

  if (
    typeof reproduction !== 'object' ||
    reproduction === null ||
    Array.isArray(reproduction) ||
    !exactKeys(reproduction, ['commit', 'files']) ||
    !Array.isArray(reproduction.files)
  ) {
    fail('/reference/phase0ArtifactSha256', 'phase0-reproduction-result');
  }

  if (reproduction.commit !== phase0HarnessCommit) {
    fail('/reference/phase0HarnessCommit', 'phase0-reproduction-commit');
  }

  if (
    reproduction.files.length !== expectedNames.length ||
    reproduction.files.some(
      (file, index) =>
        typeof file !== 'object' ||
        file === null ||
        Array.isArray(file) ||
        !exactKeys(file, ['bytes', 'name']) ||
        file.name !== expectedNames[index]
    )
  ) {
    fail('/reference/phase0ArtifactSha256', 'phase0-reproduction-files');
  }

  for (const [index, name] of expectedNames.entries()) {
    const { bytes } = requireValue(
      reproduction.files.at(index),
      '/reference/phase0ArtifactSha256',
      'phase0-reproduction-files'
    );

    if (!(bytes instanceof Uint8Array) || bytes.byteLength > maximumReaderBytes) {
      fail(`/reference/phase0ArtifactSha256/${name}`, 'phase0-reproduction-bound');
    }
    assertReproducedEvidence(name, bytes);
  }
};

const assertArtifactsAndAuthority = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext,
  harnessCommit: string
): Promise<void> => {
  for (const [field, path] of Object.entries(profile.phase1Harness.plannedArtifacts)) {
    assertPublicGitObjectPath(path, `/phase1Harness/plannedArtifacts/${field}`);

    if (
      (await readObjectKind({
        gitReader: context.gitReader,
        repository: profile.phase1Harness.repository,
        commit: harnessCommit,
        path,
        pointer: `/phase1Harness/plannedArtifacts/${field}`,
      })) === 'missing'
    ) {
      fail(`/phase1Harness/plannedArtifacts/${field}`, 'planned-artifact');
    }
  }

  for (const [path, expectedObjectId] of Object.entries(
    context.schemaLockDocument.phase0AuthorityBlobs
  )) {
    const pointer = `/schemaLockDocument/phase0AuthorityBlobs/${escapePointerToken(path)}`;
    const actual = await readObjectId({
      gitReader: context.gitReader,
      repository: profile.phase1Harness.repository,
      commit: profile.phase1Harness.baseCommit,
      path,
      pointer,
    });

    if (actual !== expectedObjectId) {
      fail(pointer, 'phase0-authority-blob');
    }
  }

  if (
    !(await context.gitReader.isAncestor(
      profile.phase1Harness.repository,
      profile.phase1Harness.baseCommit,
      harnessCommit
    ))
  ) {
    fail('/phase1Harness/commit', 'harness-ancestry');
  }
};

const assertHarnessPackageAuthority = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext,
  harnessCommit: string
): Promise<void> => {
  const [baseManifest, harnessManifest, lockBytes] = await Promise.all([
    readBoundedBlob({
      gitReader: context.gitReader,
      repository: profile.phase1Harness.repository,
      commit: profile.phase1Harness.baseCommit,
      path: integrationManifestPath,
      pointer: '/phase1Harness/commit',
    }),
    readBoundedBlob({
      gitReader: context.gitReader,
      repository: profile.phase1Harness.repository,
      commit: harnessCommit,
      path: integrationManifestPath,
      pointer: '/phase1Harness/commit',
    }),
    readBoundedBlob({
      gitReader: context.gitReader,
      repository: profile.phase1Harness.repository,
      commit: harnessCommit,
      path: integrationLockPath,
      pointer: '/phase1Harness/commit',
    }),
  ]);

  try {
    assertPhase1IntegrationManifestDelta(baseManifest, harnessManifest);
    assertPhase1IntegrationLockAuthority(lockBytes);
  } catch (error: unknown) {
    if (error instanceof Phase1PackageAuthorityError) {
      fail('/phase1Harness/commit', 'harness-package-authority');
    }

    throw error;
  }
};

const assertHarnessWorkflowAuthority = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext,
  harnessCommit: string
): Promise<void> => {
  for (const workflowPath of deletedGovernanceWorkflowPaths) {
    if (
      (await context.gitReader.objectKind(
        profile.phase1Harness.repository,
        harnessCommit,
        workflowPath
      )) !== 'missing'
    ) {
      fail('/phase1Harness/commit', 'harness-workflow-tree');
    }
  }
  const [phase0Workflow, compatibilityWorkflow, phase1Workflow] = await Promise.all([
    readBoundedBlob({
      gitReader: context.gitReader,
      repository: profile.phase1Harness.repository,
      commit: profile.phase1Harness.baseCommit,
      path: compatibilityWorkflowPath,
      pointer: '/phase1Harness/commit',
    }),
    readBoundedBlob({
      gitReader: context.gitReader,
      repository: profile.phase1Harness.repository,
      commit: harnessCommit,
      path: compatibilityWorkflowPath,
      pointer: '/phase1Harness/commit',
    }),
    readBoundedBlob({
      gitReader: context.gitReader,
      repository: profile.phase1Harness.repository,
      commit: harnessCommit,
      path: phase1WorkflowPath,
      pointer: '/phase1Harness/commit',
    }),
  ]);
  try {
    evaluatePhase1WorkflowPolicy({
      governanceMode: 'locked',
      workflows: [
        { path: compatibilityWorkflowPath, bytes: compatibilityWorkflow },
        { path: phase1WorkflowPath, bytes: phase1Workflow },
      ],
      phase0CompatibilityWorkflow: { path: compatibilityWorkflowPath, bytes: phase0Workflow },
    });
  } catch (error: unknown) {
    if (error instanceof Phase1WorkflowPolicyError) {
      fail('/phase1Harness/commit', 'harness-workflow-authority');
    }
    throw error;
  }
};

const readClosedAuthorityArray = (value: unknown, pointer: string): readonly unknown[] => {
  if (!Array.isArray(value)) {
    fail(pointer, 'accepted-authority-projection');
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  const constructorDescriptor =
    typeof prototype === 'object' && prototype !== null
      ? Object.getOwnPropertyDescriptor(prototype, 'constructor')
      : undefined;

  if (
    !constructorDescriptor ||
    !Object.hasOwn(constructorDescriptor, 'value') ||
    typeof constructorDescriptor.value !== 'function' ||
    constructorDescriptor.value.name !== 'Array' ||
    !Function.prototype.toString.call(constructorDescriptor.value).includes('[native code]')
  ) {
    fail(pointer, 'accepted-authority-projection');
  }
  const candidate = value as unknown[];
  const lengthDescriptor = Object.getOwnPropertyDescriptor(candidate, 'length');

  if (
    !lengthDescriptor ||
    !Object.hasOwn(lengthDescriptor, 'value') ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    (lengthDescriptor.value as number) < 0 ||
    (lengthDescriptor.value as number) > maximumAuthorityItems
  ) {
    fail(pointer, 'accepted-authority-projection');
  }
  const resolvedLengthDescriptor = requireValue(
    lengthDescriptor,
    pointer,
    'accepted-authority-projection'
  );
  const length = resolvedLengthDescriptor.value as number;
  const expectedKeys = new Set(['length', ...Array.from({ length }, (_, index) => String(index))]);
  const ownKeys = Reflect.ownKeys(candidate);

  if (
    ownKeys.length !== expectedKeys.size ||
    ownKeys.some((key) => typeof key !== 'string' || !expectedKeys.has(key))
  ) {
    fail(pointer, 'accepted-authority-projection');
  }
  const items: unknown[] = [];

  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(candidate, String(index));

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      fail(pointer, 'accepted-authority-projection');
    }
    const resolvedDescriptor = requireValue(descriptor, pointer, 'accepted-authority-projection');
    items.push(resolvedDescriptor.value);
  }

  return Object.freeze(items);
};

const validateExactAuthorityProjection = (authority: Phase1AcceptedHarnessAuthority): void => {
  const approvalStates = new Set(['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED']);
  const checkConclusions = new Set([
    'success',
    'neutral',
    'skipped',
    'failure',
    'cancelled',
    'timed_out',
  ]);

  if (
    typeof authority !== 'object' ||
    authority === null ||
    Array.isArray(authority) ||
    !exactKeys(authority, ['pullRequests'])
  ) {
    fail('/phase1Harness/commit', 'accepted-authority-projection');
  }
  const pullRequests = readClosedAuthorityArray(authority.pullRequests, '/phase1Harness/commit');

  for (const pullRequest of pullRequests) {
    if (
      typeof pullRequest !== 'object' ||
      pullRequest === null ||
      Array.isArray(pullRequest) ||
      !exactKeys(pullRequest, [
        'approvals',
        'author',
        'baseBranch',
        'baseCommit',
        'checks',
        'evaluatedCommit',
        'headCommit',
        'mergeCommit',
        'number',
        'requiredChecks',
        'state',
      ])
    ) {
      fail('/phase1Harness/commit', 'accepted-authority-projection');
    }
    const projectedPullRequest = pullRequest as Phase1AcceptedHarnessPullRequest;
    const approvals = readClosedAuthorityArray(
      projectedPullRequest.approvals,
      '/phase1Harness/commit'
    );
    const checks = readClosedAuthorityArray(projectedPullRequest.checks, '/phase1Harness/commit');
    const requiredChecks = readClosedAuthorityArray(
      projectedPullRequest.requiredChecks,
      '/phase1Harness/commit'
    );

    if (
      !Number.isSafeInteger(projectedPullRequest.number) ||
      projectedPullRequest.number < 1 ||
      projectedPullRequest.state !== 'closed' ||
      typeof projectedPullRequest.author !== 'string' ||
      projectedPullRequest.author.length === 0 ||
      projectedPullRequest.author.length > 100 ||
      typeof projectedPullRequest.baseBranch !== 'string' ||
      projectedPullRequest.baseBranch.length === 0 ||
      projectedPullRequest.baseBranch.length > 255 ||
      typeof projectedPullRequest.baseCommit !== 'string' ||
      !commitPattern.test(projectedPullRequest.baseCommit) ||
      typeof projectedPullRequest.mergeCommit !== 'string' ||
      !commitPattern.test(projectedPullRequest.mergeCommit) ||
      typeof projectedPullRequest.headCommit !== 'string' ||
      !commitPattern.test(projectedPullRequest.headCommit) ||
      typeof projectedPullRequest.evaluatedCommit !== 'string' ||
      !commitPattern.test(projectedPullRequest.evaluatedCommit)
    ) {
      fail('/phase1Harness/commit', 'accepted-authority-projection');
    }

    approvals.forEach((approval) => {
      if (
        typeof approval !== 'object' ||
        approval === null ||
        Array.isArray(approval) ||
        !exactKeys(approval, ['commit', 'reviewer', 'state'])
      ) {
        fail('/phase1Harness/commit', 'accepted-authority-projection');
      }
      const projectedApproval = approval as Phase1Approval;

      if (
        typeof projectedApproval.reviewer !== 'string' ||
        projectedApproval.reviewer.length === 0 ||
        projectedApproval.reviewer.length > 100 ||
        typeof projectedApproval.state !== 'string' ||
        !approvalStates.has(projectedApproval.state) ||
        typeof projectedApproval.commit !== 'string' ||
        !commitPattern.test(projectedApproval.commit)
      ) {
        fail('/phase1Harness/commit', 'accepted-authority-projection');
      }
    });
    checks.forEach((check) => {
      if (
        typeof check !== 'object' ||
        check === null ||
        Array.isArray(check) ||
        !exactKeys(check, ['conclusion', 'headSha', 'name'])
      ) {
        fail('/phase1Harness/commit', 'accepted-authority-projection');
      }
      const projectedCheck = check as Phase1Check;

      if (
        typeof projectedCheck.name !== 'string' ||
        projectedCheck.name.length === 0 ||
        projectedCheck.name.length > 256 ||
        typeof projectedCheck.conclusion !== 'string' ||
        !checkConclusions.has(projectedCheck.conclusion) ||
        typeof projectedCheck.headSha !== 'string' ||
        !commitPattern.test(projectedCheck.headSha)
      ) {
        fail('/phase1Harness/commit', 'accepted-authority-projection');
      }
    });

    if (
      requiredChecks.some(
        (name) => typeof name !== 'string' || name.length === 0 || name.length > 256
      )
    ) {
      fail('/phase1Harness/commit', 'accepted-authority-projection');
    }
  }
};

const snapshotAuthorityProjection = (
  authority: Phase1AcceptedHarnessAuthority
): Phase1AcceptedHarnessAuthority => ({
  pullRequests: readClosedAuthorityArray(authority.pullRequests, '/phase1Harness/commit').map(
    (pullRequest) => {
      const projected = pullRequest as Phase1AcceptedHarnessPullRequest;

      return {
        number: projected.number,
        state: projected.state,
        author: projected.author,
        mergeCommit: projected.mergeCommit,
        headCommit: projected.headCommit,
        evaluatedCommit: projected.evaluatedCommit,
        baseCommit: projected.baseCommit,
        baseBranch: projected.baseBranch,
        approvals: readClosedAuthorityArray(projected.approvals, '/phase1Harness/commit').map(
          (approval) => {
            const projectedApproval = approval as Phase1Approval;

            return {
              reviewer: projectedApproval.reviewer,
              state: projectedApproval.state,
              commit: projectedApproval.commit,
            };
          }
        ),
        requiredChecks: readClosedAuthorityArray(
          projected.requiredChecks,
          '/phase1Harness/commit'
        ).map((name) => name as string),
        checks: readClosedAuthorityArray(projected.checks, '/phase1Harness/commit').map((check) => {
          const projectedCheck = check as Phase1Check;

          return {
            name: projectedCheck.name,
            conclusion: projectedCheck.conclusion,
            headSha: projectedCheck.headSha,
          };
        }),
      };
    }
  ),
});

const assertExactAuthorityProjection = (
  authority: Phase1AcceptedHarnessAuthority
): Phase1AcceptedHarnessAuthority => {
  validateExactAuthorityProjection(authority);
  const snapshot = snapshotAuthorityProjection(authority);
  validateExactAuthorityProjection(snapshot);

  return snapshot;
};

const verifyAcceptedHarness = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext,
  harnessCommit: string
): Promise<Phase1AcceptedHarnessProvenance> => {
  const protectedBranch = profile.phase1Harness.plannedBranch;

  if (
    !(await context.gitReader.remoteContains(
      profile.phase1Harness.repository,
      protectedBranch,
      harnessCommit
    ))
  ) {
    fail('/phase1Harness/commit', 'accepted-protected-reachability');
  }

  const authority = assertExactAuthorityProjection(
    await context.githubReader.acceptedHarnessAuthority(
      profile.phase1Harness.repository,
      harnessCommit
    )
  );

  if (authority.pullRequests.length !== 1) {
    fail('/phase1Harness/commit', 'accepted-merge-pr');
  }

  const pullRequest = requireValue(
    authority.pullRequests.at(0),
    '/phase1Harness/commit',
    'accepted-merge-pr'
  );

  if (
    pullRequest.state !== 'closed' ||
    pullRequest.mergeCommit !== harnessCommit ||
    pullRequest.baseBranch !== protectedBranch ||
    !Number.isSafeInteger(pullRequest.number) ||
    pullRequest.number < 1
  ) {
    fail('/phase1Harness/commit', 'accepted-merge-pr');
  }

  if (
    (await context.gitReader.ensureFullCommit(
      profile.phase1Harness.repository,
      pullRequest.baseCommit
    )) !== 'complete' ||
    !(await context.gitReader.isAncestor(
      profile.phase1Harness.repository,
      profile.phase1Harness.baseCommit,
      pullRequest.baseCommit
    )) ||
    !(await context.gitReader.isAncestor(
      profile.phase1Harness.repository,
      pullRequest.baseCommit,
      harnessCommit
    ))
  ) {
    fail('/phase1Harness/commit', 'accepted-governance-history');
  }
  const delta = await context.gitReader.diffEntries(
    profile.phase1Harness.repository,
    profile.phase1Harness.baseCommit,
    harnessCommit
  );
  assertReviewHarnessDelta(delta);
  for (const workflowPath of deletedGovernanceWorkflowPaths) {
    if (!delta.some((entry) => entry.path === workflowPath && entry.status === 'deleted')) {
      fail('/phase1Harness/commit', 'harness-workflow-tree');
    }
  }
  await assertHarnessWorkflowAuthority(profile, context, harnessCommit);

  if (
    !commitPattern.test(pullRequest.headCommit) ||
    !commitPattern.test(pullRequest.evaluatedCommit) ||
    pullRequest.evaluatedCommit === harnessCommit
  ) {
    fail('/phase1Harness/commit', 'accepted-authority-projection');
  }

  const approvalReviewers = new Set(pullRequest.approvals.map(({ reviewer }) => reviewer));

  if (
    approvalReviewers.size !== pullRequest.approvals.length ||
    pullRequest.approvals.some(({ state }) => state === 'CHANGES_REQUESTED')
  ) {
    fail('/phase1Harness/commit', 'accepted-review-approval');
  }

  const approved = pullRequest.approvals.some(
    (approval) =>
      approval.state === 'APPROVED' &&
      approval.reviewer !== pullRequest.author &&
      approval.commit === pullRequest.headCommit
  );

  if (!approved) {
    fail('/phase1Harness/commit', 'accepted-review-approval');
  }
  if (pullRequest.evaluatedCommit !== pullRequest.headCommit) {
    if (
      (await context.gitReader.ensureFullCommit(
        profile.phase1Harness.repository,
        pullRequest.evaluatedCommit
      )) !== 'complete' ||
      !(await context.gitReader.isAncestor(
        profile.phase1Harness.repository,
        pullRequest.headCommit,
        pullRequest.evaluatedCommit
      ))
    ) {
      fail('/phase1Harness/commit', 'accepted-check-commit');
    }

    const evaluationParents = await context.gitReader.parents(
      profile.phase1Harness.repository,
      pullRequest.evaluatedCommit
    );

    if (
      evaluationParents.length !== 2 ||
      !evaluationParents.includes(pullRequest.headCommit) ||
      !evaluationParents.includes(pullRequest.baseCommit)
    ) {
      fail('/phase1Harness/commit', 'accepted-check-commit');
    }
  }

  const checksByName = new Map(pullRequest.checks.map((check) => [check.name, check]));
  const uniqueRequiredChecks = new Set(pullRequest.requiredChecks);
  const uniqueCheckNames = new Set(pullRequest.checks.map(({ name }) => name));

  if (
    uniqueRequiredChecks.size === 0 ||
    uniqueRequiredChecks.size !== pullRequest.requiredChecks.length ||
    uniqueCheckNames.size !== pullRequest.checks.length ||
    pullRequest.checks.some(({ headSha }) => headSha !== pullRequest.evaluatedCommit) ||
    pullRequest.requiredChecks.some((name) => {
      const check = checksByName.get(name);

      return (
        !check || check.conclusion !== 'success' || check.headSha !== pullRequest.evaluatedCommit
      );
    })
  ) {
    fail('/phase1Harness/commit', 'accepted-required-checks');
  }

  const result: Phase1AcceptedHarnessProvenance = {
    kind: 'accepted-harness',
    harnessCommit,
    protectedBranch,
    pullRequestNumber: pullRequest.number,
    publishable: true,
  };
  acceptedProvenanceResults.add(result);

  return Object.freeze(result);
};

const verifyReviewCandidate = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext,
  harnessCommit: string
): Promise<Phase1ReviewCandidateProvenance> => {
  const localState = await context.gitReader.localState(profile.phase1Harness.repository);

  if (!exactKeys(localState, ['clean', 'head']) || localState.head !== harnessCommit) {
    fail('/phase1Harness/commit', 'review-candidate-exact-head');
  }

  if (!localState.clean) {
    fail('/phase1Harness/commit', 'review-candidate-clean');
  }
  const deltaKind = assertReviewHarnessDelta(
    await context.gitReader.diffEntries(
      profile.phase1Harness.repository,
      profile.phase1Harness.baseCommit,
      harnessCommit
    )
  );
  if (deltaKind === 'rebased') {
    await assertHarnessWorkflowAuthority(profile, context, harnessCommit);
  }

  return Object.freeze({
    kind: 'review-candidate',
    harnessCommit,
    publishable: false,
  });
};

const verifyProvenance = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext
): Promise<Phase1ProvenanceResult> => {
  if (context.mode !== 'review-candidate' && context.mode !== 'accepted-harness') {
    fail('/provenance/mode', 'provenance-mode');
  }

  const harnessCommit = assertLockRelationships(profile, context);
  await assertCompleteHistory(profile, harnessCommit, context.gitReader);
  const profileSources = await assertProfileSources(profile, context);
  await assertRegistrySources(profile, context, profileSources);
  assertHttpCitations(profile, context);
  await assertUiObjects(profile, context.gitReader);
  await assertPhase0Evidence(profile, context);
  await assertArtifactsAndAuthority(profile, context, harnessCommit);
  await assertHarnessPackageAuthority(profile, context, harnessCommit);

  return context.mode === 'accepted-harness'
    ? verifyAcceptedHarness(profile, context, harnessCommit)
    : verifyReviewCandidate(profile, context, harnessCommit);
};

export const verifyPhase1ProfileProvenance = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext
): Promise<Phase1ProvenanceResult> => {
  try {
    return await verifyProvenance(profile, context);
  } catch (error: unknown) {
    if (consumeTrustedProvenanceError(error)) {
      throw error;
    }

    return fail('/', 'provenance-reader');
  }
};

export const assertPhase1ProfileProvenance = async (
  profile: Phase1Profile,
  context: Phase1ProvenanceContext
): Promise<void> => {
  await verifyPhase1ProfileProvenance(profile, context);
};

export const requireAcceptedPhase1Provenance = (
  result: Phase1ProvenanceResult
): Phase1AcceptedHarnessProvenance => {
  if (result.kind === 'accepted-harness' && acceptedProvenanceResults.has(result)) {
    return result;
  }

  return fail('/provenance/kind', 'accepted-harness-required');
};

export const authorizePhase1ProtectedExecution = (
  mode: Phase1ProtectedExecutionMode,
  provenance: Phase1ProvenanceResult
): Phase1ProtectedExecutionAuthorization => {
  if (mode !== 'mirror-control' && mode !== 'runtime-candidate') {
    return fail('/mode', 'protected-execution-mode');
  }

  return Object.freeze({ mode, provenance: requireAcceptedPhase1Provenance(provenance) });
};

const executeFile = promisify(execFile);

export const runPhase1GitCommand: Phase1CommandRunner = async ({
  command,
  args,
  cwd,
  maximumBytes,
  environment,
}) => {
  try {
    const { stdout } = await executeFile(command, [...args], {
      cwd,
      encoding: 'buffer',
      maxBuffer: maximumBytes,
      timeout: 30_000,
      env: environment,
    });

    return stdout;
  } catch {
    return fail('/git', 'git-command');
  }
};

const decodeBoundedAscii = (bytes: Uint8Array): string => {
  if (bytes.byteLength > maximumReaderBytes) {
    fail('/git', 'git-output-bound');
  }

  const value = Buffer.from(bytes).toString('utf8').trim();

  if (/[^\u0009\u000a\u000d\u0020-\u007e]/u.test(value)) {
    fail('/git', 'git-output-encoding');
  }

  return value;
};

const rawDeltaHeaderPattern =
  /^:(?<oldMode>[0-7]{6}) (?<newMode>[0-7]{6}) (?<oldObject>[0-9a-f]{40}) (?<newObject>[0-9a-f]{40}) (?<status>[AMDT])$/u;
const gitDeltaStatus = Object.freeze({
  A: 'added',
  M: 'modified',
  D: 'deleted',
  T: 'type-changed',
} as const);

const parseRawGitDelta = (bytes: Uint8Array): readonly Phase1GitDeltaEntry[] => {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > maximumReaderBytes) {
    return fail('/git', 'git-delta-bound');
  }
  let source: string;

  try {
    source = new TextDecoder('utf8', { fatal: true }).decode(bytes);
  } catch {
    return fail('/git', 'git-delta-encoding');
  }
  if (source.length === 0) {
    return Object.freeze([]);
  }
  const fields = source.split('\0');

  if (fields.at(-1) !== '' || (fields.length - 1) % 2 !== 0) {
    return fail('/git', 'git-delta-format');
  }
  fields.pop();
  const entries: Phase1GitDeltaEntry[] = [];
  const paths = new Set<string>();

  for (let index = 0; index < fields.length; index += 2) {
    const header = fields[index] ?? '';
    const path = fields[index + 1] ?? '';
    const match = rawDeltaHeaderPattern.exec(header);

    if (!match?.groups) {
      return fail('/git', 'git-delta-format');
    }
    assertRepositoryPath(path, '/git');
    const {
      oldMode = '',
      newMode = '',
      oldObject = '',
      newObject = '',
      status = '',
    } = match.groups;
    const zeroObject = '0'.repeat(40);
    const statusIsConsistent =
      (status === 'A' &&
        oldMode === '000000' &&
        oldObject === zeroObject &&
        newMode !== '000000' &&
        newObject !== zeroObject) ||
      (status === 'D' &&
        newMode === '000000' &&
        newObject === zeroObject &&
        oldMode !== '000000' &&
        oldObject !== zeroObject) ||
      (status === 'M' &&
        oldMode !== '000000' &&
        newMode !== '000000' &&
        oldObject !== zeroObject &&
        newObject !== zeroObject) ||
      (status === 'T' &&
        oldMode !== '000000' &&
        newMode !== '000000' &&
        oldMode !== newMode &&
        oldObject !== zeroObject &&
        newObject !== zeroObject);

    if (!statusIsConsistent || paths.has(path)) {
      return fail('/git', 'git-delta-format');
    }
    paths.add(path);
    entries.push(
      Object.freeze({
        status: gitDeltaStatus[status],
        path,
        oldMode,
        newMode,
      })
    );
    if (entries.length > maximumGitDeltaItems) {
      return fail('/git', 'git-delta-bound');
    }
  }
  entries.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));

  return Object.freeze(entries);
};

const assertGitCommit = (commit: string): void => {
  if (!commitPattern.test(commit)) {
    fail('/git', 'git-commit');
  }
};

export const createProductionPhase1GitReader = (
  repositoryRoots: Readonly<Record<string, string>>,
  runner: Phase1CommandRunner = runPhase1GitCommand
): Phase1GitReader => {
  const rootFor = (repository: string): string => {
    const root = repositoryRoots[repository];

    return typeof root === 'string' && root.length > 0 ? root : fail('/git', 'git-repository');
  };
  const run = (repository: string, args: readonly string[], maximumBytes = maximumReaderBytes) =>
    runner({
      command: 'git',
      args,
      cwd: rootFor(repository),
      maximumBytes,
      environment: gitEnvironment,
    });

  return {
    ensureFullCommit: async (repository, commit) => {
      if (!commitPattern.test(commit)) {
        return 'missing';
      }

      try {
        const shallow = decodeBoundedAscii(
          await run(repository, ['rev-parse', '--is-shallow-repository'], 64)
        );

        if (shallow === 'true') {
          await run(
            repository,
            ['fetch', '--no-tags', '--unshallow', 'origin'],
            maximumReaderBytes
          );
        } else if (shallow !== 'false') {
          return 'shallow';
        }

        await run(repository, ['fetch', '--no-tags', 'origin', commit], maximumReaderBytes);
        await run(repository, ['cat-file', '-e', `${commit}^{commit}`], 64);

        const finalShallow = decodeBoundedAscii(
          await run(repository, ['rev-parse', '--is-shallow-repository'], 64)
        );

        return finalShallow === 'false' ? 'complete' : 'shallow';
      } catch {
        return 'missing';
      }
    },
    readBlob: async (repository, commit, path) => {
      assertGitCommit(commit);
      assertPublicGitObjectPath(path, '/git/path');
      const revision = `${commit}:${path}`;
      const kind = decodeBoundedAscii(await run(repository, ['cat-file', '-t', revision], 64));

      if (kind !== 'blob') {
        fail('/git', 'git-object-kind');
      }

      return run(repository, ['cat-file', '-p', revision], maximumReaderBytes);
    },
    objectId: async (repository, commit, path) => {
      assertGitCommit(commit);
      assertPublicGitObjectPath(path, '/git/path');

      return decodeBoundedAscii(
        await run(repository, ['rev-parse', '--verify', `${commit}:${path}`], 64)
      );
    },
    objectKind: async (repository, commit, path) => {
      assertGitCommit(commit);
      assertPublicGitObjectPath(path, '/git/path');

      try {
        const kind = decodeBoundedAscii(
          await run(repository, ['cat-file', '-t', `${commit}:${path}`], 64)
        );

        return kind === 'blob' || kind === 'tree' ? kind : 'missing';
      } catch {
        return 'missing';
      }
    },
    parents: async (repository, commit) => {
      if (!commitPattern.test(commit)) {
        return [];
      }

      try {
        const line = decodeBoundedAscii(
          await run(repository, ['rev-list', '--parents', '-n', '1', commit], 256)
        );
        const [resolvedCommit, ...parents] = line.split(' ');

        return resolvedCommit === commit && parents.every((parent) => commitPattern.test(parent))
          ? parents
          : [];
      } catch {
        return [];
      }
    },
    isAncestor: async (repository, ancestor, descendant) => {
      if (!commitPattern.test(ancestor) || !commitPattern.test(descendant)) {
        return false;
      }

      try {
        await run(repository, ['merge-base', '--is-ancestor', ancestor, descendant], 64);

        return true;
      } catch {
        return false;
      }
    },
    localState: async (repository) => {
      const head = decodeBoundedAscii(await run(repository, ['rev-parse', 'HEAD'], 64));
      const status = decodeBoundedAscii(
        await run(repository, ['status', '--porcelain=v1', '--untracked-files=all'])
      );

      return { head, clean: status.length === 0 };
    },
    remoteContains: async (repository, branch, commit) => {
      if (!/^[\w.-]+$/u.test(branch) || !commitPattern.test(commit)) {
        return false;
      }

      try {
        await run(repository, ['fetch', '--no-tags', 'origin', branch], maximumReaderBytes);
        await run(
          repository,
          ['merge-base', '--is-ancestor', commit, `refs/remotes/origin/${branch}`],
          64
        );

        return true;
      } catch {
        return false;
      }
    },
    diffEntries: async (repository, fromCommit, toCommit) => {
      assertGitCommit(fromCommit);
      assertGitCommit(toCommit);

      return parseRawGitDelta(
        await run(
          repository,
          [
            'diff-tree',
            '--no-commit-id',
            '-r',
            '--raw',
            '-z',
            '--no-renames',
            '--abbrev=40',
            fromCommit,
            toCommit,
            '--',
          ],
          maximumReaderBytes
        )
      );
    },
  };
};

/* eslint-enable max-lines, complexity, no-control-regex, no-restricted-syntax, no-await-in-loop, unicorn/prevent-abbreviations, unicorn/no-array-for-each, unicorn/escape-case, @typescript-eslint/consistent-type-definitions, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/promise-function-async, @silverhand/fp/no-mutating-methods, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
