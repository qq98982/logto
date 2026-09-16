/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, unicorn/prevent-abbreviations -- The provenance matrix mutates injected readers and authority projections without touching a worktree or network. */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { inspect } from 'node:util';

import type * as Yaml from 'yaml';

import { phase1CodeownersCoveragePaths } from '../governance-authority.js';
import type { Phase1Profile, Phase1SchemaLockDocument } from '../profile.js';
import { Phase1ProfileValidationError } from '../profile.js';
import { phase1WorkflowActionPins } from '../workflow-policy.js';

import {
  assertPhase1ProfileProvenance,
  authorizePhase1ProtectedExecution,
  createProductionPhase1GitReader,
  requireAcceptedPhase1Provenance,
  verifyPhase1ProfileProvenance,
  type Phase1AcceptedHarnessAuthority,
  type Phase1CommandRequest,
  type Phase1GitDeltaEntry,
  type Phase1GitReader,
  type Phase1GithubReader,
  type Phase1ProvenanceContext,
  type Phase1ProvenanceResult,
  type Phase1SourceEvidenceRef,
  type Phase0EvidenceReproductionRequest,
  type Phase0EvidenceReproducer,
} from './provenance.js';

const required = <Value>(value: Value | undefined): Value => {
  if (value === undefined) {
    throw new Error('Synthetic provenance fixture is incomplete');
  }

  return value;
};

const require = createRequire(import.meta.url);
const yamlPackage = ['ya', 'ml'].join('');
const { parse: parseYaml, stringify: stringifyYaml } = require(yamlPackage) as typeof Yaml;
const repositoryRoot = path.resolve(process.cwd(), '../..');

const oracleCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const phase0Commit = '40135e37201f36ac05ece1eff82e37bb6d9649f1';
const harnessCommit = '3333333333333333333333333333333333333333';
const schemaCommit = '4444444444444444444444444444444444444444';
const governanceCommit = '7777777777777777777777777777777777777777';
const governanceReviewer = 'reviewer';
const oracleRepository = 'https://example.test/oracle.git';
const harnessRepository = oracleRepository;
const profilePaths = Array.from({ length: 31 }, (_, index) => `sources/source-${index}.ts`);
const createScenarioEvidence = (scenarioId: 'discovery' | 'password-code', marker: string) => {
  const observations = [
    {
      stepId: `${scenarioId}.step`,
      kind: 'semantic-state',
      value: { marker, sequence: scenarioId },
    },
  ];

  return {
    schemaVersion: 1,
    scenarioId,
    oracle: { target: 'oracle', observations },
    candidate: {
      target: 'candidate',
      observations: JSON.parse(JSON.stringify(observations)) as unknown,
    },
    differences: [],
  };
};
const createPhase0EvidenceBytes = (marker: string) => {
  const digestCharacter = marker === 'fresh-a' ? 'a' : 'b';
  const normalizedDigest = `sha256:${digestCharacter.repeat(64)}`;
  const encode = (value: unknown) =>
    Buffer.from(`${JSON.stringify(value)}${marker === 'fresh-a' ? '' : '\n'}`);

  return {
    'discovery.json': encode(createScenarioEvidence('discovery', marker)),
    'negative-control.json': encode({
      schemaVersion: 1,
      faultInjection: 'discovery-issuer',
      differencePaths: ['/observations/0/value/issuer'],
    }),
    'password-code.json': encode(createScenarioEvidence('password-code', marker)),
    'run.json': encode({
      schemaVersion: 1,
      referenceCommit: oracleCommit,
      oracleImageDigest: normalizedDigest,
      candidateImageDigest: normalizedDigest,
      scenarios: [
        { scenarioId: 'discovery', differenceCount: 0 },
        { scenarioId: 'password-code', differenceCount: 0 },
      ],
      negativeControl: { differencePath: '/observations/0/value/issuer' },
    }),
  } as const;
};
const phase0EvidenceBytes = createPhase0EvidenceBytes('fresh-a');
const reproducePhase0Evidence = (evidenceBytes: typeof phase0EvidenceBytes) => async () =>
  ({
    commit: phase0Commit,
    files: Object.entries(evidenceBytes).map(([name, bytes]) => ({
      name: name as keyof typeof phase0EvidenceBytes,
      bytes,
    })),
  }) as const;
const mutatePhase0Evidence = (
  name: keyof typeof phase0EvidenceBytes,
  mutate: (value: Record<string, unknown>) => void
) => {
  const value = JSON.parse(phase0EvidenceBytes[name].toString('utf8')) as Record<string, unknown>;
  mutate(value);

  return { ...phase0EvidenceBytes, [name]: Buffer.from(JSON.stringify(value)) };
};
const replacePhase0EvidenceSource = (
  name: keyof typeof phase0EvidenceBytes,
  source: Uint8Array
) => ({ ...phase0EvidenceBytes, [name]: Buffer.from(source) });
const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
const schemaBytes = Buffer.from('{"synthetic":"schema"}');
const authorityPaths = [
  'compatibility/baseline-manifest.json',
  'docker-compose.compatibility.yml',
  '.scripts/compatibility/run.sh',
  'packages/integration-tests/src/compatibility/model.ts',
  'packages/integration-tests/src/compatibility/scenario.ts',
  'packages/integration-tests/src/compatibility/config.ts',
  'packages/integration-tests/src/compatibility/target-client.ts',
  'packages/integration-tests/src/compatibility/normalize.ts',
  'packages/integration-tests/src/compatibility/compare.ts',
  'packages/integration-tests/src/compatibility/evidence.ts',
  'packages/integration-tests/src/compatibility/cli.ts',
  'packages/integration-tests/src/compatibility/scenarios/index.ts',
] as const;
const plannedArtifacts = {
  profileLoader: 'planned/profile.ts',
  scenarioRegistry: 'planned/scenarios.ts',
  candidateInvariantRegistry: 'planned/invariants.ts',
  fixtureProvisioner: 'planned/fixtures.ts',
  semanticProjectionRegistry: 'planned/projections.ts',
  normalizerRegistry: 'planned/normalizers.ts',
  browserRunner: 'planned/browser.ts',
  oracleSnapshotDirectory: 'planned/snapshots',
  acceptanceRecordDirectory: 'planned/records',
} as const;
const authorityBlobs = Object.fromEntries(
  authorityPaths.map((path, index) => [path, `${index.toString(16).padStart(40, 'a')}`.slice(-40)])
) as unknown as Phase1SchemaLockDocument['phase0AuthorityBlobs'];

const deltaEntry = (
  status: Phase1GitDeltaEntry['status'],
  path: string,
  oldMode: string,
  newMode: string
): Phase1GitDeltaEntry => Object.freeze({ status, path, oldMode, newMode });
const addedFile = (path: string) => deltaEntry('added', path, '000000', '100644');
const addedScript = (path: string) => deltaEntry('added', path, '000000', '100755');
const modifiedFile = (path: string) => deltaEntry('modified', path, '100644', '100644');
const deletedFile = (path: string) => deltaEntry('deleted', path, '100644', '000000');
const sortDelta = (entries: readonly Phase1GitDeltaEntry[]) => {
  const sorted = [...entries];
  sorted.sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));

  return Object.freeze(sorted);
};
const governanceDelta = sortDelta([
  modifiedFile('.github/CODEOWNERS'),
  deletedFile('.github/workflows/alteration-compatibility-integration-test.yml'),
  deletedFile('.github/workflows/changesets.yml'),
  deletedFile('.github/workflows/close-stale.yml'),
  deletedFile('.github/workflows/codeql-analysis.yml'),
  deletedFile('.github/workflows/commitlint.yml'),
  modifiedFile('.github/workflows/compatibility-test.yml'),
  deletedFile('.github/workflows/integration-test.yml'),
  deletedFile('.github/workflows/main.yml'),
  deletedFile('.github/workflows/master-codecov-report.yml'),
  deletedFile('.github/workflows/pen-tests.yml'),
  deletedFile('.github/workflows/release.yml'),
  deletedFile('.github/workflows/repository-dispatch.yml'),
  deletedFile('.github/workflows/rerun.yml'),
  deletedFile('.github/workflows/update-pr-metadata.yml'),
]);
const featureDelta = sortDelta([
  addedFile('.github/workflows/phase1-compatibility-test.yml'),
  addedScript('.scripts/compatibility/phase1-conformance-driver.sh'),
  addedScript('.scripts/compatibility/phase1-reference-state-driver.sh'),
  addedScript('.scripts/compatibility/run-phase1-conformance.sh'),
  addedScript('.scripts/compatibility/run-phase1.sh'),
  addedFile('compatibility/phase-1-acceptance/README.md'),
  addedFile('compatibility/phase-1-schema-lock.json'),
  addedFile('compatibility/phases/phase-1-capabilities.json'),
  addedFile('docker-compose.phase1-compatibility.yml'),
  addedFile('packages/integration-tests/src/compatibility/phase-1/profile.ts'),
  modifiedFile('packages/integration-tests/package.json'),
  modifiedFile('pnpm-lock.yaml'),
]);
const rebasedReviewDelta = sortDelta([...governanceDelta, ...featureDelta]);
const phase0CodeownersBytes = Buffer.from(
  execFileSync('git', ['show', `${phase0Commit}:.github/CODEOWNERS`], {
    cwd: repositoryRoot,
  })
);
const governanceCodeownersFor = (reviewer: string) =>
  Buffer.concat([
    phase0CodeownersBytes,
    Buffer.from(
      `\n# Aster Phase 1 acceptance authority\n${phase1CodeownersCoveragePaths
        .map((coveragePath) => `${coveragePath} @qq98982 @${reviewer}`)
        .join('\n')}\n`
    ),
  ]);
const governanceCodeownersBytes = governanceCodeownersFor(governanceReviewer);
const phase0CompatibilityWorkflowBytes = Buffer.from(
  execFileSync('git', ['show', `${phase0Commit}:.github/workflows/compatibility-test.yml`], {
    cwd: repositoryRoot,
  })
);
const hardenedCompatibilityWorkflowBytes = (() => {
  const workflow = parseYaml(phase0CompatibilityWorkflowBytes.toString('utf8')) as {
    jobs: Record<string, { steps: Array<{ uses?: string; with?: Record<string, unknown> }> }>;
  };

  for (const job of Object.values(workflow.jobs)) {
    for (const step of job.steps) {
      if (!step.uses) {
        continue;
      }
      const [action] = step.uses.split('@');
      const pin = phase1WorkflowActionPins[action as keyof typeof phase1WorkflowActionPins];

      step.uses = `${action}@${pin}`;
      if (action === 'pnpm/action-setup') {
        step.with = { version: '10.15.1' };
      } else if (action === 'actions/setup-node') {
        step.with = { 'node-version': '22.23.2' };
      }
    }
  }

  return Buffer.from(stringifyYaml(workflow));
})();
const phase1WorkflowBytes = readFileSync(
  path.join(repositoryRoot, '.github/workflows/phase1-compatibility-test.yml')
);
const integrationLockBytes = readFileSync(path.join(repositoryRoot, 'pnpm-lock.yaml'));
const packageAuthorityBase = {
  name: '@logto/integration-tests',
  private: true,
  type: 'module',
  scripts: { build: 'tsup' },
  devDependencies: { typescript: '^5.5.3' },
  dependencies: { otplib: '^12.0.1' },
};
const packageAuthorityHarness = {
  ...packageAuthorityBase,
  scripts: {
    ...packageAuthorityBase.scripts,
    'compatibility:phase1': 'node ./lib/compatibility/phase-1/cli.js',
    'test:compatibility:phase1':
      'pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/phase-1/',
  },
  devDependencies: {
    ...packageAuthorityBase.devDependencies,
    '@playwright/test': '1.62.1',
    ajv: '8.20.0',
    'ajv-formats': '3.0.1',
    'jsonc-parser': '3.3.1',
    parse5: '7.2.1',
    'tough-cookie': '5.1.2',
    yaml: '2.9.0',
  },
};
const packageAuthorityBaseBytes = Buffer.from(`${JSON.stringify(packageAuthorityBase)}\n`);
const packageAuthorityHarnessBytes = Buffer.from(`${JSON.stringify(packageAuthorityHarness)}\n`);
const phase0FixtureProfile = Object.freeze({
  fixtures: Object.freeze({
    dataTenant: Object.freeze({
      subject: Object.freeze({ id: 'phase1-user', username: 'phase1-user' }),
      applications: Object.freeze([
        Object.freeze({ id: 'phase1-app', isThirdParty: false as const }),
        Object.freeze({ id: 'phase1-browser', isThirdParty: true as const }),
      ]),
    }),
  }),
}) as unknown as Pick<Phase1Profile, 'fixtures'>;

const provenanceProfile = () =>
  ({
    reference: {
      oracleRepository,
      oracleCommit,
      phase0HarnessCommit: phase0Commit,
      phase0EvidencePath: 'compatibility/phase-0-evidence',
      phase0ArtifactSha256: Object.fromEntries(
        Object.entries(phase0EvidenceBytes).map(([name, bytes]) => [name, sha256(bytes)])
      ),
    },
    profileSchema: {
      repository: 'aster',
      path: 'compatibility/phase-1-profile.schema.json',
      sourceCommit: schemaCommit,
      sha256: sha256(schemaBytes),
    },
    phase1Harness: {
      repository: harnessRepository,
      baseCommit: phase0Commit,
      commit: harnessCommit,
      plannedBranch: 'aster-phase1-harness',
      plannedArtifacts: { ...plannedArtifacts },
    },
    uiSource: {
      repository: oracleRepository,
      commit: oracleCommit,
      consoleTree: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      experienceTree: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      demoAppTree: 'cccccccccccccccccccccccccccccccccccccccc',
      pnpmLockBlob: 'dddddddddddddddddddddddddddddddddddddddd',
    },
    browserFlows: [
      { id: 'flow-a', sourceEvidence: profilePaths.slice(0, 8) },
      { id: 'flow-b', sourceEvidence: profilePaths.slice(8, 19) },
      {
        id: 'flow-c',
        sourceEvidence: [required(profilePaths.at(8)), ...profilePaths.slice(18, 24)],
      },
      {
        id: 'flow-d',
        sourceEvidence: [
          required(profilePaths.at(8)),
          required(profilePaths.at(18)),
          required(profilePaths.at(24)),
          required(profilePaths.at(9)),
          required(profilePaths.at(19)),
          required(profilePaths.at(20)),
        ],
      },
    ],
    consoleOrganizationTokenRequest: {
      sourceEvidence: profilePaths.slice(25, 28),
      sourceCapabilities: ['capability-a'],
    },
    interactionOperations: [
      {
        id: 'get',
        sourceEvidence: profilePaths.slice(27, 30),
        sourceCapabilities: ['capability-a'],
      },
      {
        id: 'post',
        sourceEvidence: profilePaths.slice(29, 31),
        sourceCapabilities: ['capability-a'],
      },
    ],
    fixtures: phase0FixtureProfile.fixtures,
  }) as unknown as Phase1Profile;

const acceptedAuthority = (): Phase1AcceptedHarnessAuthority => ({
  pullRequests: [
    {
      number: 7,
      state: 'closed',
      author: 'author',
      mergeCommit: harnessCommit,
      headCommit: '5555555555555555555555555555555555555555',
      evaluatedCommit: '6666666666666666666666666666666666666666',
      baseCommit: governanceCommit,
      baseBranch: 'aster-phase1-harness',
      approvals: [
        {
          reviewer: 'reviewer',
          state: 'APPROVED',
          commit: '5555555555555555555555555555555555555555',
        },
      ],
      requiredChecks: ['build', 'test'],
      checks: [
        {
          name: 'build',
          conclusion: 'success',
          headSha: '6666666666666666666666666666666666666666',
        },
        {
          name: 'test',
          conclusion: 'success',
          headSha: '6666666666666666666666666666666666666666',
        },
      ],
    },
  ],
});

type MutableAuthority = Record<string, unknown>;
type MutableAuthorityEntry = Record<string, unknown>;

const mutateAcceptedAuthority = (
  context: Phase1ProvenanceContext,
  mutate: (authority: MutableAuthority) => void
): void => {
  const authority = structuredClone(acceptedAuthority()) as unknown as MutableAuthority;
  mutate(authority);
  context.githubReader.acceptedHarnessAuthority = async () =>
    authority as unknown as Phase1AcceptedHarnessAuthority;
};

const authorityPullRequest = (authority: MutableAuthority): MutableAuthorityEntry =>
  required((authority.pullRequests as MutableAuthorityEntry[]).at(0));

const authorityApproval = (authority: MutableAuthority): MutableAuthorityEntry =>
  required((authorityPullRequest(authority).approvals as MutableAuthorityEntry[]).at(0));

const authorityCheck = (authority: MutableAuthority): MutableAuthorityEntry =>
  required((authorityPullRequest(authority).checks as MutableAuthorityEntry[]).at(0));

const sparseArray = <Value>(values: readonly Value[], holeIndex: number): Value[] => {
  const sparse = [...values];
  Reflect.deleteProperty(sparse, String(holeIndex));

  return sparse;
};

const expectGenericSanitizedProvenanceFailure = async (
  operation: Promise<unknown>,
  privateSentinel: string
): Promise<void> => {
  try {
    await operation;
    throw new Error('Expected generic provenance validation to fail');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    expect(error).toMatchObject({
      message: 'Invalid Phase 1 provenance',
      stage: 'provenance',
      pointers: ['/'],
      rules: ['provenance-reader'],
    });
    expect(String(error)).not.toContain(privateSentinel);
    expect(inspect(error)).not.toContain(privateSentinel);
    expect(JSON.stringify(error)).not.toContain(privateSentinel);
    expect((error as Error).stack).not.toContain(privateSentinel);
    expect(error).not.toHaveProperty('cause');
    const errorRecord = error as Record<PropertyKey, unknown>;
    const ownValues = Reflect.ownKeys(errorRecord)
      .map((key) => inspect(errorRecord[key]))
      .join('\n');
    expect(ownValues).not.toContain(privateSentinel);
  }
};

const createReaders = (mode: Phase1ProvenanceContext['mode'] = 'review-candidate') => {
  const calls = {
    github: 0,
    prepared: [] as string[],
    reproductions: [] as Phase0EvidenceReproductionRequest[],
    gitBlobReads: [] as Array<Readonly<{ commit: string; path: string }>>,
    gitDeltas: [] as Array<Readonly<{ fromCommit: string; toCommit: string }>>,
  };
  const gitReader: Phase1GitReader = {
    ensureFullCommit: async (repository, commit) => {
      calls.prepared.push(`${repository}:${commit}`);
      return 'complete';
    },
    // eslint-disable-next-line complexity -- The fake reader dispatches exact immutable fixture blobs by commit/path.
    readBlob: async (_repository, commit, path) => {
      calls.gitBlobReads.push({ commit, path });

      if (path.startsWith('compatibility/phase-0-evidence/')) {
        throw new Error('private Phase 0 evidence must not be read as a Git blob');
      }

      const evidenceName = path.replace('compatibility/phase-0-evidence/', '');

      if (Object.hasOwn(phase0EvidenceBytes, evidenceName)) {
        return phase0EvidenceBytes[evidenceName as keyof typeof phase0EvidenceBytes];
      }

      if (path === '.github/CODEOWNERS') {
        return commit === phase0Commit ? phase0CodeownersBytes : governanceCodeownersBytes;
      }
      if (path === '.github/workflows/compatibility-test.yml') {
        return commit === phase0Commit
          ? phase0CompatibilityWorkflowBytes
          : hardenedCompatibilityWorkflowBytes;
      }
      if (path === '.github/workflows/phase1-compatibility-test.yml') {
        return phase1WorkflowBytes;
      }

      if (path === 'packages/integration-tests/package.json') {
        return commit === phase0Commit ? packageAuthorityBaseBytes : packageAuthorityHarnessBytes;
      }
      if (path === 'pnpm-lock.yaml' && commit === harnessCommit) {
        return integrationLockBytes;
      }

      return Buffer.from('synthetic source');
    },
    objectId: async (_repository, commit, path) => {
      if (commit === oracleCommit) {
        const uiObjects: Readonly<Record<string, string>> = {
          'packages/console': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          'packages/experience': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
          'packages/demo-app': 'cccccccccccccccccccccccccccccccccccccccc',
          'pnpm-lock.yaml': 'dddddddddddddddddddddddddddddddddddddddd',
        };

        return uiObjects[path] ?? 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
      }

      if (commit === phase0Commit && Object.hasOwn(authorityBlobs, path)) {
        return authorityBlobs[path as keyof typeof authorityBlobs];
      }

      return 'ffffffffffffffffffffffffffffffffffffffff';
    },
    objectKind: async (_repository, commit, path) => {
      if (
        commit === harnessCommit &&
        governanceDelta.some((entry) => entry.status === 'deleted' && entry.path === path)
      ) {
        return 'missing';
      }
      return path.endsWith('snapshots') || path.endsWith('records') ? 'tree' : 'blob';
    },
    parents: async (_repository, commit) =>
      commit === '6666666666666666666666666666666666666666'
        ? ['7777777777777777777777777777777777777777', '5555555555555555555555555555555555555555']
        : [],
    isAncestor: async () => true,
    localState: async () => ({ head: harnessCommit, clean: true }),
    remoteContains: async () => true,
    diffEntries: async (_repository, fromCommit, toCommit) => {
      calls.gitDeltas.push({ fromCommit, toCommit });

      if (fromCommit === phase0Commit && toCommit === governanceCommit) {
        return governanceDelta;
      }
      if (fromCommit === governanceCommit && toCommit === harnessCommit) {
        return featureDelta;
      }
      if (fromCommit === phase0Commit && toCommit === harnessCommit) {
        return mode === 'accepted-harness' ? rebasedReviewDelta : featureDelta;
      }

      return [];
    },
  };
  const githubReader: Phase1GithubReader = {
    acceptedHarnessAuthority: async () => {
      calls.github += 1;
      return acceptedAuthority();
    },
  };
  const phase0EvidenceReproducer = async (request: Phase0EvidenceReproductionRequest) => {
    calls.reproductions.push(request);

    return reproducePhase0Evidence(phase0EvidenceBytes)();
  };

  return { calls, gitReader, githubReader, phase0EvidenceReproducer };
};

const provenanceContext = (
  mode: Phase1ProvenanceContext['mode'] = 'review-candidate'
): Phase1ProvenanceContext => {
  const { gitReader, githubReader, phase0EvidenceReproducer } = createReaders(mode);
  const browserSourceEvidence: Phase1SourceEvidenceRef[] = profilePaths
    .slice(0, 25)
    .map((path) => ({
      commit: oracleCommit,
      path,
    }));
  const profileSourceEvidence: Phase1SourceEvidenceRef[] = profilePaths.map((path) => ({
    commit: oracleCommit,
    path,
  }));

  return {
    mode,
    schemaBytes,
    profileLock: { sourceCommit: schemaCommit, sha256: sha256(schemaBytes) },
    schemaLockDocument: {
      schemaVersion: 1,
      phase0BaseCommit: phase0Commit,
      schemaSourceCommit: schemaCommit,
      schemaSha256: sha256(schemaBytes),
      phase0AuthorityBlobs: authorityBlobs,
    },
    baselineCapabilityIds: new Set(['capability-a']),
    browserSourceEvidence,
    registrySourceEvidence: [
      ...profileSourceEvidence,
      { commit: phase0Commit, path: 'packages/integration-tests/src/compatibility/scenario.ts' },
    ],
    phase0EvidenceReproducer,
    gitReader,
    githubReader,
  };
};

const expectProvenanceFailure = async (
  operation: Promise<unknown>,
  pointer: string,
  rule: string
) => {
  try {
    await operation;
    throw new Error('Expected provenance validation to fail');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    expect(error).toMatchObject({
      message: 'Invalid Phase 1 provenance',
      stage: 'provenance',
      pointers: [pointer],
      rules: [rule],
    });
  }
};

describe('Phase 1 source and acceptance provenance', () => {
  it('returns non-publishable review-candidate evidence without querying GitHub', async () => {
    const readers = createReaders();
    const context = {
      ...provenanceContext('review-candidate'),
      gitReader: readers.gitReader,
      githubReader: readers.githubReader,
      phase0EvidenceReproducer: readers.phase0EvidenceReproducer,
    };
    const result = await verifyPhase1ProfileProvenance(provenanceProfile(), context);
    expect(result).toEqual({
      kind: 'review-candidate',
      harnessCommit,
      publishable: false,
    });
    expect(readers.calls.github).toBe(0);
    expect(readers.calls.gitDeltas).toEqual([
      { fromCommit: phase0Commit, toCommit: harnessCommit },
    ]);
    expect(readers.calls.reproductions).toEqual([
      {
        repository: oracleRepository,
        commit: phase0Commit,
        lifecyclePath: '.scripts/compatibility/run.sh',
        files: ['discovery.json', 'negative-control.json', 'password-code.json', 'run.json'],
      },
    ]);
    for (const path of profilePaths) {
      expect(readers.calls.gitBlobReads).toContainEqual({ commit: oracleCommit, path });
    }
    expect(() => requireAcceptedPhase1Provenance(result)).toThrow(Phase1ProfileValidationError);
    expect(() =>
      requireAcceptedPhase1Provenance(JSON.parse(JSON.stringify(result)) as Phase1ProvenanceResult)
    ).toThrow(Phase1ProfileValidationError);
    expect(() => authorizePhase1ProtectedExecution('mirror-control', result)).toThrow(
      Phase1ProfileValidationError
    );
  });

  it('review-candidate accepts only the exact prebootstrap feature delta or rebased union', async () => {
    const prebootstrap = provenanceContext('review-candidate');
    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), prebootstrap)
    ).resolves.toMatchObject({ kind: 'review-candidate', publishable: false });

    const rebased = provenanceContext('review-candidate');
    rebased.gitReader.diffEntries = async (_repository, fromCommit, toCommit) =>
      fromCommit === phase0Commit && toCommit === harnessCommit ? rebasedReviewDelta : [];
    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), rebased)
    ).resolves.toMatchObject({ kind: 'review-candidate', publishable: false });
  });

  it('prebootstrap review does not claim or read governance content', async () => {
    const context = provenanceContext('review-candidate');
    const originalReadBlob = context.gitReader.readBlob;
    context.gitReader.readBlob = async (repository, commit, path) => {
      if (path === '.github/CODEOWNERS' || path.startsWith('.github/workflows/')) {
        throw new Error('prebootstrap must not read governance content');
      }

      return originalReadBlob(repository, commit, path);
    };

    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), context)
    ).resolves.toMatchObject({ kind: 'review-candidate', publishable: false });
  });

  it.each(['compatibility workflow', 'Phase 1 workflow'])(
    'rebased review rejects arbitrary %s content',
    async (target) => {
      const context = provenanceContext('review-candidate');
      context.gitReader.diffEntries = async () => rebasedReviewDelta;
      const originalReadBlob = context.gitReader.readBlob;
      context.gitReader.readBlob = async (repository, commit, path) => {
        if (
          (target === 'CODEOWNERS' && path === '.github/CODEOWNERS' && commit === harnessCommit) ||
          (target === 'compatibility workflow' &&
            path === '.github/workflows/compatibility-test.yml' &&
            commit === harnessCommit) ||
          (target === 'Phase 1 workflow' &&
            path === '.github/workflows/phase1-compatibility-test.yml' &&
            commit === harnessCommit)
        ) {
          return Buffer.from('unreviewed governance content\n');
        }

        return originalReadBlob(repository, commit, path);
      };
      await expectProvenanceFailure(
        verifyPhase1ProfileProvenance(provenanceProfile(), context),
        '/phase1Harness/commit',
        'harness-workflow-authority'
      );
    }
  );

  it.each([
    {
      name: 'unrelated source addition',
      entries: sortDelta([...featureDelta, addedFile('packages/core/unsafe.ts')]),
    },
    {
      name: 'required helper omission',
      entries: featureDelta.filter(
        ({ path }) => path !== '.scripts/compatibility/phase1-reference-state-driver.sh'
      ),
    },
    {
      name: 'script regular-file mode',
      entries: featureDelta.map((entry) =>
        entry.path === '.scripts/compatibility/phase1-conformance-driver.sh'
          ? addedFile(entry.path)
          : entry
      ),
    },
    {
      name: 'feature deletion',
      entries: featureDelta.map((entry) =>
        entry.path === 'compatibility/phase-1-schema-lock.json' ? deletedFile(entry.path) : entry
      ),
    },
    {
      name: 'extra workflow in rebased union',
      entries: sortDelta([...rebasedReviewDelta, addedFile('.github/workflows/unreviewed.yml')]),
    },
    {
      name: 'malformed injected delta entry',
      entries: [
        ...featureDelta,
        { ...addedFile('packages/core/unsafe.ts'), extra: true },
      ] as unknown as readonly Phase1GitDeltaEntry[],
    },
  ])('review-candidate rejects $name', async ({ entries }) => {
    const context = provenanceContext('review-candidate');
    context.gitReader.diffEntries = async () => entries;
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      'review-harness-delta'
    );
  });

  it('keeps hostile changed paths out of provenance diagnostics', async () => {
    const marker = 'private-delta-path-marker';
    const context = provenanceContext('review-candidate');
    context.gitReader.diffEntries = async () =>
      sortDelta([...featureDelta, addedFile(`packages/core/${marker}.ts`)]);

    try {
      await verifyPhase1ProfileProvenance(provenanceProfile(), context);
      throw new Error('Expected delta rejection');
    } catch (error: unknown) {
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 provenance',
        pointers: ['/phase1Harness/commit'],
        rules: ['review-harness-delta'],
      });
      expect(String(error)).not.toContain(marker);
      expect((error as Error).stack).not.toContain(marker);
    }
  });

  it('returns accepted evidence only for the protected reviewed merge', async () => {
    const readers = createReaders('accepted-harness');
    const context = {
      ...provenanceContext('accepted-harness'),
      gitReader: readers.gitReader,
      githubReader: readers.githubReader,
      phase0EvidenceReproducer: readers.phase0EvidenceReproducer,
    };
    const result = await verifyPhase1ProfileProvenance(provenanceProfile(), context);
    expect(requireAcceptedPhase1Provenance(result)).toEqual({
      kind: 'accepted-harness',
      harnessCommit,
      protectedBranch: 'aster-phase1-harness',
      pullRequestNumber: 7,
      publishable: true,
    });
    expect(authorizePhase1ProtectedExecution('runtime-candidate', result)).toEqual({
      mode: 'runtime-candidate',
      provenance: result,
    });
    const forgedValues = [
      JSON.parse(JSON.stringify(result)),
      structuredClone(result),
      { ...result },
      {
        kind: 'accepted-harness',
        harnessCommit,
        protectedBranch: 'aster-phase1-harness',
        pullRequestNumber: 7,
        publishable: true,
      },
    ] as const;

    for (const forged of forgedValues) {
      expect(() => requireAcceptedPhase1Provenance(forged as Phase1ProvenanceResult)).toThrow(
        Phase1ProfileValidationError
      );
    }
    await expect(
      assertPhase1ProfileProvenance(provenanceProfile(), provenanceContext('accepted-harness'))
    ).resolves.toBeUndefined();
    expect(readers.calls.gitDeltas).toEqual([
      { fromCommit: phase0Commit, toCommit: harnessCommit },
    ]);
    expect(readers.calls.prepared).toContain(`${harnessRepository}:${governanceCommit}`);
  });

  it.each([
    {
      name: 'governance workflow added instead of deleted',
      entries: governanceDelta.map((entry) =>
        entry.path === '.github/workflows/main.yml' ? addedFile(entry.path) : entry
      ),
      rule: 'review-harness-delta',
      target: 'governance',
    },
    {
      name: 'extra governance path',
      entries: sortDelta([...governanceDelta, modifiedFile('README.md')]),
      rule: 'review-harness-delta',
      target: 'governance',
    },
    {
      name: 'H omits conformance driver',
      entries: featureDelta.filter(
        ({ path }) => path !== '.scripts/compatibility/phase1-conformance-driver.sh'
      ),
      rule: 'review-harness-delta',
      target: 'feature',
    },
    {
      name: 'H adds executable TypeScript',
      entries: featureDelta.map((entry) =>
        entry.path === 'packages/integration-tests/src/compatibility/phase-1/profile.ts'
          ? deltaEntry('added', entry.path, '000000', '100755')
          : entry
      ),
      rule: 'review-harness-delta',
      target: 'feature',
    },
  ])('accepted-harness rejects $name', async ({ entries, rule, target }) => {
    const context = provenanceContext('accepted-harness');
    context.gitReader.diffEntries = async () =>
      target === 'governance' ? sortDelta([...entries, ...featureDelta]) : entries;
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      rule
    );
  });

  it.each(['compatibility workflow', 'Phase 1 workflow'])(
    'accepted-harness rejects arbitrary G_H/H %s content',
    async (target) => {
      const context = provenanceContext('accepted-harness');
      const originalReadBlob = context.gitReader.readBlob;
      context.gitReader.readBlob = async (repository, commit, path) => {
        if (
          (target === 'CODEOWNERS' &&
            path === '.github/CODEOWNERS' &&
            commit === governanceCommit) ||
          (target === 'compatibility workflow' &&
            path === '.github/workflows/compatibility-test.yml' &&
            commit === harnessCommit) ||
          (target === 'Phase 1 workflow' &&
            path === '.github/workflows/phase1-compatibility-test.yml' &&
            commit === harnessCommit)
        ) {
          return Buffer.from('unreviewed governance content\n');
        }

        return originalReadBlob(repository, commit, path);
      };
      await expectProvenanceFailure(
        verifyPhase1ProfileProvenance(provenanceProfile(), context),
        '/phase1Harness/commit',
        'harness-workflow-authority'
      );
    }
  );

  it('accepted harness does not read CODEOWNERS or couple its reviewer to a bootstrap', async () => {
    const context = provenanceContext('accepted-harness');
    context.gitReader.diffEntries = async () =>
      sortDelta([
        ...featureDelta,
        ...governanceDelta.filter(({ path }) => path !== '.github/CODEOWNERS'),
      ]);
    const originalReadBlob = context.gitReader.readBlob;
    context.gitReader.readBlob = async (repository, commit, path) => {
      if (path === '.github/CODEOWNERS') {
        throw new Error('CODEOWNERS is not acceptance authority');
      }
      return originalReadBlob(repository, commit, path);
    };
    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), context)
    ).resolves.toMatchObject({ kind: 'accepted-harness' });
  });

  it.each(['release.yml', 'update-pr-metadata.yml', 'repository-dispatch.yml'])(
    'rejects a retained %s at H even when the diff omits that unchanged file',
    async (workflow) => {
      const context = provenanceContext('accepted-harness');
      const originalKind = context.gitReader.objectKind;
      const path = `.github/workflows/${workflow}`;
      context.gitReader.diffEntries = async () =>
        sortDelta([...featureDelta, ...governanceDelta.filter((entry) => entry.path !== path)]);
      context.gitReader.objectKind = async (repository, commit, candidate) =>
        commit === harnessCommit && candidate === path
          ? 'blob'
          : originalKind(repository, commit, candidate);
      await expectProvenanceFailure(
        verifyPhase1ProfileProvenance(provenanceProfile(), context),
        '/phase1Harness/commit',
        'harness-workflow-tree'
      );
    }
  );

  it('requires deletion evidence even when objectKind reports a legacy workflow missing', async () => {
    const context = provenanceContext('accepted-harness');
    context.gitReader.diffEntries = async () =>
      sortDelta([
        ...featureDelta,
        ...governanceDelta.filter(({ path }) => path !== '.github/workflows/release.yml'),
      ]);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      'harness-workflow-tree'
    );
  });

  it.each(['missing governance commit', 'Phase 0 is not an ancestor', 'H is not a descendant'])(
    'accepted-harness rejects when %s',
    async (name) => {
      const context = provenanceContext('accepted-harness');
      const originalEnsure = context.gitReader.ensureFullCommit;
      const originalAncestor = context.gitReader.isAncestor;
      context.gitReader.ensureFullCommit = async (repository, commit) =>
        name === 'missing governance commit' && commit === governanceCommit
          ? 'missing'
          : originalEnsure(repository, commit);
      context.gitReader.isAncestor = async (repository, ancestor, descendant) => {
        if (
          (name === 'Phase 0 is not an ancestor' &&
            ancestor === phase0Commit &&
            descendant === governanceCommit) ||
          (name === 'H is not a descendant' &&
            ancestor === governanceCommit &&
            descendant === harnessCommit)
        ) {
          return false;
        }

        return originalAncestor(repository, ancestor, descendant);
      };
      await expectProvenanceFailure(
        verifyPhase1ProfileProvenance(provenanceProfile(), context),
        '/phase1Harness/commit',
        'accepted-governance-history'
      );
    }
  );

  it('accepts required checks evaluated directly on the reviewed PR head', async () => {
    const context = provenanceContext('accepted-harness');
    context.githubReader.acceptedHarnessAuthority = async () => {
      const authority = acceptedAuthority();
      const pullRequest = required(authority.pullRequests.at(0));

      return {
        pullRequests: [
          {
            ...pullRequest,
            evaluatedCommit: pullRequest.headCommit,
            checks: pullRequest.checks.map((check) => ({
              ...check,
              headSha: pullRequest.headCommit,
            })),
          },
        ],
      };
    };
    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), context)
    ).resolves.toMatchObject({ kind: 'accepted-harness', publishable: true });
  });

  it.each([
    {
      name: 'oracle/UI commit equality',
      pointer: '/reference/oracleCommit',
      rule: 'oracle-commit-lock',
      mutate: (profile: Phase1Profile) => {
        (profile.reference as { oracleCommit: string }).oracleCommit = phase0Commit;
      },
    },
    {
      name: 'harness base equality',
      pointer: '/reference/phase0HarnessCommit',
      rule: 'phase0-commit-lock',
      mutate: (profile: Phase1Profile) => {
        (profile.reference as { phase0HarnessCommit: string }).phase0HarnessCommit = oracleCommit;
      },
    },
    {
      name: 'repository equality',
      pointer: '/uiSource/repository',
      rule: 'repository-lock',
      mutate: (profile: Phase1Profile) => {
        (profile.uiSource as { repository: string }).repository = 'https://wrong.example/repo.git';
      },
    },
    {
      name: 'schema bytes hash',
      pointer: '/profileSchema/sha256',
      rule: 'schema-lock',
      mutate: (profile: Phase1Profile) => {
        (profile.profileSchema as { sha256: string }).sha256 = 'a'.repeat(64);
      },
    },
    {
      name: 'schema lock source',
      pointer: '/profileSchema/sourceCommit',
      rule: 'schema-lock',
      mutate: (_profile: Phase1Profile, context: Phase1ProvenanceContext) => {
        (context.profileLock as { sourceCommit: string }).sourceCommit = oracleCommit;
      },
    },
  ])('rejects a mutated $name at the exact pointer', async ({ mutate, pointer, rule }) => {
    const profile = provenanceProfile();
    const context = provenanceContext();
    mutate(profile, context);
    await expectProvenanceFailure(verifyPhase1ProfileProvenance(profile, context), pointer, rule);
  });

  it('rejects pairwise oracle/UI and Phase 0/base drift', async () => {
    const uiDrift = provenanceProfile();
    (uiDrift.uiSource as { commit: string }).commit = phase0Commit;
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(uiDrift, provenanceContext()),
      '/reference/oracleCommit',
      'oracle-ui-lock'
    );

    const baseDrift = provenanceProfile();
    (baseDrift.phase1Harness as { baseCommit: string }).baseCommit = oracleCommit;
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(baseDrift, provenanceContext()),
      '/reference/phase0HarnessCommit',
      'phase0-base-lock'
    );
  });

  it.each([
    ['packages/console', '/uiSource/consoleTree'],
    ['packages/experience', '/uiSource/experienceTree'],
    ['packages/demo-app', '/uiSource/demoAppTree'],
    ['pnpm-lock.yaml', '/uiSource/pnpmLockBlob'],
  ] as const)('rejects an object mismatch for %s', async (path, pointer) => {
    const context = provenanceContext();
    const originalObjectId = context.gitReader.objectId;
    context.gitReader.objectId = async (repository, commit, candidatePath) =>
      commit === oracleCommit && candidatePath === path
        ? '0'.repeat(40)
        : originalObjectId(repository, commit, candidatePath);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      pointer,
      'ui-object-lock'
    );
  });

  it('rejects a harness commit that does not descend from the Phase 0 base', async () => {
    const context = provenanceContext();
    context.gitReader.isAncestor = async () => false;
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      'harness-ancestry'
    );
  });

  it('rejects a nonauthoritative browser source union', async () => {
    const context = provenanceContext();
    (context.browserSourceEvidence as Phase1SourceEvidenceRef[])[0] = {
      commit: oracleCommit,
      path: 'sources/missing.ts',
    };
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/browserFlows/0/sourceEvidence/0',
      'browser-source-exact-set'
    );
  });

  it('accepts four raw browser arrays of 8/11/7/6 with a 25-path first-occurrence union', async () => {
    const profile = provenanceProfile();
    expect(profile.browserFlows.map(({ sourceEvidence }) => sourceEvidence.length)).toEqual([
      8, 11, 7, 6,
    ]);
    expect(profile.browserFlows.flatMap(({ sourceEvidence }) => sourceEvidence)).toHaveLength(32);
    await expect(
      verifyPhase1ProfileProvenance(profile, provenanceContext())
    ).resolves.toMatchObject({ kind: 'review-candidate' });
  });

  it.each([
    {
      name: '24 unique paths',
      mutate: (profile: Phase1Profile) => {
        const flow = required(profile.browserFlows.at(3));
        (flow.sourceEvidence as string[])[2] = required(profilePaths.at(16));
      },
    },
    {
      name: '26 unique paths',
      mutate: (profile: Phase1Profile) => {
        const flow = required(profile.browserFlows.at(3));
        (flow.sourceEvidence as string[]).push('sources/browser-extra.ts');
      },
    },
  ])('rejects raw browser arrays whose union has $name', async ({ mutate }) => {
    const profile = provenanceProfile();
    mutate(profile);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(profile, provenanceContext()),
      '/browserFlows',
      'browser-source-path-count'
    );
  });

  it.each([
    {
      name: 'all 31 profile paths instead of the browser 25',
      mutate: (context: Phase1ProvenanceContext) => {
        context.browserSourceEvidence = profilePaths.map((path) => ({
          commit: oracleCommit,
          path,
        }));
      },
      pointer: '/browserSourceEvidence/25',
    },
    {
      name: 'one omitted browser path',
      mutate: (context: Phase1ProvenanceContext) => {
        context.browserSourceEvidence = context.browserSourceEvidence.slice(0, -1);
      },
      pointer: '/browserFlows/3/sourceEvidence/2',
    },
    {
      name: 'two reordered browser paths',
      mutate: (context: Phase1ProvenanceContext) => {
        const references = [...context.browserSourceEvidence];
        const first = required(references.at(0));
        const second = required(references.at(1));
        [references[0], references[1]] = [second, first];
        context.browserSourceEvidence = references;
      },
      pointer: '/browserFlows/0/sourceEvidence/0',
    },
    {
      name: 'one extra browser path',
      mutate: (context: Phase1ProvenanceContext) => {
        context.browserSourceEvidence = [
          ...context.browserSourceEvidence,
          { commit: oracleCommit, path: 'sources/extra-browser.ts' },
        ];
      },
      pointer: '/browserSourceEvidence/25',
    },
  ])('rejects browser source evidence with $name', async ({ mutate, pointer }) => {
    const context = provenanceContext();
    mutate(context);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      pointer,
      'browser-source-exact-set'
    );
  });

  it('rejects a registry union that omits one profile-owned oracle source', async () => {
    const context = provenanceContext();
    context.registrySourceEvidence = context.registrySourceEvidence.filter(
      ({ path }) => path !== required(profilePaths.at(30))
    );
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/interactionOperations/1/sourceEvidence/1',
      'registry-source-coverage'
    );
  });

  it.each([
    {
      name: 'duplicate oracle path',
      expectedIndex: 31,
      mutate: (context: Phase1ProvenanceContext) => {
        const references = [...context.registrySourceEvidence];
        references.splice(31, 0, {
          commit: oracleCommit,
          path: required(profilePaths.at(0)),
        });
        context.registrySourceEvidence = references;
      },
    },
    {
      name: 'duplicate Phase 0 path',
      expectedIndex: 32,
      mutate: (context: Phase1ProvenanceContext) => {
        context.registrySourceEvidence = [
          ...context.registrySourceEvidence,
          {
            commit: phase0Commit,
            path: 'packages/integration-tests/src/compatibility/scenario.ts',
          },
        ];
      },
    },
  ])('rejects registry source evidence with $name', async ({ mutate, expectedIndex }) => {
    const context = provenanceContext();
    mutate(context);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      `/registrySourceEvidence/${expectedIndex}/path`,
      'registry-source-exact-set'
    );
  });

  it('accepts and verifies Task 6 extra oracle citations outside the profile-owned 31', async () => {
    const readers = createReaders();
    const context = {
      ...provenanceContext(),
      gitReader: readers.gitReader,
      githubReader: readers.githubReader,
      phase0EvidenceReproducer: readers.phase0EvidenceReproducer,
    };
    const extraOraclePaths = [
      'packages/core/src/oidc/init.ts',
      'packages/integration-tests/src/tests/api/oidc/discovery.test.ts',
    ] as const;
    context.registrySourceEvidence = [
      ...context.registrySourceEvidence,
      ...extraOraclePaths.map((path): Phase1SourceEvidenceRef => ({ commit: oracleCommit, path })),
    ];

    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), context)
    ).resolves.toMatchObject({ kind: 'review-candidate' });
    for (const path of extraOraclePaths) {
      expect(readers.calls.gitBlobReads).toContainEqual({ commit: oracleCommit, path });
    }
  });

  it('treats the same path at oracle and Phase 0 commits as distinct structured citations', async () => {
    const readers = createReaders();
    const context = {
      ...provenanceContext(),
      gitReader: readers.gitReader,
      githubReader: readers.githubReader,
      phase0EvidenceReproducer: readers.phase0EvidenceReproducer,
    };
    const sharedPath = 'packages/integration-tests/src/compatibility/scenario.ts';
    context.registrySourceEvidence = [
      ...context.registrySourceEvidence,
      { commit: oracleCommit, path: sharedPath },
    ];

    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), context)
    ).resolves.toMatchObject({ kind: 'review-candidate' });
    expect(readers.calls.gitBlobReads).toContainEqual({ commit: oracleCommit, path: sharedPath });
    expect(readers.calls.gitBlobReads).toContainEqual({ commit: phase0Commit, path: sharedPath });
  });

  it('rejects an extra oracle citation whose exact-commit blob is missing', async () => {
    const context = provenanceContext();
    const missingPath = 'packages/core/src/oidc/missing.ts';
    const originalReadBlob = context.gitReader.readBlob;
    context.registrySourceEvidence = [
      ...context.registrySourceEvidence,
      { commit: oracleCommit, path: missingPath },
    ];
    context.gitReader.readBlob = async (repository, commit, path) => {
      if (commit === oracleCommit && path === missingPath) {
        throw new Error('synthetic missing blob');
      }

      return originalReadBlob(repository, commit, path);
    };
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/',
      'provenance-reader'
    );
  });

  it('rejects a registry citation outside the two pinned commits', async () => {
    const context = provenanceContext();
    context.registrySourceEvidence = [
      ...context.registrySourceEvidence,
      {
        commit: 'ffffffffffffffffffffffffffffffffffffffff',
        path: 'packages/core/src/oidc/init.ts',
      } as unknown as Phase1SourceEvidenceRef,
    ];
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/registrySourceEvidence/32/commit',
      'source-evidence-commit'
    );
  });

  it('treats the registry source evidence oracle portion as an order-independent exact set', async () => {
    const context = provenanceContext();
    const references = [...context.registrySourceEvidence];
    const first = required(references.at(0));
    const second = required(references.at(1));
    [references[0], references[1]] = [second, first];
    context.registrySourceEvidence = references;
    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), context)
    ).resolves.toMatchObject({ kind: 'review-candidate' });
  });

  it.each([
    'compatibility/phase-0-evidence/run.json',
    './compatibility/phase-0-evidence/run.json',
    'compatibility/./phase-0-evidence/run.json',
  ])('rejects private Phase 0 registry alias %s before any Git read', async (privatePath) => {
    const readers = createReaders();
    const context = {
      ...provenanceContext(),
      gitReader: readers.gitReader,
      githubReader: readers.githubReader,
      phase0EvidenceReproducer: readers.phase0EvidenceReproducer,
    };
    context.registrySourceEvidence = [
      ...context.registrySourceEvidence,
      { commit: phase0Commit, path: privatePath },
    ];
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/registrySourceEvidence/32/path',
      'phase0-private-evidence-path'
    );
    expect(readers.calls.gitBlobReads).not.toContainEqual({
      commit: phase0Commit,
      path: privatePath,
    });
  });

  it('rejects private aliases before injected objectKind and objectId reads', async () => {
    const artifactProfile = provenanceProfile();
    (
      artifactProfile.phase1Harness.plannedArtifacts as unknown as Record<string, string>
    ).browserRunner = 'compatibility/./phase-0-evidence/run.json';
    const artifactContext = provenanceContext();
    const originalObjectKind = artifactContext.gitReader.objectKind;
    artifactContext.gitReader.objectKind = async (repository, commit, path) =>
      path.includes('phase-0-evidence')
        ? Promise.reject(new Error('objectKind must not receive private paths'))
        : originalObjectKind(repository, commit, path);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(artifactProfile, artifactContext),
      '/phase1Harness/plannedArtifacts/browserRunner',
      'phase0-private-evidence-path'
    );

    const authorityContext = provenanceContext();
    (
      authorityContext.schemaLockDocument as unknown as {
        phase0AuthorityBlobs: Record<string, string>;
      }
    ).phase0AuthorityBlobs = {
      './compatibility/phase-0-evidence/run.json': 'a'.repeat(40),
    };
    const originalObjectId = authorityContext.gitReader.objectId;
    authorityContext.gitReader.objectId = async (repository, commit, path) =>
      path.includes('phase-0-evidence')
        ? Promise.reject(new Error('objectId must not receive private paths'))
        : originalObjectId(repository, commit, path);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), authorityContext),
      '/schemaLockDocument/phase0AuthorityBlobs/.~1compatibility~1phase-0-evidence~1run.json',
      'phase0-private-evidence-path'
    );
  });

  it('rejects a source union with anything other than 31 unique profile paths', async () => {
    const profile = provenanceProfile();
    const operation = required(profile.interactionOperations.at(1));
    (operation.sourceEvidence as string[])[1] = required(profilePaths.at(25));
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(profile, provenanceContext()),
      '/interactionOperations/1/sourceEvidence/1',
      'profile-source-path-count'
    );
  });

  it('rejects a Phase 0 capability citation absent from the baseline', async () => {
    const profile = provenanceProfile();
    (profile.consoleOrganizationTokenRequest.sourceCapabilities as string[])[0] =
      'missing-capability';
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(profile, provenanceContext()),
      '/consoleOrganizationTokenRequest/sourceCapabilities/0',
      'phase0-capability-citation'
    );
  });

  it('accepts fresh Phase 0 bytes independently of the private evidence hash map', async () => {
    const profile = provenanceProfile();
    const privateHashes = profile.reference.phase0ArtifactSha256 as Record<string, string>;
    for (const [index, name] of Object.keys(privateHashes).entries()) {
      privateHashes[name] = `${index + 1}`.repeat(64);
    }
    const freshGroups = [phase0EvidenceBytes, createPhase0EvidenceBytes('fresh-b')] as const;
    const expectedPrivateHashes = { ...privateHashes };
    for (const name of Object.keys(phase0EvidenceBytes) as Array<
      keyof typeof phase0EvidenceBytes
    >) {
      expect(sha256(freshGroups[0][name])).not.toBe(sha256(freshGroups[1][name]));
    }

    for (const freshBytes of freshGroups) {
      const context = provenanceContext();
      context.phase0EvidenceReproducer = reproducePhase0Evidence(freshBytes);
      await expect(verifyPhase1ProfileProvenance(profile, context)).resolves.toMatchObject({
        kind: 'review-candidate',
      });
      expect(profile.reference.phase0ArtifactSha256).toEqual(expectedPrivateHashes);
    }
  });

  it('rejects malformed private evidence hash metadata without comparing fresh bytes', async () => {
    const profile = provenanceProfile();
    (profile.reference.phase0ArtifactSha256 as Record<string, string>)['run.json'] = 'A'.repeat(64);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(profile, provenanceContext()),
      '/reference/phase0ArtifactSha256/run.json',
      'phase0-evidence-map'
    );
  });

  it.each([
    {
      name: 'comment',
      bytes: Buffer.from(`/*comment*/${phase0EvidenceBytes['discovery.json'].toString('utf8')}`),
      rule: 'phase0-strict-json',
    },
    {
      name: 'trailing comma',
      bytes: Buffer.from(
        phase0EvidenceBytes['discovery.json'].toString('utf8').replace(/\}$/u, ',}')
      ),
      rule: 'phase0-strict-json',
    },
    {
      name: 'duplicate root key',
      bytes: Buffer.from(
        phase0EvidenceBytes['discovery.json']
          .toString('utf8')
          .replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1')
      ),
      rule: 'phase0-strict-json-duplicate-key',
    },
    {
      name: 'duplicate nested key',
      bytes: Buffer.from(
        phase0EvidenceBytes['discovery.json']
          .toString('utf8')
          .replace('"target":"oracle"', '"target":"oracle","target":"oracle"')
      ),
      rule: 'phase0-strict-json-duplicate-key',
    },
    {
      name: 'invalid UTF-8',
      bytes: Buffer.from([0xff]),
      rule: 'phase0-strict-json-utf8',
    },
  ])('rejects strict Phase 0 JSON $name', async ({ bytes, rule }) => {
    const context = provenanceContext();
    context.phase0EvidenceReproducer = reproducePhase0Evidence(
      replacePhase0EvidenceSource('discovery.json', bytes)
    );
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase0Reproduction/discovery.json',
      rule
    );
  });

  it.each([
    { name: 'candidate +1 within tolerance', delta: 1, oracleTolerance: 5, candidateTolerance: 5 },
    {
      name: 'different tolerances use the minimum',
      delta: 2,
      oracleTolerance: 10,
      candidateTolerance: 2,
    },
  ])(
    'accepts timestamp comparison when $name',
    async ({ delta, oracleTolerance, candidateTolerance }) => {
      const evidenceBytes = mutatePhase0Evidence('discovery.json', (value) => {
        const oracle = value.oracle as { observations: Array<Record<string, unknown>> };
        const candidate = value.candidate as { observations: Array<Record<string, unknown>> };
        required(oracle.observations.at(0)).value = {
          $timestamp: 100,
          $toleranceSeconds: oracleTolerance,
        };
        required(candidate.observations.at(0)).value = {
          $timestamp: 100 + delta,
          $toleranceSeconds: candidateTolerance,
        };
      });
      const context = provenanceContext();
      context.phase0EvidenceReproducer = reproducePhase0Evidence(evidenceBytes);
      await expect(
        verifyPhase1ProfileProvenance(provenanceProfile(), context)
      ).resolves.toMatchObject({ kind: 'review-candidate' });
    }
  );

  it.each([
    {
      name: 'scenario root extra field',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json',
      rule: 'phase0-evidence-keys',
      mutate: (value: Record<string, unknown>) => {
        value.extra = true;
      },
    },
    {
      name: 'scenario target extra field',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/oracle',
      rule: 'phase0-evidence-keys',
      mutate: (value: Record<string, unknown>) => {
        (value.oracle as Record<string, unknown>).extra = true;
      },
    },
    {
      name: 'observation extra field',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/oracle/observations/0',
      rule: 'phase0-evidence-keys',
      mutate: (value: Record<string, unknown>) => {
        const oracle = value.oracle as { observations: Array<Record<string, unknown>> };
        required(oracle.observations.at(0)).extra = true;
      },
    },
    {
      name: 'discovery scenario ID',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/scenarioId',
      rule: 'phase0-scenario-contract',
      mutate: (value: Record<string, unknown>) => {
        value.scenarioId = 'wrong';
      },
    },
    {
      name: 'password scenario ID',
      file: 'password-code.json' as const,
      pointer: '/phase0Reproduction/password-code.json/scenarioId',
      rule: 'phase0-scenario-contract',
      mutate: (value: Record<string, unknown>) => {
        value.scenarioId = 'wrong';
      },
    },
    {
      name: 'oracle label',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/oracle/target',
      rule: 'phase0-scenario-contract',
      mutate: (value: Record<string, unknown>) => {
        (value.oracle as Record<string, unknown>).target = 'candidate';
      },
    },
    {
      name: 'candidate label',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/candidate/target',
      rule: 'phase0-scenario-contract',
      mutate: (value: Record<string, unknown>) => {
        (value.candidate as Record<string, unknown>).target = 'oracle';
      },
    },
    {
      name: 'empty oracle observations',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/oracle/observations',
      rule: 'phase0-scenario-observations',
      mutate: (value: Record<string, unknown>) => {
        (value.oracle as Record<string, unknown>).observations = [];
      },
    },
    {
      name: 'candidate step mismatch',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/candidate/observations/0',
      rule: 'phase0-scenario-observations',
      mutate: (value: Record<string, unknown>) => {
        const candidate = value.candidate as { observations: Array<Record<string, unknown>> };
        required(candidate.observations.at(0)).stepId = 'wrong.step';
      },
    },
    {
      name: 'candidate kind mismatch',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/candidate/observations/0',
      rule: 'phase0-scenario-observations',
      mutate: (value: Record<string, unknown>) => {
        const candidate = value.candidate as { observations: Array<Record<string, unknown>> };
        required(candidate.observations.at(0)).kind = 'http';
      },
    },
    {
      name: 'candidate value mismatch',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/candidate/observations',
      rule: 'phase0-scenario-comparison',
      mutate: (value: Record<string, unknown>) => {
        const candidate = value.candidate as { observations: Array<Record<string, unknown>> };
        required(candidate.observations.at(0)).value = { marker: 'wrong' };
      },
    },
    {
      name: 'timestamp beyond minimum tolerance',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/candidate/observations',
      rule: 'phase0-scenario-comparison',
      mutate: (value: Record<string, unknown>) => {
        const oracle = value.oracle as { observations: Array<Record<string, unknown>> };
        const candidate = value.candidate as { observations: Array<Record<string, unknown>> };
        required(oracle.observations.at(0)).value = {
          $timestamp: 100,
          $toleranceSeconds: 10,
        };
        required(candidate.observations.at(0)).value = {
          $timestamp: 103,
          $toleranceSeconds: 2,
        };
      },
    },
    {
      name: 'malformed timestamp marker',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/candidate/observations/0/value',
      rule: 'phase0-scenario-timestamp-marker',
      mutate: (value: Record<string, unknown>) => {
        const candidate = value.candidate as { observations: Array<Record<string, unknown>> };
        required(candidate.observations.at(0)).value = {
          $timestamp: 100,
          $toleranceSeconds: -1,
        };
      },
    },
    {
      name: 'nonzero scenario differences',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json/differences',
      rule: 'phase0-scenario-differences',
      mutate: (value: Record<string, unknown>) => {
        value.differences = [{ path: '/value', oracle: 1, candidate: 2 }];
      },
    },
    {
      name: 'credential-bearing evidence',
      file: 'discovery.json' as const,
      pointer: '/phase0Reproduction/discovery.json',
      rule: 'phase0-evidence-sanitized',
      mutate: (value: Record<string, unknown>) => {
        const oracle = value.oracle as { observations: Array<Record<string, unknown>> };
        required(oracle.observations.at(0)).value = { authorization: 'Bearer private-value' };
      },
    },
    {
      name: 'negative fault',
      file: 'negative-control.json' as const,
      pointer: '/phase0Reproduction/negative-control.json/faultInjection',
      rule: 'phase0-negative-control-contract',
      mutate: (value: Record<string, unknown>) => {
        value.faultInjection = 'wrong';
      },
    },
    {
      name: 'negative root extra field',
      file: 'negative-control.json' as const,
      pointer: '/phase0Reproduction/negative-control.json',
      rule: 'phase0-evidence-keys',
      mutate: (value: Record<string, unknown>) => {
        value.extra = true;
      },
    },
    {
      name: 'negative path',
      file: 'negative-control.json' as const,
      pointer: '/phase0Reproduction/negative-control.json/differencePaths',
      rule: 'phase0-negative-control-contract',
      mutate: (value: Record<string, unknown>) => {
        value.differencePaths = ['/wrong'];
      },
    },
    {
      name: 'run reference commit',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/referenceCommit',
      rule: 'phase0-run-contract',
      mutate: (value: Record<string, unknown>) => {
        value.referenceCommit = phase0Commit;
      },
    },
    {
      name: 'run root extra field',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json',
      rule: 'phase0-evidence-keys',
      mutate: (value: Record<string, unknown>) => {
        value.extra = true;
      },
    },
    {
      name: 'run scenario extra field',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/scenarios/0',
      rule: 'phase0-evidence-keys',
      mutate: (value: Record<string, unknown>) => {
        const scenarios = value.scenarios as Array<Record<string, unknown>>;
        required(scenarios.at(0)).extra = true;
      },
    },
    {
      name: 'run negative-control extra field',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/negativeControl',
      rule: 'phase0-evidence-keys',
      mutate: (value: Record<string, unknown>) => {
        (value.negativeControl as Record<string, unknown>).extra = true;
      },
    },
    {
      name: 'run digest format',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/oracleImageDigest',
      rule: 'phase0-run-contract',
      mutate: (value: Record<string, unknown>) => {
        value.oracleImageDigest = 'latest';
      },
    },
    {
      name: 'run digest mismatch',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/candidateImageDigest',
      rule: 'phase0-run-mirror-digest',
      mutate: (value: Record<string, unknown>) => {
        value.candidateImageDigest = `sha256:${'b'.repeat(64)}`;
      },
    },
    {
      name: 'run scenario order',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/scenarios/0/scenarioId',
      rule: 'phase0-run-scenarios',
      mutate: (value: Record<string, unknown>) => {
        const scenarios = value.scenarios as Array<Record<string, unknown>>;
        scenarios.reverse();
      },
    },
    {
      name: 'run nonzero difference count',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/scenarios/0/differenceCount',
      rule: 'phase0-run-scenarios',
      mutate: (value: Record<string, unknown>) => {
        const scenarios = value.scenarios as Array<Record<string, unknown>>;
        required(scenarios.at(0)).differenceCount = 1;
      },
    },
    {
      name: 'run negative path',
      file: 'run.json' as const,
      pointer: '/phase0Reproduction/run.json/negativeControl/differencePath',
      rule: 'phase0-run-negative-control',
      mutate: (value: Record<string, unknown>) => {
        (value.negativeControl as Record<string, unknown>).differencePath = '/wrong';
      },
    },
  ])('rejects Phase 0 semantic mutation $name', async ({ file, mutate, pointer, rule }) => {
    const context = provenanceContext();
    context.phase0EvidenceReproducer = reproducePhase0Evidence(mutatePhase0Evidence(file, mutate));
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      pointer,
      rule
    );
  });

  it('never includes an untrusted nested evidence key in timestamp-marker diagnostics', async () => {
    const privateSentinel = 'private-dynamic-evidence-key-sentinel';
    const evidence = mutatePhase0Evidence('discovery.json', (value) => {
      const candidate = value.candidate as { observations: Array<Record<string, unknown>> };
      required(candidate.observations.at(0)).value = {
        [privateSentinel]: { $timestamp: 100, $toleranceSeconds: -1 },
      };
    });
    const context = provenanceContext();
    context.phase0EvidenceReproducer = reproducePhase0Evidence(evidence);

    try {
      await verifyPhase1ProfileProvenance(provenanceProfile(), context);
      throw new Error('Expected provenance validation to fail');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Phase1ProfileValidationError);
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 provenance',
        stage: 'provenance',
        pointers: ['/phase0Reproduction/discovery.json/candidate/observations/0/value'],
        rules: ['phase0-scenario-timestamp-marker'],
      });
      expect(String(error)).not.toContain(privateSentinel);
      expect(inspect(error)).not.toContain(privateSentinel);
      expect(JSON.stringify(error)).not.toContain(privateSentinel);
      expect((error as Error).stack).not.toContain(privateSentinel);
    }
  });

  it.each([
    {
      name: 'missing output',
      pointer: '/reference/phase0ArtifactSha256',
      rule: 'phase0-reproduction-files',
      reproduce: async () => ({
        commit: phase0Commit,
        files: Object.entries(phase0EvidenceBytes)
          .filter(([name]) => name !== 'run.json')
          .map(([name, bytes]) => ({ name, bytes })),
      }),
    },
    {
      name: 'extra output',
      pointer: '/reference/phase0ArtifactSha256',
      rule: 'phase0-reproduction-files',
      reproduce: async () => ({
        commit: phase0Commit,
        files: [
          ...Object.entries(phase0EvidenceBytes).map(([name, bytes]) => ({ name, bytes })),
          { name: 'extra.json', bytes: Buffer.from('{}') },
        ],
      }),
    },
    {
      name: 'reordered output',
      pointer: '/reference/phase0ArtifactSha256',
      rule: 'phase0-reproduction-files',
      reproduce: async () => ({
        commit: phase0Commit,
        files: Object.entries(phase0EvidenceBytes)
          .map(([name, bytes]) => ({ name, bytes }))
          .reverse(),
      }),
    },
    {
      name: 'wrong commit',
      pointer: '/reference/phase0HarnessCommit',
      rule: 'phase0-reproduction-commit',
      reproduce: async () => ({
        commit: oracleCommit,
        files: Object.entries(phase0EvidenceBytes).map(([name, bytes]) => ({ name, bytes })),
      }),
    },
    {
      name: 'oversized output',
      pointer: '/reference/phase0ArtifactSha256/discovery.json',
      rule: 'phase0-reproduction-bound',
      reproduce: async () => ({
        commit: phase0Commit,
        files: Object.entries(phase0EvidenceBytes).map(([name, bytes]) => ({
          name,
          bytes: name === 'discovery.json' ? Buffer.alloc(1024 * 1024 + 1) : bytes,
        })),
      }),
    },
    {
      name: 'private path-shaped output name',
      pointer: '/reference/phase0ArtifactSha256',
      rule: 'phase0-reproduction-files',
      reproduce: async () => ({
        commit: phase0Commit,
        files: Object.entries(phase0EvidenceBytes).map(([name, bytes]) => ({
          name: name === 'run.json' ? 'compatibility/phase-0-evidence/run.json' : name,
          bytes,
        })),
      }),
    },
  ])('rejects Phase 0 reproduction with $name', async ({ reproduce, pointer, rule }) => {
    const context = provenanceContext();
    context.phase0EvidenceReproducer = reproduce as unknown as Phase0EvidenceReproducer;
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      pointer,
      rule
    );
  });

  it('rejects shallow or missing commit history before reading source', async () => {
    for (const availability of ['shallow', 'missing'] as const) {
      const context = provenanceContext();
      context.gitReader.ensureFullCommit = async () => availability;
      await expectProvenanceFailure(
        verifyPhase1ProfileProvenance(provenanceProfile(), context),
        '/reference/oracleCommit',
        'complete-history'
      );
    }
  });

  it('rejects a missing planned artifact and an authority blob mismatch', async () => {
    const firstAuthorityPath = required(authorityPaths.at(0));
    const missingArtifact = provenanceContext();
    missingArtifact.gitReader.objectKind = async (_repository, commit, path) =>
      commit === harnessCommit && path === plannedArtifacts.browserRunner ? 'missing' : 'blob';
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), missingArtifact),
      '/phase1Harness/plannedArtifacts/browserRunner',
      'planned-artifact'
    );

    const wrongAuthority = provenanceContext();
    wrongAuthority.gitReader.objectId = async (_repository, commit, path) => {
      if (commit === phase0Commit && path === firstAuthorityPath) {
        return '0'.repeat(40);
      }

      if (commit === phase0Commit && Object.hasOwn(authorityBlobs, path)) {
        return authorityBlobs[path as keyof typeof authorityBlobs];
      }

      const uiObjects: Readonly<Record<string, string>> = {
        'packages/console': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'packages/experience': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'packages/demo-app': 'cccccccccccccccccccccccccccccccccccccccc',
        'pnpm-lock.yaml': 'dddddddddddddddddddddddddddddddddddddddd',
      };

      return uiObjects[path] ?? 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    };
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), wrongAuthority),
      `/schemaLockDocument/phase0AuthorityBlobs/${firstAuthorityPath.replaceAll('~', '~0').replaceAll('/', '~1')}`,
      'phase0-authority-blob'
    );
  });

  it('translates package manifest and lockfile authority failures to one static provenance rule', async () => {
    const marker = 'private-package-delta-marker';
    const manifest = provenanceContext();
    const originalReadBlob = manifest.gitReader.readBlob;
    manifest.gitReader.readBlob = async (repository, commit, path) =>
      commit === harnessCommit && path === 'packages/integration-tests/package.json'
        ? Buffer.from(`${JSON.stringify({ ...packageAuthorityHarness, [marker]: true })}\n`)
        : originalReadBlob(repository, commit, path);
    try {
      await verifyPhase1ProfileProvenance(provenanceProfile(), manifest);
      throw new Error('Expected package authority failure');
    } catch (error: unknown) {
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 provenance',
        pointers: ['/phase1Harness/commit'],
        rules: ['harness-package-authority'],
      });
      expect(String(error)).not.toContain(marker);
      expect((error as Error).stack).not.toContain(marker);
    }

    const lock = provenanceContext();
    const originalLockReadBlob = lock.gitReader.readBlob;
    lock.gitReader.readBlob = async (repository, commit, path) =>
      commit === harnessCommit && path === 'pnpm-lock.yaml'
        ? Buffer.concat([integrationLockBytes, Buffer.from('\n')])
        : originalLockReadBlob(repository, commit, path);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), lock),
      '/phase1Harness/commit',
      'harness-package-authority'
    );
  });

  it('review-candidate requires exact clean local HEAD', async () => {
    const wrongHead = provenanceContext();
    wrongHead.gitReader.localState = async () => ({ head: phase0Commit, clean: true });
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), wrongHead),
      '/phase1Harness/commit',
      'review-candidate-exact-head'
    );

    const dirty = provenanceContext();
    dirty.gitReader.localState = async () => ({ head: harnessCommit, clean: false });
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), dirty),
      '/phase1Harness/commit',
      'review-candidate-clean'
    );
  });

  it('rejects a runtime mode outside the closed provenance enum', async () => {
    const context = provenanceContext();
    context.mode = 'runtime-candidate' as unknown as Phase1ProvenanceContext['mode'];
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/provenance/mode',
      'provenance-mode'
    );
  });

  it.each([
    {
      name: 'pullRequests must be an array',
      mutate: (authority: MutableAuthority) => {
        authority.pullRequests = {};
      },
    },
    {
      name: 'pull request entry must be an exact object',
      mutate: (authority: MutableAuthority) => {
        authority.pullRequests = [null];
      },
    },
    {
      name: 'pull request rejects extra keys',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).extra = true;
      },
    },
    {
      name: 'pull request number must be an integer',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).number = '7';
      },
    },
    {
      name: 'pull request state must be closed',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).state = 'open';
      },
    },
    {
      name: 'pull request author must be a string',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).author = null;
      },
    },
    {
      name: 'pull request author is bounded',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).author = 'a'.repeat(101);
      },
    },
    {
      name: 'base branch must be a string',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).baseBranch = 1;
      },
    },
    {
      name: 'base branch is bounded',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).baseBranch = 'b'.repeat(256);
      },
    },
    ...(['baseCommit', 'mergeCommit', 'headCommit', 'evaluatedCommit'] as const).map((field) => ({
      name: `${field} must be a commit string`,
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority)[field] = null;
      },
    })),
    {
      name: 'codeOwnerReviewRequired must be boolean',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).codeOwnerReviewRequired = 'true';
      },
    },
    {
      name: 'approvals must be an array',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).approvals = {};
      },
    },
    {
      name: 'approval entry must be an exact object',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).approvals = [null];
      },
    },
    {
      name: 'approval rejects extra keys',
      mutate: (authority: MutableAuthority) => {
        authorityApproval(authority).extra = true;
      },
    },
    {
      name: 'approval reviewer must be a string',
      mutate: (authority: MutableAuthority) => {
        authorityApproval(authority).reviewer = 1;
      },
    },
    {
      name: 'approval reviewer is bounded',
      mutate: (authority: MutableAuthority) => {
        authorityApproval(authority).reviewer = 'r'.repeat(101);
      },
    },
    {
      name: 'approval state must be a closed enum',
      mutate: (authority: MutableAuthority) => {
        authorityApproval(authority).state = 'PENDING';
      },
    },
    {
      name: 'approval commit must be a commit string',
      mutate: (authority: MutableAuthority) => {
        authorityApproval(authority).commit = 1;
      },
    },
    {
      name: 'approval codeOwner must be boolean',
      mutate: (authority: MutableAuthority) => {
        authorityApproval(authority).codeOwner = 1;
      },
    },
    {
      name: 'checks must be an array',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).checks = {};
      },
    },
    {
      name: 'check entry must be an exact object',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).checks = [null];
      },
    },
    {
      name: 'check rejects extra keys',
      mutate: (authority: MutableAuthority) => {
        authorityCheck(authority).extra = true;
      },
    },
    {
      name: 'check name must be a string',
      mutate: (authority: MutableAuthority) => {
        authorityCheck(authority).name = 1;
      },
    },
    {
      name: 'check name is bounded',
      mutate: (authority: MutableAuthority) => {
        authorityCheck(authority).name = 'c'.repeat(257);
      },
    },
    {
      name: 'check conclusion must be a closed enum',
      mutate: (authority: MutableAuthority) => {
        authorityCheck(authority).conclusion = 'queued';
      },
    },
    {
      name: 'check headSha must be a commit string',
      mutate: (authority: MutableAuthority) => {
        authorityCheck(authority).headSha = null;
      },
    },
    {
      name: 'requiredChecks must be an array',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).requiredChecks = {};
      },
    },
    {
      name: 'required check entries must be strings',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).requiredChecks = [null];
      },
    },
    {
      name: 'required check names are bounded',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).requiredChecks = ['c'.repeat(257)];
      },
    },
    {
      name: 'bypassActors must be an array',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).bypassActors = {};
      },
    },
    {
      name: 'bypass actor entries must be strings',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).bypassActors = [1];
      },
    },
    {
      name: 'bypass actor names are bounded',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).bypassActors = ['a'.repeat(101)];
      },
    },
  ])('rejects malformed accepted authority projection when $name', async ({ mutate }) => {
    const context = provenanceContext('accepted-harness');
    mutateAcceptedAuthority(context, mutate);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      'accepted-authority-projection'
    );
  });

  it.each([
    {
      name: 'pullRequests has a leading sparse hole',
      mutate: (authority: MutableAuthority) => {
        authority.pullRequests = sparseArray([authorityPullRequest(authority)], 0);
      },
    },
    {
      name: 'approvals has a middle sparse hole',
      mutate: (authority: MutableAuthority) => {
        const approval = authorityApproval(authority);
        authorityPullRequest(authority).approvals = sparseArray([approval, approval, approval], 1);
      },
    },
    {
      name: 'checks has a trailing sparse hole',
      mutate: (authority: MutableAuthority) => {
        const check = authorityCheck(authority);
        authorityPullRequest(authority).checks = sparseArray([check, check, check], 2);
      },
    },
    {
      name: 'requiredChecks has a sparse hole that would otherwise bypass all required checks',
      mutate: (authority: MutableAuthority) => {
        const pullRequest = authorityPullRequest(authority);
        pullRequest.requiredChecks = sparseArray(['build'], 0);
        pullRequest.checks = [];
      },
    },
    {
      name: 'bypassActors has a leading sparse hole',
      mutate: (authority: MutableAuthority) => {
        authorityPullRequest(authority).bypassActors = sparseArray(['administrator'], 0);
      },
    },
    ...(['pullRequests', 'approvals', 'checks', 'requiredChecks'] as const).map((field) => ({
      name: `${field} rejects an extra enumerable property`,
      mutate: (authority: MutableAuthority) => {
        const pullRequest = authorityPullRequest(authority);
        const array =
          field === 'pullRequests'
            ? (authority.pullRequests as unknown[])
            : (pullRequest[field] as unknown[]);
        (array as unknown as Record<string, unknown>).privateExtra = true;
      },
    })),
    {
      name: 'requiredChecks rejects a symbol property',
      mutate: (authority: MutableAuthority) => {
        const requiredChecks = authorityPullRequest(authority).requiredChecks as unknown[];
        (requiredChecks as unknown as Record<PropertyKey, unknown>)[Symbol('private')] = true;
      },
    },
    {
      name: 'requiredChecks rejects an accessor index',
      mutate: (authority: MutableAuthority) => {
        const requiredChecks = authorityPullRequest(authority).requiredChecks as unknown[];
        Object.defineProperty(requiredChecks, '0', {
          configurable: true,
          enumerable: true,
          get: () => 'build',
        });
      },
    },
    {
      name: 'approvals rejects a nonplain Array prototype',
      mutate: (authority: MutableAuthority) => {
        const approvals = authorityPullRequest(authority).approvals as unknown[];
        Object.setPrototypeOf(approvals, {});
      },
    },
    {
      name: 'approvals rejects a proxy that mutates its reported prototype',
      mutate: (authority: MutableAuthority) => {
        const pullRequest = authorityPullRequest(authority);
        pullRequest.approvals = new Proxy(pullRequest.approvals as unknown[], {
          getPrototypeOf: () => null,
        });
      },
    },
  ])('rejects nonclosed accepted authority array when $name', async ({ mutate }) => {
    const context = provenanceContext('accepted-harness');
    mutateAcceptedAuthority(context, mutate);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      'accepted-authority-projection'
    );
  });

  it.each(['throwing accessor', 'throwing proxy'] as const)(
    'maps a malformed authority %s to a generic sanitized reader failure',
    async (kind) => {
      const privateSentinel = `private-authority-${kind}-sentinel`;
      const context = provenanceContext('accepted-harness');
      context.githubReader.acceptedHarnessAuthority = async () => {
        if (kind === 'throwing accessor') {
          return Object.defineProperty({}, 'pullRequests', {
            enumerable: true,
            get: () => {
              throw new Error(privateSentinel);
            },
          }) as Phase1AcceptedHarnessAuthority;
        }

        return new Proxy(
          {},
          {
            ownKeys: () => {
              throw new Error(privateSentinel);
            },
          }
        ) as Phase1AcceptedHarnessAuthority;
      };

      try {
        await verifyPhase1ProfileProvenance(provenanceProfile(), context);
        throw new Error('Expected provenance validation to fail');
      } catch (error: unknown) {
        expect(error).toBeInstanceOf(Phase1ProfileValidationError);
        expect(error).toMatchObject({
          message: 'Invalid Phase 1 provenance',
          stage: 'provenance',
          pointers: ['/'],
          rules: ['provenance-reader'],
        });
        expect(String(error)).not.toContain(privateSentinel);
        expect(inspect(error)).not.toContain(privateSentinel);
        expect(JSON.stringify(error)).not.toContain(privateSentinel);
        expect((error as Error).stack).not.toContain(privateSentinel);
      }
    }
  );

  it.each([
    {
      name: 'duplicate reviewer with a later CHANGES_REQUESTED record',
      mutate: (pullRequest: MutableAuthorityEntry) => {
        const approval = required((pullRequest.approvals as MutableAuthorityEntry[]).at(0));
        pullRequest.approvals = [approval, { ...approval, state: 'CHANGES_REQUESTED' }];
      },
    },
    {
      name: 'duplicate reviewer with a later DISMISSED record',
      mutate: (pullRequest: MutableAuthorityEntry) => {
        const approval = required((pullRequest.approvals as MutableAuthorityEntry[]).at(0));
        pullRequest.approvals = [approval, { ...approval, state: 'DISMISSED' }];
      },
    },
    {
      name: 'duplicate reviewer with two APPROVED records',
      mutate: (pullRequest: MutableAuthorityEntry) => {
        const approval = required((pullRequest.approvals as MutableAuthorityEntry[]).at(0));
        pullRequest.approvals = [approval, { ...approval }];
      },
    },
    {
      name: 'a current CHANGES_REQUESTED record from another reviewer',
      mutate: (pullRequest: MutableAuthorityEntry) => {
        const approval = required((pullRequest.approvals as MutableAuthorityEntry[]).at(0));
        pullRequest.approvals = [
          approval,
          { ...approval, reviewer: 'blocking-reviewer', state: 'CHANGES_REQUESTED' },
        ];
      },
    },
    {
      name: 'only an approval for the wrong head commit',
      mutate: (pullRequest: MutableAuthorityEntry) => {
        const approval = required((pullRequest.approvals as MutableAuthorityEntry[]).at(0));
        pullRequest.approvals = [{ ...approval, commit: phase0Commit }];
      },
    },
    {
      name: 'only the author approval',
      mutate: (pullRequest: MutableAuthorityEntry) => {
        const approval = required((pullRequest.approvals as MutableAuthorityEntry[]).at(0));
        pullRequest.approvals = [{ ...approval, reviewer: pullRequest.author }];
      },
    },
  ])('rejects accepted authority approval state when $name', async ({ mutate }) => {
    const context = provenanceContext('accepted-harness');
    mutateAcceptedAuthority(context, (authority) => {
      mutate(authorityPullRequest(authority));
    });
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      'accepted-review-approval'
    );
  });

  it.each(['two current approvals from different reviewers', 'approved plus dismissed reviewers'])(
    'accepts %s when one unique current nonauthor CODEOWNER approval covers the head',
    async (name) => {
      const context = provenanceContext('accepted-harness');
      mutateAcceptedAuthority(context, (authority) => {
        const pullRequest = authorityPullRequest(authority);
        const approval = required((pullRequest.approvals as MutableAuthorityEntry[]).at(0));
        pullRequest.approvals = [
          approval,
          {
            ...approval,
            reviewer: 'second-reviewer',
            state:
              name === 'two current approvals from different reviewers' ? 'APPROVED' : 'DISMISSED',
          },
        ];
      });
      await expect(
        verifyPhase1ProfileProvenance(provenanceProfile(), context)
      ).resolves.toMatchObject({ kind: 'accepted-harness', publishable: true });
    }
  );

  it.each([
    {
      name: 'protected reachability',
      rule: 'accepted-protected-reachability',
      mutate: (context: Phase1ProvenanceContext) => {
        context.gitReader.remoteContains = async () => false;
      },
    },
    {
      name: 'actual merge commit',
      rule: 'accepted-merge-pr',
      mutate: (context: Phase1ProvenanceContext) => {
        context.githubReader.acceptedHarnessAuthority = async () => {
          const authority = acceptedAuthority();
          return {
            pullRequests: [
              { ...required(authority.pullRequests.at(0)), mergeCommit: phase0Commit },
            ],
          };
        };
      },
    },
    {
      name: 'nonauthor CODEOWNER approval',
      rule: 'accepted-review-approval',
      mutate: (context: Phase1ProvenanceContext) => {
        context.githubReader.acceptedHarnessAuthority = async () => {
          const authority = acceptedAuthority();
          const pullRequest = required(authority.pullRequests.at(0));
          const approval = required(pullRequest.approvals.at(0));
          return {
            pullRequests: [
              {
                ...pullRequest,
                approvals: [{ ...approval, reviewer: 'author' }],
              },
            ],
          };
        };
      },
    },
    {
      name: 'no bypass actors',
      rule: 'accepted-authority-projection',
      mutate: (context: Phase1ProvenanceContext) => {
        context.githubReader.acceptedHarnessAuthority = async () => {
          const authority = acceptedAuthority();
          return {
            pullRequests: [
              { ...required(authority.pullRequests.at(0)), bypassActors: ['administrator'] },
            ],
          };
        };
      },
    },
    {
      name: 'checks on evaluated SHA',
      rule: 'accepted-required-checks',
      mutate: (context: Phase1ProvenanceContext) => {
        context.githubReader.acceptedHarnessAuthority = async () => {
          const authority = acceptedAuthority();
          const pullRequest = required(authority.pullRequests.at(0));
          const firstCheck = required(pullRequest.checks.at(0));
          const secondCheck = required(pullRequest.checks.at(1));
          return {
            pullRequests: [
              {
                ...pullRequest,
                checks: [{ ...firstCheck, headSha: pullRequest.headCommit }, secondCheck],
              },
            ],
          };
        };
      },
    },
    {
      name: 'unrelated evaluated SHA',
      rule: 'accepted-check-commit',
      mutate: (context: Phase1ProvenanceContext) => {
        const originalIsAncestor = context.gitReader.isAncestor;
        context.gitReader.isAncestor = async (repository, ancestor, descendant) =>
          ancestor === '5555555555555555555555555555555555555555' &&
          descendant === '6666666666666666666666666666666666666666'
            ? false
            : originalIsAncestor(repository, ancestor, descendant);
      },
    },
    {
      name: 'evaluated merge parents without the PR head',
      rule: 'accepted-check-commit',
      mutate: (context: Phase1ProvenanceContext) => {
        context.gitReader.parents = async () => [
          '7777777777777777777777777777777777777777',
          '8888888888888888888888888888888888888888',
        ];
      },
    },
    {
      name: 'duplicate required check name',
      rule: 'accepted-required-checks',
      mutate: (context: Phase1ProvenanceContext) => {
        context.githubReader.acceptedHarnessAuthority = async () => {
          const authority = acceptedAuthority();
          const pullRequest = required(authority.pullRequests.at(0));
          const firstCheck = required(pullRequest.checks.at(0));

          return {
            pullRequests: [
              {
                ...pullRequest,
                checks: [...pullRequest.checks, { ...firstCheck, conclusion: 'failure' }],
              },
            ],
          };
        };
      },
    },
  ])('accepted-harness rejects invalid $name', async ({ mutate, rule }) => {
    const context = provenanceContext('accepted-harness');
    mutate(context);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/phase1Harness/commit',
      rule
    );
  });

  it('sanitizes reader failures without exposing raw output or causes', async () => {
    const context = provenanceContext();
    context.gitReader.readBlob = async () => {
      throw new Error('private-output-sentinel');
    };

    try {
      await verifyPhase1ProfileProvenance(provenanceProfile(), context);
      throw new Error('Expected provenance validation to fail');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Phase1ProfileValidationError);
      expect(String(error)).not.toContain('private-output-sentinel');
      expect(error).not.toHaveProperty('cause');
    }
  });

  it('sanitizes Git delta reader failures without exposing raw output', async () => {
    const marker = 'private-git-delta-reader-sentinel';
    const context = provenanceContext();
    context.gitReader.diffEntries = async () => {
      throw new Error(marker);
    };

    await expectGenericSanitizedProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      marker
    );
  });

  it.each([
    {
      name: 'Git reader',
      mode: 'review-candidate' as const,
      inject: (context: Phase1ProvenanceContext, error: Phase1ProfileValidationError) => {
        context.gitReader.readBlob = async () => {
          throw error;
        };
      },
      errorShape: 'plain' as const,
    },
    {
      name: 'Phase 0 reproducer',
      mode: 'review-candidate' as const,
      inject: (context: Phase1ProvenanceContext, error: Phase1ProfileValidationError) => {
        context.phase0EvidenceReproducer = async () => {
          throw error;
        };
      },
      errorShape: 'plain' as const,
    },
    {
      name: 'GitHub reader subclass',
      mode: 'accepted-harness' as const,
      inject: (context: Phase1ProvenanceContext, error: Phase1ProfileValidationError) => {
        context.githubReader.acceptedHarnessAuthority = async () => {
          throw error;
        };
      },
      errorShape: 'subclass' as const,
    },
    {
      name: 'Git reader stage accessor',
      mode: 'review-candidate' as const,
      inject: (context: Phase1ProvenanceContext, error: Phase1ProfileValidationError) => {
        context.gitReader.readBlob = async () => {
          throw error;
        };
      },
      errorShape: 'stage-accessor' as const,
    },
    {
      name: 'Phase 0 reproducer stage proxy',
      mode: 'review-candidate' as const,
      inject: (context: Phase1ProvenanceContext, error: Phase1ProfileValidationError) => {
        context.phase0EvidenceReproducer = async () => {
          throw error;
        };
      },
      errorShape: 'stage-proxy' as const,
    },
    {
      name: 'GitHub reader prototype proxy',
      mode: 'accepted-harness' as const,
      inject: (context: Phase1ProvenanceContext, error: Phase1ProfileValidationError) => {
        context.githubReader.acceptedHarnessAuthority = async () => {
          throw error;
        };
      },
      errorShape: 'prototype-proxy' as const,
    },
  ])(
    'maps a forged same-class error from the $name to a fresh generic sanitized error',
    async ({ mode, inject, errorShape }) => {
      const privateSentinel = 'private-forged-provenance-error-sentinel';
      class ForgedProvenanceValidationError extends Phase1ProfileValidationError {}
      const baseError =
        errorShape === 'subclass'
          ? new ForgedProvenanceValidationError(
              'provenance',
              [`/${privateSentinel}`],
              [privateSentinel]
            )
          : new Phase1ProfileValidationError(
              'provenance',
              [`/${privateSentinel}`],
              [privateSentinel]
            );
      Object.defineProperty(baseError, 'cause', {
        configurable: true,
        enumerable: true,
        value: new Error(privateSentinel),
      });
      const forged = (() => {
        if (errorShape === 'stage-accessor') {
          return Object.defineProperty(baseError, 'stage', {
            configurable: true,
            get: () => {
              throw new Error(privateSentinel);
            },
          });
        }

        if (errorShape === 'stage-proxy') {
          return new Proxy(baseError, {
            get: (target, property, receiver) => {
              if (property === 'stage') {
                throw new Error(privateSentinel);
              }

              return Reflect.get(target, property, receiver) as unknown;
            },
          });
        }

        if (errorShape === 'prototype-proxy') {
          return new Proxy(baseError, {
            getPrototypeOf: () => {
              throw new Error(privateSentinel);
            },
          });
        }

        return baseError;
      })();
      const context = provenanceContext(mode);
      inject(context, forged);

      await expectGenericSanitizedProvenanceFailure(
        verifyPhase1ProfileProvenance(provenanceProfile(), context),
        privateSentinel
      );
    }
  );

  it('preserves a branded production Git object-kind error through the aggregate verifier', async () => {
    const context = provenanceContext();
    context.gitReader = createProductionPhase1GitReader(
      { [oracleRepository]: '/synthetic/oracle' },
      async ({ args }) => {
        if (args.includes('--is-shallow-repository')) {
          return Buffer.from('false\n');
        }

        if (args.includes('-t')) {
          return Buffer.from('tree\n');
        }

        return Buffer.from('');
      }
    );
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/git',
      'git-object-kind'
    );
  });

  it('rejects an oversized injected Git blob at its static source pointer', async () => {
    const context = provenanceContext();
    context.gitReader.readBlob = async () => Buffer.alloc(1024 * 1024 + 1);
    await expectProvenanceFailure(
      verifyPhase1ProfileProvenance(provenanceProfile(), context),
      '/browserFlows/0/sourceEvidence/0',
      'git-reader-bound'
    );
  });

  it('accepts only the exact reviewed combined harness and Aster source delta shape', async () => {
    const currentHarnessCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: repositoryRoot,
      encoding: 'utf8',
    }).trim();
    const productionReader = createProductionPhase1GitReader({
      [oracleRepository]: repositoryRoot,
    });
    const combinedDelta = await productionReader.diffEntries(
      oracleRepository,
      phase0Commit,
      currentHarnessCommit
    );

    expect(combinedDelta.length).toBeGreaterThan(1000);

    const accepted = provenanceContext();
    accepted.gitReader.diffEntries = async () => combinedDelta;
    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), accepted)
    ).resolves.toMatchObject({
      kind: 'review-candidate',
      harnessCommit,
      publishable: false,
    });

    const acceptedHarness = provenanceContext('accepted-harness');
    const { readBlob } = acceptedHarness.gitReader;
    let workflowAuthorityRead = false;
    acceptedHarness.gitReader.readBlob = async (repository, commit, sourcePath) => {
      if (
        commit === harnessCommit &&
        sourcePath === '.github/workflows/phase1-compatibility-test.yml'
      ) {
        workflowAuthorityRead = true;
      }

      return readBlob(repository, commit, sourcePath);
    };
    acceptedHarness.gitReader.diffEntries = async () => combinedDelta;
    await expect(
      verifyPhase1ProfileProvenance(provenanceProfile(), acceptedHarness)
    ).resolves.toMatchObject({
      kind: 'accepted-harness',
      harnessCommit,
      protectedBranch: 'aster-phase1-harness',
      pullRequestNumber: 7,
      publishable: true,
    });
    expect(workflowAuthorityRead).toBe(true);

    const first = required(combinedDelta.at(0));
    const invalidDeltas = [
      combinedDelta.slice(0, -1),
      [{ ...first, path: `${first.path}.changed` }, ...combinedDelta.slice(1)],
      [
        { ...first, status: first.status === 'added' ? ('modified' as const) : ('added' as const) },
        ...combinedDelta.slice(1),
      ],
      [
        { ...first, newMode: first.newMode === '100644' ? '100755' : '100644' },
        ...combinedDelta.slice(1),
      ],
    ];

    for (const invalidDelta of invalidDeltas) {
      const invalid = provenanceContext();
      invalid.gitReader.diffEntries = async () => invalidDelta;
      await expectProvenanceFailure(
        verifyPhase1ProfileProvenance(provenanceProfile(), invalid),
        '/phase1Harness/commit',
        'review-harness-delta'
      );
    }
  });

  it('the production Git reader uses exact commit object reads and bounded commands', async () => {
    const calls: Phase1CommandRequest[] = [];
    const reader = createProductionPhase1GitReader(
      { [oracleRepository]: '/synthetic/oracle' },
      async (request) => {
        calls.push(request);

        if (request.args.includes('--is-shallow-repository')) {
          return Buffer.from('false\n');
        }

        if (request.args.includes('-t')) {
          return Buffer.from('blob\n');
        }

        if (request.args.includes('-p')) {
          return Buffer.from('blob-bytes');
        }

        return Buffer.from('');
      }
    );
    const bytes = await reader.readBlob(oracleRepository, oracleCommit, 'source/file.ts');
    expect(bytes).toEqual(Buffer.from('blob-bytes'));
    expect(calls.some(({ args }) => args.includes(`${oracleCommit}:source/file.ts`))).toBe(true);
    expect(calls.every(({ maximumBytes }) => maximumBytes <= 1024 * 1024)).toBe(true);
    expect(calls.every(({ environment }) => !Object.hasOwn(environment, 'HOME'))).toBe(true);
    expect(
      calls.every(
        ({ environment }) =>
          environment.GIT_CONFIG_GLOBAL === '/dev/null' &&
          environment.GIT_CONFIG_SYSTEM === '/dev/null' &&
          environment.GIT_CONFIG_KEY_0 === 'credential.helper' &&
          environment.GIT_CONFIG_VALUE_0 === '' &&
          environment.GIT_TERMINAL_PROMPT === '0'
      )
    ).toBe(true);
    expect(
      calls.some(
        ({ args }) => args.includes('source/file.ts') && !args.join(' ').includes(oracleCommit)
      )
    ).toBe(false);
  });

  it('the production Git reader parses a bounded exact raw delta without replacement objects', async () => {
    const calls: Phase1CommandRequest[] = [];
    const zero = '0'.repeat(40);
    const first = '1'.repeat(40);
    const second = '2'.repeat(40);
    const raw = Buffer.from(
      `:100644 000000 ${first} ${zero} D\0z/deleted.json\0` +
        `:000000 100755 ${zero} ${second} A\0a/script.sh\0` +
        `:100644 100644 ${first} ${second} M\0m/modified.json\0` +
        `:120000 100644 ${first} ${second} T\0t/type-changed.json\0`
    );
    const reader = createProductionPhase1GitReader(
      { [oracleRepository]: '/synthetic/oracle' },
      async (request) => {
        calls.push(request);
        return raw;
      }
    );

    await expect(
      reader.diffEntries(oracleRepository, phase0Commit, harnessCommit)
    ).resolves.toEqual([
      {
        status: 'added',
        path: 'a/script.sh',
        oldMode: '000000',
        newMode: '100755',
      },
      {
        status: 'modified',
        path: 'm/modified.json',
        oldMode: '100644',
        newMode: '100644',
      },
      {
        status: 'type-changed',
        path: 't/type-changed.json',
        oldMode: '120000',
        newMode: '100644',
      },
      {
        status: 'deleted',
        path: 'z/deleted.json',
        oldMode: '100644',
        newMode: '000000',
      },
    ] satisfies Phase1GitDeltaEntry[]);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      args: [
        'diff-tree',
        '--no-commit-id',
        '-r',
        '--raw',
        '-z',
        '--no-renames',
        '--abbrev=40',
        phase0Commit,
        harnessCommit,
        '--',
      ],
    });
    expect(calls[0]?.maximumBytes).toBeLessThanOrEqual(1024 * 1024);
    expect(calls[0]?.environment.GIT_NO_REPLACE_OBJECTS).toBe('1');
  });

  it.each([
    [
      'missing terminal NUL',
      Buffer.from(':000000 100644 ' + '0'.repeat(40) + ' ' + '1'.repeat(40) + ' A\0safe.json'),
    ],
    [
      'rename status',
      Buffer.from(
        ':100644 100644 ' + '1'.repeat(40) + ' ' + '2'.repeat(40) + ' R100\0old.json\0new.json\0'
      ),
    ],
    [
      'duplicate path',
      Buffer.from(
        ':000000 100644 ' +
          '0'.repeat(40) +
          ' ' +
          '1'.repeat(40) +
          ' A\0safe.json\0:100644 100644 ' +
          '1'.repeat(40) +
          ' ' +
          '2'.repeat(40) +
          ' M\0safe.json\0'
      ),
    ],
    [
      'unsafe path',
      Buffer.from(
        ':000000 100644 ' + '0'.repeat(40) + ' ' + '1'.repeat(40) + ' A\0../escape.json\0'
      ),
    ],
    ['invalid UTF-8', Buffer.from([0xff, 0x00])],
    [
      'inconsistent add mode',
      Buffer.from(':100644 100644 ' + '1'.repeat(40) + ' ' + '2'.repeat(40) + ' A\0safe.json\0'),
    ],
    [
      'zero object for an addition',
      Buffer.from(':000000 100644 ' + '0'.repeat(40) + ' ' + '0'.repeat(40) + ' A\0safe.json\0'),
    ],
  ] as const)('the production Git reader rejects a raw delta with %s', async (_name, raw) => {
    const reader = createProductionPhase1GitReader(
      { [oracleRepository]: '/synthetic/oracle' },
      async () => raw
    );

    await expect(
      reader.diffEntries(oracleRepository, phase0Commit, harnessCommit)
    ).rejects.toMatchObject({
      stage: 'provenance',
      pointers: ['/git'],
    });
  });

  it('the production Git reader bounds raw delta bytes and entry count', async () => {
    const zero = '0'.repeat(40);
    const object = '1'.repeat(40);
    const excessiveEntries = Buffer.from(
      Array.from(
        { length: 4097 },
        (_value, index) =>
          `:000000 100644 ${zero} ${object} A\0generated/${index.toString().padStart(4, '0')}.json\0`
      ).join('')
    );

    for (const raw of [excessiveEntries, Buffer.alloc(1024 * 1024 + 1)]) {
      const reader = createProductionPhase1GitReader(
        { [oracleRepository]: '/synthetic/oracle' },
        async () => raw
      );
      await expect(
        reader.diffEntries(oracleRepository, phase0Commit, harnessCommit)
      ).rejects.toMatchObject({
        stage: 'provenance',
        pointers: ['/git'],
      });
    }
  });

  it('the production Git reader unshallows and verifies the exact fetched commit', async () => {
    const calls: Phase1CommandRequest[] = [];
    let shallowReads = 0;
    const reader = createProductionPhase1GitReader(
      { [oracleRepository]: '/synthetic/oracle' },
      async (request) => {
        calls.push(request);

        if (request.args.includes('--is-shallow-repository')) {
          shallowReads += 1;

          return Buffer.from(shallowReads === 1 ? 'true\n' : 'false\n');
        }

        return Buffer.from('');
      }
    );
    await expect(reader.ensureFullCommit(oracleRepository, oracleCommit)).resolves.toBe('complete');
    expect(calls.some(({ args }) => args.includes('--unshallow'))).toBe(true);
    expect(calls.some(({ args }) => args.includes(oracleCommit))).toBe(true);
    expect(calls.some(({ args }) => args.includes(`${oracleCommit}^{commit}`))).toBe(true);
  });

  it('the production Git reader rejects private Phase 0 paths before every object command', async () => {
    const calls: Phase1CommandRequest[] = [];
    const reader = createProductionPhase1GitReader(
      { [oracleRepository]: '/synthetic/oracle' },
      async (request) => {
        calls.push(request);

        return Buffer.from('');
      }
    );
    const privatePaths = [
      'compatibility/phase-0-evidence/run.json',
      './compatibility/phase-0-evidence/run.json',
      'compatibility/./phase-0-evidence/run.json',
    ];

    for (const privatePath of privatePaths) {
      await expect(
        reader.readBlob(oracleRepository, phase0Commit, privatePath)
      ).rejects.toMatchObject({
        stage: 'provenance',
        rules: ['phase0-private-evidence-path'],
      });
      await expect(
        reader.objectId(oracleRepository, phase0Commit, privatePath)
      ).rejects.toMatchObject({
        stage: 'provenance',
        rules: ['phase0-private-evidence-path'],
      });
      await expect(
        reader.objectKind(oracleRepository, phase0Commit, privatePath)
      ).rejects.toMatchObject({
        stage: 'provenance',
        rules: ['phase0-private-evidence-path'],
      });
    }
    expect(calls).toHaveLength(0);
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop, unicorn/prevent-abbreviations */
