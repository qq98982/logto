/* eslint-disable complexity, max-lines, no-restricted-syntax, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The closed Phase 2 CLI owns exact grammar, canonical paths, private session lifetime, real mode orchestration, and success-only atomic publication. */
import { constants as fsConstants } from 'node:fs';
import { chmod, lstat, mkdtemp, open, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import type { JsonValue } from '../normalize.js';
import { writeSecureJsonArtifact } from '../phase-1/secure-evidence-sink.js';

import {
  runClientCredentialsCandidateInvariants,
  type CandidateInvariantControlEvidence,
} from './candidate-invariants/client-credentials.js';
import { createPhase2EvidenceEnvelope, type Phase2TargetProvenance } from './envelope.js';
import {
  createCandidatePhase2FixtureProvisioner,
  createReferencePhase2FixtureProvisioner,
  runWithPhase2Fixture,
  type Phase2FixtureProvisioner,
  type ProvisionedPhase2Fixture,
} from './fixtures.js';
import {
  loadPhase2Profile,
  type Phase2ProfilePaths,
  type Phase2ProfileRegistries,
} from './profile.js';
import {
  assertClientCredentialsEvidenceIsSanitized,
  createClientCredentialsJwtAudit,
} from './projections/client-credentials.js';
import { compareTokenStatus } from './projections/token-status.js';
import {
  inspectLaunchedPhase2HarnessSource,
  recheckCleanPhase2HarnessSource,
  type Phase2SourceIdentity,
} from './provenance.js';
import {
  createCommandPhase2ScenarioStateDriver,
  fetchPhase2Discovery,
  fetchPhase2PublicJwks,
  preparePhase2TargetForExecution,
  validatePhase2TargetDescriptor,
  verifyPhase2Target,
  type Phase2TargetDescriptor,
  type PreparedPhase2Target,
  type VerifiedPhase2Target,
} from './runtime.js';
import {
  assertDiscoveryAbsentFieldsContract,
  assertDiscoveryEndpointFieldsContract,
  assertDiscoveryGrantContract,
  clientCredentialsScenarioIds,
  compareClientCredentialsProjections,
  createClientCredentialsScenarioRegistry,
  runClientCredentialsNegativeControls,
  waitForClientCredentialsFixtureReady,
  type ClientCredentialsControlResult,
  type ClientCredentialsScenarioResult,
} from './scenarios/client-credentials.js';
import {
  runTokenStatusScenarios,
  tokenStatusScenarioIds,
  type TokenStatusScenarioResult,
} from './scenarios/token-status.js';

export type Phase2CliCommand =
  | Readonly<{
      mode: 'oracle';
      profilePath: string;
      schemaPath: string;
      targetPath: string;
      outputPath: string;
      tempRoot: string;
    }>
  | Readonly<{
      mode: 'differential';
      profilePath: string;
      schemaPath: string;
      oracleTargetPath: string;
      candidateTargetPath: string;
      outputPath: string;
      tempRoot: string;
    }>
  | Readonly<{
      mode: 'candidate-invariants';
      profilePath: string;
      schemaPath: string;
      targetPath: string;
      outputPath: string;
      tempRoot: string;
    }>;

export type Phase2CliDependencies = Readonly<{
  loadProfile(paths: Phase2ProfilePaths): Promise<Phase2ProfileRegistries>;
  readTarget(path: string): Promise<Phase2TargetDescriptor>;
  executeOracle(
    input: Readonly<{
      profile: Phase2ProfileRegistries;
      target: PreparedPhase2Target;
      sessionRoot: string;
    }>
  ): Promise<unknown>;
  executeDifferential(
    input: Readonly<{
      profile: Phase2ProfileRegistries;
      oracle: PreparedPhase2Target;
      candidate: PreparedPhase2Target;
      sessionRoot: string;
    }>
  ): Promise<unknown>;
  executeCandidateInvariants(
    input: Readonly<{
      profile: Phase2ProfileRegistries;
      target: PreparedPhase2Target;
      sessionRoot: string;
    }>
  ): Promise<unknown>;
  publish(outputPath: string, value: JsonValue): Promise<void>;
  removeSessionRoot(sessionRoot: string): Promise<void>;
  stdout(message: string): void | Promise<void>;
  stderr(message: string): void | Promise<void>;
  inspectHarness(runtimeCapability: string | undefined): Promise<Phase2SourceIdentity>;
  recheckHarness(capability: Phase2SourceIdentity): Promise<void>;
  verifyTarget(target: Phase2TargetDescriptor): Promise<VerifiedPhase2Target>;
  prepareTarget(
    target: VerifiedPhase2Target,
    sessionRoot: string,
    namespace: 'oracle' | 'candidate'
  ): Promise<PreparedPhase2Target>;
}>;

type TargetScenarioEvidence = Readonly<{
  target: 'oracle' | 'candidate';
  scenarios: ReadonlyArray<ClientCredentialsScenarioResult | TokenStatusScenarioResult>;
  discovery: Readonly<{
    grantTypesSupported: readonly string[];
    endpointFieldsAppend: readonly ['introspection_endpoint', 'revocation_endpoint'];
    stillAbsent: readonly string[];
  }>;
  controls: readonly ClientCredentialsControlResult[];
}>;

const invalidArguments = 'Invalid Phase 2 arguments.\n';
const runFailure = 'Phase 2 client credentials command failed.\n';
const scenarioFailurePattern =
  /^Phase 2 scenario failed: (oracle|candidate)\/(client-credentials\.[a-z-]+|token-status\.[a-z-]+)$/u;
const stageFailurePattern =
  /^Phase 2 stage failed: (oracle|candidate)-(fixture|discovery|controls|comparison|status-(?:admission|authorization|bootstrap|verification|identification|submit|bridge-(?:url|send|http-(?:200|302|303|400|404|other))|consent-read|consent-write|resume|token-(?:http|body|type|access|refresh)|introspection)|status-comparison-(?:kind|status|headers|body(?:-(?:sub|client_id|exp|iat|iss|scope|token_type))?|grant)|status-scope-(?:short|full|resource|offline|other)-(?:short|full|resource|offline|other))(?::.*)?$/u;
const commandFailurePattern =
  /^Phase 2 command stage failed: differential-(target-path|target-read|target-pair|target-verify|target-prepare|execution|harness|evidence|publish)$/u;
const profileScenarioIdIsClosed = (value: string): boolean =>
  (clientCredentialsScenarioIds as readonly string[]).includes(value) ||
  (tokenStatusScenarioIds as readonly string[]).includes(value);
const successMessages = Object.freeze({
  oracle: 'Phase 2 client credentials oracle complete.\n',
  differential: 'Phase 2 client credentials differential complete.\n',
  'candidate-invariants': 'Phase 2 client credentials candidate invariants complete.\n',
});
const maximumInputBytes = 1024 * 1024;
const fixedOutputNames = Object.freeze({
  oracle: 'phase-2-client-credentials-oracle.json',
  differential: 'phase-2-client-credentials-differential.json',
  'candidate-invariants': 'phase-2-client-credentials-candidate-invariants.json',
});

const findRepositoryRoot = (): string => {
  let current = path.dirname(fileURLToPath(import.meta.url));
  for (let remaining = 8; remaining > 0; remaining -= 1) {
    if (
      path.basename(current) === 'integration-tests' &&
      path.basename(path.dirname(current)) === 'packages'
    ) {
      return path.resolve(current, '../..');
    }
    current = path.dirname(current);
  }
  return fail();
};
const repositoryRoot = findRepositoryRoot();
const runtimeEntryPath = path.resolve(
  repositoryRoot,
  'packages/integration-tests/lib/compatibility/phase-2/cli.js'
);

const fail = (): never => {
  throw new TypeError(invalidArguments.trim());
};

const parseFlagMap = (
  values: readonly string[],
  allowed: ReadonlySet<string>
): ReadonlyMap<string, string> => {
  if (values.length !== allowed.size * 2) {
    return fail();
  }
  const result = new Map<string, string>();
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (
      !name ||
      !value ||
      name.includes('=') ||
      !allowed.has(name) ||
      result.has(name) ||
      value.startsWith('--') ||
      /\p{Cc}/u.test(value) ||
      Buffer.byteLength(value) > 4096
    ) {
      return fail();
    }
    result.set(name, value);
  }
  return result;
};

const required = (values: ReadonlyMap<string, string>, name: string): string =>
  values.get(name) ?? fail();

export const parsePhase2Arguments = (arguments_: readonly string[]): Phase2CliCommand => {
  const [mode, ...rest] = arguments_;
  if (mode === 'oracle' || mode === 'candidate-invariants') {
    const values = parseFlagMap(
      rest,
      new Set(['--profile', '--schema', '--target', '--output', '--temp-root'])
    );
    return Object.freeze({
      mode,
      profilePath: required(values, '--profile'),
      schemaPath: required(values, '--schema'),
      targetPath: required(values, '--target'),
      outputPath: required(values, '--output'),
      tempRoot: required(values, '--temp-root'),
    });
  }
  if (mode === 'differential') {
    const values = parseFlagMap(
      rest,
      new Set([
        '--profile',
        '--schema',
        '--oracle-target',
        '--candidate-target',
        '--output',
        '--temp-root',
      ])
    );
    return Object.freeze({
      mode,
      profilePath: required(values, '--profile'),
      schemaPath: required(values, '--schema'),
      oracleTargetPath: required(values, '--oracle-target'),
      candidateTargetPath: required(values, '--candidate-target'),
      outputPath: required(values, '--output'),
      tempRoot: required(values, '--temp-root'),
    });
  }
  return fail();
};

const currentUid = (): number => {
  const uid = process.getuid?.();
  return typeof uid === 'number' ? uid : fail();
};

const validatePrivateRoot = async (value: string): Promise<string> => {
  if (!path.isAbsolute(value) || path.normalize(value) !== value) {
    return fail();
  }
  const [state, resolved] = await Promise.all([lstat(value), realpath(value)]).catch(fail);
  if (
    state.isSymbolicLink() ||
    !state.isDirectory() ||
    state.uid !== currentUid() ||
    (state.mode & 0o777) !== 0o700 ||
    resolved !== value
  ) {
    return fail();
  }
  return value;
};

const validateInputFile = async (value: string): Promise<string> => {
  if (!path.isAbsolute(value) || path.normalize(value) !== value) {
    return fail();
  }
  const [state, resolved] = await Promise.all([lstat(value), realpath(value)]).catch(fail);
  if (
    state.isSymbolicLink() ||
    !state.isFile() ||
    state.size > maximumInputBytes ||
    resolved !== value
  ) {
    return fail();
  }
  return value;
};

const validateOutputPath = async (
  mode: Phase2CliCommand['mode'],
  outputPath: string,
  temporaryRoot: string
): Promise<string> => {
  if (
    !path.isAbsolute(outputPath) ||
    path.normalize(outputPath) !== outputPath ||
    path.dirname(outputPath) !== temporaryRoot ||
    path.basename(outputPath) !== fixedOutputNames[mode]
  ) {
    return fail();
  }
  try {
    await lstat(outputPath);
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
  return outputPath;
};

const inspectJsonNode = (node: JsonNode | undefined): void => {
  if (!node) {
    return fail();
  }
  if (node.type === 'object') {
    const names = new Set<string>();
    for (const property of node.children ?? []) {
      const [nameNode, valueNode] = property.children ?? [];
      const name: unknown = nameNode?.value;
      if (typeof name !== 'string' || names.has(name)) {
        return fail();
      }
      names.add(name);
      inspectJsonNode(valueNode);
    }
  } else if (node.type === 'array') {
    for (const child of node.children ?? []) {
      inspectJsonNode(child);
    }
  }
};

const readStrictJson = async (filePath: string): Promise<unknown> => {
  const [before, resolved] = await Promise.all([lstat(filePath), realpath(filePath)]).catch(fail);
  if (
    before.isSymbolicLink() ||
    !before.isFile() ||
    before.size > maximumInputBytes ||
    resolved !== filePath
  ) {
    return fail();
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);
  try {
    const state = await handle.stat();
    if (
      !state.isFile() ||
      state.size > maximumInputBytes ||
      state.dev !== before.dev ||
      state.ino !== before.ino
    ) {
      return fail();
    }
    const bytes = new Uint8Array(state.size);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset);
      if (bytesRead <= 0) {
        return fail();
      }
      offset += bytesRead;
    }
    const [openedAfter, pathAfter] = await Promise.all([handle.stat(), lstat(filePath)]);
    if (
      openedAfter.dev !== state.dev ||
      openedAfter.ino !== state.ino ||
      openedAfter.size !== state.size ||
      openedAfter.mtimeMs !== state.mtimeMs ||
      pathAfter.isSymbolicLink() ||
      pathAfter.dev !== state.dev ||
      pathAfter.ino !== state.ino ||
      pathAfter.size !== state.size ||
      pathAfter.mtimeMs !== state.mtimeMs
    ) {
      return fail();
    }
    const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
    const errors: ParseError[] = [];
    const tree = parseTree(text, errors, {
      allowEmptyContent: false,
      allowTrailingComma: false,
      disallowComments: true,
    });
    if (!tree || errors.length > 0) {
      return fail();
    }
    inspectJsonNode(tree);
    return JSON.parse(text) as unknown;
  } finally {
    await handle.close();
  }
};

export const readPhase2TargetDescriptor = async (
  filePath: string
): Promise<Phase2TargetDescriptor> =>
  validatePhase2TargetDescriptor(await readStrictJson(await validateInputFile(filePath)));

const projectDiscovery = async (
  descriptor: Phase2TargetDescriptor,
  profile: Phase2ProfileRegistries
): Promise<TargetScenarioEvidence['discovery']> => {
  const discovery = await fetchPhase2Discovery(descriptor.target);
  const grantTypes = assertDiscoveryGrantContract(
    discovery.grant_types_supported,
    profile.discovery.grantTypesSupportedAppend,
    descriptor.kind
  );
  return Object.freeze({
    grantTypesSupported: grantTypes,
    endpointFieldsAppend: assertDiscoveryEndpointFieldsContract(
      discovery,
      profile.discovery.endpointFieldsAppend,
      new URL('oidc', descriptor.target.coreUrl).toString()
    ),
    stillAbsent: assertDiscoveryAbsentFieldsContract(
      discovery,
      profile.discovery.stillAbsent,
      descriptor.kind
    ),
  });
};

const provisionerFor = (prepared: PreparedPhase2Target): Phase2FixtureProvisioner => {
  const { descriptor } = prepared;
  return descriptor.kind === 'oracle'
    ? createReferencePhase2FixtureProvisioner({
        target: descriptor.target,
        foreignTarget: descriptor.foreignTarget,
      })
    : createCandidatePhase2FixtureProvisioner({
        executablePath: descriptor.fixtureExecutable?.path ?? fail(),
        target: descriptor.target,
        foreignTarget: descriptor.foreignTarget,
        environment: {
          ASTER_FIXTURE_SOCKET: descriptor.fixtureSocket,
        },
        identityFence: prepared.fence,
      });
};

const publicTargetProvenance = (verified: VerifiedPhase2Target): Phase2TargetProvenance =>
  Object.freeze({
    sourceCommit: verified.descriptor.sourceCommit,
    imageDigest: verified.descriptor.imageDigest,
    topology: Object.freeze({
      primaryRole: verified.topology.primary.service,
      foreignRole: verified.topology.foreign.service,
    }),
    drivers: Object.freeze({
      state: Object.freeze({ role: 'state-driver', sha256: verified.stateDriver.sha256 }),
      ...(verified.fixtureExecutable && {
        fixture: Object.freeze({
          role: 'fixture-executable' as const,
          sha256: verified.fixtureExecutable.sha256,
        }),
      }),
      ...(verified.invariantDriver && {
        invariant: Object.freeze({
          role: 'invariant-driver' as const,
          sha256: verified.invariantDriver.sha256,
        }),
      }),
    }),
  });

const runTargetScenarios = async (
  profile: Phase2ProfileRegistries,
  prepared: PreparedPhase2Target
): Promise<TargetScenarioEvidence> => {
  const { descriptor } = prepared;
  const state = await createCommandPhase2ScenarioStateDriver({
    descriptor,
    identityFence: prepared.fence,
  });
  const jwtAudit = createClientCredentialsJwtAudit();
  const provisioner = provisionerFor(prepared);
  const scenarios = await runWithPhase2Fixture(provisioner, async (fixture) => {
    await waitForClientCredentialsFixtureReady(descriptor.target, fixture.public);
    const jwks = await fetchPhase2PublicJwks(descriptor.target);
    const results: ClientCredentialsScenarioResult[] = [];
    for (const scenario of createClientCredentialsScenarioRegistry(profile)) {
      try {
        results.push(
          await scenario.run({
            target: descriptor.target,
            fixture,
            jwks,
            state,
            jwtAudit,
          })
        );
      } catch {
        throw new Error(`Phase 2 scenario failed: ${descriptor.kind}/${scenario.id}`);
      }
    }
    let statusScenarios: readonly TokenStatusScenarioResult[];
    try {
      statusScenarios = await runTokenStatusScenarios(profile, descriptor.target, fixture);
    } catch (error: unknown) {
      if (error instanceof Error && scenarioFailurePattern.test(error.message)) {
        throw error;
      }
      const step =
        error instanceof Error
          ? /^Invalid Phase 2 public user token issuance \((admission|authorization|bootstrap|verification|identification|submit|bridge-(?:url|send|http-(?:200|302|303|400|404|other))|consent-read|consent-write|resume|token-(?:http|body|type|access|refresh))\)$/u.exec(
              error.message
            )?.[1]
          : undefined;
      throw new Error(
        'Phase 2 stage failed: ' + descriptor.kind + '-status-' + (step ?? 'introspection')
      );
    }
    return Object.freeze([...results, ...statusScenarios]);
  }).catch((error: unknown) => {
    if (
      error instanceof Error &&
      (scenarioFailurePattern.test(error.message) || stageFailurePattern.test(error.message))
    ) {
      throw error;
    }
    throw new Error(`Phase 2 stage failed: ${descriptor.kind}-fixture`);
  });
  const success = scenarios.find(
    ({ id }) => id === 'client-credentials.organization-resource-scope'
  )?.projection;
  const authenticationError = scenarios.find(
    ({ id }) => id === 'client-credentials.wrong-secret-basic'
  )?.projection;
  if (!success || !authenticationError || 'kind' in success || 'kind' in authenticationError) {
    return fail();
  }
  const discovery = await projectDiscovery(descriptor, profile).catch(() => {
    throw new Error(`Phase 2 stage failed: ${descriptor.kind}-discovery`);
  });
  let controls: readonly ClientCredentialsControlResult[];
  try {
    controls = runClientCredentialsNegativeControls({
      success,
      authenticationError,
      discoveryGrantTypes: discovery.grantTypesSupported,
    });
  } catch {
    throw new Error(`Phase 2 stage failed: ${descriptor.kind}-controls`);
  }
  const evidence = Object.freeze({
    target: descriptor.kind,
    scenarios,
    discovery,
    controls,
  });
  assertClientCredentialsEvidenceIsSanitized(evidence);
  return evidence;
};

const executeOracle = async (
  input: Readonly<{
    profile: Phase2ProfileRegistries;
    target: PreparedPhase2Target;
    sessionRoot: string;
  }>
): Promise<unknown> => {
  if (input.target.descriptor.kind !== 'oracle') {
    return fail();
  }
  const target = await runTargetScenarios(input.profile, input.target);
  return Object.freeze({ schemaVersion: 1, mode: 'oracle', target });
};

const statusScopeClass = (value: unknown): 'short' | 'full' | 'resource' | 'offline' | 'other' => {
  switch (value) {
    case 'openid profile': {
      return 'short';
    }
    case 'openid profile email address phone': {
      return 'full';
    }
    case 'openid profile email address phone read:profile': {
      return 'resource';
    }
    case 'openid offline_access profile email address phone': {
      return 'offline';
    }
    default: {
      return 'other';
    }
  }
};

const executeDifferential = async (
  input: Readonly<{
    profile: Phase2ProfileRegistries;
    oracle: PreparedPhase2Target;
    candidate: PreparedPhase2Target;
    sessionRoot: string;
  }>
): Promise<unknown> => {
  if (
    input.oracle.descriptor.kind !== 'oracle' ||
    input.candidate.descriptor.kind !== 'candidate'
  ) {
    return fail();
  }
  const oracle = await runTargetScenarios(input.profile, input.oracle);
  const candidate = await runTargetScenarios(input.profile, input.candidate);
  const comparisons = oracle.scenarios.map((oracleScenario, index) => {
    const candidateScenario = candidate.scenarios[index];
    if (!candidateScenario || candidateScenario.id !== oracleScenario.id) {
      return fail();
    }
    const found =
      'kind' in oracleScenario.projection && 'kind' in candidateScenario.projection
        ? compareTokenStatus(oracleScenario.projection, candidateScenario.projection)
        : !('kind' in oracleScenario.projection) && !('kind' in candidateScenario.projection)
          ? compareClientCredentialsProjections(
              oracleScenario.projection,
              candidateScenario.projection
            )
          : fail();
    if (found.length > 0) {
      if (oracleScenario.id === 'token-status.public-access-active') {
        const first =
          found.find(
            (path) =>
              typeof path === 'string' &&
              /^\/body\/(sub|client_id|exp|iat|iss|scope|token_type)$/u.test(path)
          ) ?? found[0];
        if (
          first === '/body/scope' &&
          'kind' in oracleScenario.projection &&
          'kind' in candidateScenario.projection
        ) {
          throw new Error(
            'Phase 2 stage failed: candidate-status-scope-' +
              statusScopeClass(oracleScenario.projection.body?.scope) +
              '-' +
              statusScopeClass(candidateScenario.projection.body?.scope)
          );
        }
        if (
          typeof first === 'string' &&
          /^\/(kind|status|headers|body(?:\/(?:sub|client_id|exp|iat|iss|scope|token_type))?|grant)$/u.test(
            first
          )
        ) {
          throw new Error(
            'Phase 2 stage failed: candidate-status-comparison-' + first.slice(1).replace('/', '-')
          );
        }
      }
      throw new Error('Phase 2 stage failed: candidate-comparison');
    }
    return Object.freeze({ scenarioId: oracleScenario.id, differenceCount: 0 });
  });
  if (
    JSON.stringify(oracle.discovery) !== JSON.stringify(candidate.discovery) ||
    oracle.controls.length !== candidate.controls.length
  ) {
    return fail();
  }
  return Object.freeze({
    schemaVersion: 1,
    mode: 'differential',
    oracle,
    candidate,
    comparisons: Object.freeze(comparisons),
  });
};

const executeCandidateInvariants = async (
  input: Readonly<{
    profile: Phase2ProfileRegistries;
    target: PreparedPhase2Target;
    sessionRoot: string;
  }>
): Promise<unknown> => {
  const prepared = input.target;
  const { descriptor: target } = prepared;
  if (target.kind !== 'candidate' || !target.invariantDriver || !target.fixtureSocket) {
    return fail();
  }
  const { invariantDriver } = target;
  const provisioner = provisionerFor(prepared);
  const invariants: readonly CandidateInvariantControlEvidence[] = await runWithPhase2Fixture(
    provisioner,
    async (fixture: ProvisionedPhase2Fixture) => {
      await waitForClientCredentialsFixtureReady(target.target, fixture.public);
      return runClientCredentialsCandidateInvariants(input.profile, {
        target: target.target,
        foreignTarget: target.foreignTarget,
        fixture,
        driverPath: invariantDriver.path,
        controlSocket: invariantDriver.controlSocket,
        topology: prepared.topology,
        identityFence: prepared.fence,
      });
    }
  );
  return Object.freeze({ schemaVersion: 1, mode: 'candidate-invariants', invariants });
};

const defaultDependencies: Phase2CliDependencies = Object.freeze({
  loadProfile: loadPhase2Profile,
  readTarget: readPhase2TargetDescriptor,
  executeOracle,
  executeDifferential,
  executeCandidateInvariants,
  publish: async (outputPath, value) => {
    await writeSecureJsonArtifact(outputPath, value);
  },
  removeSessionRoot: async (sessionRoot) => {
    const before = await lstat(sessionRoot).catch(fail);
    if (before.isSymbolicLink() || !before.isDirectory() || before.uid !== currentUid()) {
      return fail();
    }
    await rm(sessionRoot, { force: true, recursive: true });
    try {
      await lstat(sessionRoot);
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
  },
  stdout: (message) => {
    process.stdout.write(message);
  },
  stderr: (message) => {
    process.stderr.write(message);
  },
  inspectHarness: async (runtimeCapability) =>
    inspectLaunchedPhase2HarnessSource(repositoryRoot, runtimeEntryPath, runtimeCapability),
  recheckHarness: recheckCleanPhase2HarnessSource,
  verifyTarget: verifyPhase2Target,
  prepareTarget: preparePhase2TargetForExecution,
});

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

export const runPhase2Cli = async (
  arguments_: readonly string[],
  dependencies: Phase2CliDependencies = defaultDependencies,
  runtimeCapability?: string
): Promise<void> => {
  const command = parsePhase2Arguments(arguments_);
  const temporaryRoot = await validatePrivateRoot(command.tempRoot);
  const [profilePath, schemaPath] = await Promise.all([
    validateInputFile(command.profilePath),
    validateInputFile(command.schemaPath),
  ]);
  if (profilePath === schemaPath) {
    return fail();
  }
  const outputPath = await validateOutputPath(command.mode, command.outputPath, temporaryRoot);
  const sessionRoot = await mkdtemp(path.join(temporaryRoot, 'phase2-client-credentials-run-'));
  await chmod(sessionRoot, 0o700);
  let evidence: ReturnType<typeof createPhase2EvidenceEnvelope> | undefined;
  let executionError: unknown;
  try {
    const profile = await dependencies.loadProfile({ profilePath, schemaPath });
    const harness = await dependencies.inspectHarness(runtimeCapability);
    const execution = await (async () => {
      if (command.mode === 'differential') {
        const [oracleTargetPath, candidateTargetPath] = await Promise.all([
          validateInputFile(command.oracleTargetPath),
          validateInputFile(command.candidateTargetPath),
        ]).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-target-path');
        });
        if (oracleTargetPath === candidateTargetPath) {
          return fail();
        }
        const [oracle, candidate] = await Promise.all([
          dependencies.readTarget(oracleTargetPath),
          dependencies.readTarget(candidateTargetPath),
        ]).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-target-read');
        });
        if (
          oracle.projectName === candidate.projectName ||
          [oracle.primaryContainerId, oracle.foreignContainerId].some((id) =>
            [candidate.primaryContainerId, candidate.foreignContainerId].includes(id)
          )
        ) {
          throw new Error('Phase 2 command stage failed: differential-target-pair');
        }
        const [oracleCapability, candidateCapability] = await Promise.all([
          dependencies.verifyTarget(oracle),
          dependencies.verifyTarget(candidate),
        ]).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-target-verify');
        });
        const [preparedOracle, preparedCandidate] = await Promise.all([
          dependencies.prepareTarget(oracleCapability, sessionRoot, 'oracle'),
          dependencies.prepareTarget(candidateCapability, sessionRoot, 'candidate'),
        ]).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-target-prepare');
        });
        const payload = await dependencies
          .executeDifferential({
            profile,
            oracle: preparedOracle,
            candidate: preparedCandidate,
            sessionRoot,
          })
          .catch((error: unknown) => {
            if (
              error instanceof Error &&
              (scenarioFailurePattern.test(error.message) ||
                stageFailurePattern.test(error.message))
            ) {
              throw error;
            }
            throw new Error('Phase 2 command stage failed: differential-execution');
          });
        await Promise.all([
          preparedOracle.fence.assertStable(),
          preparedCandidate.fence.assertStable(),
        ]).catch(() => {
          throw new Error('Phase 2 command stage failed: differential-harness');
        });
        return {
          payload,
          oracle: publicTargetProvenance(oracleCapability),
          candidate: publicTargetProvenance(candidateCapability),
        };
      }
      const target = await dependencies.readTarget(await validateInputFile(command.targetPath));
      const capability = await dependencies.verifyTarget(target);
      const prepared = await dependencies.prepareTarget(
        capability,
        sessionRoot,
        command.mode === 'oracle' ? 'oracle' : 'candidate'
      );
      const payload =
        command.mode === 'oracle'
          ? await dependencies.executeOracle({ profile, target: prepared, sessionRoot })
          : await dependencies.executeCandidateInvariants({
              profile,
              target: prepared,
              sessionRoot,
            });
      await prepared.fence.assertStable();
      return command.mode === 'oracle'
        ? { payload, oracle: publicTargetProvenance(capability) }
        : { payload, candidate: publicTargetProvenance(capability) };
    })();
    try {
      await dependencies.recheckHarness(harness);
    } catch (error: unknown) {
      if (command.mode === 'differential') {
        throw new Error('Phase 2 command stage failed: differential-harness');
      }
      throw error;
    }
    try {
      evidence = createPhase2EvidenceEnvelope({
        mode: command.mode,
        profile,
        harness,
        payload: execution.payload as JsonValue,
        ...('oracle' in execution && execution.oracle ? { oracle: execution.oracle } : {}),
        ...('candidate' in execution && execution.candidate
          ? { candidate: execution.candidate }
          : {}),
      });
    } catch (error: unknown) {
      if (command.mode === 'differential') {
        throw new Error('Phase 2 command stage failed: differential-evidence');
      }
      throw error;
    }
  } catch (error: unknown) {
    executionError = error;
  }
  try {
    await dependencies.removeSessionRoot(sessionRoot);
  } catch (cleanupError: unknown) {
    if (executionError !== undefined) {
      throw new AggregateError([executionError, cleanupError], runFailure.trim());
    }
    throw cleanupError;
  }
  if (executionError !== undefined) {
    throw executionError instanceof Error ? executionError : new Error(runFailure.trim());
  }
  try {
    await dependencies.publish(outputPath, evidence as unknown as JsonValue);
  } catch (error: unknown) {
    if (command.mode === 'differential') {
      throw new Error('Phase 2 command stage failed: differential-publish');
    }
    throw error;
  }
  await safeWrite(dependencies.stdout, successMessages[command.mode]);
};

export const runPhase2CliMain = async (
  arguments_: readonly string[] = process.argv.slice(2),
  runtimeCapability?: string,
  dependencies: Phase2CliDependencies = defaultDependencies
): Promise<number> => {
  try {
    await runPhase2Cli(arguments_, dependencies, runtimeCapability);
    return 0;
  } catch (error: unknown) {
    const original = error instanceof AggregateError ? (error.errors[0] as unknown) : error;
    const match = original instanceof Error ? scenarioFailurePattern.exec(original.message) : null;
    const stage = original instanceof Error ? stageFailurePattern.exec(original.message) : null;
    const commandStage =
      original instanceof Error ? commandFailurePattern.exec(original.message) : null;
    await safeWrite(
      dependencies.stderr,
      error instanceof TypeError && error.message === invalidArguments.trim()
        ? invalidArguments
        : match?.[1] && match[2] && profileScenarioIdIsClosed(match[2])
          ? `Phase 2 client credentials command failed (${match[1]}/${match[2]}).\n`
          : stage?.[1] && stage[2]
            ? `Phase 2 client credentials command failed (${stage[1]}-${stage[2]}).\n`
            : commandStage?.[1]
              ? `Phase 2 client credentials command failed (differential-${commandStage[1]}).\n`
              : error instanceof AggregateError
                ? 'Phase 2 client credentials command failed (differential-cleanup).\n'
                : runFailure
    );
    return 1;
  }
};

const directEntry = typeof process.argv[1] === 'string' ? path.resolve(process.argv[1]) : undefined;
if (directEntry === fileURLToPath(import.meta.url) || directEntry === runtimeEntryPath) {
  process.exitCode = await runPhase2CliMain();
}

/* eslint-enable complexity, max-lines, no-restricted-syntax, no-await-in-loop, no-bitwise, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
