/* eslint-disable max-lines -- CLI modes share one closed dependency and error-handling boundary. */
import { readFile as readFileFromDisk } from 'node:fs/promises';
import path from 'node:path';

import { compareJson } from './compare.js';
import { loadCompatibilityConfig } from './config.js';
import {
  assertEvidenceIsSanitized,
  assertSafeScenarioEvidenceId,
  negativeControlEvidenceGuard,
  resolveEvidenceDirectory,
  writeNegativeControlEvidence,
  writeRunEvidence,
  writeScenarioEvidence,
  type EvidenceWriterOptions,
} from './evidence.js';
import {
  runEvidenceGuard,
  scenarioEvidenceGuard,
  type Difference,
  type RunEvidence,
  type ScenarioEvidence,
  type TargetConfig,
  type TargetEvidence,
} from './model.js';
import { runScenarioForTarget, type CompatibilityScenario } from './scenario.js';
import { defaultCompatibilityScenarios } from './scenarios/index.js';

const referenceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const expectedFaultPath = '/observations/0/value/issuer';
const imageDigestPattern = /^sha256:[\da-f]{64}$/;
const absoluteJsonPointerPattern = /^(?:\/(?:[^~]|~[01])*)+$/;

type CompatibilityConfig = { oracle: TargetConfig; candidate: TargetConfig };
type OutputWriter = (message: string) => void | Promise<void>;

export type CompatibilityCliDependencies = {
  loadConfig: (env: Readonly<Record<string, string | undefined>>) => CompatibilityConfig;
  scenarios: readonly CompatibilityScenario[];
  runScenario: (scenario: CompatibilityScenario, target: TargetConfig) => Promise<TargetEvidence>;
  compare: (oracle: unknown, candidate: unknown) => Difference[];
  writeScenario: (input: unknown, options?: EvidenceWriterOptions) => Promise<string>;
  writeNegativeControl: (input: unknown, options?: EvidenceWriterOptions) => Promise<string>;
  writeRun: (input: unknown, options?: EvidenceWriterOptions) => Promise<string>;
  readFile: (filePath: string) => Promise<string>;
  stdout: OutputWriter;
  stderr: OutputWriter;
};

type CompatibilityMode =
  | { kind: 'positive' }
  | { kind: 'fault'; injection: 'discovery-issuer' }
  | { kind: 'finalize'; negativeControlPath: string };

class FixedDiagnosticError extends Error {}

const defaultDependencies: CompatibilityCliDependencies = {
  loadConfig: loadCompatibilityConfig,
  scenarios: defaultCompatibilityScenarios,
  runScenario: runScenarioForTarget,
  compare: compareJson,
  writeScenario: writeScenarioEvidence,
  writeNegativeControl: writeNegativeControlEvidence,
  writeRun: writeRunEvidence,
  readFile: async (filePath) => readFileFromDisk(filePath, 'utf8'),
  stdout: (message) => {
    console.log(message);
  },
  stderr: (message) => {
    console.error(message);
  },
};

const parseArguments = (args: readonly string[]): CompatibilityMode => {
  if (args.length === 0) {
    return { kind: 'positive' };
  }

  if (args.length === 2 && args[0] === '--fault-injection') {
    if (args[1] !== 'discovery-issuer') {
      throw new Error('Invalid compatibility arguments');
    }

    return { kind: 'fault', injection: args[1] };
  }

  if (
    args.length === 3 &&
    args[0] === '--finalize-run' &&
    args[1] === '--negative-control-path' &&
    args[2] !== undefined &&
    absoluteJsonPointerPattern.test(args[2])
  ) {
    return { kind: 'finalize', negativeControlPath: args[2] };
  }

  throw new Error('Invalid compatibility arguments');
};

const writeStatus = async (writer: OutputWriter, message: string) => {
  try {
    await writer(message);
  } catch {
    // Reporting failure must not expose or replace the fixed CLI outcome.
  }
};

const validateScenarioRegistry = (scenarios: readonly CompatibilityScenario[]): void => {
  if (scenarios.length === 0) {
    throw new Error('Invalid compatibility scenario registry');
  }

  const ids = scenarios.map(({ id }) => {
    assertSafeScenarioEvidenceId(id);
    return id;
  });

  if (new Set(ids).size !== ids.length) {
    throw new Error('Invalid compatibility scenario registry');
  }
};

const compareTargetEvidence = (
  dependencies: CompatibilityCliDependencies,
  oracle: TargetEvidence,
  candidate: TargetEvidence
) =>
  dependencies.compare(
    { observations: oracle.observations },
    { observations: candidate.observations }
  );

const runTargetPair = async (
  scenario: CompatibilityScenario,
  config: CompatibilityConfig,
  dependencies: CompatibilityCliDependencies
) => {
  const [oracle, candidate] = await Promise.all([
    dependencies.runScenario(scenario, config.oracle),
    dependencies.runScenario(scenario, config.candidate),
  ]);

  return { oracle, candidate };
};

const createScenarioEvidence = (
  scenarioId: string,
  oracle: TargetEvidence,
  candidate: TargetEvidence,
  differences: Difference[]
): ScenarioEvidence => {
  const result = scenarioEvidenceGuard.safeParse({
    schemaVersion: 1,
    scenarioId,
    oracle,
    candidate,
    differences,
  });

  if (!result.success) {
    throw new Error('Invalid scenario evidence');
  }

  return result.data;
};

const runPositive = async (
  env: Readonly<Record<string, string | undefined>>,
  dependencies: CompatibilityCliDependencies
) => {
  const config = dependencies.loadConfig(env);
  const results = await dependencies.scenarios.reduce<Promise<number[]>>(
    async (previousResults, scenario) => {
      const collectedResults = await previousResults;
      const { oracle, candidate } = await runTargetPair(scenario, config, dependencies);
      const differences = compareTargetEvidence(dependencies, oracle, candidate);
      const evidence = createScenarioEvidence(scenario.id, oracle, candidate, differences);

      await dependencies.writeScenario(evidence, { env });
      await writeStatus(
        dependencies.stdout,
        `Scenario ${scenario.id}: ${differences.length} difference(s)`
      );

      return [...collectedResults, differences.length];
    },
    Promise.resolve([])
  );

  return results.every((differenceCount) => differenceCount === 0) ? 0 : 1;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const injectDiscoveryIssuer = (candidate: TargetEvidence): TargetEvidence => {
  const [firstObservation] = candidate.observations;

  if (!firstObservation || !isRecord(firstObservation.value)) {
    throw new TypeError('Discovery issuer injection target is missing');
  }

  const firstValue = firstObservation.value;
  const { issuer } = firstValue;

  if (typeof issuer !== 'string') {
    throw new TypeError('Discovery issuer injection target is missing');
  }

  const injectedIssuer =
    issuer === 'https://fault.invalid/discovery-issuer'
      ? 'https://alternate-fault.invalid/discovery-issuer'
      : 'https://fault.invalid/discovery-issuer';

  return {
    ...candidate,
    observations: candidate.observations.map((observation, index) =>
      index === 0
        ? { ...observation, value: { ...firstValue, issuer: injectedIssuer } }
        : structuredClone(observation)
    ),
  };
};

const runFaultInjection = async (
  env: Readonly<Record<string, string | undefined>>,
  dependencies: CompatibilityCliDependencies
) => {
  const config = dependencies.loadConfig(env);
  // Discovery issuer mutation is the single Phase-0 negative control; later scenarios reuse it.
  const scenario = dependencies.scenarios.find(({ id }) => id === 'discovery');

  if (!scenario) {
    throw new Error('Discovery scenario is unavailable');
  }

  const { oracle, candidate } = await runTargetPair(scenario, config, dependencies);

  if (compareTargetEvidence(dependencies, oracle, candidate).length > 0) {
    await writeStatus(dependencies.stderr, 'Compatibility negative-control precondition failed.');
    return 1;
  }

  const injectedCandidate = injectDiscoveryIssuer(candidate);
  const differences = compareTargetEvidence(dependencies, oracle, injectedCandidate);
  const paths = differences.map(({ path: differencePath }) => differencePath).toSorted();

  if (paths.length !== 1 || paths[0] !== expectedFaultPath) {
    await writeStatus(dependencies.stderr, 'Compatibility negative control failed.');
    return 3;
  }

  await dependencies.writeNegativeControl(
    {
      schemaVersion: 1,
      faultInjection: 'discovery-issuer',
      differencePaths: paths,
    },
    { env }
  );
  await writeStatus(
    dependencies.stdout,
    'Compatibility negative control detected the issuer fault.'
  );

  return 2;
};

const getFinalizationEvidenceDirectory = (env: Readonly<Record<string, string | undefined>>) => {
  try {
    return resolveEvidenceDirectory(env);
  } catch {
    throw new FixedDiagnosticError('Invalid ASTER_EVIDENCE_DIR.');
  }
};

const parseEvidenceJson = (source: string, description: string): unknown => {
  try {
    return JSON.parse(source);
  } catch {
    throw new Error(`Invalid ${description}`);
  }
};

const loadPositiveEvidence = async (
  scenario: CompatibilityScenario,
  evidenceDirectory: string,
  dependencies: CompatibilityCliDependencies
) => {
  const source = await dependencies.readFile(path.join(evidenceDirectory, `${scenario.id}.json`));
  const input = parseEvidenceJson(source, 'positive scenario evidence');
  assertEvidenceIsSanitized(input);
  const result = scenarioEvidenceGuard.safeParse(input);

  if (!result.success || result.data.scenarioId !== scenario.id) {
    throw new Error('Invalid positive scenario evidence');
  }

  return result.data;
};

const loadNegativeControlEvidence = async (
  evidenceDirectory: string,
  expectedDifferencePath: string,
  dependencies: CompatibilityCliDependencies
) => {
  const source = await dependencies.readFile(path.join(evidenceDirectory, 'negative-control.json'));
  const input = parseEvidenceJson(source, 'negative-control evidence');
  assertEvidenceIsSanitized(input);
  const result = negativeControlEvidenceGuard.safeParse(input);

  if (
    !result.success ||
    result.data.differencePaths.length !== 1 ||
    result.data.differencePaths[0] !== expectedDifferencePath
  ) {
    throw new Error('Invalid negative-control evidence');
  }

  return result.data;
};

const requireImageDigest = (
  env: Readonly<Record<string, string | undefined>>,
  variable: 'ASTER_ORACLE_IMAGE_DIGEST' | 'ASTER_CANDIDATE_IMAGE_DIGEST'
) => {
  const value = env[variable];

  if (value === undefined || !imageDigestPattern.test(value)) {
    throw new FixedDiagnosticError(`Invalid ${variable}.`);
  }

  return value;
};

const runFinalize = async (
  mode: Extract<CompatibilityMode, { kind: 'finalize' }>,
  env: Readonly<Record<string, string | undefined>>,
  dependencies: CompatibilityCliDependencies
) => {
  const oracleImageDigest = requireImageDigest(env, 'ASTER_ORACLE_IMAGE_DIGEST');
  const candidateImageDigest = requireImageDigest(env, 'ASTER_CANDIDATE_IMAGE_DIGEST');
  const evidenceDirectory = getFinalizationEvidenceDirectory(env);
  await loadNegativeControlEvidence(evidenceDirectory, mode.negativeControlPath, dependencies);
  const scenarioEvidence = await dependencies.scenarios.reduce<Promise<ScenarioEvidence[]>>(
    async (previousEvidence, scenario) => [
      ...(await previousEvidence),
      await loadPositiveEvidence(scenario, evidenceDirectory, dependencies),
    ],
    Promise.resolve([])
  );
  const input: RunEvidence = {
    schemaVersion: 1,
    referenceCommit,
    oracleImageDigest,
    candidateImageDigest,
    scenarios: scenarioEvidence.map(({ scenarioId, differences }) => ({
      scenarioId,
      differenceCount: differences.length,
    })),
    negativeControl: { differencePath: mode.negativeControlPath },
  };
  const parsedInput = runEvidenceGuard.safeParse(input);

  if (!parsedInput.success) {
    throw new Error('Invalid run evidence');
  }

  const runPath = await dependencies.writeRun(parsedInput.data, { env });
  const written = parseEvidenceJson(await dependencies.readFile(runPath), 'written run evidence');
  assertEvidenceIsSanitized(written);

  if (
    !runEvidenceGuard.safeParse(written).success ||
    compareJson(parsedInput.data, written).length > 0
  ) {
    throw new Error('Invalid written run evidence');
  }

  await writeStatus(dependencies.stdout, 'Compatibility run evidence finalized.');
  return 0;
};

export const runCompatibilityCli = async (
  args: readonly string[] = process.argv.slice(2),
  env: Readonly<Record<string, string | undefined>> = process.env,
  injectedDependencies: Partial<CompatibilityCliDependencies> = {}
): Promise<number> => {
  const mode = (() => {
    try {
      return parseArguments(args);
    } catch {
      return null;
    }
  })();

  if (!mode) {
    const stderr = injectedDependencies.stderr ?? defaultDependencies.stderr;
    await writeStatus(stderr, 'Invalid compatibility arguments.');
    return 1;
  }

  const dependencies = { ...defaultDependencies, ...injectedDependencies };

  try {
    validateScenarioRegistry(dependencies.scenarios);

    switch (mode.kind) {
      case 'positive': {
        return await runPositive(env, dependencies);
      }
      case 'fault': {
        return await runFaultInjection(env, dependencies);
      }
      case 'finalize': {
        return await runFinalize(mode, env, dependencies);
      }
    }
  } catch (error: unknown) {
    await writeStatus(
      dependencies.stderr,
      error instanceof FixedDiagnosticError ? error.message : 'Compatibility operation failed.'
    );
    return 1;
  }
};

const isMainModule =
  process.argv[1]?.replaceAll('\\', '/').endsWith('/compatibility/cli.js') === true;

if (isMainModule) {
  const exitCode = await runCompatibilityCli();

  if (exitCode !== 0) {
    // eslint-disable-next-line @silverhand/fp/no-mutation -- This is the executable entry-point contract.
    process.exitCode = exitCode;
  }
}
/* eslint-enable max-lines */
