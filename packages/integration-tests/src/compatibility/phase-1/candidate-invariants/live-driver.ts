/* eslint-disable complexity, no-restricted-syntax -- This adapter validates hostile process results and topology attestations before exposing one sanitized invariant projection. */
import path from 'node:path';
import { types as nodeTypes } from 'node:util';

import { parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import type { JsonObject } from '../../normalize.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../clients/command-provisioner.js';
import {
  candidateInvariantScenarioIdGuard,
  cloneAndDeepFreeze,
  snapshotClosedDataGraph,
  type CandidateInvariantScenarioId,
} from '../model.js';
import type { Phase1EvidenceRuntimeContext } from '../snapshots/runtime-context.js';

import { assertCandidateInvariantProjectionIsSanitized } from './evidence.js';
import type {
  Phase1CandidateInvariantRuntimeDependencies,
  Phase1LiveCandidateInvariantResult,
} from './runtime.js';

type CommandEnvironment = Readonly<Record<string, string | undefined>>;
type ProcessRunner = (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;

export type Phase1LiveCandidateInvariantExecutorOptions = Readonly<{
  repositoryRoot: string;
  environment?: CommandEnvironment;
  runner?: ProcessRunner;
}>;

const diagnostic = 'Invalid phase 1 live candidate invariant driver';
const projectNamePattern = /^aster-phase1-[0-9a-f]{16}$/u;
const containerIdPattern = /^[0-9a-f]{12,64}$/u;
const timeoutMs = 120_000;
const maximumOutputBytes = 65_536;
const terminalKeys = Object.freeze(['schemaVersion', 'kind', 'invariantId', 'projection'] as const);
const resultKeys = Object.freeze([
  'exitCode',
  'signal',
  'stdout',
  'stderr',
  'timedOut',
  'killed',
  'reaped',
] as const);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const record = (value: unknown): Readonly<Record<string, unknown>> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }

  return value as Readonly<Record<string, unknown>>;
};

const exactRecord = (
  value: unknown,
  keys: readonly string[]
): Readonly<Record<string, unknown>> => {
  const result = record(value);
  const ownKeys = Reflect.ownKeys(result);

  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
  ) {
    return fail();
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(result, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail();
    }
  }

  return result;
};

const own = (value: Readonly<Record<string, unknown>>, key: string): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);

  return descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable
    ? descriptor.value
    : fail();
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

const parseStrictJson = (source: string): unknown => {
  if (
    source.length === 0 ||
    source.codePointAt(0) === 0xfe_ff ||
    /[\r\n]/u.test(source) ||
    Buffer.byteLength(source, 'utf8') > maximumOutputBytes
  ) {
    return fail();
  }
  const errors: ParseError[] = [];
  const root = parseTree(source, errors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });

  if (!root || errors.length > 0) {
    return fail();
  }
  inspectJsonNode(root);

  try {
    return JSON.parse(source);
  } catch {
    return fail();
  }
};

const safeContainerId = (value: unknown): string =>
  typeof value === 'string' && containerIdPattern.test(value) ? value : fail();

const persistenceId = (value: unknown): string => {
  const state = record(value);
  const identifier = own(state, 'persistenceId');

  return typeof identifier === 'string' && identifier.startsWith('container:')
    ? safeContainerId(identifier.slice('container:'.length))
    : fail();
};

const candidateContainers = (
  context: Phase1EvidenceRuntimeContext
): Readonly<{ primary: string; foreign: string }> => {
  const attestations = record(context.isolationAttestations);
  const oracle = record(own(attestations, 'oracle'));
  const candidate = record(own(attestations, 'candidate'));
  const primary = persistenceId(own(candidate, 'data'));
  const admin = persistenceId(own(candidate, 'admin'));
  const foreign = persistenceId(own(candidate, 'foreign'));
  const oracleIds: ReadonlySet<string> = new Set([
    persistenceId(own(oracle, 'data')),
    persistenceId(own(oracle, 'admin')),
    persistenceId(own(oracle, 'foreign')),
  ]);

  if (
    primary !== admin ||
    primary === foreign ||
    oracleIds.has(primary) ||
    oracleIds.has(foreign)
  ) {
    return fail();
  }

  return Object.freeze({ primary, foreign });
};

const requireProcessResult = (value: unknown): CommandRunnerResult => {
  const result = exactRecord(value, resultKeys);
  const exitCode = own(result, 'exitCode');
  const signal = own(result, 'signal');
  const stdout = own(result, 'stdout');
  const stderr = own(result, 'stderr');
  const timedOut = own(result, 'timedOut');
  const killed = own(result, 'killed');
  const reaped = own(result, 'reaped');

  if (
    exitCode !== 0 ||
    signal !== null ||
    typeof stdout !== 'string' ||
    typeof stderr !== 'string' ||
    stderr.length > 0 ||
    typeof timedOut !== 'boolean' ||
    typeof killed !== 'boolean' ||
    typeof reaped !== 'boolean' ||
    timedOut ||
    killed ||
    !reaped ||
    Buffer.byteLength(stdout, 'utf8') > maximumOutputBytes ||
    Buffer.byteLength(stderr, 'utf8') > maximumOutputBytes
  ) {
    return fail();
  }

  return Object.freeze({
    exitCode,
    signal,
    stdout,
    stderr,
    timedOut,
    killed,
    reaped,
  });
};

const terminalResult = (
  stdout: string,
  expectedId: CandidateInvariantScenarioId
): Phase1LiveCandidateInvariantResult => {
  const terminal = exactRecord(parseStrictJson(stdout), terminalKeys);
  const parsedId = candidateInvariantScenarioIdGuard.safeParse(own(terminal, 'invariantId'));
  const projection = snapshotClosedDataGraph<JsonObject>(own(terminal, 'projection'));

  if (
    own(terminal, 'schemaVersion') !== 1 ||
    own(terminal, 'kind') !== 'phase1-candidate-invariant-terminal' ||
    !parsedId.success ||
    parsedId.data !== expectedId ||
    projection === undefined ||
    Array.isArray(projection)
  ) {
    return fail();
  }
  assertCandidateInvariantProjectionIsSanitized(projection);

  return cloneAndDeepFreeze({ id: parsedId.data, projection });
};

export const createPhase1LiveCandidateInvariantExecutor = (
  options: Phase1LiveCandidateInvariantExecutorOptions
): Phase1CandidateInvariantRuntimeDependencies['runLiveInvariant'] => {
  const environment = options.environment ?? process.env;
  const runner = options.runner ?? runPhase1FixtureCommand;
  const repositoryRoot = path.resolve(options.repositoryRoot);
  const driverPath = path.join(
    repositoryRoot,
    '.scripts/compatibility/phase1-candidate-invariants-driver.sh'
  );

  return async (id, context) => {
    try {
      if (path.resolve(context.repositoryRoot) !== repositoryRoot) {
        return fail();
      }
      const projectName = environment.ASTER_PHASE1_TOPOLOGY_ID;
      const pathValue = environment.PATH;

      if (
        typeof projectName !== 'string' ||
        !projectNamePattern.test(projectName) ||
        typeof pathValue !== 'string' ||
        pathValue.length === 0 ||
        pathValue.length > 4096 ||
        ![...pathValue].every((character) => {
          const codePoint = character.codePointAt(0);

          return codePoint !== undefined && codePoint >= 0x20 && codePoint !== 0x7f;
        })
      ) {
        return fail();
      }
      const containers = candidateContainers(context);
      const result = requireProcessResult(
        await runner({
          command: driverPath,
          args: [
            '--invariant-id',
            id,
            '--project-name',
            projectName,
            '--primary-container-id',
            containers.primary,
            '--foreign-container-id',
            containers.foreign,
          ],
          stdin: '',
          env: { PATH: pathValue },
          timeoutMs,
          maxStdoutBytes: maximumOutputBytes,
          maxStderrBytes: maximumOutputBytes,
          shell: false,
        })
      );

      return terminalResult(result.stdout, id);
    } catch {
      throw new TypeError(diagnostic);
    }
  };
};

/* eslint-enable complexity, no-restricted-syntax */
