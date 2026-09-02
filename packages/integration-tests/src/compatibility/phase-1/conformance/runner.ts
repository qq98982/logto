/* eslint-disable max-lines, complexity, no-restricted-syntax, curly, no-await-in-loop, prefer-destructuring, capitalized-comments, @typescript-eslint/ban-types, @typescript-eslint/no-confusing-void-expression, unicorn/prefer-code-point, unicorn/numeric-separators-style, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This authority owns strict terminal parsing, detached process groups, bounded byte streams, and branded conformance results. */
import { spawn } from 'node:child_process';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

import { parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import { jsonValueGuard } from '../../model.js';
import {
  asterPhase1BuildRootEnvironmentVariable,
  requireAsterPhase1BuildPath,
} from '../build-root.js';
import { assertPhase1EvidenceIsSanitized } from '../evidence.js';
import { cloneAndDeepFreeze, snapshotClosedDataGraph } from '../model.js';
import { assertConformanceExecution } from '../profile-semantics/conformance.js';
import type { Phase1Profile } from '../profile-types.js';

import {
  createPhase1ConformanceConfig,
  phase1ConformanceSuiteCommit,
  type Phase1ConformancePlanId,
  type Phase1ConformancePublicConfig,
  type Phase1ConformancePublicPlan,
} from './config.js';

export const phase1ConformanceAdapterControlIds = Object.freeze([
  'oidf-basic-1',
  'oidf-basic-2',
  'oidf-post-1',
] as const);

export type Phase1ConformanceMode = 'review-candidate' | 'mirror-control' | 'runtime-candidate';

export type Phase1ConformanceProcessRequest = Readonly<{
  command: string;
  args: readonly string[];
  cwd: string;
  stdin: string;
  env: Readonly<Record<string, string>>;
  timeoutMs: 300_000;
  maxStdoutBytes: 65_536;
  maxStderrBytes: 65_536;
  shell: false;
}>;

export type Phase1ConformanceProcessResult = Readonly<{
  pid: number | undefined;
  processGroupId: number | undefined;
  exitCode: number | undefined;
  signal: string | undefined;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  killed: boolean;
  reaped: boolean;
}>;

export type Phase1ConformanceProcessRunner = (
  request: Phase1ConformanceProcessRequest
) => Promise<Phase1ConformanceProcessResult>;

export type Phase1ConformanceAdapterControl = Readonly<{
  id: (typeof phase1ConformanceAdapterControlIds)[number];
  projection: Readonly<Record<string, unknown>>;
}>;

export type Phase1ConformanceOfficialResult = Readonly<{
  planId: Phase1ConformancePlanId;
  resultId: string;
  status: 'PASSED';
  variant: Readonly<Record<string, unknown>>;
  result: Readonly<Record<string, unknown>>;
}>;

export type Phase1ConformanceRunResult = Readonly<{
  schemaVersion: 1;
  mode: Phase1ConformanceMode;
  adapterControls: readonly Phase1ConformanceAdapterControl[];
  officialResults: readonly Phase1ConformanceOfficialResult[];
}>;

export type RunPhase1ConformanceDependencies = Readonly<{
  checkedOutSuiteCommit: string;
  repositoryRoot: string;
  scriptPath: string;
  workingDirectory: string;
  environment: Readonly<Record<string, string>>;
  runner?: Phase1ConformanceProcessRunner;
}>;

const diagnostic = 'Invalid phase 1 conformance runner';
const timeoutMs = 300_000;
const maximumOutputBytes = 65_536;
const killGraceMs = 100;
const groupReapTimeoutMs = 2000;
const groupPollMs = 10;
const resultIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$/u;
const terminalKeys = Object.freeze([
  'schemaVersion',
  'kind',
  'suiteCommit',
  'adapterControlId',
  'planId',
  'variant',
  'status',
  'resultId',
  'result',
] as const);
const controlTerminalKeys = Object.freeze([
  'schemaVersion',
  'kind',
  'suiteCommit',
  'adapterControlId',
  'status',
  'result',
] as const);
const processResultKeys = Object.freeze([
  'pid',
  'processGroupId',
  'exitCode',
  'signal',
  'stdout',
  'stderr',
  'timedOut',
  'killed',
  'reaped',
] as const);
const resultAuthorities = new WeakSet<object>();
const productionRequests = new WeakSet<object>();
const activeProcessGroups = new Set<number>();
const interruptionSignals = Object.freeze(['SIGINT', 'SIGTERM', 'SIGHUP'] as const);
const interruptionExitCodes = Object.freeze({ SIGINT: 130, SIGTERM: 143, SIGHUP: 129 } as const);
let processCleanupInstalled = false;
let processCleanupRunning = false;

type OwnedProcessRequest = Omit<
  Phase1ConformanceProcessRequest,
  'timeoutMs' | 'maxStdoutBytes' | 'maxStderrBytes'
> &
  Readonly<{ timeoutMs: number; maxStdoutBytes: number; maxStderrBytes: number }>;

const exactKeys = (value: Readonly<Record<string, unknown>>, expected: readonly string[]) => {
  const keys = Reflect.ownKeys(value);
  return (
    keys.length === expected.length &&
    keys.every((key) => typeof key === 'string' && expected.includes(key))
  );
};
const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const inspectJsonNode = (node: JsonNode | undefined): void => {
  if (!node) throw new TypeError(diagnostic);
  if (node.type === 'object') {
    const names = new Set<string>();
    for (const property of node.children ?? []) {
      const [nameNode, valueNode] = property.children ?? [];
      const name: unknown = nameNode?.value;
      if (typeof name !== 'string' || names.has(name)) throw new TypeError(diagnostic);
      names.add(name);
      inspectJsonNode(valueNode);
    }
  } else if (node.type === 'array') {
    for (const child of node.children ?? []) inspectJsonNode(child);
  }
};

const parseStrictJson = (source: string): unknown => {
  try {
    if (source.length === 0 || source.charCodeAt(0) === 0xfeff || /[\r\n]/u.test(source))
      throw new TypeError(diagnostic);
    const errors: ParseError[] = [];
    const root = parseTree(source, errors, {
      allowEmptyContent: false,
      allowTrailingComma: false,
      disallowComments: true,
    });
    if (!root || errors.length > 0) throw new TypeError(diagnostic);
    inspectJsonNode(root);
    return JSON.parse(source) as unknown;
  } catch {
    throw new TypeError(diagnostic);
  }
};

const signalGroup = (pid: number | undefined, signal: NodeJS.Signals): void => {
  if (!pid || pid <= 0) return;
  try {
    process.kill(-pid, signal);
  } catch {
    /* already exited */
  }
};
const groupExists = (pid: number | undefined): boolean => {
  if (!pid || pid <= 0) return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error: unknown) {
    return !(
      typeof error === 'object' &&
      error !== null &&
      Object.getOwnPropertyDescriptor(error, 'code')?.value === 'ESRCH'
    );
  }
};
const delay = async (milliseconds: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
const fenceGroup = async (pid: number | undefined, force: boolean): Promise<boolean> => {
  if (!groupExists(pid)) return true;
  if (!force) {
    signalGroup(pid, 'SIGTERM');
    await delay(killGraceMs);
  }
  if (groupExists(pid)) signalGroup(pid, 'SIGKILL');
  const deadline = Date.now() + groupReapTimeoutMs;
  while (groupExists(pid) && Date.now() < deadline) await delay(groupPollMs);
  return !groupExists(pid);
};

const killActiveProcessGroups = (): void => {
  for (const processGroupId of activeProcessGroups) {
    signalGroup(processGroupId, 'SIGKILL');
  }
};

const processExitCleanup = () => {
  killActiveProcessGroups();
};

const removeProcessCleanup = (): void => {
  if (!processCleanupInstalled) return;
  for (const signal of interruptionSignals) {
    process.removeListener(signal, processSignalHandlers[signal]);
  }
  process.removeListener('exit', processExitCleanup);
  processCleanupInstalled = false;
};

const relayProcessSignal = (signal: (typeof interruptionSignals)[number]): void => {
  if (processCleanupRunning) return;
  processCleanupRunning = true;
  killActiveProcessGroups();
  removeProcessCleanup();
  process.exitCode = interruptionExitCodes[signal];
};

const processSignalHandlers = Object.freeze({
  SIGHUP: () => relayProcessSignal('SIGHUP'),
  SIGINT: () => relayProcessSignal('SIGINT'),
  SIGTERM: () => relayProcessSignal('SIGTERM'),
});

const installProcessCleanup = (): void => {
  if (processCleanupInstalled) return;
  for (const signal of interruptionSignals) {
    process.on(signal, processSignalHandlers[signal]);
  }
  process.on('exit', processExitCleanup);
  processCleanupInstalled = true;
};

const registerProcessGroup = (processGroupId: number | undefined): void => {
  if (!processGroupId || processGroupId <= 0) return;
  activeProcessGroups.add(processGroupId);
  installProcessCleanup();
};

const releaseProcessGroup = (processGroupId: number | undefined): void => {
  if (processGroupId) activeProcessGroups.delete(processGroupId);
  if (activeProcessGroups.size === 0 && !processCleanupRunning) removeProcessCleanup();
};

const runOwnedProcess = async (
  request: OwnedProcessRequest
): Promise<Phase1ConformanceProcessResult> =>
  new Promise((resolve) => {
    const child = spawn(request.command, [...request.args], {
      cwd: request.cwd,
      detached: true,
      env: { ...request.env },
      shell: request.shell,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;
    let killed = false;
    let settled = false;
    let terminating = false;
    let forceKillTimer: NodeJS.Timeout | undefined;
    const pid = child.pid;
    registerProcessGroup(pid);
    const terminate = (timeout: boolean) => {
      timedOut ||= timeout;
      killed = true;
      if (terminating) return;
      terminating = true;
      signalGroup(pid, 'SIGTERM');
      forceKillTimer = setTimeout(() => signalGroup(pid, 'SIGKILL'), killGraceMs);
    };
    const append = (stream: 'stdout' | 'stderr', chunk: Buffer | string) => {
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      const chunks = stream === 'stdout' ? stdoutChunks : stderrChunks;
      const current = stream === 'stdout' ? stdoutBytes : stderrBytes;
      const maximum = stream === 'stdout' ? request.maxStdoutBytes : request.maxStderrBytes;
      const remaining = Math.max(0, maximum + 1 - current);
      if (remaining > 0) chunks.push(bytes.subarray(0, remaining));
      if (stream === 'stdout') stdoutBytes += bytes.byteLength;
      else stderrBytes += bytes.byteLength;
      if (current + bytes.byteLength > maximum) terminate(false);
    };
    child.stdout.on('data', (chunk: Buffer | string) => append('stdout', chunk));
    child.stderr.on('data', (chunk: Buffer | string) => append('stderr', chunk));
    child.stdout.once('error', () => terminate(false));
    child.stderr.once('error', () => terminate(false));
    child.stdin.once('error', () => terminate(false));
    child.once('error', () => terminate(false));
    const timer = setTimeout(() => terminate(true), request.timeoutMs);
    child.once('close', (exitCode, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      void (async () => {
        const reaped = await fenceGroup(pid, killed);
        releaseProcessGroup(pid);
        const decode = (chunks: readonly Buffer[]) => {
          try {
            return new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks));
          } catch {
            killed = true;
            return '';
          }
        };
        resolve({
          pid,
          processGroupId: pid,
          exitCode: exitCode ?? undefined,
          signal: signal ?? undefined,
          stdout: decode(stdoutChunks),
          stderr: decode(stderrChunks),
          timedOut,
          killed: killed || !reaped,
          reaped,
        });
      })();
    });
    try {
      child.stdin.end(request.stdin);
    } catch {
      terminate(false);
    }
  });

const runProductionProcess: Phase1ConformanceProcessRunner = async (request) => {
  if (!productionRequests.delete(request)) {
    throw new TypeError(diagnostic);
  }

  return runOwnedProcess(request);
};

export const runPhase1ConformanceProcessForTesting = async (
  request: OwnedProcessRequest
): Promise<Phase1ConformanceProcessResult> => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError(diagnostic);
  }
  if (
    !Number.isSafeInteger(request.timeoutMs) ||
    request.timeoutMs < 1 ||
    request.timeoutMs > timeoutMs ||
    !Number.isSafeInteger(request.maxStdoutBytes) ||
    request.maxStdoutBytes < 1 ||
    request.maxStdoutBytes > maximumOutputBytes ||
    !Number.isSafeInteger(request.maxStderrBytes) ||
    request.maxStderrBytes < 1 ||
    request.maxStderrBytes > maximumOutputBytes
  ) {
    throw new TypeError(diagnostic);
  }

  return runOwnedProcess(request);
};

const requireProcessResult = (value: unknown): Phase1ConformanceProcessResult => {
  const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(value);
  if (!snapshot || Array.isArray(snapshot) || !exactKeys(snapshot, processResultKeys))
    throw new TypeError(diagnostic);
  const result = snapshot as unknown as Phase1ConformanceProcessResult;
  if (
    (result.pid !== undefined && (!Number.isSafeInteger(result.pid) || result.pid <= 0)) ||
    result.pid !== result.processGroupId ||
    result.exitCode !== 0 ||
    result.signal !== undefined ||
    typeof result.stdout !== 'string' ||
    typeof result.stderr !== 'string' ||
    result.timedOut ||
    result.killed ||
    !result.reaped ||
    Buffer.byteLength(result.stdout) > maximumOutputBytes ||
    Buffer.byteLength(result.stderr) > maximumOutputBytes ||
    result.stderr.length > 0
  )
    throw new TypeError(diagnostic);
  return result;
};
const requireSanitizedResult = (value: unknown): Readonly<Record<string, unknown>> => {
  if (!isRecord(value) || !jsonValueGuard.safeParse(value).success) throw new TypeError(diagnostic);
  assertPhase1EvidenceIsSanitized(value);
  return value;
};

const parseOfficialTerminal = (
  source: string,
  plan: Phase1ConformancePublicPlan
): Phase1ConformanceOfficialResult => {
  const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(parseStrictJson(source));
  const reservedIds = new Set<string>([
    ...phase1ConformanceAdapterControlIds,
    'oidcc-basic-certification-test-plan',
    'oidcc-config-certification-test-plan',
  ]);
  if (
    !snapshot ||
    Array.isArray(snapshot) ||
    !exactKeys(snapshot, terminalKeys) ||
    snapshot.schemaVersion !== 1 ||
    snapshot.kind !== 'phase1-conformance-terminal' ||
    snapshot.suiteCommit !== phase1ConformanceSuiteCommit ||
    snapshot.adapterControlId !== 'phase1-conformance.runner.strict-terminal' ||
    snapshot.planId !== plan.id ||
    !isDeepStrictEqual(snapshot.variant, plan.variant) ||
    snapshot.status !== 'PASSED' ||
    typeof snapshot.resultId !== 'string' ||
    !resultIdPattern.test(snapshot.resultId) ||
    reservedIds.has(snapshot.resultId)
  )
    throw new TypeError(diagnostic);
  return cloneAndDeepFreeze({
    planId: plan.id,
    resultId: snapshot.resultId,
    status: 'PASSED' as const,
    variant: plan.variant,
    result: requireSanitizedResult(snapshot.result),
  });
};
const parseControlTerminal = (
  source: string,
  clientId: Phase1ConformanceAdapterControl['id']
): Phase1ConformanceAdapterControl => {
  const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(parseStrictJson(source));
  if (
    !snapshot ||
    Array.isArray(snapshot) ||
    !exactKeys(snapshot, controlTerminalKeys) ||
    snapshot.schemaVersion !== 1 ||
    snapshot.kind !== 'phase1-conformance-adapter-control-terminal' ||
    snapshot.suiteCommit !== phase1ConformanceSuiteCommit ||
    snapshot.adapterControlId !== clientId ||
    snapshot.status !== 'PASSED'
  )
    throw new TypeError(diagnostic);
  const projection = requireSanitizedResult(snapshot.result);

  if (!isDeepStrictEqual(projection, { configured: true, redirectUriMatches: true })) {
    throw new TypeError(diagnostic);
  }

  return cloneAndDeepFreeze({ id: clientId, projection });
};

const requireDependencies = (dependencies: RunPhase1ConformanceDependencies): void => {
  const expectedScript = path.join(
    dependencies.repositoryRoot,
    '.scripts/compatibility/run-phase1-conformance.sh'
  );
  const environment = snapshotClosedDataGraph<Record<string, unknown>>(dependencies.environment);
  if (
    dependencies.checkedOutSuiteCommit !== phase1ConformanceSuiteCommit ||
    !path.isAbsolute(dependencies.repositoryRoot) ||
    path.resolve(dependencies.repositoryRoot) !== dependencies.repositoryRoot ||
    dependencies.scriptPath !== expectedScript ||
    dependencies.workingDirectory !== dependencies.repositoryRoot ||
    (dependencies.runner !== undefined && typeof dependencies.runner !== 'function') ||
    (dependencies.runner !== undefined && process.env.NODE_ENV !== 'test') ||
    !environment ||
    Array.isArray(environment) ||
    !exactKeys(environment, [
      'PATH',
      'ASTER_PHASE1_BUILD_ROOT',
      'ASTER_PHASE1_HARNESS_COMMIT',
      'ASTER_PHASE1_CONFORMANCE_ROOT',
      'ASTER_PHASE1_CONFORMANCE_DRIVER',
    ]) ||
    environment.PATH !== '/usr/bin:/bin' ||
    typeof environment.ASTER_PHASE1_BUILD_ROOT !== 'string' ||
    typeof environment.ASTER_PHASE1_HARNESS_COMMIT !== 'string' ||
    !/^[0-9a-f]{40}$/u.test(environment.ASTER_PHASE1_HARNESS_COMMIT) ||
    typeof environment.ASTER_PHASE1_CONFORMANCE_ROOT !== 'string' ||
    typeof environment.ASTER_PHASE1_CONFORMANCE_DRIVER !== 'string' ||
    environment.ASTER_PHASE1_CONFORMANCE_DRIVER !==
      `${dependencies.repositoryRoot}/.scripts/compatibility/phase1-conformance-driver.sh`
  )
    throw new TypeError(diagnostic);
  requireAsterPhase1BuildPath(environment.ASTER_PHASE1_CONFORMANCE_ROOT, {
    [asterPhase1BuildRootEnvironmentVariable]: environment.ASTER_PHASE1_BUILD_ROOT,
  });
};
const runRequest = async (
  request: Phase1ConformanceProcessRequest,
  dependencies: RunPhase1ConformanceDependencies
) => {
  const runner = dependencies.runner ?? runProductionProcess;
  const raw: unknown = await runner(request).catch(() => {
    throw new TypeError(diagnostic);
  });
  return requireProcessResult(raw).stdout;
};
const commonRequest = (
  dependencies: RunPhase1ConformanceDependencies,
  args: readonly string[],
  stdin: string
): Phase1ConformanceProcessRequest =>
  (() => {
    const request = Object.freeze({
      command: dependencies.scriptPath,
      args: Object.freeze([...args]),
      cwd: dependencies.workingDirectory,
      stdin,
      env: cloneAndDeepFreeze(dependencies.environment),
      timeoutMs,
      maxStdoutBytes: maximumOutputBytes,
      maxStderrBytes: maximumOutputBytes,
      shell: false,
    });
    productionRequests.add(request);
    return request;
  })();
const runAdapterControl = async (
  config: Phase1ConformancePublicConfig,
  client: Phase1ConformancePublicConfig['staticClients'][number],
  dependencies: RunPhase1ConformanceDependencies
) =>
  parseControlTerminal(
    await runRequest(
      commonRequest(
        dependencies,
        ['--adapter-control-id', client.id],
        JSON.stringify({
          schemaVersion: 1,
          suite: config.suite,
          target: config.target,
          staticClient: client,
          plans: config.plans,
        })
      ),
      dependencies
    ),
    client.id
  );
const runPlan = async (
  config: Phase1ConformancePublicConfig,
  plan: Phase1ConformancePublicPlan,
  dependencies: RunPhase1ConformanceDependencies
) =>
  parseOfficialTerminal(
    await runRequest(
      commonRequest(
        dependencies,
        ['--plan-id', plan.id],
        JSON.stringify({
          schemaVersion: 1,
          suite: config.suite,
          target: config.target,
          staticClients: config.staticClients,
          planId: plan.id,
          variant: plan.variant,
        })
      ),
      dependencies
    ),
    plan
  );

const runSequentially = async <Input, Result>(
  inputs: readonly Input[],
  run: (input: Input) => Promise<Result>
): Promise<readonly Result[]> => {
  const results: Result[] = [];

  for (const input of inputs) {
    results.push(await run(input));
  }

  return Object.freeze(results);
};

export const runPhase1Conformance = async (
  profile: Readonly<Phase1Profile>,
  mode: Phase1ConformanceMode,
  dependencies: RunPhase1ConformanceDependencies
): Promise<Phase1ConformanceRunResult> => {
  try {
    if (!['review-candidate', 'mirror-control', 'runtime-candidate'].includes(mode))
      throw new TypeError(diagnostic);
    requireDependencies(dependencies);
    assertConformanceExecution(profile, {
      checkedOutSuiteCommit: dependencies.checkedOutSuiteCommit,
    });
    const config = createPhase1ConformanceConfig(profile);
    const adapterControls = await runSequentially(config.staticClients, async (client) =>
      runAdapterControl(config, client, dependencies)
    );
    const officialResults =
      mode === 'runtime-candidate'
        ? await runSequentially(config.plans, async (plan) => runPlan(config, plan, dependencies))
        : Object.freeze([]);
    const officialResultIds = officialResults.map(({ resultId }) => resultId);

    if (new Set(officialResultIds).size !== officialResultIds.length) {
      throw new TypeError(diagnostic);
    }
    const result = cloneAndDeepFreeze({
      schemaVersion: 1 as const,
      mode,
      adapterControls,
      officialResults,
    });
    resultAuthorities.add(result);
    return result;
  } catch {
    throw new TypeError(diagnostic);
  }
};
export function assertValidatedPhase1ConformanceRunResult(
  value: unknown
): asserts value is Phase1ConformanceRunResult {
  if (typeof value !== 'object' || value === null || !resultAuthorities.has(value))
    throw new TypeError(diagnostic);
}

export const createBrandedPhase1ConformanceRunResultForTesting = (
  value: Phase1ConformanceRunResult
): Phase1ConformanceRunResult => {
  if (process.env.NODE_ENV !== 'test') {
    throw new TypeError(diagnostic);
  }
  const snapshot = snapshotClosedDataGraph<Phase1ConformanceRunResult>(value);

  if (!snapshot) {
    throw new TypeError(diagnostic);
  }
  const result = cloneAndDeepFreeze(snapshot);
  resultAuthorities.add(result);

  return result;
};

/* eslint-enable max-lines, complexity, no-restricted-syntax, curly, no-await-in-loop, prefer-destructuring, capitalized-comments, @typescript-eslint/ban-types, @typescript-eslint/no-confusing-void-expression, unicorn/prefer-code-point, unicorn/numeric-separators-style, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
