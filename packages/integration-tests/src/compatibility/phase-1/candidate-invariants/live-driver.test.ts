/* eslint-disable @typescript-eslint/consistent-type-assertions -- Hostile tests intentionally construct partial runtime contexts at the external adapter boundary. */
import type { CommandRunnerRequest, CommandRunnerResult } from '../clients/command-provisioner.js';
import { candidateInvariantScenarioIds } from '../model.js';
import type { Phase1EvidenceRuntimeContext } from '../snapshots/runtime-context.js';

import { candidateInvariantContracts } from './index.js';
import { createPhase1LiveCandidateInvariantExecutor } from './live-driver.js';

const primaryContainerId = '1'.repeat(64);
const foreignContainerId = '2'.repeat(64);
const projectName = 'aster-phase1-0123456789abcdef';
const invariantId = candidateInvariantScenarioIds[0];
const projection = candidateInvariantContracts[0].positiveControl.expectedProjection;

const context = (overrides: Record<string, unknown> = {}): Phase1EvidenceRuntimeContext =>
  ({
    authorization: { mode: 'runtime-candidate' },
    oracleImageDigest: `sha256:${'3'.repeat(64)}`,
    candidateImageDigest: `sha256:${'4'.repeat(64)}`,
    evidenceDirectory: '/var/tmp/henry-build/evidence',
    oracleSnapshotPath: '/var/tmp/henry-build/oracle.json',
    repositoryRoot: '/home/henry/repo/logto',
    conformanceRoot: '/var/tmp/henry-build/conformance',
    targets: {},
    isolationAttestations: {
      oracle: {
        data: { persistenceId: '3'.repeat(64) },
        admin: { persistenceId: '3'.repeat(64) },
        foreign: { persistenceId: '4'.repeat(64) },
      },
      candidate: {
        data: { persistenceId: primaryContainerId },
        admin: { persistenceId: primaryContainerId },
        foreign: { persistenceId: foreignContainerId },
      },
    },
    ...overrides,
  }) as Phase1EvidenceRuntimeContext;

const terminal = (value: unknown = projection) => ({
  schemaVersion: 1,
  kind: 'phase1-candidate-invariant-terminal',
  invariantId,
  projection: value,
});

const result = (
  stdout: unknown,
  overrides: Partial<CommandRunnerResult> = {}
): CommandRunnerResult => ({
  exitCode: 0,
  signal: null,
  stdout: typeof stdout === 'string' ? stdout : JSON.stringify(stdout),
  stderr: '',
  timedOut: false,
  killed: false,
  reaped: true,
  ...overrides,
});

describe('Phase 1 live candidate invariant driver adapter', () => {
  it('binds one invariant to the exact candidate topology and closed process request', async () => {
    const runner = import.meta.jest.fn(async (_request: CommandRunnerRequest) =>
      result(terminal())
    );
    const execute = createPhase1LiveCandidateInvariantExecutor({
      repositoryRoot: '/home/henry/repo/logto',
      environment: { PATH: '/usr/bin:/bin', ASTER_PHASE1_TOPOLOGY_ID: projectName },
      runner,
    });

    await expect(execute(invariantId, context())).resolves.toEqual({
      id: invariantId,
      projection,
    });
    expect(runner).toHaveBeenCalledWith({
      command:
        '/home/henry/repo/logto/.scripts/compatibility/phase1-candidate-invariants-driver.sh',
      args: [
        '--invariant-id',
        invariantId,
        '--project-name',
        projectName,
        '--primary-container-id',
        primaryContainerId,
        '--foreign-container-id',
        foreignContainerId,
      ],
      stdin: '',
      env: { PATH: '/usr/bin:/bin' },
      timeoutMs: 120_000,
      maxStdoutBytes: 65_536,
      maxStderrBytes: 65_536,
      shell: false,
    });
  });

  const invalidOutputs: ReadonlyArray<
    readonly [
      string,
      string | Readonly<Record<string, unknown>>,
      Readonly<Record<string, unknown>> | undefined,
      Partial<CommandRunnerResult> | undefined,
    ]
  > = [
    ['wrong id', terminal({}), { invariantId: candidateInvariantScenarioIds[1] }, undefined],
    ['extra terminal key', { ...terminal(), extra: true }, undefined, undefined],
    ['duplicate key', '{"schemaVersion":1,"schemaVersion":1}', undefined, undefined],
    ['BOM', `\uFEFF${JSON.stringify(terminal())}`, undefined, undefined],
    ['newline', `${JSON.stringify(terminal())}\n`, undefined, undefined],
    ['credential field', terminal({ password: 'private-value' }), undefined, undefined],
    ['stderr', terminal(), undefined, { stderr: 'private stderr' }],
    ['nonzero', terminal(), undefined, { exitCode: 1 }],
    ['signal', terminal(), undefined, { signal: 'SIGTERM' }],
    ['timeout', terminal(), undefined, { timedOut: true, killed: true }],
    ['not reaped', terminal(), undefined, { reaped: false }],
  ];

  it.each(invalidOutputs)('rejects %s output', async (_name, output, patch, resultPatch) => {
    const value = typeof output === 'string' ? output : JSON.stringify({ ...output, ...patch });
    const execute = createPhase1LiveCandidateInvariantExecutor({
      repositoryRoot: '/home/henry/repo/logto',
      environment: { PATH: '/usr/bin:/bin', ASTER_PHASE1_TOPOLOGY_ID: projectName },
      runner: async () => result(value, resultPatch),
    });

    await expect(execute(invariantId, context())).rejects.toThrow(
      /^Invalid phase 1 live candidate invariant driver$/u
    );
  });

  it.each([
    ['missing topology', {}],
    ['wrong topology', { ASTER_PHASE1_TOPOLOGY_ID: 'wrong' }],
    ['missing PATH', { ASTER_PHASE1_TOPOLOGY_ID: projectName }],
  ] as const)('rejects %s before invoking the runner', async (_name, environment) => {
    const runner = import.meta.jest.fn(async () => result(terminal()));
    const execute = createPhase1LiveCandidateInvariantExecutor({
      repositoryRoot: '/home/henry/repo/logto',
      environment,
      runner,
    });

    await expect(execute(invariantId, context())).rejects.toThrow(
      /^Invalid phase 1 live candidate invariant driver$/u
    );
    expect(runner).not.toHaveBeenCalled();
  });

  it('rejects aliased or malformed candidate persistence attestations', async () => {
    const runner = import.meta.jest.fn(async () => result(terminal()));
    const execute = createPhase1LiveCandidateInvariantExecutor({
      repositoryRoot: '/home/henry/repo/logto',
      environment: { PATH: '/usr/bin:/bin', ASTER_PHASE1_TOPOLOGY_ID: projectName },
      runner,
    });
    const malformed = context({
      isolationAttestations: {
        candidate: {
          data: { persistenceId: primaryContainerId },
          admin: { persistenceId: foreignContainerId },
          foreign: { persistenceId: primaryContainerId },
        },
      },
    });

    await expect(execute(invariantId, malformed)).rejects.toThrow(
      /^Invalid phase 1 live candidate invariant driver$/u
    );
    expect(runner).not.toHaveBeenCalled();
  });
});

/* eslint-enable @typescript-eslint/consistent-type-assertions */
