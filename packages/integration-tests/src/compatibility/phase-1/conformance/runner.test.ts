/* eslint-disable max-lines, no-await-in-loop, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unnecessary-boolean-literal-compare, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The injected process seam records requests and hostile terminal variants, including bounded process polling. */
import { execFile, spawn, spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, utimes, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

import type { Phase1Profile } from '../profile-types.js';

import { phase1ConformanceSuiteCommit, phase1ConformanceSuiteRepository } from './config.js';
import {
  phase1ConformanceAdapterControlIds,
  runPhase1Conformance,
  runPhase1ConformanceProcessForTesting,
  type Phase1ConformanceProcessRequest,
  type Phase1ConformanceProcessResult,
} from './runner.js';

const callbackUri = 'https://suite.example/test/a/aster-phase1/callback';
const executeFile = promisify(execFile);
const profile = (): Phase1Profile =>
  ({
    fixtures: {
      adminTenant: {
        application: { oidcClientMetadata: { redirectUris: ['https://admin/callback'] } },
      },
      dataTenant: {
        applications: [{ oidcClientMetadata: { redirectUris: ['https://data/callback'] } }],
      },
    },
    consoleAuthentication: { grants: ['authorization_code', 'refresh_token'] },
    oidc: {
      grants: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      responseModes: ['query'],
      tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
      idTokenSigningAlgorithmsSupported: ['ES384'],
      jwksKeyMetadata: { kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
    },
    conformance: {
      suiteRepository: phase1ConformanceSuiteRepository,
      suiteCommit: phase1ConformanceSuiteCommit,
      target: {
        namespace: 'private',
        issuer: 'https://server.example/oidc',
        discoveryUrl: 'https://server.example/oidc/.well-known/openid-configuration',
        suiteBaseUrl: 'https://suite.example',
        alias: 'aster-phase1',
        callbackUri,
        tls: {
          trustDomain: 'private',
          issuer: 'private',
          asterMaterial: 'private',
          suiteMaterial: 'private',
          lifecycle: 'private',
        },
      },
      staticClients: [
        {
          id: 'oidf-basic-1',
          tokenEndpointAuthMethod: 'client_secret_basic',
          redirectUris: [callbackUri],
        },
        {
          id: 'oidf-basic-2',
          tokenEndpointAuthMethod: 'client_secret_basic',
          redirectUris: [callbackUri],
        },
        {
          id: 'oidf-post-1',
          tokenEndpointAuthMethod: 'client_secret_post',
          redirectUris: [callbackUri],
        },
      ],
      plans: [
        {
          testPlanName: 'oidcc-basic-certification-test-plan',
          displayName: 'Basic',
          variants: {
            serverMetadata: 'discovery',
            clientRegistration: 'static_client',
            responseType: 'code',
            responseMode: 'default',
            clientAuthTypes: ['client_secret_basic', 'client_secret_post'],
          },
        },
        {
          testPlanName: 'oidcc-config-certification-test-plan',
          displayName: 'Config',
          variants: { serverMetadata: 'discovery', clientRegistration: 'static_client' },
        },
      ],
    },
  }) as unknown as Phase1Profile;

const processResult = (
  stdout: unknown,
  overrides: Partial<Phase1ConformanceProcessResult> = {}
): Phase1ConformanceProcessResult => ({
  pid: 1234,
  processGroupId: 1234,
  exitCode: 0,
  signal: undefined,
  stdout: typeof stdout === 'string' ? stdout : JSON.stringify(stdout),
  stderr: '',
  timedOut: false,
  killed: false,
  reaped: true,
  ...overrides,
});

const terminalFor = (
  request: Phase1ConformanceProcessRequest,
  resultId = 'oidf-result-opaque-001'
) => {
  const input = JSON.parse(request.stdin) as {
    planId?: string;
    variant?: unknown;
    staticClient?: { id: string };
  };

  if (request.args[0] === '--adapter-control-id') {
    return {
      schemaVersion: 1,
      kind: 'phase1-conformance-adapter-control-terminal',
      suiteCommit: phase1ConformanceSuiteCommit,
      adapterControlId: input.staticClient?.id,
      status: 'PASSED',
      result: { configured: true, redirectUriMatches: true },
    };
  }
  return {
    schemaVersion: 1,
    kind: 'phase1-conformance-terminal',
    suiteCommit: phase1ConformanceSuiteCommit,
    adapterControlId: 'phase1-conformance.runner.strict-terminal',
    planId: input.planId,
    variant: input.variant,
    status: 'PASSED',
    resultId,
    result: { outcome: 'passed', checks: { completed: true } },
  };
};

const dependencies = (
  runner: (request: Phase1ConformanceProcessRequest) => Promise<Phase1ConformanceProcessResult>
) => ({
  checkedOutSuiteCommit: phase1ConformanceSuiteCommit,
  repositoryRoot: '/repo',
  scriptPath: '/repo/.scripts/compatibility/run-phase1-conformance.sh',
  workingDirectory: '/repo',
  environment: {
    PATH: '/usr/bin:/bin',
    ASTER_PHASE1_BUILD_ROOT: '/var/tmp/henry-build',
    ASTER_PHASE1_HARNESS_COMMIT: 'a'.repeat(40),
    ASTER_PHASE1_CONFORMANCE_ROOT: '/var/tmp/henry-build/conformance-test',
    ASTER_PHASE1_CONFORMANCE_DRIVER: '/repo/.scripts/compatibility/phase1-conformance-driver.sh',
  },
  runner,
});

describe('Phase 1 conformance runner', () => {
  it.each(['review-candidate', 'mirror-control'] as const)(
    'emits adapter controls and no official result in %s mode',
    async (mode) => {
      let calls = 0;
      const result = await runPhase1Conformance(
        profile(),
        mode,
        dependencies(async (request) => {
          calls += 1;
          return processResult(terminalFor(request));
        })
      );

      expect(calls).toBe(3);
      expect(result.adapterControls.map(({ id }) => id)).toEqual(
        phase1ConformanceAdapterControlIds
      );
      expect(result.officialResults).toEqual([]);
    }
  );

  it('executes the fixed repository driver for adapter controls and rejects official plans', async () => {
    const driverPath = path.resolve(
      process.cwd(),
      '../..',
      '.scripts/compatibility/phase1-conformance-driver.sh'
    );
    const config = {
      schemaVersion: 1,
      suite: { commit: phase1ConformanceSuiteCommit },
      target: { callbackUri },
      staticClient: {
        id: 'oidf-basic-1',
        tokenEndpointAuthMethod: 'client_secret_basic',
        redirectUris: [callbackUri],
      },
      plans: [],
    };
    const control = await runPhase1ConformanceProcessForTesting({
      command: driverPath,
      args: ['--adapter-control-id', 'oidf-basic-1'],
      cwd: path.dirname(driverPath),
      stdin: JSON.stringify(config),
      env: { PATH: '/usr/bin:/bin' },
      timeoutMs: 5000,
      maxStdoutBytes: 65_536,
      maxStderrBytes: 65_536,
      shell: false,
    });

    expect(JSON.parse(control.stdout)).toEqual({
      schemaVersion: 1,
      kind: 'phase1-conformance-adapter-control-terminal',
      suiteCommit: phase1ConformanceSuiteCommit,
      adapterControlId: 'oidf-basic-1',
      status: 'PASSED',
      result: { configured: true, redirectUriMatches: true },
    });
    expect(control).toMatchObject({ exitCode: 0, stderr: '', reaped: true });

    const official = await runPhase1ConformanceProcessForTesting({
      command: driverPath,
      args: ['--plan-id', 'oidcc-basic-certification-test-plan'],
      cwd: path.dirname(driverPath),
      stdin: JSON.stringify(config),
      env: { PATH: '/usr/bin:/bin' },
      timeoutMs: 5000,
      maxStdoutBytes: 65_536,
      maxStderrBytes: 65_536,
      shell: false,
    });

    expect(official).toMatchObject({ exitCode: 1, stdout: '', stderr: '', reaped: true });
  });

  it('runs and reaps a real detached process group', async () => {
    const result = await runPhase1ConformanceProcessForTesting({
      command: process.execPath,
      args: ['-e', 'process.stdout.write("terminal")'],
      cwd: process.cwd(),
      stdin: '',
      env: { PATH: '/usr/bin:/bin' },
      timeoutMs: 300_000,
      maxStdoutBytes: 65_536,
      maxStderrBytes: 65_536,
      shell: false,
    });

    expect(result).toMatchObject({
      exitCode: 0,
      stdout: 'terminal',
      stderr: '',
      timedOut: false,
      killed: false,
      reaped: true,
    });
    expect(result.pid).toBeGreaterThan(0);
    expect(result.processGroupId).toBe(result.pid);
  });

  it('marks invalid UTF-8 process output unusable without exposing bytes', async () => {
    const result = await runPhase1ConformanceProcessForTesting({
      command: process.execPath,
      args: ['-e', 'process.stdout.write(Buffer.from([255]))'],
      cwd: process.cwd(),
      stdin: '',
      env: { PATH: '/usr/bin:/bin' },
      timeoutMs: 300_000,
      maxStdoutBytes: 65_536,
      maxStderrBytes: 65_536,
      shell: false,
    });

    expect(result.stdout).toBe('');
    expect(result.killed).toBe(true);
  });

  it('kills a SIGTERM-resistant process tree and waits for group disappearance', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/conformance-process-tree-');
    const pidPath = path.join(root, 'pids.json');
    const childSource =
      'process.on("SIGTERM",()=>{});setInterval(()=>process.stdout.write("x"),10);';
    const parentSource = [
      'const {spawn}=require("node:child_process");',
      'const fs=require("node:fs");',
      `const child=spawn(process.execPath,['-e',${JSON.stringify(childSource)}],{stdio:['ignore','ignore','ignore']});`,
      `fs.writeFileSync(${JSON.stringify(pidPath)},JSON.stringify({parentPid:process.pid,childPid:child.pid}));`,
      'process.on("SIGTERM",()=>{});',
      'process.stdout.write("ready");',
      'setInterval(()=>{},1000);',
    ].join('');
    const started = Date.now();

    try {
      const result = await runPhase1ConformanceProcessForTesting({
        command: process.execPath,
        args: ['-e', parentSource],
        cwd: root,
        stdin: '',
        env: { PATH: '/usr/bin:/bin' },
        timeoutMs: 100,
        maxStdoutBytes: 32,
        maxStderrBytes: 32,
        shell: false,
      });
      const pids = JSON.parse(await readFile(pidPath, 'utf8')) as {
        parentPid: number;
        childPid: number;
      };
      const exists = (pid: number) => {
        try {
          process.kill(pid, 0);
          return true;
        } catch {
          return false;
        }
      };

      expect(result).toMatchObject({ timedOut: true, killed: true, reaped: true });
      expect(result.pid).toBe(pids.parentPid);
      expect(result.processGroupId).toBe(pids.parentPid);
      expect(result.stdout.length).toBeLessThanOrEqual(32);
      expect(Date.now() - started).toBeLessThan(3000);
      expect(exists(pids.parentPid)).toBe(false);
      expect(exists(pids.childPid)).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('reaps detached conformance descendants when the owning Node process is interrupted', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/conformance-interruption-');
    const pidPath = path.join(root, 'pids.json');
    const runnerUrl = new URL('runner.js', import.meta.url).href;
    const childSource = 'process.on("SIGTERM",()=>{});setInterval(()=>{},1000);';
    const parentSource = [
      'const {spawn}=require("node:child_process");',
      'const fs=require("node:fs");',
      `const child=spawn(process.execPath,['-e',${JSON.stringify(childSource)}],{stdio:['ignore','ignore','ignore']});`,
      `fs.writeFileSync(${JSON.stringify(pidPath)},JSON.stringify({parentPid:process.pid,childPid:child.pid}));`,
      'process.on("SIGTERM",()=>{});',
      'setInterval(()=>{},1000);',
    ].join('');
    const helperSource = [
      `import { runPhase1ConformanceProcessForTesting } from ${JSON.stringify(runnerUrl)};`,
      'await runPhase1ConformanceProcessForTesting({',
      `command:${JSON.stringify(process.execPath)},`,
      `args:['-e',${JSON.stringify(parentSource)}],`,
      `cwd:${JSON.stringify(root)},stdin:'',env:{PATH:'/usr/bin:/bin'},`,
      'timeoutMs:300000,maxStdoutBytes:32,maxStderrBytes:32,shell:false});',
    ].join('');
    const helper = spawn(process.execPath, ['--input-type=module', '-e', helperSource], {
      cwd: root,
      env: { ...process.env, NODE_ENV: 'test' },
      stdio: 'ignore',
    });
    let parentPid: number | undefined;
    let childPid: number | undefined;
    const exists = (pid: number | undefined) => {
      if (!pid) {
        return false;
      }
      try {
        process.kill(pid, 0);
        return true;
      } catch {
        return false;
      }
    };

    try {
      for (let attempt = 0; attempt < 200; attempt += 1) {
        try {
          const pids = JSON.parse(await readFile(pidPath, 'utf8')) as {
            parentPid: number;
            childPid: number;
          };
          parentPid = pids.parentPid;
          childPid = pids.childPid;
          break;
        } catch {
          await new Promise((resolve) => {
            setTimeout(resolve, 10);
          });
        }
      }
      expect(parentPid).toBeGreaterThan(0);
      expect(childPid).toBeGreaterThan(0);
      helper.kill('SIGTERM');
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error('interruption helper timed out'));
        }, 5000);
        helper.once('close', () => {
          clearTimeout(timer);
          resolve();
        });
      });
      for (
        let attempt = 0;
        attempt < 200 && (exists(parentPid) || exists(childPid));
        attempt += 1
      ) {
        await new Promise((resolve) => {
          setTimeout(resolve, 10);
        });
      }
      expect(exists(parentPid)).toBe(false);
      expect(exists(childPid)).toBe(false);
    } finally {
      helper.kill('SIGKILL');
      if (parentPid) {
        try {
          process.kill(-parentPid, 'SIGKILL');
        } catch {
          // The owned test group is already gone.
        }
      }
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects a failed adapter-control terminal before emitting detected evidence', async () => {
    await expect(
      runPhase1Conformance(
        profile(),
        'mirror-control',
        dependencies(async (request) => {
          const terminal = terminalFor(request);
          return processResult(
            request.args[1] === 'oidf-basic-2' ? { ...terminal, status: 'FAILED' } : terminal
          );
        })
      )
    ).rejects.toThrow('Invalid phase 1 conformance runner');
  });

  it('runs exactly the two profiled plans with fixed process bounds in runtime mode', async () => {
    const requests: Phase1ConformanceProcessRequest[] = [];
    const result = await runPhase1Conformance(
      profile(),
      'runtime-candidate',
      dependencies(async (request) => {
        requests.push(request);
        if (request.args[0] === '--adapter-control-id') {
          return processResult(terminalFor(request));
        }
        const planInput = JSON.parse(request.stdin) as { planId: string };
        const suffix = planInput.planId === 'oidcc-basic-certification-test-plan' ? '001' : '002';
        return processResult(terminalFor(request, `oidf-result-opaque-${suffix}`));
      })
    );

    expect(requests).toHaveLength(5);
    expect(requests.every(({ shell }) => shell === false)).toBe(true);
    expect(requests.every(({ timeoutMs }) => timeoutMs === 300_000)).toBe(true);
    expect(requests.every(({ maxStdoutBytes }) => maxStdoutBytes === 65_536)).toBe(true);
    expect(requests.every(({ maxStderrBytes }) => maxStderrBytes === 65_536)).toBe(true);
    expect(
      requests
        .map(({ command }) => command)
        .every((value) => value.endsWith('run-phase1-conformance.sh'))
    ).toBe(true);
    expect(result.officialResults.map(({ planId }) => planId)).toEqual([
      'oidcc-basic-certification-test-plan',
      'oidcc-config-certification-test-plan',
    ]);
    expect(result.officialResults.map(({ result: value }) => value)).toEqual([
      { outcome: 'passed', checks: { completed: true } },
      { outcome: 'passed', checks: { completed: true } },
    ]);
  });

  it('waits for each owned invocation before starting the next one', async () => {
    const sequence: string[] = [];
    let active = 0;
    let maximumActive = 0;

    await runPhase1Conformance(
      profile(),
      'runtime-candidate',
      dependencies(async (request) => {
        const id = request.args[1] ?? 'missing';
        sequence.push(id);
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await new Promise((resolve) => {
          setImmediate(resolve);
        });
        active -= 1;
        const suffix = id === 'oidcc-config-certification-test-plan' ? '002' : '001';

        return processResult(terminalFor(request, `oidf-result-opaque-${suffix}`));
      })
    );

    expect(maximumActive).toBe(1);
    expect(sequence).toEqual([
      'oidf-basic-1',
      'oidf-basic-2',
      'oidf-post-1',
      'oidcc-basic-certification-test-plan',
      'oidcc-config-certification-test-plan',
    ]);
  });

  it.each([
    [
      'timeout',
      (_request: Phase1ConformanceProcessRequest) =>
        processResult('{}', { timedOut: true, killed: true }),
    ],
    [
      'signal',
      (_request: Phase1ConformanceProcessRequest) =>
        processResult('{}', { exitCode: undefined, signal: 'SIGTERM', killed: true }),
    ],
    [
      'unreaped',
      (_request: Phase1ConformanceProcessRequest) => processResult('{}', { reaped: false }),
    ],
    [
      'progress-only',
      (_request: Phase1ConformanceProcessRequest) => processResult('still running'),
    ],
    [
      'multiple terminal objects',
      (_request: Phase1ConformanceProcessRequest) => processResult('{}\n{}'),
    ],
    [
      'secret stderr',
      (request: Phase1ConformanceProcessRequest) =>
        processResult(terminalFor(request), { stderr: 'Bearer private-terminal-secret' }),
    ],
    [
      'oversized stdout',
      (_request: Phase1ConformanceProcessRequest) => processResult('x'.repeat(65_537)),
    ],
    [
      'oversized stderr',
      (request: Phase1ConformanceProcessRequest) =>
        processResult(terminalFor(request), { stderr: 'x'.repeat(65_537) }),
    ],
    [
      'wrong suite commit',
      (request: Phase1ConformanceProcessRequest) =>
        processResult({ ...terminalFor(request), suiteCommit: '1'.repeat(40) }),
    ],
    [
      'wrong adapter control',
      (request: Phase1ConformanceProcessRequest) =>
        processResult({ ...terminalFor(request), adapterControlId: 'wrong' }),
    ],
    [
      'wrong plan',
      (request: Phase1ConformanceProcessRequest) =>
        processResult({ ...terminalFor(request), planId: 'wrong-plan' }),
    ],
    [
      'wrong variant',
      (request: Phase1ConformanceProcessRequest) =>
        processResult({ ...terminalFor(request), variant: { changed: true } }),
    ],
    [
      'wrong status',
      (request: Phase1ConformanceProcessRequest) =>
        processResult({ ...terminalFor(request), status: 'FAILED' }),
    ],
    [
      'duplicate terminal key',
      (request: Phase1ConformanceProcessRequest) => {
        const terminal = JSON.stringify(terminalFor(request));
        return processResult(
          terminal.replace('"status":"PASSED"', '"status":"FAILED","status":"PASSED"')
        );
      },
    ],
    [
      'BOM terminal',
      (request: Phase1ConformanceProcessRequest) =>
        processResult(`\uFEFF${JSON.stringify(terminalFor(request))}`),
    ],
    [
      'plan name as result ID',
      (request: Phase1ConformanceProcessRequest) => {
        const input = JSON.parse(request.stdin) as { planId: string };
        return processResult(terminalFor(request, input.planId));
      },
    ],
    [
      'secret-bearing result',
      (request: Phase1ConformanceProcessRequest) =>
        processResult({ ...terminalFor(request), result: { accessToken: 'secret-token-value' } }),
    ],
  ] as const)('rejects %s with a fixed non-echoing diagnostic', async (_name, respond) => {
    let error: unknown;
    try {
      await runPhase1Conformance(
        profile(),
        'runtime-candidate',
        dependencies(async (request) =>
          request.args[0] === '--adapter-control-id'
            ? processResult(terminalFor(request))
            : respond(request)
        )
      );
    } catch (error_: unknown) {
      error = error_;
    }

    expect(String(error)).toBe('TypeError: Invalid phase 1 conformance runner');
    expect(`${String(error)} ${JSON.stringify(error)}`).not.toMatch(
      /private-terminal-secret|wrong-plan/u
    );
  });

  it('pins the shell wrapper to the exact suite commit without parsing JSON in shell', async () => {
    const source = await readFile(
      path.resolve(process.cwd(), '../../.scripts/compatibility/run-phase1-conformance.sh'),
      'utf8'
    );
    expect(source).toContain(phase1ConformanceSuiteCommit);
    expect(source).toContain(phase1ConformanceSuiteRepository);
    expect(source).toContain('/var/tmp/henry-build');
    expect(source).toContain('ASTER_PHASE1_BUILD_ROOT');
    expect(source).toContain('DEFAULT_BUILD_ROOT');
    expect(source).toContain('capture_build_root_identity');
    expect(source).toContain('assert_build_root_identity');
    expect(source).not.toMatch(/\bjq\b|JSON\.parse|python/iu);
    expect(source).toContain("readonly TRUSTED_PATH='/usr/bin:/bin'");
    expect(source).toContain(
      "readonly DRIVER_RELATIVE='.scripts/compatibility/phase1-conformance-driver.sh'"
    );
    expect(source).toContain('ASTER_PHASE1_HARNESS_COMMIT');
    expect(source).toContain('GIT_NO_REPLACE_OBJECTS=1');
    expect(source).toContain('--no-replace-objects');
    expect(source).toContain('remote get-url origin');
    expect(source).toContain('hash-object');
    expect(source).toContain('ls-files --error-unmatch');
  });

  it('uses replacement-disabled Git authority against a clean HEAD with refs/replace', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/conformance-replace-ref-');
    const relative = '.scripts/compatibility/phase1-conformance-driver.sh';
    const filePath = path.join(root, relative);

    try {
      await mkdir(path.dirname(filePath), { recursive: true });
      await writeFile(filePath, 'original\n');
      await executeFile('git', ['init', '-q'], { cwd: root });
      await executeFile('git', ['config', 'user.name', 'test'], { cwd: root });
      await executeFile('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root });
      await executeFile('git', ['add', '.'], { cwd: root });
      await executeFile('git', ['commit', '-qm', 'original'], { cwd: root });
      const { stdout: headOutput } = await executeFile('git', ['rev-parse', 'HEAD'], { cwd: root });
      const head = headOutput.trim();
      await writeFile(filePath, 'replacement\n');
      await executeFile('git', ['add', relative], { cwd: root });
      const { stdout: treeOutput } = await executeFile('git', ['write-tree'], { cwd: root });
      const { stdout: replacementOutput } = await executeFile(
        'git',
        ['commit-tree', treeOutput.trim(), '-m', 'replacement'],
        { cwd: root }
      );
      await executeFile('git', ['reset', '--hard', '-q', head], { cwd: root });
      await executeFile('git', ['replace', head, replacementOutput.trim()], { cwd: root });
      const replaced = await executeFile('git', ['show', `HEAD:${relative}`], { cwd: root });
      const authoritative = await executeFile(
        'git',
        ['--no-replace-objects', 'show', `HEAD:${relative}`],
        { cwd: root, env: { ...process.env, GIT_NO_REPLACE_OBJECTS: '1' } }
      );
      const { stdout: status } = await executeFile(
        'git',
        ['--no-replace-objects', 'status', '--porcelain=v1', '--untracked-files=all'],
        { cwd: root, env: { ...process.env, GIT_NO_REPLACE_OBJECTS: '1' } }
      );

      expect(replaced.stdout).toBe('replacement\n');
      expect(authoritative.stdout).toBe('original\n');
      expect(status).toBe('');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('detects malicious raw driver bytes hidden by a local clean filter', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/conformance-clean-filter-');
    const relative = '.scripts/compatibility/phase1-conformance-driver.sh';
    const filePath = path.join(root, relative);

    try {
      await mkdir(path.dirname(filePath), { recursive: true });
      await writeFile(filePath, 'benign123\n');
      await executeFile('git', ['init', '-q'], { cwd: root });
      await executeFile('git', ['config', 'user.name', 'test'], { cwd: root });
      await executeFile('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root });
      await mkdir(path.join(root, '.git/info'), { recursive: true });
      await writeFile(path.join(root, '.git/info/attributes'), '*.sh filter=cleaner\n');
      const filterPath = path.join(root, '.git/clean-filter.sh');
      await writeFile(filterPath, '#!/bin/sh\ncat >/dev/null\nprintf "benign123\\n"\n', {
        mode: 0o700,
      });
      await executeFile('git', ['config', 'filter.cleaner.clean', filterPath], { cwd: root });
      await executeFile('git', ['config', 'filter.cleaner.smudge', 'cat'], { cwd: root });
      await executeFile('git', ['config', 'core.trustctime', 'false'], { cwd: root });
      await executeFile('git', ['config', 'core.checkStat', 'minimal'], { cwd: root });
      await executeFile('git', ['add', '.'], { cwd: root });
      await executeFile('git', ['commit', '-qm', 'safe'], { cwd: root });
      const originalState = await stat(filePath);
      await writeFile(filePath, 'evilbytes\n');
      await utimes(filePath, originalState.atime, originalState.mtime);
      const { stdout: status } = await executeFile(
        'git',
        ['status', '--porcelain=v1', '--untracked-files=all'],
        { cwd: root }
      );
      const { stdout: expected } = await executeFile('git', ['rev-parse', `HEAD:${relative}`], {
        cwd: root,
      });
      const { stdout: filtered } = await executeFile(
        'git',
        ['hash-object', `--path=${relative}`, filePath],
        { cwd: root }
      );
      const { stdout: raw } = await executeFile('git', ['hash-object', '--no-filters', filePath], {
        cwd: root,
      });
      const wrapper = await readFile(
        path.resolve(process.cwd(), '../../.scripts/compatibility/run-phase1-conformance.sh'),
        'utf8'
      );

      expect(status).toBe('');
      expect(filtered.trim()).toBe(expected.trim());
      expect(raw.trim()).not.toBe(expected.trim());
      expect(wrapper).toContain('hash-object --no-filters');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects a canonical-origin repository whose clean HEAD differs from the expected harness commit', async () => {
    const root = await mkdtemp('/var/tmp/henry-build/conformance-wrapper-repo-');
    const scriptDirectory = path.join(root, '.scripts/compatibility');
    const scriptPath = path.join(scriptDirectory, 'run-phase1-conformance.sh');
    const driverPath = path.join(scriptDirectory, 'phase1-conformance-driver.sh');
    const source = await readFile(
      path.resolve(process.cwd(), '../../.scripts/compatibility/run-phase1-conformance.sh'),
      'utf8'
    );

    try {
      await mkdir(scriptDirectory, { recursive: true, mode: 0o700 });
      await Promise.all([
        writeFile(scriptPath, source, { mode: 0o700 }),
        writeFile(driverPath, '#!/usr/bin/env bash\nexit 0\n', { mode: 0o700 }),
      ]);
      await chmod(scriptPath, 0o700);
      await executeFile('git', ['init', '-q'], { cwd: root });
      await executeFile('git', ['config', 'user.name', 'test'], { cwd: root });
      await executeFile('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root });
      await executeFile(
        'git',
        ['remote', 'add', 'origin', 'https://github.com/qq98982/logto.git'],
        {
          cwd: root,
        }
      );
      await executeFile('git', ['add', '.'], { cwd: root });
      await executeFile('git', ['commit', '-qm', 'fixture'], { cwd: root });
      const { stdout } = await executeFile('git', ['rev-parse', 'HEAD'], { cwd: root });
      const actualHead = stdout.trim();
      const wrongHead = `${actualHead.startsWith('a') ? 'b' : 'a'}${actualHead.slice(1)}`;

      await expect(
        executeFile(scriptPath, [], {
          cwd: root,
          env: {
            PATH: '/usr/bin:/bin',
            ASTER_PHASE1_HARNESS_COMMIT: wrongHead,
            ASTER_PHASE1_CONFORMANCE_ROOT: path.join(root, 'private-root'),
            ASTER_PHASE1_CONFORMANCE_DRIVER: driverPath,
          },
        })
      ).rejects.toMatchObject({ code: 1 });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects substituted repository paths and environment keys before the runner', async () => {
    let touched = false;
    await expect(
      runPhase1Conformance(profile(), 'mirror-control', {
        ...dependencies(async () => {
          touched = true;
          return processResult({});
        }),
        environment: {
          PATH: '/tmp/private-bin',
          ASTER_PHASE1_BUILD_ROOT: '/var/tmp/henry-build',
          ASTER_PHASE1_HARNESS_COMMIT: 'a'.repeat(40),
          ASTER_PHASE1_CONFORMANCE_ROOT: '/var/tmp/henry-build/conformance-test',
          ASTER_PHASE1_CONFORMANCE_DRIVER:
            '/repo/.scripts/compatibility/phase1-conformance-driver.sh',
          GITHUB_TOKEN: 'private',
        },
      })
    ).rejects.toThrow('Invalid phase 1 conformance runner');
    expect(touched).toBe(false);
  });

  it('accepts a conformance root beneath a custom safe build root', async () => {
    let touched = false;
    const custom = dependencies(async (request) => {
      touched = true;
      return processResult(terminalFor(request));
    });

    await expect(
      runPhase1Conformance(profile(), 'mirror-control', {
        ...custom,
        environment: {
          ...custom.environment,
          ASTER_PHASE1_BUILD_ROOT: '/var/tmp/aster-portable-conformance',
          ASTER_PHASE1_CONFORMANCE_ROOT: '/var/tmp/aster-portable-conformance/private',
        },
      })
    ).resolves.toMatchObject({ mode: 'mirror-control' });
    expect(touched).toBe(true);
  });

  it('rejects an unsafe configurable build root before the runner', async () => {
    let touched = false;
    const custom = dependencies(async () => {
      touched = true;
      return processResult({});
    });

    await expect(
      runPhase1Conformance(profile(), 'mirror-control', {
        ...custom,
        environment: {
          ...custom.environment,
          ASTER_PHASE1_BUILD_ROOT: '/var/tmp',
        },
      })
    ).rejects.toThrow('Invalid phase 1 conformance runner');
    expect(touched).toBe(false);
  });

  it('rejects duplicate official result IDs before branding', async () => {
    await expect(
      runPhase1Conformance(
        profile(),
        'runtime-candidate',
        dependencies(async (request) =>
          processResult(
            request.args[0] === '--adapter-control-id'
              ? terminalFor(request)
              : terminalFor(request, 'oidf-result-duplicate')
          )
        )
      )
    ).rejects.toThrow('Invalid phase 1 conformance runner');
  });

  it('driver rejects wrong redirect and client method with empty output', () => {
    const driverPath = path.resolve(
      process.cwd(),
      '../../.scripts/compatibility/phase1-conformance-driver.sh'
    );
    const base = {
      schemaVersion: 1,
      suite: { commit: phase1ConformanceSuiteCommit },
      target: { callbackUri },
      staticClient: {
        id: 'oidf-basic-1',
        tokenEndpointAuthMethod: 'client_secret_basic',
        redirectUris: [callbackUri],
      },
    };
    const valid = spawnSync(driverPath, ['--adapter-control-id', 'oidf-basic-1'], {
      input: JSON.stringify(base),
      encoding: 'utf8',
      env: { PATH: '/usr/bin:/bin' },
    });

    expect(valid.status).toBe(0);
    expect(JSON.parse(valid.stdout)).toMatchObject({
      status: 'PASSED',
      result: { configured: true, redirectUriMatches: true },
    });
    for (const invalid of [
      {
        ...base,
        staticClient: { ...base.staticClient, redirectUris: ['https://wrong.example/callback'] },
      },
      {
        ...base,
        staticClient: { ...base.staticClient, tokenEndpointAuthMethod: 'client_secret_post' },
      },
    ]) {
      const result = spawnSync(driverPath, ['--adapter-control-id', 'oidf-basic-1'], {
        input: JSON.stringify(invalid),
        encoding: 'utf8',
        env: { PATH: '/usr/bin:/bin' },
      });

      expect(result.status).toBe(1);
      expect(result.stdout).toBe('');
      expect(result.stderr).toBe('');
    }
  });
});

/* eslint-enable max-lines, no-await-in-loop, @typescript-eslint/no-unnecessary-condition, @typescript-eslint/no-unnecessary-boolean-literal-compare, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
