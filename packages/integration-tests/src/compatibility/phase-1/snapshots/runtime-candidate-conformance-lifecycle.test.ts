/* eslint-disable max-lines, complexity, no-await-in-loop, no-template-curly-in-string, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This process fixture mutates isolated process state and intentionally embeds literal shell interpolation syntax. */
import { execFile, spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const lifecycleSourcePath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase1-runtime-candidate-conformance.sh'
);
const wrapperSourcePath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase1-conformance.sh'
);
const driverSourcePath = path.join(
  repositoryRoot,
  '.scripts/compatibility/phase1-conformance-driver.sh'
);
const candidateInput = `sha256:${'5'.repeat(64)}`;

type Behavior =
  | 'cleanup-query-failure'
  | 'plan-failure'
  | 'signal'
  | 'setup-signal'
  | 'wrong-container'
  | 'wrong-project'
  | 'wrong-image'
  | 'wrong-driver'
  | 'wrong-runner';

type Fixture = Readonly<{
  root: string;
  repository: string;
  aster: string;
  buildRoot: string;
  runRoot: string;
  captureRoot: string;
  dockerLog: string;
  dockerState: string;
  lifecycle: string;
}>;

const git = async (cwd: string, args: readonly string[]): Promise<string> => {
  const result = await executeFile('/usr/bin/git', [...args], { cwd });

  return result.stdout.trim();
};

const initializeRepository = async (
  root: string,
  origin: string,
  message: string
): Promise<string> => {
  await git(root, ['init', '-q']);
  await git(root, ['config', 'user.name', 'fixture']);
  await git(root, ['config', 'user.email', 'fixture@example.invalid']);
  await git(root, ['remote', 'add', 'origin', origin]);
  await git(root, ['add', '.']);
  await git(root, ['commit', '-qm', message]);

  return git(root, ['rev-parse', 'HEAD']);
};

const fakeDockerSource = (
  statePath: string,
  logPath: string,
  suiteCommit: string
): string => `#!/usr/bin/node
const fs = require('node:fs');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const net = require('node:net');
const statePath = ${JSON.stringify(statePath)};
const logPath = ${JSON.stringify(logPath)};
let args = process.argv.slice(2);
fs.appendFileSync(logPath, JSON.stringify(args) + '\\n');
if (args[0] === '--root' && args[2] === '--runroot') args = args.slice(4);
const readState = () => JSON.parse(fs.readFileSync(statePath, 'utf8'));
const writeState = (value) => fs.writeFileSync(statePath, JSON.stringify(value));
const imageIds = {
  candidate: 'sha256:' + 'c'.repeat(64),
  postgres: 'sha256:' + '1'.repeat(64),
  mongo: 'sha256:' + '2'.repeat(64),
  nginx: 'sha256:' + '3'.repeat(64),
  runner: 'sha256:' + '4'.repeat(64),
  suite: 'sha256:' + 'a'.repeat(64),
};
const serviceNames = [
  'candidate-primary-postgres', 'candidate-primary-init', 'candidate-conformance-core',
  'candidate-fixture-coordinator', 'suite-mongo', 'suite-server', 'suite-nginx', 'oidf-runner',
];
const projectOption = () => args[args.indexOf('--project-name') + 1];
const filterProject = () => (args.find((value) => value.startsWith('label=com.docker.compose.project=')) ?? '').split('=').at(-1);
const parseEnv = (file) => Object.fromEntries(fs.readFileSync(file, 'utf8').trim().split('\\n').map((line) => {
  const index = line.indexOf('=');
  return [line.slice(0, index), line.slice(index + 1)];
}));
const idFor = (project, service) => crypto.createHash('sha256').update(project + ':' + service).digest('hex');
const imageFor = (service, environment) => {
  if (service === 'candidate-primary-postgres') return imageIds.postgres;
  if (service.startsWith('candidate-')) return environment.ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST;
  if (service === 'suite-mongo') return imageIds.mongo;
  if (service === 'suite-server') return environment.ASTER_PHASE1_OIDF_SUITE_IMAGE_DIGEST;
  if (service === 'suite-nginx') return imageIds.nginx;
  return imageIds.runner;
};
const containerDocument = (project, service, environment) => ({
  Id: idFor(project, service),
  Image: imageFor(service, environment),
  State: service === 'candidate-primary-init'
    ? { Status: 'exited', ExitCode: 0 }
    : { Status: 'running', ExitCode: 0, Health: { Status: 'healthy' } },
  Config: { Labels: {
    'com.docker.compose.project': project,
    'com.docker.compose.service': service,
    'com.aster.phase1.topology': 'runtime-candidate-conformance',
  } },
  Mounts: service === 'oidf-runner'
    ? [
        {
          Type: 'bind',
          Source: environment.ASTER_PHASE1_CONFORMANCE_DRIVER_FILE,
          Destination: '/opt/aster/phase1-conformance-driver.sh',
          RW: false,
        },
        {
          Type: 'bind',
          Source: environment.ASTER_PHASE1_CONFORMANCE_RUNNER_FILE,
          Destination: '/opt/aster/phase1-conformance-runner.mjs',
          RW: false,
        },
      ]
    : [],
});
if (args[0] === 'system' && args[1] === 'service') {
  const socket = args.at(-1).replace(/^unix:\\/\\//, '');
  const server = net.createServer(() => {});
  server.listen(socket);
  process.on('SIGTERM', () => server.close(() => process.exit(0)));
  process.on('SIGINT', () => server.close(() => process.exit(0)));
  setInterval(() => {}, 2147483647);
}
if (args[0] === 'pull' || args[0] === 'load') process.exit(0);
if (args[0] === 'ps' && args.length === 1) {
  const socket = (process.env.DOCKER_HOST ?? '').replace(/^unix:\\/\\//, '');
  process.exit(socket && fs.existsSync(socket) ? 0 : 1);
}
if (args[0] === 'compose' && args.includes('version')) process.exit(0);
if (args[0] === 'image' && args[1] === 'inspect') {
  const input = args.at(-1);
  const format = args[args.indexOf('--format') + 1] ?? '';
  let id = imageIds.candidate;
  if (input.includes('postgres')) id = imageIds.postgres;
  else if (input.includes('mongo')) id = imageIds.mongo;
  else if (input.includes('nginx')) id = imageIds.nginx;
  else if (input.includes('node')) id = imageIds.runner;
  else if (input === imageIds.suite) id = imageIds.suite;
  if (format.includes('maven-resolution')) {
    process.stdout.write(id + '|${suiteCommit}|source-pom-not-fully-offline-locked');
  } else process.stdout.write(id);
  process.exit(0);
}
if (args[0] === 'image' && args[1] === 'save') {
  fs.writeFileSync(args[args.indexOf('--output') + 1], 'candidate-image-archive');
  process.exit(0);
}
if (args[0] === 'build') {
  const state = readState();
  if (state.hangBuild === true) {
    fs.writeFileSync(state.setupMarker, String(process.pid) + '\\n');
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0);
  } else {
    const iidFile = args[args.indexOf('--iidfile') + 1];
    fs.writeFileSync(iidFile, imageIds.suite + '\\n');
    process.exit(0);
  }
}
if (args[0] === 'compose') {
  const command = args.includes('config')
    ? 'config'
    : args.includes('up')
      ? 'up'
      : args.includes('ps')
        ? 'ps'
        : '';
  const project = projectOption();
  if (command === 'config') process.exit(args.includes('--quiet') ? 0 : 1);
  if (command === 'up') {
    const environment = parseEnv(args[args.indexOf('--env-file') + 1]);
    const state = readState();
    state.projects[project] = { environment, containers: {}, network: true, volume: true };
    for (const service of serviceNames) state.projects[project].containers[idFor(project, service)] = service;
    writeState(state);
    process.exit(0);
  }
  if (command === 'ps') {
    const service = args.at(-1);
    const state = readState();
    if (state.projects[project]?.containers[idFor(project, service)]) process.stdout.write(idFor(project, service));
    process.exit(0);
  }
}
if (args[0] === 'inspect' && args[1] === '--format') {
  const id = args.at(-1);
  const state = readState();
  for (const [project, value] of Object.entries(state.projects)) {
    const service = value.containers[id];
    if (!service) continue;
    const document = containerDocument(project, service, value.environment);
    process.stdout.write([
      document.Id, document.State.Status, document.State.Health?.Status ?? '',
      document.State.ExitCode, document.Image, project, service, 'runtime-candidate-conformance',
    ].join('|'));
    process.exit(0);
  }
  process.exit(1);
}
if (args[0] === 'inspect') {
  const state = readState();
  const documents = args.slice(1).map((id) => {
    for (const [project, value] of Object.entries(state.projects)) {
      const service = value.containers[id];
      if (service) return containerDocument(project, service, value.environment);
    }
    process.exit(1);
  });
  process.stdout.write(JSON.stringify(documents));
  process.exit(0);
}
if (args[0] === 'ps' && args[1] === '-aq') {
  if (readState().cleanupQueriesActive === true) process.exit(2);
  const project = filterProject();
  process.stdout.write(Object.keys(readState().projects[project]?.containers ?? {}).join('\\n'));
  process.exit(0);
}
if (args[0] === 'rm') {
  const id = args.at(-1);
  const state = readState();
  for (const value of Object.values(state.projects)) delete value.containers[id];
  writeState(state);
  process.exit(0);
}
if ((args[0] === 'network' || args[0] === 'volume') && args[1] === 'ls') {
  if (readState().cleanupQueriesActive === true) process.exit(2);
  const project = filterProject();
  const value = readState().projects[project];
  if (value?.[args[0]]) process.stdout.write(project + '-' + args[0]);
  process.exit(0);
}
if ((args[0] === 'network' || args[0] === 'volume') && args[1] === 'rm') {
  const state = readState();
  const project = args[2].replace(/-(network|volume)$/, '');
  if (state.projects[project]) state.projects[project][args[0]] = false;
  writeState(state);
  process.exit(0);
}
if (args[0] === 'exec' && args[1] === '--interactive') {
  const state = readState();
  const containerId = args[2];
  let environment;
  for (const value of Object.values(state.projects)) {
    if (value.containers[containerId]) environment = value.environment;
  }
  if (!environment || args[3] !== '/opt/aster/phase1-conformance-driver.sh') process.exit(1);
  const result = cp.spawnSync(environment.ASTER_PHASE1_CONFORMANCE_DRIVER_FILE, args.slice(4), {
    input: fs.readFileSync(0),
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
  });
  process.stdout.write(result.stdout ?? '');
  process.stderr.write(result.stderr ?? '');
  if (readState().cleanupQueryFailure === true && args.includes('--plan-id')) {
    const next = readState();
    next.cleanupQueriesActive = true;
    writeState(next);
  }
  process.exit(result.status ?? 1);
}
process.exit(1);
`;

const fakeCliSource = (
  captureRoot: string,
  behavior: Behavior,
  suiteCommit: string
): string => `import { appendFileSync, chmodSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
const args = process.argv.slice(2);
if (args[0] === 'prepare-review-profile') {
  writeFileSync(args[args.indexOf('--output') + 1], '{}\\n', { mode: 0o600 });
  process.exit(0);
}
const root = process.env.ASTER_PHASE1_CONFORMANCE_ROOT;
const descriptorPath = path.join(root, 'runtime-candidate-conformance.json');
const captureRoot = ${JSON.stringify(captureRoot)};
mkdirSync(captureRoot, { recursive: true, mode: 0o700 });
const descriptor = JSON.parse(readFileSync(descriptorPath, 'utf8'));
copyFileSync(descriptorPath, path.join(captureRoot, descriptor.projectName + '.json'));
appendFileSync(path.join(captureRoot, 'run-roots.log'), path.dirname(root) + '\\n');
appendFileSync(path.join(captureRoot, 'started.log'), descriptor.projectName + '\\n');
const behavior = ${JSON.stringify(behavior)};
const reachesPlan = behavior === 'plan-failure' || behavior === 'cleanup-query-failure';
if (behavior === 'signal') setInterval(() => {}, 2147483647);
if (behavior === 'wrong-container') descriptor.runnerContainerId = 'f'.repeat(64);
if (behavior === 'wrong-project') descriptor.projectName = 'aster-phase1-conformance-' + 'd'.repeat(16);
if (behavior === 'wrong-image') descriptor.runnerImageId = 'sha256:' + 'd'.repeat(64);
if (behavior === 'wrong-driver') descriptor.driverSha256 = '0'.repeat(64);
if (behavior === 'wrong-runner') descriptor.runnerSha256 = '0'.repeat(64);
if (!reachesPlan) {
  writeFileSync(descriptorPath, JSON.stringify(descriptor) + '\\n');
  chmodSync(descriptorPath, 0o400);
}
const repository = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../../../..');
const wrapper = path.join(repository, '.scripts/compatibility/run-phase1-conformance.sh');
const driver = path.join(repository, '.scripts/compatibility/phase1-conformance-driver.sh');
const head = spawnSync('/usr/bin/git', ['rev-parse', 'HEAD'], { cwd: repository, encoding: 'utf8' }).stdout.trim();
const environment = {
  PATH: '/usr/bin:/bin',
  ASTER_PHASE1_BUILD_ROOT: process.env.ASTER_PHASE1_BUILD_ROOT,
  ASTER_PHASE1_HARNESS_COMMIT: head,
  ASTER_PHASE1_CONFORMANCE_ROOT: root,
  ASTER_PHASE1_CONFORMANCE_DRIVER: driver,
};
const input = JSON.stringify({
  schemaVersion: 1,
  suite: { commit: ${JSON.stringify(suiteCommit)} },
  target: { callbackUri: 'https://suite.example/callback' },
  staticClient: { id: 'oidf-basic-1', tokenEndpointAuthMethod: 'client_secret_basic', redirectUris: ['https://suite.example/callback'] },
  plans: [],
});
const adapter = spawnSync(wrapper, ['--adapter-control-id', 'oidf-basic-1'], { input, env: environment, encoding: 'utf8' });
writeFileSync(path.join(captureRoot, 'bridge-diagnostic.json'), JSON.stringify({
  status: adapter.status,
  stdout: adapter.stdout,
  stderr: adapter.stderr,
}));
if (!reachesPlan) process.exit(adapter.status === 0 ? 2 : 1);
if (adapter.status !== 0 || JSON.parse(adapter.stdout).status !== 'PASSED') process.exit(3);
const plan = spawnSync(wrapper, ['--plan-id', 'oidcc-basic-certification-test-plan'], { input, env: environment, encoding: 'utf8' });
process.exit(plan.status === 0 ? 4 : 1);
`;

const createFixture = async (behavior: Behavior): Promise<Fixture> => {
  const root = await mkdtemp('/var/tmp/henry-build/aster-conformance-lifecycle-test.');
  const repository = path.join(root, 'logto');
  const aster = path.join(root, 'aster');
  const suite = path.join(root, 'suite');
  const buildRoot = path.join(root, 'build');
  const captureRoot = path.join(root, 'capture');
  const dockerState = path.join(root, 'docker-state.json');
  const dockerLog = path.join(root, 'docker.log');
  const fakeDocker = path.join(root, 'fake-docker');
  const fakePnpm = path.join(root, 'fake-pnpm');

  await Promise.all([
    mkdir(path.join(repository, '.scripts/compatibility'), { recursive: true, mode: 0o700 }),
    mkdir(path.join(repository, 'packages/integration-tests/lib/compatibility/phase-1'), {
      recursive: true,
      mode: 0o700,
    }),
    mkdir(path.join(aster, 'compatibility'), { recursive: true, mode: 0o700 }),
    mkdir(suite, { recursive: true, mode: 0o700 }),
    mkdir(buildRoot, { mode: 0o700 }),
    mkdir(captureRoot, { mode: 0o700 }),
  ]);
  await writeFile(path.join(suite, 'pom.xml'), '<project/>\n');
  const suiteCommit = await initializeRepository(suite, suite, 'suite');
  await Promise.all([
    writeFile(path.join(aster, 'compatibility/phase-1-profile.json'), '{}\n'),
    writeFile(path.join(aster, 'compatibility/phase-1-profile.schema.json'), '{}\n'),
  ]);
  await initializeRepository(aster, 'https://github.com/qq98982/aster.git', 'aster');
  await Promise.all([
    writeFile(
      dockerState,
      JSON.stringify({
        projects: {},
        cleanupQueryFailure: behavior === 'cleanup-query-failure',
        cleanupQueriesActive: false,
        hangBuild: behavior === 'setup-signal',
        setupMarker: path.join(captureRoot, 'setup-started.log'),
      })
    ),
    writeFile(dockerLog, ''),
    writeFile(fakeDocker, fakeDockerSource(dockerState, dockerLog, suiteCommit), { mode: 0o700 }),
    writeFile(fakePnpm, '#!/bin/sh\n[ "$1" = --version ] && printf "10.15.1\\n"\nexit 0\n', {
      mode: 0o700,
    }),
  ]);
  await executeFile(process.execPath, ['--check', fakeDocker]);
  const [lifecycleSource, wrapperSource, driverSource] = await Promise.all([
    readFile(lifecycleSourcePath, 'utf8'),
    readFile(wrapperSourcePath, 'utf8'),
    readFile(driverSourcePath, 'utf8'),
  ]);
  const lifecycle = path.join(
    repository,
    '.scripts/compatibility/run-phase1-runtime-candidate-conformance.sh'
  );
  const wrapper = path.join(repository, '.scripts/compatibility/run-phase1-conformance.sh');
  const pki = path.join(repository, '.scripts/compatibility/phase1-conformance-pki.sh');
  const cli = path.join(repository, 'packages/integration-tests/lib/compatibility/phase-1/cli.js');
  const transformedLifecycle = lifecycleSource
    .replace(
      "readonly SUITE_REPOSITORY='https://gitlab.com/openid/conformance-suite.git'",
      `readonly SUITE_REPOSITORY=${JSON.stringify(suite)}`
    )
    .replace(
      "readonly SUITE_COMMIT='0dc0e3a21ec411e92c808e5b2e2258592c22b594'",
      `readonly SUITE_COMMIT=${JSON.stringify(suiteCommit)}`
    )
    .replace(
      'DOCKER_BIN="$(trusted_system_binary /usr/bin/docker)"',
      `DOCKER_BIN="$(trusted_binary ${JSON.stringify(fakeDocker)})"`
    )
    .replace(
      'PODMAN_BIN="$(trusted_system_binary /usr/bin/podman)"',
      `PODMAN_BIN="$(trusted_binary ${JSON.stringify(fakeDocker)})"`
    )
    .replace(
      'PNPM_BIN="$(trusted_binary pnpm)"',
      `PNPM_BIN="$(trusted_binary ${JSON.stringify(fakePnpm)})"`
    );
  const dockerAuthorityStart = wrapperSource.indexOf("DOCKER_PATH=''");
  const nodeAuthorityStart = wrapperSource.indexOf("NODE_PATH=''", dockerAuthorityStart);
  const transformedWrapper =
    `${wrapperSource.slice(0, dockerAuthorityStart)}DOCKER_PATH=${JSON.stringify(
      fakeDocker
    )}\n${wrapperSource.slice(nodeAuthorityStart)}`
      .replace(
        "readonly SUITE_COMMIT='0dc0e3a21ec411e92c808e5b2e2258592c22b594'",
        `readonly SUITE_COMMIT=${JSON.stringify(suiteCommit)}`
      )
      .replaceAll('"${DOCKER_PATH}"', JSON.stringify(fakeDocker));
  const runner = path.join(repository, '.scripts/compatibility/phase1-conformance-runner.mjs');
  await Promise.all([
    writeFile(lifecycle, transformedLifecycle, { mode: 0o755 }),
    writeFile(wrapper, transformedWrapper, { mode: 0o755 }),
    writeFile(
      path.join(repository, '.scripts/compatibility/phase1-conformance-driver.sh'),
      driverSource,
      {
        mode: 0o755,
      }
    ),
    writeFile(
      runner,
      "import { spawnSync } from 'node:child_process';\nimport { readFileSync } from 'node:fs';\nconst result = spawnSync(process.env.ASTER_PHASE1_CONFORMANCE_DRIVER_FILE, process.argv.slice(2), { input: readFileSync(0), encoding: 'utf8' });\nprocess.stdout.write(result.stdout ?? '');\nprocess.stderr.write(result.stderr ?? '');\nprocess.exit(result.status ?? 1);\n",
      { mode: 0o644 }
    ),
    writeFile(
      pki,
      '#!/bin/sh\nset -eu\nroot=$1\nmkdir -m 700 "$root/pki" "$root/pki/host-only" "$root/pki/aster" "$root/pki/suite"\nprintf key >"$root/pki/host-only/root-ca.key"\nprintf key >"$root/pki/aster/tls.key"\nprintf key >"$root/pki/suite/tls.key"\nprintf cert >"$root/pki/root-ca.crt"\nprintf cert >"$root/pki/aster/tls.crt"\nprintf cert >"$root/pki/suite/tls.crt"\nchmod 400 "$root/pki/host-only/root-ca.key" "$root/pki/aster/tls.key" "$root/pki/suite/tls.key"\nchmod 444 "$root/pki/root-ca.crt" "$root/pki/aster/tls.crt" "$root/pki/suite/tls.crt"\n',
      { mode: 0o755 }
    ),
    writeFile(cli, fakeCliSource(captureRoot, behavior, suiteCommit)),
    writeFile(
      path.join(repository, 'docker-compose.phase1-runtime-candidate-conformance.yml'),
      '{}\n'
    ),
    writeFile(path.join(repository, 'Dockerfile.phase1-oidf-suite'), 'FROM scratch\n'),
  ]);
  await initializeRepository(repository, 'https://github.com/qq98982/logto.git', 'fixture');

  return {
    root,
    repository,
    aster,
    buildRoot,
    runRoot: path.join(buildRoot, 'aster-phase1-runtime-candidate-conformance'),
    captureRoot,
    dockerLog,
    dockerState,
    lifecycle,
  };
};

const lifecycleEnvironment = (fixture: Fixture, image = candidateInput) => ({
  ...process.env,
  PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`,
  ASTER_PHASE1_BUILD_ROOT: fixture.buildRoot,
  ASTER_PHASE1_ASTER_ROOT: fixture.aster,
  ASTER_PHASE1_CANDIDATE_IMAGE: image,
});

const activeResources = async (fixture: Fixture): Promise<boolean> => {
  const state = JSON.parse(await readFile(fixture.dockerState, 'utf8')) as {
    projects: Record<
      string,
      { containers: Record<string, string>; network: boolean; volume: boolean }
    >;
  };

  return Object.values(state.projects).some(
    ({ containers, network, volume }) => Object.keys(containers).length > 0 || network || volume
  );
};

const runFailure = async (fixture: Fixture, image = candidateInput): Promise<void> => {
  await expect(
    executeFile(fixture.lifecycle, [], {
      cwd: fixture.repository,
      env: lifecycleEnvironment(fixture, image),
      timeout: 30_000,
    })
  ).rejects.toMatchObject({ code: 1 });
};

const waitForChildExit = async (child: ReturnType<typeof spawn>, timeoutMs: number) =>
  new Promise<{ code: number | undefined; signal: NodeJS.Signals | undefined }>(
    (resolve, reject) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        resolve({
          code: child.exitCode ?? undefined,
          signal: child.signalCode ?? undefined,
        });
        return;
      }
      const timer = setTimeout(() => {
        reject(new Error('conformance lifecycle exit timed out'));
      }, timeoutMs);
      child.once('exit', (code, signal) => {
        clearTimeout(timer);
        resolve({ code: code ?? undefined, signal: signal ?? undefined });
      });
    }
  );

const processExists = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

const interruptLifecycleAt = async (
  fixture: Fixture,
  markerName: string,
  markerContainsOwnedPid = false
): Promise<
  Readonly<{
    code: number | undefined;
    signal: NodeJS.Signals | undefined;
    ownedPid: number | undefined;
  }>
> => {
  const child = spawn(fixture.lifecycle, [], {
    cwd: fixture.repository,
    env: lifecycleEnvironment(fixture),
    stdio: 'ignore',
  });
  const marker = path.join(fixture.captureRoot, markerName);

  try {
    const startupDeadline = Date.now() + 20_000;
    while (Date.now() < startupDeadline) {
      try {
        await stat(marker);
        break;
      } catch {
        await new Promise((resolve) => {
          setTimeout(resolve, 20);
        });
      }
    }
    await stat(marker);
    let ownedPid: number | undefined;
    if (markerContainsOwnedPid) {
      const markerSource = await readFile(marker, 'utf8');
      const markerValue = markerSource.trim();
      if (!/^[1-9][0-9]*$/u.test(markerValue)) {
        throw new Error('invalid owned setup pid marker');
      }
      ownedPid = Number(markerValue);
      if (!Number.isSafeInteger(ownedPid) || !processExists(ownedPid)) {
        throw new Error('owned setup process was not alive before interruption');
      }
    }
    child.kill('SIGTERM');
    const exit = await waitForChildExit(child, 10_000);
    if (ownedPid !== undefined) {
      for (let attempt = 0; attempt < 200 && processExists(ownedPid); attempt += 1) {
        await new Promise((resolve) => {
          setTimeout(resolve, 10);
        });
      }
      if (processExists(ownedPid)) {
        throw new Error('owned setup process survived lifecycle cleanup');
      }
    }
    return { ...exit, ownedPid };
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGKILL');
      await waitForChildExit(child, 5000).catch(() => false);
    }
  }
};

afterEach(async () => {
  for (const root of await readdir('/var/tmp/henry-build')) {
    if (root.startsWith('aster-conformance-lifecycle-test.')) {
      await rm(path.join('/var/tmp/henry-build', root), { recursive: true, force: true });
    }
  }
});

describe('runtime-candidate conformance lifecycle and runner bridge', () => {
  it('rejects a mutable candidate before compose and keeps compose builds disabled', async () => {
    const fixture = await createFixture('plan-failure');

    await runFailure(fixture, 'candidate:latest');
    const log = await readFile(fixture.dockerLog, 'utf8');

    expect(log).not.toContain('"up"');
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('bridges adapter control, preserves plan rejection, and removes private material', async () => {
    const fixture = await createFixture('plan-failure');

    await runFailure(fixture);
    const [log, roots] = await Promise.all([
      readFile(fixture.dockerLog, 'utf8'),
      readFile(path.join(fixture.captureRoot, 'run-roots.log'), 'utf8'),
    ]);
    const bridgeDiagnostic = await readFile(
      path.join(fixture.captureRoot, 'bridge-diagnostic.json'),
      'utf8'
    );
    const captureEntries = await readdir(fixture.captureRoot);
    const descriptorName = captureEntries.find((name) => name.endsWith('.json'));

    expect(descriptorName).toBeDefined();
    const descriptorPath = path.join(fixture.captureRoot, descriptorName ?? 'missing');
    const descriptor = JSON.parse(await readFile(descriptorPath, 'utf8')) as Record<
      string,
      unknown
    >;
    const serialized = JSON.stringify(descriptor);
    const runRoot = roots.trim();

    expect(Object.keys(descriptor)).toEqual([
      'schemaVersion',
      'kind',
      'projectName',
      'runnerContainerId',
      'suiteCommit',
      'suiteImageId',
      'candidateImageId',
      'runnerImageId',
      'driverPath',
      'driverBlob',
      'driverSha256',
      'runnerPath',
      'runnerBlob',
      'runnerSha256',
      'engineSocket',
      'topologyId',
    ]);
    expect(serialized).not.toMatch(/password|secret|token|private.?key|credential/iu);
    expect(log).toContain('"--no-build"');
    expect(log).toContain('"config","--quiet"');
    expect(log).toContain('"build"');
    expect(log).toContain('aster-phase1-conformance-podman-graph');
    expect(log).toContain('"system","service"');
    expect(log).toContain('"image","save"');
    expect(log).toContain('"load","--input"');
    expect({ log, bridgeDiagnostic }).toEqual(
      expect.objectContaining({ log: expect.stringContaining('"exec","--interactive"') })
    );
    expect(log).not.toContain('/dev/shm');
    expect(log).not.toContain('/var/lib/docker');
    expect(await activeResources(fixture)).toBe(false);
    await expect(stat(runRoot)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(stat(path.join(runRoot, 'pki/host-only/root-ca.key'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('preserves recovery material when cleanup engine queries fail', async () => {
    const fixture = await createFixture('cleanup-query-failure');

    await runFailure(fixture);
    expect(await activeResources(fixture)).toBe(true);
    const runs = await readdir(fixture.runRoot);

    expect(runs).toHaveLength(1);
    const preservedRun = path.join(fixture.runRoot, runs[0] ?? 'missing');
    const [composeMetadata, caKeyMetadata] = await Promise.all([
      stat(path.join(preservedRun, 'compose.env')),
      stat(path.join(preservedRun, 'pki/host-only/root-ca.key')),
    ]);

    expect(composeMetadata.mode % 0o1000).toBe(0o400);
    expect(caKeyMetadata.mode % 0o1000).toBe(0o400);
  });

  it.each([
    'wrong-container',
    'wrong-project',
    'wrong-image',
    'wrong-driver',
    'wrong-runner',
  ] as const)('fails closed for %s descriptor or runtime identity', async (behavior) => {
    const fixture = await createFixture(behavior);

    await runFailure(fixture);
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('interrupts an owned setup process group and removes private engine state', async () => {
    const fixture = await createFixture('setup-signal');
    const exit = await interruptLifecycleAt(fixture, 'setup-started.log', true);

    expect(exit.code === 143 || exit.signal === 'SIGTERM').toBe(true);
    expect(exit.ownedPid).toBeGreaterThan(0);
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('cleans the owned project and run directory on TERM', async () => {
    const fixture = await createFixture('signal');
    const exit = await interruptLifecycleAt(fixture, 'started.log');

    expect(exit.code === 143 || exit.signal === 'SIGTERM').toBe(true);
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('uses fresh projects on repeated runs and inherits no prior resources', async () => {
    const fixture = await createFixture('plan-failure');

    await runFailure(fixture);
    await runFailure(fixture);
    const startedSource = await readFile(path.join(fixture.captureRoot, 'started.log'), 'utf8');
    const started = startedSource.trim().split('\n');

    expect(started).toHaveLength(2);
    expect(new Set(started).size).toBe(2);
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });
});

/* eslint-enable max-lines, complexity, no-await-in-loop, no-template-curly-in-string, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation */
