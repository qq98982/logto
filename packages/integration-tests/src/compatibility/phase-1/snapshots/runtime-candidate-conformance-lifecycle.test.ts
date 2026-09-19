/* eslint-disable max-lines, complexity, no-await-in-loop, no-template-curly-in-string, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-let, @silverhand/fp/no-mutation -- This process fixture mutates isolated process state and intentionally embeds literal shell interpolation syntax. */
import { execFile, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  truncate,
  writeFile,
} from 'node:fs/promises';
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
const candidateImageId = `sha256:${'c'.repeat(64)}`;
const exportName = 'phase-1-conformance.json';
const maximumCandidateArchiveSize = 32 * 1024 * 1024 * 1024;

type Behavior =
  | 'success'
  | 'cleanup-run-removal-failure'
  | 'cleanup-query-failure'
  | 'fixture-cleanup-failure'
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
  candidateArchive: string;
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
if (args[0] === 'pull') process.exit(0);
if (args[0] === 'load') {
  const state = readState();
  state.privateCandidateImageId = state.archiveLoadedImageId;
  writeState(state);
  process.exit(0);
}
if (args[0] === 'ps' && args.length === 1) {
  const socket = (process.env.DOCKER_HOST ?? '').replace(/^unix:\\/\\//, '');
  process.exit(socket && fs.existsSync(socket) ? 0 : 1);
}
if (args[0] === 'compose' && args.includes('version')) process.exit(0);
if (args[0] === 'image' && args[1] === 'inspect') {
  const input = args.at(-1);
  const format = args[args.indexOf('--format') + 1] ?? '';
  const state = readState();
  const privateEngine = (process.env.DOCKER_HOST ?? '').startsWith('unix://');
  let id = imageIds.candidate;
  if (input.includes('postgres')) id = imageIds.postgres;
  else if (input.includes('mongo')) id = imageIds.mongo;
  else if (input.includes('nginx')) id = imageIds.nginx;
  else if (input.includes('node')) id = imageIds.runner;
  else if (input === imageIds.suite) id = imageIds.suite;
  else if (privateEngine && /^sha256:[0-9a-f]{64}$/.test(input)) {
    if (state.privateCandidateImageId !== input) process.exit(1);
    id = input;
  }
  if (format.includes('maven-resolution')) {
    process.stdout.write(id + '|${suiteCommit}|source-pom-not-fully-offline-locked');
  } else process.stdout.write(id);
  process.exit(0);
}
if (args[0] === 'image' && args[1] === 'save') {
  fs.writeFileSync(args[args.indexOf('--output') + 1], 'candidate-image-archive');
  process.exit(0);
}
if (args[0] === 'image' && args[1] === 'exists') {
  process.exit(readState().privateCandidateImageId === args[2] ? 0 : 1);
}
if (args[0] === 'rmi') {
  const state = readState();
  if (state.privateCandidateImageId !== args[1]) process.exit(1);
  state.privateCandidateImageId = null;
  writeState(state);
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
    const topology = state.projects[project] ?? {
      environment,
      containers: {},
      network: true,
      volume: true,
    };
    topology.environment = environment;
    topology.network = true;
    topology.volume = true;
    for (const service of serviceNames.filter((candidate) => args.includes(candidate))) {
      topology.containers[idFor(project, service)] = service;
    }
    state.projects[project] = topology;
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
  const hasUser = args[2] === '--user';
  if (hasUser && args[3] !== process.getuid() + ':' + process.getgid()) process.exit(1);
  const containerIndex = hasUser ? 4 : 2;
  const containerId = args[containerIndex];
  let environment;
  let service;
  for (const value of Object.values(state.projects)) {
    if (value.containers[containerId]) {
      environment = value.environment;
      service = value.containers[containerId];
    }
  }
  if (!environment) process.exit(1);
  const fixtureCommandIndex = args.indexOf('/usr/local/bin/aster-admin', containerIndex + 1);
  if (service === 'candidate-fixture-coordinator' && fixtureCommandIndex >= 0 &&
      args[fixtureCommandIndex + 1] === 'fixture' && args[fixtureCommandIndex + 2] === 'apply') {
    if (!hasUser) process.exit(1);
    const fixturePrefix = args.slice(containerIndex + 1, fixtureCommandIndex);
    if (JSON.stringify(fixturePrefix) !== JSON.stringify([
      '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin',
      'ASTER_FIXTURE_SOCKET=/run/aster-fixture/coordinator.sock',
    ])) process.exit(1);
    const descriptor = JSON.parse(fs.readFileSync(0, 'utf8'));
    fs.appendFileSync(logPath, JSON.stringify(['fixture-operation', descriptor.operation]) + '\\n');
    if (descriptor.operation === 'provision') {
      if (descriptor.recipe !== 'none' && state.keyOnlyBaseline === true) process.exit(1);
      state.fixtureProvisioned = true;
      writeState(state);
      process.stdout.write(JSON.stringify({
        schemaVersion: 1,
        operation: 'provision',
        public: {
          schemaVersion: 1,
          recipe: descriptor.recipe,
          allocations: descriptor.recipe === 'none' ? [] : [{ allocationId: descriptor.allocationId }],
        },
      }));
      process.exit(0);
    }
    if (descriptor.operation === 'cleanup' && state.fixtureProvisioned === true) {
      if (state.fixtureCleanupFailure === true && descriptor.recipe === 'oidfConformance') process.exit(1);
      if (descriptor.recipe === 'none') state.keyOnlyBaseline = false;
      state.fixtureProvisioned = false;
      writeState(state);
      process.stdout.write(JSON.stringify({ schemaVersion: 1, operation: 'cleanup', ok: true }));
      process.exit(0);
    }
    process.exit(1);
  }
  if (args[3] !== '/opt/aster/phase1-conformance-driver.sh') process.exit(1);
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
writeFileSync(path.join(captureRoot, 'public-environment.txt'), [
  process.env.ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST ?? '',
  process.env.ASTER_PHASE1_CANDIDATE_ARCHIVE ?? '',
  process.env.ASTER_PHASE1_CANDIDATE_IMAGE_ID ?? '',
].join('|'));
const descriptor = JSON.parse(readFileSync(descriptorPath, 'utf8'));
copyFileSync(descriptorPath, path.join(captureRoot, descriptor.projectName + '.json'));
appendFileSync(path.join(captureRoot, 'run-roots.log'), path.dirname(root) + '\\n');
appendFileSync(path.join(captureRoot, 'started.log'), descriptor.projectName + '\\n');
const behavior = ${JSON.stringify(behavior)};
const reachesPlan = behavior === 'success' || behavior === 'cleanup-run-removal-failure' ||
  behavior === 'plan-failure' ||
  behavior === 'cleanup-query-failure' || behavior === 'fixture-cleanup-failure';
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
if (behavior === 'success' || behavior === 'cleanup-run-removal-failure') {
  const artifact = JSON.stringify({
    schemaVersion: 1, mode: 'runtime-candidate', sanitizerSuccess: true,
    provenance: { imageDigest: process.env.ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST },
    adapterControls: [{ id: 'oidf-basic-1' }, { id: 'oidf-basic-2' }, { id: 'oidf-post-1' }],
    officialResultIds: ['basic-result-1', 'config-result-1'],
    planResults: [
      { planId: 'oidcc-basic-certification-test-plan', resultId: 'basic-result-1' },
      { planId: 'oidcc-config-certification-test-plan', resultId: 'config-result-1' },
    ],
  }, null, 2) + '\\n';
  const evidence = path.join(process.env.ASTER_PHASE1_EVIDENCE_DIR, 'phase-1-conformance.json');
  writeFileSync(evidence, artifact, { flag: 'wx', mode: 0o400 });
  writeFileSync(path.join(captureRoot, 'expected-artifact.json'), artifact);
  if (behavior === 'cleanup-run-removal-failure') chmodSync(path.dirname(path.dirname(root)), 0o500);
  process.exit(0);
}
const plan = spawnSync(wrapper, ['--plan-id', 'oidcc-basic-certification-test-plan'], { input, env: environment, encoding: 'utf8' });
writeFileSync(path.join(captureRoot, 'basic-diagnostic.json'), JSON.stringify({
  invoked: true,
  status: plan.status,
  stdout: plan.stdout,
  stderr: plan.stderr,
}));
process.exit(plan.status === 0 ? 4 : 1);
`;

const createFixture = async (behavior: Behavior): Promise<Fixture> => {
  const root = await mkdtemp('/var/tmp/henry-build/aster-conformance-lifecycle-test.');
  const repository = path.join(root, 'logto');
  const aster = path.join(root, 'aster');
  const suite = path.join(root, 'suite');
  const buildRoot = path.join(root, 'build');
  const captureRoot = path.join(root, 'capture');
  const candidateArchive = path.join(buildRoot, 'candidate-image.tar');
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
    writeFile(
      path.join(aster, 'compatibility/phase-1-profile.json'),
      '{"fixtures":{},"conformance":{}}\n'
    ),
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
        privateCandidateImageId: null,
        archiveLoadedImageId: candidateImageId,
        hangBuild: behavior === 'setup-signal',
        setupMarker: path.join(captureRoot, 'setup-started.log'),
        fixtureProvisioned: false,
        fixtureCleanupFailure: behavior === 'fixture-cleanup-failure',
        keyOnlyBaseline: true,
      })
    ),
    writeFile(dockerLog, ''),
    writeFile(candidateArchive, 'candidate-image-archive', { mode: 0o600 }),
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
  const artifactContract = path.join(
    repository,
    'packages/integration-tests/lib/compatibility/phase-1/artifact-contract.js'
  );
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
      `const planId = process.argv[3];
process.stdout.write(JSON.stringify({
  schemaVersion: 1,
  kind: 'phase1-conformance-official-failure-terminal',
  suiteCommit: ${JSON.stringify(suiteCommit)},
  planId,
  module: null,
  status: 'FAILED',
  result: 'FAILED',
  failureCategory: 'suite-api',
}));
process.exit(1);
`,
      { mode: 0o644 }
    ),
    writeFile(
      pki,
      '#!/bin/sh\nset -eu\nroot=$1\nmkdir -m 700 "$root/pki" "$root/pki/host-only" "$root/pki/aster" "$root/pki/suite"\nprintf key >"$root/pki/host-only/root-ca.key"\nprintf key >"$root/pki/aster/tls.key"\nprintf key >"$root/pki/suite/tls.key"\nprintf cert >"$root/pki/root-ca.crt"\nprintf cert >"$root/pki/aster/tls.crt"\nprintf cert >"$root/pki/suite/tls.crt"\nchmod 400 "$root/pki/host-only/root-ca.key" "$root/pki/aster/tls.key" "$root/pki/suite/tls.key"\nchmod 444 "$root/pki/root-ca.crt" "$root/pki/aster/tls.crt" "$root/pki/suite/tls.crt"\n',
      { mode: 0o755 }
    ),
    writeFile(cli, fakeCliSource(captureRoot, behavior, suiteCommit)),
    writeFile(
      artifactContract,
      `export const parseStrictPhase1ArtifactJson = (bytes) => {
  if (bytes.length < 1 || bytes.length > 1048576) throw new Error('invalid size');
  return JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes));
};
export const assertPhase1PublicArtifactValue = (value) => {
  if (JSON.stringify(value).includes('fixture-secret')) throw new Error('private data');
};\n`
    ),
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
    candidateArchive,
    dockerLog,
    dockerState,
    lifecycle,
  };
};

type CandidateChannel = Readonly<{
  image?: string;
  archive?: string;
  imageId?: string;
}>;
const systemCandidateChannel: CandidateChannel = Object.freeze({ image: candidateInput });
const candidateInputEnvironmentNames = new Set([
  'ASTER_PHASE1_CANDIDATE_IMAGE',
  'ASTER_PHASE1_CANDIDATE_ARCHIVE',
  'ASTER_PHASE1_CANDIDATE_IMAGE_ID',
  'ASTER_PHASE1_CONFORMANCE_EXPORT_DIR',
]);

const lifecycleEnvironment = (
  fixture: Fixture,
  candidate: CandidateChannel = systemCandidateChannel,
  exportDirectory?: string
): NodeJS.ProcessEnv => {
  const inheritedEnvironment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !candidateInputEnvironmentNames.has(name))
  );
  const environment: NodeJS.ProcessEnv = {
    ...inheritedEnvironment,
    PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`,
    ASTER_PHASE1_BUILD_ROOT: fixture.buildRoot,
    ASTER_PHASE1_ASTER_ROOT: fixture.aster,
  };

  if (candidate.image !== undefined) {
    environment.ASTER_PHASE1_CANDIDATE_IMAGE = candidate.image;
  }
  if (candidate.archive !== undefined) {
    environment.ASTER_PHASE1_CANDIDATE_ARCHIVE = candidate.archive;
  }
  if (candidate.imageId !== undefined) {
    environment.ASTER_PHASE1_CANDIDATE_IMAGE_ID = candidate.imageId;
  }
  if (exportDirectory !== undefined) {
    environment.ASTER_PHASE1_CONFORMANCE_EXPORT_DIR = exportDirectory;
  }

  return environment;
};

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

const runFailure = async (
  fixture: Fixture,
  candidate: CandidateChannel = systemCandidateChannel,
  exportDirectory?: string
): Promise<void> => {
  await expect(
    executeFile(fixture.lifecycle, [], {
      cwd: fixture.repository,
      env: lifecycleEnvironment(fixture, candidate, exportDirectory),
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
  it('exports only the original sanitized JSON bytes after successful cleanup', async () => {
    const fixture = await createFixture('success');
    const output = path.join(fixture.buildRoot, 'published');
    await mkdir(output, { mode: 0o700 });

    const { stdout } = await executeFile(fixture.lifecycle, [], {
      cwd: fixture.repository,
      env: lifecycleEnvironment(fixture, systemCandidateChannel, output),
      timeout: 30_000,
    });
    const [expected, actual, metadata] = await Promise.all([
      readFile(path.join(fixture.captureRoot, 'expected-artifact.json')),
      readFile(path.join(output, exportName)),
      stat(path.join(output, exportName)),
    ]);

    expect(actual.equals(expected)).toBe(true);
    expect(await readdir(output)).toEqual([exportName]);
    expect(metadata.mode % 0o1000).toBe(0o600);
    expect(metadata.nlink).toBe(1);
    expect(stdout).toContain(
      `ASTER_PHASE1_CONFORMANCE_EXPORT_SHA256=${createHash('sha256').update(expected).digest('hex')}`
    );
    expect(stdout).toContain(`ASTER_PHASE1_CONFORMANCE_EXPORT_BYTES=${expected.length}`);
    expect(stdout).toContain('Aster runtime candidate conformance gate passed');
    expect(actual.toString('utf8')).not.toMatch(/cookie-value|private-key-value|fixture-secret/iu);
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('does not publish when conformance or cleanup fails', async () => {
    for (const behavior of ['plan-failure', 'success'] as const) {
      const fixture = await createFixture(behavior);
      const output = path.join(fixture.buildRoot, 'published');
      await mkdir(output, { mode: 0o700 });
      if (behavior === 'success') {
        const state = JSON.parse(await readFile(fixture.dockerState, 'utf8')) as Record<
          string,
          unknown
        >;
        state.fixtureCleanupFailure = true;
        await writeFile(fixture.dockerState, JSON.stringify(state));
      }

      await runFailure(fixture, systemCandidateChannel, output);
      expect(await readdir(output)).toEqual([]);
    }
  });

  it('withdraws a published result if run directory cleanup fails', async () => {
    const fixture = await createFixture('cleanup-run-removal-failure');
    const output = path.join(fixture.buildRoot, 'published');
    await mkdir(output, { mode: 0o700 });

    try {
      await expect(
        executeFile(fixture.lifecycle, [], {
          cwd: fixture.repository,
          env: lifecycleEnvironment(fixture, systemCandidateChannel, output),
          timeout: 30_000,
        })
      ).rejects.toMatchObject({
        code: 1,
        stdout: expect.not.stringContaining('Aster runtime candidate conformance gate passed'),
      });
      expect(await readdir(output)).toEqual([]);
    } finally {
      await chmod(fixture.runRoot, 0o700);
    }
  });

  it.each([
    'symlink',
    'occupied',
    'occupied-link',
    'relative',
    'outside',
    'run-root',
    'world-readable',
  ] as const)('rejects %s export directory without publishing', async (kind) => {
    const fixture = await createFixture('success');
    const output = path.join(fixture.buildRoot, 'published');
    await mkdir(output, { mode: 0o700 });
    let selected = output;
    switch (kind) {
      case 'symlink': {
        selected = path.join(fixture.buildRoot, 'linked');
        await symlink(output, selected);
        break;
      }
      case 'occupied': {
        await writeFile(path.join(output, exportName), 'existing', { mode: 0o400 });
        break;
      }
      case 'occupied-link': {
        await symlink(fixture.candidateArchive, path.join(output, exportName));
        break;
      }
      case 'relative': {
        selected = 'published';
        break;
      }
      case 'outside': {
        selected = fixture.captureRoot;
        break;
      }
      case 'run-root': {
        selected = fixture.runRoot;
        break;
      }
      case 'world-readable': {
        await chmod(output, 0o755);
        break;
      }
    }

    await runFailure(fixture, systemCandidateChannel, selected);
    expect(await readdir(output)).toEqual(
      kind === 'occupied' || kind === 'occupied-link' ? [exportName] : []
    );
    if (kind === 'occupied') {
      expect(await readFile(path.join(output, exportName), 'utf8')).toBe('existing');
    } else if (kind === 'occupied-link') {
      expect(await readFile(fixture.candidateArchive, 'utf8')).toBe('candidate-image-archive');
    }
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('rejects a mutable candidate before compose and keeps compose builds disabled', async () => {
    const fixture = await createFixture('plan-failure');

    await runFailure(fixture, { image: 'candidate:latest' });
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
    const basicDiagnostic = JSON.parse(
      await readFile(path.join(fixture.captureRoot, 'basic-diagnostic.json'), 'utf8')
    ) as { invoked: boolean; status: number | undefined; stdout: string; stderr: string };
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
    expect(basicDiagnostic).toMatchObject({ invoked: true, status: 1, stderr: '' });
    expect(JSON.parse(basicDiagnostic.stdout)).toMatchObject({
      planId: 'oidcc-basic-certification-test-plan',
      status: 'FAILED',
      failureCategory: 'suite-api',
    });
    const fixtureOperations = [
      ...log.matchAll(/\["fixture-operation","(provision|cleanup)"\]/gu),
    ].map((match) => match[1]);
    const firstRemoveIndex = log.indexOf('["rm","--force"');

    expect(fixtureOperations).toEqual(['provision', 'cleanup', 'provision', 'cleanup']);
    expect(firstRemoveIndex).toBeGreaterThan(log.lastIndexOf('["fixture-operation","cleanup"]'));
    expect(log).not.toContain('/dev/shm');
    expect(log).not.toContain('/var/lib/docker');
    expect(await activeResources(fixture)).toBe(false);
    await expect(stat(runRoot)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(stat(path.join(runRoot, 'pki/host-only/root-ca.key'))).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('loads a caller-owned private archive, reaches Basic fail-closed, and preserves the archive', async () => {
    const fixture = await createFixture('plan-failure');
    await chmod(fixture.candidateArchive, 0o400);
    const before = await stat(fixture.candidateArchive);

    await runFailure(fixture, {
      image: '',
      archive: fixture.candidateArchive,
      imageId: candidateImageId,
    });
    const [log, after, archiveSource, publicEnvironment, basicDiagnosticSource] = await Promise.all(
      [
        readFile(fixture.dockerLog, 'utf8'),
        stat(fixture.candidateArchive),
        readFile(fixture.candidateArchive, 'utf8'),
        readFile(path.join(fixture.captureRoot, 'public-environment.txt'), 'utf8'),
        readFile(path.join(fixture.captureRoot, 'basic-diagnostic.json'), 'utf8'),
      ]
    );
    const captureEntries = await readdir(fixture.captureRoot);
    const descriptorName = captureEntries.find(
      (name) => name.startsWith('aster-phase1-conformance-') && name.endsWith('.json')
    );
    const descriptor = JSON.parse(
      await readFile(path.join(fixture.captureRoot, descriptorName ?? 'missing'), 'utf8')
    ) as Record<string, unknown>;
    const serializedDescriptor = JSON.stringify(descriptor);

    expect(log).toContain(`"load","--input","${fixture.candidateArchive}"`);
    expect(log).not.toContain('"image","save"');
    expect(log).toContain('"exec","--interactive"');
    expect(descriptor.candidateImageId).toBe(candidateImageId);
    expect(serializedDescriptor).not.toContain(fixture.candidateArchive);
    expect(serializedDescriptor).not.toMatch(/candidateArchive|archiveHash/iu);
    expect(publicEnvironment).toBe(`${candidateImageId}||`);
    const basicDiagnostic = JSON.parse(basicDiagnosticSource) as {
      invoked: boolean;
      status: number;
      stdout: string;
      stderr: string;
    };

    expect(basicDiagnostic).toMatchObject({ invoked: true, status: 1, stderr: '' });
    expect(JSON.parse(basicDiagnostic.stdout)).toMatchObject({
      planId: 'oidcc-basic-certification-test-plan',
      status: 'FAILED',
      failureCategory: 'suite-api',
    });
    expect(after.mode % 0o1000).toBe(before.mode % 0o1000);
    expect(after.size).toBe(before.size);
    expect(archiveSource).toBe('candidate-image-archive');
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('does not let a cached expected image conceal a mismatched archive', async () => {
    const fixture = await createFixture('plan-failure');
    const state = JSON.parse(await readFile(fixture.dockerState, 'utf8')) as Record<
      string,
      unknown
    >;
    state.privateCandidateImageId = candidateImageId;
    state.archiveLoadedImageId = `sha256:${'d'.repeat(64)}`;
    await writeFile(fixture.dockerState, JSON.stringify(state));

    await runFailure(fixture, {
      archive: fixture.candidateArchive,
      imageId: candidateImageId,
    });
    const log = await readFile(fixture.dockerLog, 'utf8');

    expect(log).toContain(`"image","exists","${candidateImageId}"`);
    expect(log).toContain(`"rmi","${candidateImageId}"`);
    expect(log).toContain(`"load","--input","${fixture.candidateArchive}"`);
    expect(log).not.toContain('"up"');
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
  });

  it('opens a caller archive aliased to the fixed lock path without truncating it', async () => {
    const fixture = await createFixture('plan-failure');
    const lockArchive = path.join(fixture.buildRoot, 'aster-phase1-conformance-podman.lock');
    const source = 'candidate-image-archive-at-lock-path';
    await writeFile(lockArchive, source, { mode: 0o600 });

    await runFailure(fixture, { archive: lockArchive, imageId: candidateImageId });
    const [afterSource, metadata] = await Promise.all([
      readFile(lockArchive, 'utf8'),
      stat(lockArchive),
    ]);

    expect(afterSource).toBe(source);
    expect(metadata.mode % 0o1000).toBe(0o600);
  });

  it.each([
    {
      name: 'wrong mode',
      prepare: async (fixture: Fixture) => {
        await chmod(fixture.candidateArchive, 0o640);
        return { archive: fixture.candidateArchive, imageId: candidateImageId };
      },
    },
    {
      name: 'relative path',
      prepare: async (fixture: Fixture) => ({
        archive: path.relative(fixture.repository, fixture.candidateArchive),
        imageId: candidateImageId,
      }),
    },
    {
      name: 'path outside build root',
      prepare: async (fixture: Fixture) => {
        const outsideArchive = path.join(fixture.root, 'outside-candidate.tar');
        await writeFile(outsideArchive, 'candidate-image-archive', { mode: 0o600 });
        return { archive: outsideArchive, imageId: candidateImageId };
      },
    },
    {
      name: 'symlink',
      prepare: async (fixture: Fixture) => {
        const archiveLink = path.join(fixture.buildRoot, 'candidate-image-link.tar');
        await symlink(fixture.candidateArchive, archiveLink);
        return { archive: archiveLink, imageId: candidateImageId };
      },
    },
    {
      name: 'wrong gid',
      prepare: async (fixture: Fixture) => {
        await executeFile('/usr/bin/podman', ['unshare', 'chown', '0:1', fixture.candidateArchive]);
        const metadata = await stat(fixture.candidateArchive);
        if (metadata.uid !== process.getuid?.() || metadata.gid === process.getgid?.()) {
          throw new Error('failed to construct deterministic wrong-gid archive');
        }
        return { archive: fixture.candidateArchive, imageId: candidateImageId };
      },
    },
    {
      name: 'oversize sparse file',
      prepare: async (fixture: Fixture) => {
        await truncate(fixture.candidateArchive, maximumCandidateArchiveSize + 1);
        return { archive: fixture.candidateArchive, imageId: candidateImageId };
      },
    },
    {
      name: 'missing image ID pair',
      prepare: async (fixture: Fixture) => ({ archive: fixture.candidateArchive }),
    },
    {
      name: 'missing archive pair',
      prepare: async () => ({ imageId: candidateImageId }),
    },
    {
      name: 'both input channels',
      prepare: async (fixture: Fixture) => ({
        image: candidateInput,
        archive: fixture.candidateArchive,
        imageId: candidateImageId,
      }),
    },
    {
      name: 'wrong image ID',
      prepare: async (fixture: Fixture) => ({
        archive: fixture.candidateArchive,
        imageId: `sha256:${'d'.repeat(64)}`,
      }),
    },
  ])('fails closed before compose for archive input with $name', async ({ prepare }) => {
    const fixture = await createFixture('plan-failure');
    const candidate = await prepare(fixture);

    await runFailure(fixture, candidate);
    const log = await readFile(fixture.dockerLog, 'utf8');

    expect(log).not.toContain('"up"');
    expect(await activeResources(fixture)).toBe(false);
    expect(await readdir(fixture.runRoot)).toEqual([]);
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

  it('removes generated OIDF secrets even when fixture cleanup fails', async () => {
    const fixture = await createFixture('fixture-cleanup-failure');

    await runFailure(fixture);
    expect(await activeResources(fixture)).toBe(false);
    const runs = await readdir(fixture.runRoot);

    expect(runs).toHaveLength(1);
    const preservedRun = path.join(fixture.runRoot, runs[0] ?? 'missing');
    for (const relative of [
      'secrets/phase1-user',
      'secrets/oidf-basic-1',
      'secrets/oidf-basic-2',
      'secrets/oidf-post-1',
      'secrets/oidf-conformance-public.json',
      'fixture/oidf-conformance-provision.json',
      'fixture/oidf-conformance-provision-response.json',
      'fixture/oidf-conformance-cleanup.json',
      'fixture/oidf-conformance-cleanup-response.json',
      'fixture/baseline-release-provision.json',
      'fixture/baseline-release-provision-response.json',
      'fixture/baseline-release-cleanup.json',
      'fixture/baseline-release-cleanup-response.json',
    ]) {
      await expect(stat(path.join(preservedRun, relative))).rejects.toMatchObject({
        code: 'ENOENT',
      });
    }
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
