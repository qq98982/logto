/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types -- This contract test keeps the complete security-sensitive runner and cleanup retry harnesses together for source and behavioral auditing. */
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';

const repositoryRoot = path.resolve(process.cwd(), '../..');
const runnerPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase2-client-credentials.sh'
);
const buildRoot = '/var/tmp/henry-build';

let source = '';
let temporaryRoot = '';

const runBash = async (scriptPath: string): Promise<Readonly<{ code: number; stderr: string }>> =>
  new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/bash', [scriptPath], {
      cwd: repositoryRoot,
      env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    const stderr: Buffer[] = [];
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (signal !== null || code === null) {
        reject(new Error('cleanup harness terminated by signal'));
        return;
      }
      resolve({ code, stderr: Buffer.concat(stderr).toString('utf8') });
    });
  });

const grepMatches = async (pattern: string, line: string): Promise<boolean> =>
  new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/grep', ['-E', pattern], {
      cwd: repositoryRoot,
      env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      stdio: ['pipe', 'ignore', 'ignore'],
    });
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (signal !== null || (code !== 0 && code !== 1)) {
        reject(new Error('grep allowlist check failed'));
        return;
      }
      resolve(code === 0);
    });
    child.stdin.end(`${line}\n`);
  });

const runEmbeddedNode = async (
  program: string,
  arguments_: readonly string[]
): Promise<Readonly<{ code: number; stderr: string }>> =>
  new Promise((resolve, reject) => {
    const child = spawn('/usr/bin/node', ['--input-type=module', '-', ...arguments_], {
      cwd: repositoryRoot,
      env: { LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      stdio: ['pipe', 'ignore', 'pipe'],
    });
    const stderr: Buffer[] = [];
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code, signal) => {
      if (signal !== null || code === null) {
        reject(new Error('embedded Node harness terminated by signal'));
        return;
      }
      resolve({ code, stderr: Buffer.concat(stderr).toString('utf8') });
    });
    child.stdin.end(program);
  });

const embeddedNodeProgram = (anchor: string): string => {
  const anchorIndex = source.indexOf(anchor);
  const openingIndex = source.indexOf("<<'NODE'", anchorIndex);
  const programStart = source.indexOf('\n', openingIndex) + 1;
  const programEnd = source.indexOf('\nNODE\n', programStart);
  if (anchorIndex < 0 || openingIndex < 0 || programStart === 0 || programEnd < 0) {
    throw new Error(`embedded Node program is missing after ${anchor}`);
  }
  return source.slice(programStart, programEnd);
};

const writeFakeLauncher = async (
  directory: string,
  behavior: 'success' | 'differential-failure' | 'replace-oracle' | 'extra-artifact'
): Promise<Readonly<{ launcherPath: string; tracePath: string }>> => {
  const launcherPath = path.join(directory, 'fake-launcher.mjs');
  const tracePath = path.join(directory, 'launcher.trace');
  const launcher = `
import { appendFile, chmod, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
const behavior = ${JSON.stringify(behavior)};
const tracePath = ${JSON.stringify(tracePath)};
const option = (command, name) => command[command.indexOf(name) + 1];
export const launchPhase2Batch = async (commands) => {
  const command = commands[0];
  const mode = command[0];
  await appendFile(tracePath, JSON.stringify(command) + '\\n', { mode: 0o600 });
  if (behavior === 'differential-failure' && mode === 'differential') return 1;
  const output = option(command, '--output');
  await writeFile(output, mode.padEnd(32, '.'), { mode: 0o600 });
  await chmod(output, 0o600);
  if (mode === 'differential' && behavior === 'replace-oracle') {
    const oracle = option(command, '--oracle-evidence');
    const replacement = oracle + '.replacement';
    await writeFile(replacement, 'replaced-oracle-artifact.......', { mode: 0o600 });
    await chmod(replacement, 0o600);
    await rename(replacement, oracle);
  }
  if (mode === 'differential' && behavior === 'extra-artifact') {
    const temporaryRoot = option(command, '--temp-root');
    await writeFile(path.join(temporaryRoot, 'unexpected.json'), '{}', { mode: 0o600 });
  }
  return 0;
};
export const diagnosticForPhase2Batch = (error) =>
  'Phase 2 client credentials batch failed (' + error.message + ').\\n';
`;
  await writeFile(launcherPath, launcher, { mode: 0o600 });
  return { launcherPath, tracePath };
};

const runEvidenceSequence = async (
  behavior: 'success' | 'differential-failure' | 'replace-oracle' | 'extra-artifact'
): Promise<
  Readonly<{ code: number; stderr: string; commands: ReadonlyArray<readonly string[]> }>
> => {
  const directory = await mkdtemp(path.join(temporaryRoot, 'evidence-sequence-'));
  const evidenceDirectory = path.join(directory, 'evidence');
  await mkdir(evidenceDirectory, { mode: 0o700 });
  const { launcherPath, tracePath } = await writeFakeLauncher(directory, behavior);
  const names = [
    'phase-2-client-credentials-oracle.json',
    'phase-2-client-credentials-differential.json',
    'phase-2-client-credentials-candidate-invariants.json',
  ] as const;
  const result = await runEmbeddedNode(embeddedNodeProgram("failure_stage='evidence-sequence'"), [
    launcherPath,
    path.join(directory, 'profile.json'),
    path.join(directory, 'schema.json'),
    path.join(directory, 'oracle-target.json'),
    path.join(directory, 'candidate-target.json'),
    ...names.map((name) => path.join(evidenceDirectory, name)),
    evidenceDirectory,
  ]);
  const trace = await readFile(tracePath, 'utf8');
  return {
    ...result,
    commands: trace
      .trim()
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as readonly string[]),
  };
};

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

const evidenceTopology = (kind: 'oracle' | 'candidate') => ({
  sourceCommit: `${kind}-commit`,
  imageDigest: `${kind}-image`,
  topology: { primaryRole: `${kind}-primary-core`, foreignRole: `${kind}-foreign-core` },
  drivers: {
    state: { role: 'state-driver', sha256: `${kind}-state-sha` },
    ...(kind === 'candidate'
      ? {
          fixture: { role: 'fixture-executable', sha256: 'fixture-sha' },
          invariant: { role: 'invariant-driver', sha256: 'invariant-sha' },
        }
      : {}),
  },
});

const runEvidenceValidation = async (
  scenarioCount: number,
  invariantCount: number,
  controlCount = 18
): Promise<Readonly<{ code: number; stderr: string }>> => {
  const directory = await mkdtemp(path.join(temporaryRoot, 'evidence-validation-'));
  const profilePath = path.join(directory, 'profile.json');
  const schemaPath = path.join(directory, 'schema.json');
  const oraclePath = path.join(directory, 'oracle.json');
  const differentialPath = path.join(directory, 'differential.json');
  const invariantPath = path.join(directory, 'invariants.json');
  const oracleEnvPath = path.join(directory, 'oracle.env');
  const candidateEnvPath = path.join(directory, 'candidate.env');
  const differentialScenarioIds = Array.from({ length: 139 }, (_, index) => `scenario-${index}`);
  const invariantIds = Array.from({ length: 13 }, (_, index) => `invariant-${index}`);
  const profile = {
    baseAcceptance: { phase: 1 },
    differentialScenarios: differentialScenarioIds,
    candidateInvariantScenarios: invariantIds,
  };
  const profileText = JSON.stringify(profile);
  const schemaText = '{}';
  await Promise.all([
    writeFile(profilePath, profileText, { mode: 0o600 }),
    writeFile(schemaPath, schemaText, { mode: 0o600 }),
    writeFile(oracleEnvPath, 'PASSWORD=private-oracle-password\n', { mode: 0o600 }),
    writeFile(candidateEnvPath, 'STATUS_API_KEY=private-candidate-key\n', { mode: 0o600 }),
  ]);
  const harness = {
    repositoryUrl: 'https://example.invalid/harness.git',
    headCommit: 'harness-head',
    headTree: 'harness-tree',
    runtimeBundleSha256: 'a'.repeat(64),
  };
  const provenance = (mode: 'oracle' | 'differential' | 'candidate-invariants') => ({
    profileSha256: sha256(profileText),
    schemaSha256: sha256(schemaText),
    baseAcceptance: profile.baseAcceptance,
    harness,
    ...(mode === 'candidate-invariants' ? {} : { oracle: evidenceTopology('oracle') }),
    ...(mode === 'oracle' ? {} : { candidate: evidenceTopology('candidate') }),
  });
  const controlNames = [
    'status',
    'challenge',
    'error',
    'audience',
    'scope',
    'client-id',
    'organization-id',
    'typ',
    'alg',
    'kid',
    'discovery-grant-order',
    'unexpected-field',
    'status',
    'path',
    'cookie-clearing',
    'oauth',
    'claimKeys',
    'discovery-fields',
  ];
  const controls = controlNames.slice(0, controlCount).map((name, index) => ({
    name,
    pointer: `/controls/${index}`,
    detected: true,
  }));
  const target = (kind: 'oracle' | 'candidate', count: number) => ({
    target: kind,
    scenarios: differentialScenarioIds.slice(0, count).map((id) => ({ id, projection: {} })),
    discovery: {},
    controls,
  });
  const oracle = {
    schemaVersion: 1,
    mode: 'oracle',
    provenance: provenance('oracle'),
    sanitizerSuccess: true,
    payload: { schemaVersion: 1, mode: 'oracle', target: target('oracle', scenarioCount) },
  };
  const differential = {
    schemaVersion: 1,
    mode: 'differential',
    provenance: provenance('differential'),
    sanitizerSuccess: true,
    payload: {
      schemaVersion: 1,
      mode: 'differential',
      oracle: target('oracle', scenarioCount),
      candidate: target('candidate', scenarioCount),
      comparisons: differentialScenarioIds.slice(0, scenarioCount).map((scenarioId) => ({
        scenarioId,
        differenceCount: 0,
      })),
    },
  };
  const invariants = {
    schemaVersion: 1,
    mode: 'candidate-invariants',
    provenance: provenance('candidate-invariants'),
    sanitizerSuccess: true,
    payload: {
      schemaVersion: 1,
      mode: 'candidate-invariants',
      invariants: invariantIds.slice(0, invariantCount).map((id) => ({
        id,
        candidate: {},
        positiveControl: { detected: true },
        negativeControl: { detected: true, pointer: `/invariants/${id}` },
      })),
    },
  };
  await Promise.all([
    writeFile(oraclePath, JSON.stringify(oracle), { mode: 0o600 }),
    writeFile(differentialPath, JSON.stringify(differential), { mode: 0o600 }),
    writeFile(invariantPath, JSON.stringify(invariants), { mode: 0o600 }),
  ]);
  return runEmbeddedNode(embeddedNodeProgram('scan_evidence_for_private_values() {'), [
    profilePath,
    schemaPath,
    oraclePath,
    differentialPath,
    invariantPath,
    oracleEnvPath,
    candidateEnvPath,
    'harness-head',
    'harness-tree',
    'oracle-commit',
    'candidate-commit',
    'oracle-image',
    'candidate-image',
    'oracle-state-sha',
    'candidate-state-sha',
    'invariant-sha',
    'fixture-sha',
    'private-runtime-path',
  ]);
};

beforeAll(async () => {
  await mkdir(buildRoot, { mode: 0o700, recursive: true });
  temporaryRoot = await mkdtemp(path.join(buildRoot, 'aster-phase2-live-topology-test-'));
  source = await readFile(runnerPath, 'utf8');
});

afterAll(async () => {
  await rm(temporaryRoot, { force: true, recursive: true });
});

describe('Phase 2 client-credentials live topology runner', () => {
  it('requires pinned explicit inputs and creates two isolated real compose projects', () => {
    for (const required of [
      'ASTER_PHASE2_ASTER_ROOT',
      'ASTER_PHASE2_ORACLE_IMAGE',
      'ASTER_PHASE2_CANDIDATE_IMAGE',
      'ASTER_PHASE2_ENGINE_SOCKET',
      'ASTER_PHASE2_BUILD_ROOT',
      'sha256:76a9977bfc5ea3ed5b7623b879c27256670e377e27b987e8af99b53d55b30bbd',
      'aster-phase2-client-credentials-',
      'ORACLE_PROJECT_NAME',
      'CANDIDATE_PROJECT_NAME',
      '[[ "$ORACLE_PROJECT_NAME" != "$CANDIDATE_PROJECT_NAME" ]]',
    ]) {
      expect(source).toContain(required);
    }
    expect(source).toContain('docker-compose.phase1-runtime-candidate-differential.yml');
    expect(source).toContain('phase1-podman-differential-topology.mjs');
    expect(source).toMatch(
      /ORACLE_SERVICES=\([\s\S]*oracle-primary-postgres[\s\S]*oracle-foreign-core[\s\S]*\)/u
    );
    expect(source).toMatch(
      /CANDIDATE_SERVICES=\([\s\S]*candidate-primary-postgres[\s\S]*candidate-fixture-coordinator[\s\S]*\)/u
    );
    expect(source).toContain('assert_exact_project_services');
    expect(source).toContain('assert_distinct_container_ids');
    expect(source).toContain('\'{{index .Config.Labels "com.docker.compose.service"}}\'');
    expect(source).not.toContain(`{{.Label "com.docker.compose.service"}}`);
    expect(source).toContain(
      '--max-time 30 --output /dev/null --write-out \'%{http_code}\' --unix-socket "$ENGINE_SOCKET" http://localhost/libpod/_ping'
    );
    expect(source).toContain(
      '--max-time 30 --unix-socket "$ENGINE_SOCKET" http://localhost/version'
    );
    expect(source).toContain('topology_identity');
    expect(source).not.toMatch(/compose_up[^\n]*(?:phase0|browser|conformance)/u);
  });

  it('locks the service closure, staged startup, fixed loopback ports, and readiness', () => {
    for (const service of [
      'oracle-primary-postgres',
      'oracle-primary-redis',
      'oracle-primary-core',
      'oracle-foreign-postgres',
      'oracle-foreign-redis',
      'oracle-foreign-core',
      'candidate-primary-postgres',
      'candidate-primary-init',
      'candidate-primary-core',
      'candidate-foreign-postgres',
      'candidate-foreign-init',
      'candidate-foreign-core',
      'candidate-fixture-coordinator',
    ]) {
      expect(source).toContain(service);
    }
    for (const port of ['3311', '3411', '3312', '3412', '3321', '3421', '3322', '3422']) {
      expect(source).toContain(port);
    }
    for (const binding of [
      '3411|http://localhost:3411/oidc',
      '3412|http://localhost:3412/oidc',
      '3421|http://localhost:3421/oidc',
      '3422|http://localhost:3422/oidc',
    ]) {
      expect(source).toContain(binding);
    }
    expect(source).toContain('start_compose_stage');
    expect(source).toContain('start_loopback_proxy');
    expect(source).toContain('published_port');
    expect(source).toContain('port_state');
    expect(source).toContain('port_is_released');
    expect(source).toMatch(/sport = :\$\{port\}/u);
    expect(source).toContain('port_is_listened_by_pid');
    expect(source).toContain('http_ready');
    expect(source).toContain(
      'printf \'Host: localhost:%s\\r\\nConnection: close\\r\\n\\r\\n\' "$port"'
    );
    expect(source).not.toContain("printf 'Host: localhost\\r\\nConnection: close\\r\\n\\r\\n'");
    expect(source).toContain('wait_for_fixture_socket');
    expect(source).toMatch(/deadline=\$\(\(SECONDS \+ 180\)\)/u);
    expect(source).toMatch(
      /if \[\[ "\$status" == running && -n "\$health" && "\$health" != healthy \]\]; then[\s\S]*--connect-timeout 3 --max-time 3[\s\S]*libpod\/containers\/\$\{id\}\/healthcheck[\s\S]*\/usr\/bin\/sleep 3\n\s*continue/u
    );
    expect(source).toMatch(
      /\[\[ "\$status\|\$exit_code\|\$health" == 'running\|0\|healthy' \]\] && return 0/u
    );
    expect(source).toContain('[[ "$status" != exited || "$exit_code" == 0 ]] || return 1');
    expect(source).toContain('PODMAN_API_VERSION="$("$CURL_BIN"');
    expect(source).toContain('readonly PODMAN_API_VERSION');
    expect(source).not.toContain('assert_driver_discovery_port');
    expect(source).not.toMatch(/--filter\s+"publish=\$\{?port/u);
    expect(source).not.toMatch(
      /CANDIDATE_SERVICES=\([\s\S]*candidate-(?:phase0|connector-host|saml-host|script-host)/u
    );
  });

  it('retries a failed active health probe while the matching container stays running', async () => {
    const tracePath = path.join(temporaryRoot, 'healthcheck-retry.trace');
    const counterPath = path.join(temporaryRoot, 'healthcheck-retry.count');
    const harnessPath = path.join(temporaryRoot, 'healthcheck-retry-harness.sh');
    const containerId = 'a'.repeat(64);
    const project = 'aster-phase2-client-credentials-1111111111111111';
    const harness = `#!/usr/bin/env bash
set -euo pipefail
source ${JSON.stringify(runnerPath)}
TRACE=${JSON.stringify(tracePath)}
COUNTER=${JSON.stringify(counterPath)}
ORACLE_PROJECT_NAME=aster-phase2-client-credentials-0000000000000000
CANDIDATE_PROJECT_NAME=${project}
ENGINE_SOCKET=/var/tmp/henry-build/fake-podman.sock
PODMAN_API_VERSION=5.4.0
CURL_BIN=curl_stub
printf '0\n' >"$COUNTER"
compose_for() {
  [[ "$1 $2 $3 $4 $5" == 'candidate ps --all -q candidate-primary-postgres' ]] || return 1
  printf '%s\\n' ${containerId}
}
docker_cli() {
  [[ "$1" == inspect ]] || return 1
  inspect_count="$(<"$COUNTER")"
  inspect_count=$((inspect_count + 1))
  printf '%s\n' "$inspect_count" >"$COUNTER"
  if [[ "$inspect_count" == 1 ]]; then
    printf '%s|running|0|starting|%s|candidate-primary-postgres\\n' ${containerId} ${project}
  else
    printf '%s|running|0|healthy|%s|candidate-primary-postgres\\n' ${containerId} ${project}
  fi
}
curl_stub() {
  printf 'curl:%s\\n' "$*" >>"$TRACE"
  return 28
}
export -f curl_stub
wait_for_service candidate candidate-primary-postgres
[[ "$(<"$COUNTER")" == 2 ]]
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
    await expect(readFile(tracePath, 'utf8')).resolves.toBe(
      `curl:--silent --show-error --connect-timeout 3 --max-time 3 --output /dev/null --write-out %{http_code} --unix-socket /var/tmp/henry-build/fake-podman.sock http://localhost/v5.4.0/libpod/containers/${containerId}/healthcheck\n`
    );
  });

  it('builds descriptors only from actual engine and image inspection', () => {
    for (const inspectField of [
      '{{.Id}}',
      '{{.Image}}',
      '{{.Config.Image}}',
      'com.docker.compose.project',
      'com.docker.compose.service',
      'org.opencontainers.image.source',
      'org.opencontainers.image.revision',
      'io.aster.source.tree',
      'primaryContainerId',
      'foreignContainerId',
      'http://localhost:3311/',
      'http://localhost:3411/',
      'http://localhost:3312/',
      'http://localhost:3412/',
      'http://localhost:3321/',
      'http://localhost:3421/',
      'http://localhost:3322/',
      'http://localhost:3422/',
    ]) {
      expect(source).toContain(inspectField);
    }
    expect(source).toContain('6852a7b8c8984c5c12b2061e8c51faa310a36412');
    expect(source).toContain('assert_source_identity_unchanged');
    expect(source).toContain('assert_runtime_identity_unchanged');
    expect(source).toContain('git_text');
    expect(source).toContain('normalize_image_id');
    expect(source).toMatch(/\{\{\.Id\}\}\|\{\{\.Image\}\}\|\{\{\.Config\.Image\}\}/u);
  });

  it('normalizes only raw or canonical Podman image IDs to canonical sha256', async () => {
    const harnessPath = path.join(temporaryRoot, 'image-normalization-harness.sh');
    const raw = 'a'.repeat(64);
    const harness = `#!/usr/bin/env bash
set -euo pipefail
source ${JSON.stringify(runnerPath)}
[[ "$(normalize_image_id ${JSON.stringify(raw)})" == "sha256:${raw}" ]]
[[ "$(normalize_image_id sha256:${raw})" == "sha256:${raw}" ]]
if normalize_image_id "repo@example.invalid/thing@sha256:${raw}" >/dev/null 2>&1; then exit 9; fi
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });

  it('uses private artifacts, owner-only sockets, and tracked driver/admin copies', () => {
    for (const marker of [
      'chmod 0600',
      'chmod 0400 "$PRIMARY_CONFIG_FILE" "$FOREIGN_CONFIG_FILE"',
      'chmod 0500',
      'phase2-client-credentials-state-driver.sh',
      'phase2-client-credentials-invariant-driver.sh',
      '/usr/local/bin/aster-admin',
      'controlSocket:$socket',
      'fixtureSocket:$fixtureSocket',
      'verify_private_socket',
    ]) {
      expect(source).toContain(marker);
    }
    expect(source).toContain('umask 077');
    expect(source).not.toContain('/dev/shm');
  });

  it('runs oracle first, binds differential to immutable oracle evidence, then runs invariants', () => {
    expect(source).toContain('packages/integration-tests/src/compatibility/phase-2/launcher.mjs');
    expect(source).toContain("failure_stage='evidence-sequence'");
    expect(source).toContain("failure_stage='runtime-fence-after-evidence'");
    expect(source).not.toContain('compatibility:phase2 --');
    const oracle = source.indexOf("Object.freeze(['oracle'");
    const differential = source.indexOf("Object.freeze(['differential'");
    const invariants = source.indexOf("Object.freeze(['candidate-invariants'");
    expect(oracle).toBeGreaterThan(0);
    expect(differential).toBeGreaterThan(oracle);
    expect(invariants).toBeGreaterThan(differential);
    expect(source).toContain("'--oracle-evidence', oracleOutput");
    expect(source).not.toContain("'--oracle-target', oracleTarget");
    expect(source).toContain('immutableArtifact');
    expect(source).toContain('(state.mode & 0o777) !== 0o600');
    expect(source).toContain('oracleIdentity');
    expect(source).toContain('assertExactArtifacts');
    for (const artifact of [
      'phase-2-client-credentials-oracle.json',
      'phase-2-client-credentials-differential.json',
      'phase-2-client-credentials-candidate-invariants.json',
    ]) {
      expect(source).toContain(artifact);
    }
  });

  it('executes the embedded evidence sequence in exact oracle, differential, invariant order', async () => {
    const result = await runEvidenceSequence('success');

    expect(result.code).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.commands.map(([mode]) => mode)).toEqual([
      'oracle',
      'differential',
      'candidate-invariants',
    ]);
    const differential = result.commands[1] ?? [];
    const oracleOutput = result.commands[0]?.[result.commands[0].indexOf('--output') + 1];
    expect(differential[differential.indexOf('--oracle-evidence') + 1]).toBe(oracleOutput);
    expect(differential).not.toContain('--oracle-target');
  });

  it('does not run candidate invariants after an embedded differential failure', async () => {
    const result = await runEvidenceSequence('differential-failure');

    expect(result.code).toBe(1);
    expect(result.stderr).toBe('Phase 2 client credentials batch failed (differential).\n');
    expect(result.commands.map(([mode]) => mode)).toEqual(['oracle', 'differential']);
  });

  it.each(['replace-oracle', 'extra-artifact'] as const)(
    'fails closed before invariants when the launcher introduces %s',
    async (behavior) => {
      const result = await runEvidenceSequence(behavior);

      expect(result.code).toBe(1);
      expect(result.stderr).toMatch(
        /^Phase 2 client credentials batch failed \((?:artifact|differential)\)\.\n$/u
      );
      expect(result.commands.map(([mode]) => mode)).toEqual(['oracle', 'differential']);
    }
  );

  it('validates the closed evidence counts, provenance, sanitizer, and public topology', () => {
    for (const marker of [
      'scenarioCount !== 139',
      'expectedControlCount = expectedControlNames.length',
      'comparisonCount !== 139',
      'invariantCount !== 13',
      'differenceCount !== 0',
      'comparison.scenarioId !== profile.differentialScenarios[index]',
      "exactKeys(comparison, ['scenarioId','differenceCount'])",
      'sanitizerSuccess !== true',
      'runtimeBundleSha256',
      'baseAcceptance',
      'primaryRole',
      'foreignRole',
      'forbiddenPrivateValues',
    ]) {
      expect(source).toContain(marker);
    }
    for (const stale of [
      'scenarioCount !== 70',
      'controlCount !== 12',
      'comparisonCount !== 70',
      'invariantCount !== 5',
    ]) {
      expect(source).not.toContain(stale);
    }
    for (const control of [
      'discovery-grant-order',
      'unexpected-field',
      'cookie-clearing',
      'claimKeys',
      'discovery-fields',
    ]) {
      expect(source).toContain(`'${control}'`);
    }
    expect(source).toContain('!exact(side.controls, oracleControls)');
    expect(source).toContain(
      'device-(authorization|verification|consent|token|token-status|discovery)'
    );
  });

  it('executes the embedded evidence validator and rejects stale evidence cardinalities', async () => {
    await expect(runEvidenceValidation(139, 13, 18)).resolves.toEqual({ code: 0, stderr: '' });
    await expect(runEvidenceValidation(138, 13, 18)).resolves.toEqual({ code: 1, stderr: '' });
    await expect(runEvidenceValidation(139, 12, 18)).resolves.toEqual({ code: 1, stderr: '' });
    await expect(runEvidenceValidation(139, 13, 12)).resolves.toEqual({ code: 1, stderr: '' });
    await expect(runEvidenceValidation(139, 13, 17)).resolves.toEqual({ code: 1, stderr: '' });
  });

  it('keeps secrets and raw service logs out of stdout and evidence handling', () => {
    expect(source).not.toMatch(/set\s+-x/u);
    expect(source).not.toMatch(/compose[^\n]*\blogs\b/u);
    expect(source).not.toMatch(
      /(?:cat|tee|printf)[^\n]*(?:COMPOSE_ENV|PASSWORD|SECRET_VAULT_KEK|STATUS_API_KEY)/u
    );
    expect(source).not.toMatch(/docker_cli[^\n]*inspect[^\n]*\.Config\.Env/u);
    expect(source).toContain('>/dev/null 2>&1');
    expect(source).toContain('scan_evidence_for_private_values');
    expect(source).toContain('remove_state_handle_root');
    expect(source).toContain('assert_state_handle_root_clean');
    expect(source).toContain('2>"$RUN_DIR/evidence-sequence.stderr"');
    expect(source).toContain('^Phase 2 client credentials command failed ');
    expect(source).toContain('^Phase 2 client credentials launcher child failed ');
    expect(source).toContain('^Phase 2 client credentials batch failed ');
    expect(source).toContain(
      'lifecycle-request|lifecycle-response|token-response|credential-lease|projection|scenario'
    );
    expect(source).not.toContain('cat "$RUN_DIR/evidence-sequence.stderr"');
  });

  it('executes both command diagnostic allowlists against closed device stages', async () => {
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? '([^'\n]+)' "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]
    ).filter(
      (pattern): pattern is string =>
        pattern?.startsWith('^Phase 2 client credentials command failed ') === true &&
        pattern.includes('lifecycle-request')
    );
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe(patterns[1]);

    const prefix =
      'Phase 2 client credentials command failed (oracle/device-token.refresh-resource-selection';
    const acceptedLines = [
      'lifecycle-request',
      'lifecycle-response',
      'token-response',
      'credential-lease',
      'projection',
      'scenario',
    ].map((stage) => `${prefix}:${stage}).`);
    acceptedLines.push(
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:projection-cookies).',
      ...[
        'approval',
        'approval-authorize',
        'approval-capture',
        'approval-verify',
        'approval-experience-open',
        'approval-password',
        'approval-identification',
        'approval-experience-submit',
        'approval-resume-initial',
        'approval-consent-read',
        'approval-consent-write',
        'approval-resume-final',
        'transition',
        'verification-get',
        'verification-post',
      ].map(
        (stage) =>
          `Phase 2 client credentials command failed (candidate/device-verification.already-used-code:${stage}).`
      )
    );
    const rejectedLines = [
      `${prefix}:unknown-marker).`,
      `${prefix}:credential-lease:private-marker).`,
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:projection-private).',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:projection-cookies:private-marker).',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:approval:private-marker).',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:approval-password:private-marker).',
    ];
    const matchesFor = async (lines: readonly string[]) =>
      Promise.all(
        lines.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      );
    await expect(matchesFor(acceptedLines)).resolves.toEqual(
      Array.from({ length: acceptedLines.length * patterns.length }, () => true)
    );
    await expect(matchesFor(rejectedLines)).resolves.toEqual(
      Array.from({ length: rejectedLines.length * patterns.length }, () => false)
    );
  });

  it('forwards only closed consent composite projection diagnostics', async () => {
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? '([^'\n]+)' "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]
    ).filter(
      (pattern): pattern is string =>
        pattern?.includes('projection-(firstIssued|consent|completion)-') === true
    );
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe(patterns[1]);

    const acceptedLines = ['oracle', 'candidate'].flatMap((target) =>
      ['firstIssued', 'consent', 'completion'].flatMap((stage) =>
        ['status', 'cookies', 'terminal'].map(
          (field) =>
            `Phase 2 client credentials command failed (${target}/device-consent.first-party-matching-grant-required:projection-${stage}-${field}).`
        )
      )
    );
    const rejectedLines = [
      'Phase 2 client credentials command failed (candidate/device-consent.first-party-matching-grant-required:projection-completion-private).',
      'Phase 2 client credentials command failed (candidate/device-consent.first-party-matching-grant-required:projection-unknown-cookies).',
      'Phase 2 client credentials command failed (candidate/device-verification.already-used-code:projection-completion-cookies).',
      'Phase 2 client credentials command failed (candidate/device-consent.first-party-matching-grant-required:projection-completion-cookies:private-marker).',
    ];
    const matchesFor = async (lines: readonly string[]) =>
      Promise.all(
        lines.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      );
    await expect(matchesFor(acceptedLines)).resolves.toEqual(
      Array.from({ length: acceptedLines.length * patterns.length }, () => true)
    );
    await expect(matchesFor(rejectedLines)).resolves.toEqual(
      Array.from({ length: rejectedLines.length * patterns.length }, () => false)
    );
  });

  it('forwards only closed token lifecycle child projection diagnostics', async () => {
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? '([^'\n]+)' "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]
    ).filter((pattern): pattern is string => pattern?.includes('projection-sequence-') === true);
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe(patterns[1]);

    const accepted = [
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-siblingAfter-headers).',
      'Phase 2 client credentials command failed (oracle/device-token.session-bound-expiry:projection-sequence-after-oauthError).',
    ];
    const rejected = [
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-private-headers).',
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-siblingAfter-private).',
      'Phase 2 client credentials command failed (candidate/device-token-status.access-revocation:projection-sequence-siblingAfter-headers:private-marker).',
      'Phase 2 client credentials command failed (candidate/device-token.private-lifecycle:projection-sequence-after-oauthError).',
    ];
    await expect(
      Promise.all(
        accepted.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      )
    ).resolves.toEqual(Array.from({ length: accepted.length * patterns.length }, () => true));
    await expect(
      Promise.all(
        rejected.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      )
    ).resolves.toEqual(Array.from({ length: rejected.length * patterns.length }, () => false));
  });

  it('forwards only closed ID token projection diagnostics', async () => {
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? '([^'\n]+)' "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]
    ).filter(
      (pattern): pattern is string =>
        pattern?.includes(':projection-id-') === true && pattern.includes('claimTypes-')
    );
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe(patterns[1]);

    const prefix =
      'Phase 2 client credentials command failed (candidate/device-token.id-token-signature-and-claims:projection-id-';
    const acceptedLines = [
      'claimKeys',
      'claimTypes-aud',
      'claimTypes-email_verified',
      'claimTypes-auth_time',
      'header',
      'signature',
      'format',
      'issuer',
      'audience',
      'subject',
      'issuedAt',
      'lifetimeSeconds',
      'other',
    ].map((stage) => `${prefix}${stage}).`);
    const rejectedLines = [
      `${prefix}claimTypes-private-token).`,
      `${prefix}claimTypes-email:private-marker).`,
      `${prefix}private-token).`,
      `${prefix}signature:private-marker).`,
    ];
    const matchesFor = async (lines: readonly string[]) =>
      Promise.all(
        lines.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      );
    await expect(matchesFor(acceptedLines)).resolves.toEqual(
      Array.from({ length: acceptedLines.length * patterns.length }, () => true)
    );
    await expect(matchesFor(rejectedLines)).resolves.toEqual(
      Array.from({ length: rejectedLines.length * patterns.length }, () => false)
    );
  });

  it('forwards only closed ID claim-key structural diagnostics', async () => {
    const claimName = /readonly id_claim_name='([^'\n]+)'/u.exec(source)?.[1];
    expect(claimName).toBeDefined();
    const claimSet = `(none|${claimName}(,${claimName})*)`;
    const shellClaimSetReference = ['$', '{id_claim_set}'].join('');
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? "([^"\n]*Phase 2 device ID claimKeys differ[^"\n]+)" "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]?.replaceAll(shellClaimSetReference, claimSet)
    ).filter((pattern): pattern is string => pattern !== undefined);
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe(patterns[1]);

    const accepted =
      'Phase 2 device ID claimKeys differ (only on oracle: acr,amr,organizations; only on candidate: none).';
    const rejected = [
      accepted.replace('organizations', 'private-token'),
      accepted + ' private-value',
    ];
    await expect(
      Promise.all(patterns.map(async (pattern) => grepMatches(pattern, accepted)))
    ).resolves.toEqual([true, true]);
    await expect(
      Promise.all(
        rejected.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      )
    ).resolves.toEqual([false, false, false, false]);
  });

  it('executes both command diagnostic allowlists against closed sanitizer substages', async () => {
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? '([^'\n]+)' "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]
    ).filter(
      (pattern): pattern is string =>
        pattern?.startsWith('^Phase 2 client credentials command failed ') === true &&
        pattern.includes('lifecycle-request')
    );
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe(patterns[1]);

    const acceptedLines = ['oracle', 'candidate'].flatMap((prefix) =>
      [
        'target',
        'discovery',
        'controls',
        'ids',
        'client-0',
        'client-138',
        'device-0',
        'device-138',
      ].map(
        (suffix) => `Phase 2 client credentials command failed (${prefix}-sanitizer-${suffix}).`
      )
    );
    const rejectedLines = [
      'Phase 2 client credentials command failed (oracle-sanitizer-client-00).',
      'Phase 2 client credentials command failed (oracle-sanitizer-client-139).',
      'Phase 2 client credentials command failed (candidate-sanitizer-device-01).',
      'Phase 2 client credentials command failed (candidate-sanitizer-device-139).',
      'Phase 2 client credentials command failed (oracle-sanitizer-target-extra).',
      'Phase 2 client credentials command failed (oracle-sanitizer-private-value).',
    ];
    const matchesFor = async (lines: readonly string[]) =>
      Promise.all(
        lines.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      );
    await expect(matchesFor(acceptedLines)).resolves.toEqual(
      Array.from({ length: acceptedLines.length * patterns.length }, () => true)
    );
    await expect(matchesFor(rejectedLines)).resolves.toEqual(
      Array.from({ length: rejectedLines.length * patterns.length }, () => false)
    );
  });

  it('allows only closed device candidate-invariant stages in final output', async () => {
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? '([^'\n]+)' "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]
    ).filter(
      (pattern): pattern is string =>
        pattern?.startsWith('^Phase 2 client credentials command failed ') === true &&
        pattern.includes('lifecycle-request')
    );
    expect(patterns).toHaveLength(2);
    await expect(
      Promise.all(
        patterns.flatMap((pattern) => [
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-7).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-7-scan-match).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-7-normalized-query).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-1-row-sql).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-2-foreign-poll-invalid-client).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-2-abort).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-8).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-1-unknown).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-2-unknown).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-7-unknown).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (candidate-invariant-device-7-normalized-query:private-marker).'
          ),
          grepMatches(
            pattern,
            'Phase 2 client credentials command failed (oracle-invariant-device-0).'
          ),
        ])
      )
    ).resolves.toEqual(
      Array.from({ length: 2 }, () => [
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        false,
        false,
        false,
        false,
        false,
      ]).flat()
    );
  });

  it('forwards only fixed device-7 pre-driver diagnostics', async () => {
    const patterns = Array.from(
      source.matchAll(
        /\/usr\/bin\/grep -E[q]? '([^'\n]*candidate-invariant-device-7-\(prepare[^'\n]+)' "\$RUN_DIR\/evidence-sequence\.stderr"/gu
      ),
      (match) => match[1]
    ).filter((pattern): pattern is string => pattern !== undefined);
    expect(patterns).toHaveLength(2);
    expect(patterns[0]).toBe(patterns[1]);
    const accepted = [
      'prepare',
      'approval',
      'issuance',
      'evidence-open',
      'evidence-values',
      'evidence-validation',
      'evidence-lease',
      'driver-unclassified',
    ].map(
      (stage) =>
        `Phase 2 client credentials command failed (candidate-invariant-device-7-${stage}).`
    );
    const rejected = [
      'Phase 2 client credentials command failed (candidate-invariant-device-7-unknown).',
      'Phase 2 client credentials command failed (candidate-invariant-device-7-prepare:private).',
    ];
    await expect(
      Promise.all(
        accepted.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      )
    ).resolves.toEqual(Array.from({ length: 16 }, () => true));
    await expect(
      Promise.all(
        rejected.flatMap((line) => patterns.map(async (pattern) => grepMatches(pattern, line)))
      )
    ).resolves.toEqual(Array.from({ length: 4 }, () => false));
  });

  it('publishes results only after successful topology cleanup', () => {
    expect(source).toContain('.staging.XXXXXX');
    expect(source).toContain('RESULT_STAGING_IDENTITY');
    expect(source).toContain('remove_owned_result_directory');
    expect(source).toContain('verify_published_result_directory');
    expect(source).toContain('for _ in 1 2; do');
    expect(source).toContain('[[ "$cleanup_complete" == 1 ]]');
    expect(source).toContain('--no-clobber --no-target-directory');
    const cleanup = source.lastIndexOf('cleanup_resources 0');
    const publish = source.lastIndexOf('--no-clobber --no-target-directory');
    expect(cleanup).toBeGreaterThan(0);
    expect(publish).toBeGreaterThan(cleanup);
  });

  it('rejects a pre-existing invariant-handle root and fences only the root created by this run', () => {
    expect(source).toContain("INVARIANT_HANDLE_ROOT=''");
    expect(source).toContain("INVARIANT_HANDLE_ROOT_IDENTITY=''");
    expect(source).toContain(
      'INVARIANT_HANDLE_ROOT="$(/usr/bin/dirname -- "$ENGINE_SOCKET")/phase2-device-invariants"'
    );
    const rejectExisting = source.indexOf(
      '[[ ! -e "$INVARIANT_HANDLE_ROOT" && ! -L "$INVARIANT_HANDLE_ROOT" ]]'
    );
    const main = source.indexOf('\nmain() {');
    const create = source.indexOf('/usr/bin/mkdir -m 700 -- "$INVARIANT_HANDLE_ROOT"');
    const identity = source.indexOf(
      'INVARIANT_HANDLE_ROOT_IDENTITY="$(capture_path_identity "$INVARIANT_HANDLE_ROOT")"'
    );
    expect(main).toBeGreaterThan(0);
    expect(rejectExisting).toBeGreaterThan(0);
    expect(rejectExisting).toBeGreaterThan(main);
    expect(create).toBeGreaterThan(rejectExisting);
    expect(identity).toBeGreaterThan(create);
    expect(source.slice(main, create)).not.toContain(
      'remove_invariant_handle_root "$INVARIANT_HANDLE_ROOT"'
    );
    expect(source).toContain(
      ['[[ -n "$', '{INVARIANT_HANDLE_ROOT_IDENTITY:-}" ]] || return 1'].join('')
    );
    expect(source).toContain('assert_path_identity "$root" "$INVARIANT_HANDLE_ROOT_IDENTITY"');
  });

  it('accepts cleanup when every fixed port is already released', async () => {
    const harnessPath = path.join(temporaryRoot, 'released-ports-harness.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
port_state() { printf released; }
assert_ports_released 3311 3411 3312 3412 3321 3421 3322 3422
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });

  it('removes only verified retired state-handle tombstones and their private root', async () => {
    const stateRoot = await mkdtemp(path.join(temporaryRoot, 'retired-state-root-'));
    await chmod(stateRoot, 0o700);
    await Promise.all(
      ['a'.repeat(32), 'b'.repeat(32)].map(async (suffix) =>
        writeFile(
          path.join(stateRoot, `.quarantine.${suffix}`),
          '{"schemaVersion":1,"retired":true}',
          { mode: 0o600 }
        )
      )
    );
    const harnessPath = path.join(temporaryRoot, 'retired-state-root-harness.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
remove_state_handle_root ${JSON.stringify(stateRoot)}
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
    await expect(lstat(stateRoot)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it.each([
    ['armed', 'a'.repeat(32), '{"private":"opaque"}'],
    ['retired', `.quarantine.${'b'.repeat(32)}`, '{"schemaVersion":1,"retired":true}'],
  ] as const)(
    'removes a verified %s invariant handle without inspecting its payload',
    async (_, name, payload) => {
      const invariantRoot = await mkdtemp(path.join(temporaryRoot, 'invariant-root-'));
      await chmod(invariantRoot, 0o700);
      await writeFile(path.join(invariantRoot, name), payload, { mode: 0o600 });
      const harnessPath = path.join(temporaryRoot, `invariant-root-${name.slice(0, 8)}.sh`);
      const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
remove_invariant_handle_root ${JSON.stringify(invariantRoot)}
`;
      await writeFile(harnessPath, harness, { mode: 0o500 });

      await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
      await expect(lstat(invariantRoot)).rejects.toMatchObject({ code: 'ENOENT' });
    }
  );

  it.each(['unexpected', 'symlink', 'wrong-mode', 'multiple-links', 'empty', 'oversize'] as const)(
    'fails closed and preserves a %s invariant-handle entry',
    async (kind) => {
      const invariantRoot = await mkdtemp(path.join(temporaryRoot, `invalid-invariant-${kind}-`));
      await chmod(invariantRoot, 0o700);
      const entry = path.join(invariantRoot, kind === 'unexpected' ? 'foreign' : 'c'.repeat(32));
      if (kind === 'symlink') {
        const target = path.join(temporaryRoot, `invariant-target-${Date.now()}`);
        await writeFile(target, 'private', { mode: 0o600 });
        await symlink(target, entry);
      } else {
        const payload =
          kind === 'empty' ? '' : kind === 'oversize' ? 'x'.repeat(65_537) : 'private';
        await writeFile(entry, payload, { mode: kind === 'wrong-mode' ? 0o640 : 0o600 });
        if (kind === 'multiple-links') {
          await link(entry, path.join(temporaryRoot, `linked-invariant-${Date.now()}`));
        }
      }
      const harnessPath = path.join(temporaryRoot, `invalid-invariant-${kind}.sh`);
      const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
if remove_invariant_handle_root ${JSON.stringify(invariantRoot)}; then exit 19; fi
`;
      await writeFile(harnessPath, harness, { mode: 0o500 });

      await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
      await expect(lstat(entry)).resolves.toBeDefined();
    }
  );

  it('refuses to adopt a configured invariant root without this run identity', async () => {
    const invariantRoot = await mkdtemp(path.join(temporaryRoot, 'unowned-invariant-root-'));
    await chmod(invariantRoot, 0o700);
    const entry = path.join(invariantRoot, 'f'.repeat(32));
    await writeFile(entry, 'private', { mode: 0o600 });
    const harnessPath = path.join(temporaryRoot, 'unowned-invariant-root.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
INVARIANT_HANDLE_ROOT=${JSON.stringify(invariantRoot)}
INVARIANT_HANDLE_ROOT_IDENTITY=''
if remove_invariant_handle_root "$INVARIANT_HANDLE_ROOT"; then exit 19; fi
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
    await expect(lstat(entry)).resolves.toBeDefined();
  });

  it('keeps state-handle cleanup independent from invariant-handle cleanup', async () => {
    const stateRoot = await mkdtemp(path.join(temporaryRoot, 'independent-state-root-'));
    const invariantRoot = await mkdtemp(path.join(temporaryRoot, 'independent-invariant-root-'));
    await Promise.all([chmod(stateRoot, 0o700), chmod(invariantRoot, 0o700)]);
    const stateEntry = path.join(stateRoot, `.quarantine.${'d'.repeat(32)}`);
    await Promise.all([
      writeFile(stateEntry, '{"schemaVersion":1,"retired":true}', { mode: 0o600 }),
      writeFile(path.join(invariantRoot, 'e'.repeat(32)), 'private', { mode: 0o600 }),
    ]);
    const harnessPath = path.join(temporaryRoot, 'independent-handle-roots.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
remove_invariant_handle_root ${JSON.stringify(invariantRoot)}
[[ -f ${JSON.stringify(stateEntry)} ]]
remove_state_handle_root ${JSON.stringify(stateRoot)}
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
    await expect(lstat(stateRoot)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(lstat(invariantRoot)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('fails closed and preserves a dangling state-handle root symlink', async () => {
    const stateRoot = path.join(temporaryRoot, 'dangling-state-root');
    await symlink(path.join(temporaryRoot, 'missing-state-root-target'), stateRoot);
    const harnessPath = path.join(temporaryRoot, 'dangling-state-root-harness.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
if remove_state_handle_root ${JSON.stringify(stateRoot)}; then exit 19; fi
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
    await expect(lstat(stateRoot)).resolves.toBeDefined();
  });

  it.each(['unexpected', 'wrong-content', 'symlink', 'wrong-mode', 'multiple-links'] as const)(
    'fails closed and preserves a %s state-handle entry',
    async (kind) => {
      const stateRoot = await mkdtemp(path.join(temporaryRoot, `invalid-state-root-${kind}-`));
      await chmod(stateRoot, 0o700);
      const entry = path.join(
        stateRoot,
        kind === 'unexpected' ? 'foreign-state' : `.quarantine.${'c'.repeat(32)}`
      );
      if (kind === 'symlink') {
        const target = path.join(temporaryRoot, `symlink-target-${Date.now()}`);
        await writeFile(target, '{"schemaVersion":1,"retired":true}', { mode: 0o600 });
        await symlink(target, entry);
      } else {
        await writeFile(
          entry,
          kind === 'wrong-content'
            ? '{"schemaVersion":1,"retired":false}'
            : '{"schemaVersion":1,"retired":true}',
          { mode: kind === 'wrong-mode' ? 0o640 : 0o600 }
        );
        if (kind === 'multiple-links') {
          await link(entry, path.join(temporaryRoot, `linked-tombstone-${Date.now()}`));
        }
      }
      const harnessPath = path.join(temporaryRoot, `invalid-state-root-${kind}-harness.sh`);
      const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
if remove_state_handle_root ${JSON.stringify(stateRoot)}; then exit 19; fi
`;
      await writeFile(harnessPath, harness, { mode: 0o500 });

      await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
      await expect(lstat(entry)).resolves.toBeDefined();
    }
  );

  it('fails closed when the port release query fails', async () => {
    const harnessPath = path.join(temporaryRoot, 'port-query-failure-harness.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
SS_BIN=/bin/false
AWK_BIN=/usr/bin/awk
if assert_ports_released 3311; then exit 11; fi
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });

  it('fails closed when the port query returns malformed output', async () => {
    const fakeSsPath = path.join(temporaryRoot, 'malformed-ss.sh');
    const harnessPath = path.join(temporaryRoot, 'malformed-port-query-harness.sh');
    await writeFile(
      fakeSsPath,
      "#!/usr/bin/env bash\nprintf 'BROKEN zero zero nowhere nowhere\\n'\n",
      {
        mode: 0o500,
      }
    );
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
SS_BIN=${JSON.stringify(fakeSsPath)}
AWK_BIN=/usr/bin/awk
if assert_ports_released 3311; then exit 11; fi
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });

  it('treats wildcard listeners on a fixed port as occupied', async () => {
    const fakeSsPath = path.join(temporaryRoot, 'wildcard-listener-ss.sh');
    const harnessPath = path.join(temporaryRoot, 'wildcard-listener-harness.sh');
    await writeFile(
      fakeSsPath,
      "#!/usr/bin/env bash\nprintf 'LISTEN 0 128 0.0.0.0:3311 0.0.0.0:*\\n'\n",
      { mode: 0o500 }
    );
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
SS_BIN=${JSON.stringify(fakeSsPath)}
AWK_BIN=/usr/bin/awk
[[ "$(port_state 3311)" == listening ]]
if port_is_released 3311; then exit 11; fi
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });

  it('uses reverse cleanup on failure and preserves the original failure status', async () => {
    const tracePath = path.join(temporaryRoot, 'cleanup.trace');
    const harnessPath = path.join(temporaryRoot, 'cleanup-harness.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
TRACE=${JSON.stringify(tracePath)}
PROXY_PIDS=(101 102 103)
PROXY_PGIDS=(101 102 103)
PROXY_TOKENS=(a b c)
CANDIDATE_PROJECT_STARTED=1
ORACLE_PROJECT_STARTED=1
RUN_DIR=${JSON.stringify(path.join(temporaryRoot, 'run'))}
RESULT_DIR=''
stop_owned_proxy() { printf 'proxy:%s\\n' "$1" >>"$TRACE"; }
cleanup_project() { printf 'project:%s\\n' "$1" >>"$TRACE"; }
assert_ports_released() { printf 'ports:%s\\n' "$*" >>"$TRACE"; }
remove_run_root() { printf 'run-root:%s\\n' "$1" >>"$TRACE"; }
cleanup_resources 23
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });
    const result = await runBash(harnessPath);

    expect(result.code).toBe(23);
    expect(result.stderr).toBe('');
    await expect(readFile(tracePath, 'utf8')).resolves.toBe(
      [
        'proxy:103',
        'proxy:102',
        'proxy:101',
        'project:candidate',
        'project:oracle',
        'ports:3311 3411 3312 3412 3321 3421 3322 3422',
        `run-root:${path.join(temporaryRoot, 'run')}`,
        '',
      ].join('\n')
    );
  });

  it('retains failed owned resources for a second cleanup pass and converges in reverse order', async () => {
    const tracePath = path.join(temporaryRoot, 'cleanup-retry.trace');
    const harnessPath = path.join(temporaryRoot, 'cleanup-retry-harness.sh');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
TRACE=${JSON.stringify(tracePath)}
PROXY_PIDS=(101 102 103)
PROXY_PGIDS=(101 102 103)
PROXY_TOKENS=(a b c)
EXTRACTION_CONTAINER_ID=extract-owned
CANDIDATE_PROJECT_STARTED=1
ORACLE_PROJECT_STARTED=1
RUN_DIR=${JSON.stringify(path.join(temporaryRoot, 'retry-run'))}
RESULT_DIR=''
STATE_HANDLE_ROOT=''
proxy_failed=0
candidate_failed=0
extraction_failed=0
extraction_present=1
stop_owned_proxy() {
  printf 'proxy:%s\n' "$1" >>"$TRACE"
  if [[ "$1" == 103 && "$proxy_failed" == 0 ]]; then proxy_failed=1; return 1; fi
  return 0
}
docker_cli() {
  if [[ "$1 $2 $3" == 'rm --force --volumes' && "$4" == extract-owned ]]; then
    printf 'extract:%s\n' "$extraction_failed" >>"$TRACE"
    if [[ "$extraction_failed" == 0 ]]; then extraction_failed=1; return 1; fi
    extraction_present=0
    return 0
  fi
  if [[ "$1 $2" == 'ps -aq' ]]; then
    [[ "$extraction_present" == 1 ]] && printf '%s\n' extract-owned
    return 0
  fi
  return 1
}
cleanup_project() {
  printf 'project:%s\n' "$1" >>"$TRACE"
  if [[ "$1" == candidate && "$candidate_failed" == 0 ]]; then candidate_failed=1; return 1; fi
  return 0
}
remove_state_handle_root() { return 0; }
assert_ports_released() { printf 'ports\n' >>"$TRACE"; return 0; }
remove_run_root() { printf 'run-root\n' >>"$TRACE"; return 0; }
set +e
cleanup_resources 0
first=$?
printf 'state:first:%s:%s:%s:%s:%s\n' "$first" "\${PROXY_PIDS[*]}" "$EXTRACTION_CONTAINER_ID" "$CANDIDATE_PROJECT_STARTED" "$ORACLE_PROJECT_STARTED" >>"$TRACE"
cleanup_resources 0
second=$?
printf 'state:second:%s:%s:%s:%s:%s:%s\n' "$second" "\${PROXY_PIDS[*]}" "$EXTRACTION_CONTAINER_ID" "$CANDIDATE_PROJECT_STARTED" "$ORACLE_PROJECT_STARTED" "$TOPOLOGY_CLEANED" >>"$TRACE"
[[ "$first" == 1 && "$second" == 0 && \${#PROXY_PIDS[@]} == 0 && -z "$EXTRACTION_CONTAINER_ID" && "$CANDIDATE_PROJECT_STARTED" == 0 && "$ORACLE_PROJECT_STARTED" == 0 && "$TOPOLOGY_CLEANED" == 1 ]]
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });
    const result = await runBash(harnessPath);

    expect(result).toEqual({ code: 0, stderr: '' });
    await expect(readFile(tracePath, 'utf8')).resolves.toBe(
      [
        'extract:0',
        'proxy:103',
        'proxy:102',
        'proxy:101',
        'project:candidate',
        'project:oracle',
        'state:first:1:103:extract-owned:1:0',
        'extract:1',
        'proxy:103',
        'project:candidate',
        'ports',
        'run-root',
        'state:second:0:::0:0:1',
        '',
      ].join('\n')
    );
  });

  it('discovers an untracked partial-start container by the random project label and retries it', async () => {
    const tracePath = path.join(temporaryRoot, 'partial-start-cleanup.trace');
    const harnessPath = path.join(temporaryRoot, 'partial-start-cleanup-harness.sh');
    const candidateId = 'a'.repeat(64);
    const unrelatedId = 'b'.repeat(64);
    const candidateProject = 'aster-phase2-client-credentials-1111111111111111';
    const unrelatedProject = 'aster-phase2-client-credentials-2222222222222222';
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
TRACE=${JSON.stringify(tracePath)}
ORACLE_PROJECT_NAME=aster-phase2-client-credentials-0000000000000000
CANDIDATE_PROJECT_NAME=${candidateProject}
ORACLE_CONTAINER_IDS=()
CANDIDATE_CONTAINER_IDS=()
candidate_present=0
unrelated_present=1
remove_attempt=0
compose_for() {
  local role=$1 command=$2
  shift 2
  [[ "$role" == candidate ]] || return 1
  if [[ "$command" == up ]]; then
    candidate_present=1
    printf 'compose-up:%s\n' "$*" >>"$TRACE"
    return 0
  fi
  if [[ "$command" == ps ]]; then
    printf 'compose-ps-failed:%s\n' "$*" >>"$TRACE"
    return 1
  fi
  return 1
}
docker_cli() {
  if [[ "$1 $2 $3" == 'rm --force --volumes' ]]; then
    printf 'rm:%s:%s\n' "$4" "$remove_attempt" >>"$TRACE"
    [[ "$4" == ${candidateId} ]] || return 1
    if [[ "$remove_attempt" == 0 ]]; then
      remove_attempt=1
    else
      candidate_present=0
    fi
    return 0
  fi
  if [[ "$1 $2 $3" == 'ps -aq --no-trunc' ]]; then
    args=" $* "
    if [[ "$args" == *' --filter label=com.docker.compose.project=${candidateProject} '* ]]; then
      [[ "$candidate_present" == 1 ]] && printf '%s\n' ${candidateId}
      return 0
    fi
    if [[ "$args" == *' --filter label=com.docker.compose.project=${unrelatedProject} '* ]]; then
      [[ "$unrelated_present" == 1 ]] && printf '%s\n' ${unrelatedId}
      return 0
    fi
    if [[ "$args" == *' --filter id=${candidateId} '* ]]; then
      [[ "$candidate_present" == 1 ]] && printf '%s\n' ${candidateId}
      return 0
    fi
    if [[ "$args" == *' --filter id=${unrelatedId} '* ]]; then
      [[ "$unrelated_present" == 1 ]] && printf '%s\n' ${unrelatedId}
      return 0
    fi
    return 1
  fi
  if [[ "$1 $2 $3" == 'network ls -q' || "$1 $2 $3" == 'volume ls -q' ]]; then
    return 0
  fi
  return 1
}
if start_compose_stage candidate partial candidate-primary-postgres; then exit 11; fi
[[ "$candidate_present" == 1 && \${#CANDIDATE_CONTAINER_IDS[@]} == 0 ]]
if cleanup_project candidate; then exit 12; fi
printf 'after-first:%s:%s\n' "\${CANDIDATE_CONTAINER_IDS[*]}" "$candidate_present" >>"$TRACE"
cleanup_project candidate
printf 'after-second:%s:%s:%s\n' "\${CANDIDATE_CONTAINER_IDS[*]}" "$candidate_present" "$unrelated_present" >>"$TRACE"
[[ \${#CANDIDATE_CONTAINER_IDS[@]} == 0 && "$candidate_present" == 0 && "$unrelated_present" == 1 ]]
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
    const trace = await readFile(tracePath, 'utf8');
    expect(trace).toContain('compose-up:--no-deps --detach candidate-primary-postgres\n');
    expect(trace).toContain(`after-first:${candidateId}:1\n`);
    expect(trace).toContain('after-second::0:1\n');
    expect(trace.match(new RegExp(`rm:${candidateId}`, 'gu'))).toHaveLength(2);
    expect(trace).not.toContain(`rm:${unrelatedId}`);
  });

  it('fails closed when a post-cleanup engine query fails', async () => {
    const harnessPath = path.join(temporaryRoot, 'cleanup-query-failure-harness.sh');
    const counterPath = path.join(temporaryRoot, 'cleanup-query-failure.count');
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
ORACLE_PROJECT_NAME=aster-phase2-client-credentials-0000000000000000
CANDIDATE_PROJECT_NAME=aster-phase2-client-credentials-1111111111111111
CANDIDATE_CONTAINER_IDS=()
QUERY_COUNTER=${JSON.stringify(counterPath)}
printf '0\n' >"$QUERY_COUNTER"
docker_cli() {
  if [[ "$1 $2 $3" == 'ps -aq --no-trunc' ]]; then
    query_count="$(<"$QUERY_COUNTER")"
    query_count=$((query_count + 1))
    printf '%s\n' "$query_count" >"$QUERY_COUNTER"
    [[ "$query_count" == 1 ]]
    return
  fi
  return 1
}
if cleanup_project candidate; then exit 11; fi
[[ "$(<"$QUERY_COUNTER")" == 2 ]]
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });

  it('converges on the bounded retry after a late cleanup failure removed the run root', async () => {
    const runRoot = path.join(temporaryRoot, 'late-cleanup-run');
    const harnessPath = path.join(temporaryRoot, 'late-cleanup-retry-harness.sh');
    await mkdir(runRoot, { mode: 0o700 });
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
RUN_DIR=${JSON.stringify(runRoot)}
RUN_DIR_IDENTITY="$(capture_path_identity "$RUN_DIR")"
STATE_HANDLE_ROOT=owned-state-root
PROXY_PIDS=()
PROXY_PGIDS=()
PROXY_TOKENS=()
CANDIDATE_PROJECT_STARTED=0
ORACLE_PROJECT_STARTED=0
late_failures=0
remove_state_handle_root() {
  if [[ "$late_failures" == 0 ]]; then late_failures=1; return 1; fi
  return 0
}
assert_ports_released() { return 0; }
set +e
cleanup_resources 0
first=$?
[[ "$first" == 1 && ! -e "$RUN_DIR" ]]
cleanup_resources 0
second=$?
[[ "$second" == 0 && "$TOPOLOGY_CLEANED" == 1 && ! -e "$RUN_DIR" ]]
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });

  it('preserves staging for a success-path retry and removes it on failure exit', async () => {
    const resultRoot = path.join(temporaryRoot, 'results');
    const staging = path.join(resultRoot, '.staging.failure');
    const final = path.join(resultRoot, 'result.failure');
    const harnessPath = path.join(temporaryRoot, 'cleanup-result-harness.sh');
    await mkdir(staging, { mode: 0o700, recursive: true });
    const harness = `#!/usr/bin/env bash
set -u
source ${JSON.stringify(runnerPath)}
RESULT_ROOT=${JSON.stringify(resultRoot)}
RESULT_ROOT_IDENTITY="$(capture_path_identity "$RESULT_ROOT")"
RESULT_STAGING_DIR=${JSON.stringify(staging)}
RESULT_STAGING_IDENTITY="$(capture_path_identity "$RESULT_STAGING_DIR")"
RESULT_DIR=${JSON.stringify(final)}
RESULT_DIR_IDENTITY=''
RESULT_PUBLISHED=0
PROXY_PIDS=()
PROXY_PGIDS=()
PROXY_TOKENS=()
CANDIDATE_PROJECT_STARTED=1
ORACLE_PROJECT_STARTED=0
RUN_DIR=''
STATE_HANDLE_ROOT=''
cleanup_project() { return 1; }
assert_ports_released() { return 0; }
cleanup_resources 0
first=$?
[[ "$first" == 1 && -d "$RESULT_STAGING_DIR" && ! -e "$RESULT_DIR" ]]
cleanup_resources 1
second=$?
[[ "$second" == 1 && ! -e "$RESULT_STAGING_DIR" && ! -e "$RESULT_DIR" ]]
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types */
