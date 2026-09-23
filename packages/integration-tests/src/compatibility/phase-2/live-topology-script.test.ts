/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types -- This contract test keeps the complete security-sensitive runner and cleanup retry harnesses together for source and behavioral auditing. */
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
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
    expect(source).toContain('port_is_listened_by_pid');
    expect(source).toContain('http_ready');
    expect(source).toContain(
      'printf \'Host: localhost:%s\\r\\nConnection: close\\r\\n\\r\\n\' "$port"'
    );
    expect(source).not.toContain("printf 'Host: localhost\\r\\nConnection: close\\r\\n\\r\\n'");
    expect(source).toContain('wait_for_fixture_socket');
    expect(source).toMatch(
      /libpod\/containers\/\$\{id\}\/healthcheck[\s\S]*\/usr\/bin\/sleep 1\n\s*continue/u
    );
    expect(source).not.toContain('assert_driver_discovery_port');
    expect(source).not.toMatch(/--filter\s+"publish=\$\{?port/u);
    expect(source).not.toMatch(
      /CANDIDATE_SERVICES=\([\s\S]*candidate-(?:phase0|connector-host|saml-host|script-host)/u
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

  it('builds one tracked runtime bundle and runs all three modes with fixed output names', () => {
    expect(source).toContain('packages/integration-tests/src/compatibility/phase-2/launcher.mjs');
    expect(source.match(/launchPhase2Batch/gmu)).toHaveLength(2);
    expect(source).toContain("failure_stage='evidence-batch'");
    expect(source).toContain("failure_stage='runtime-fence-after-evidence'");
    expect(source).not.toContain('compatibility:phase2 --');
    for (const command of ['oracle', 'differential', 'candidate-invariants']) {
      expect(source).toContain(`Object.freeze(['${command}'`);
    }
    for (const artifact of [
      'phase-2-client-credentials-oracle.json',
      'phase-2-client-credentials-differential.json',
      'phase-2-client-credentials-candidate-invariants.json',
    ]) {
      expect(source).toContain(artifact);
    }
  });

  it('validates the closed evidence counts, provenance, sanitizer, and public topology', () => {
    for (const marker of [
      'scenarioCount !== 20',
      'controlCount !== 12',
      'comparisonCount !== 20',
      'invariantCount !== 4',
      'differenceCount !== 0',
      'sanitizerSuccess !== true',
      'runtimeBundleSha256',
      'baseAcceptance',
      'primaryRole',
      'foreignRole',
      'forbiddenPrivateValues',
    ]) {
      expect(source).toContain(marker);
    }
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
  });

  it('publishes results only after successful topology cleanup', () => {
    expect(source).toContain('.staging.XXXXXX');
    expect(source).toContain('RESULT_STAGING_IDENTITY');
    expect(source).toContain('remove_owned_result_directory');
    expect(source).toContain('verify_published_result_directory');
    expect(source).toContain('--no-clobber --no-target-directory');
    const cleanup = source.lastIndexOf('cleanup_resources 0');
    const publish = source.lastIndexOf('--no-clobber --no-target-directory');
    expect(cleanup).toBeGreaterThan(0);
    expect(publish).toBeGreaterThan(cleanup);
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

  it('converges after a late cleanup failure removed the run root', async () => {
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
late_failure=0
remove_state_handle_root() {
  if [[ "$late_failure" == 0 ]]; then late_failure=1; return 1; fi
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

  it('removes hidden result staging when topology cleanup fails', async () => {
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
status=$?
[[ "$status" == 1 && ! -e "$RESULT_STAGING_DIR" && ! -e "$RESULT_DIR" ]]
`;
    await writeFile(harnessPath, harness, { mode: 0o500 });

    await expect(runBash(harnessPath)).resolves.toEqual({ code: 0, stderr: '' });
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types */
