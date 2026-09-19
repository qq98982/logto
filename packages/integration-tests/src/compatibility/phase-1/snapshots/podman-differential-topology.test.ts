/* eslint-disable no-template-curly-in-string -- Shell contract assertions compare literal expansions. */
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const source = path.join(
  repositoryRoot,
  'docker-compose.phase1-runtime-candidate-differential.yml'
);
const generator = path.join(
  repositoryRoot,
  '.scripts/compatibility/phase1-podman-differential-topology.mjs'
);
const launcher = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase1-runtime-candidate.sh'
);
const candidates = new Set([
  'candidate-primary-init',
  'candidate-primary-core',
  'candidate-foreign-init',
  'candidate-foreign-core',
  'candidate-fixture-coordinator',
]);
type Service = Readonly<{
  depends_on?: Readonly<Record<string, unknown>>;
  volumes?: readonly string[];
  tmpfs?: readonly string[];
  userns_mode?: string;
  ports?: ReadonlyArray<{ target: number; host_ip: string; protocol: string }>;
}>;
type Topology = Readonly<{
  services: Readonly<Record<string, Service>>;
  networks: unknown;
  volumes: unknown;
}>;
const parse = async (file: string): Promise<Topology> =>
  JSON.parse(await readFile(file, 'utf8')) as Topology;

// eslint-disable-next-line complexity -- One contract checks each service against the baseline.
it('keeps bounded private candidate tmpfs and all other differential authority unchanged on Podman', async () => {
  const runDirectory = await mkdtemp('/var/tmp/henry-build/aster-p1-podman-topology-');
  const output = path.join(runDirectory, 'podman-differential-compose.json');
  try {
    const baseline = await parse(source);
    await executeFile(process.execPath, [generator, source, runDirectory, output]);
    const actual = await parse(output);
    const outputInfo = await stat(output);
    expect(outputInfo.mode.toString(8).slice(-3)).toBe('600');
    expect(actual.networks).toEqual(baseline.networks);
    expect(actual.volumes).toEqual(baseline.volumes);
    expect(Object.keys(actual.services)).toEqual(Object.keys(baseline.services));
    const runner = await readFile(launcher, 'utf8');
    const bindingBlock = runner.split('readonly LOOPBACK_PROXY_BINDINGS=(')[1]?.split('\n)')[0];
    expect(bindingBlock).toBeDefined();
    const expectedPorts = new Map<string, number[]>();
    for (const [, service, port] of bindingBlock?.matchAll(/'([^|']+)\|[^|']+\|\d+\|(\d+)'/gu) ??
      []) {
      if (!service || !port) {
        throw new Error('invalid proxy binding');
      }
      expectedPorts.set(service, [...(expectedPorts.get(service) ?? []), Number(port)]);
    }
    expect(expectedPorts.size).toBe(6);
    expect([...expectedPorts.values()].every((ports) => ports.length === 2)).toBe(true);

    for (const [name, service] of Object.entries(baseline.services)) {
      const generated = actual.services[name];
      const targets = expectedPorts.get(name);
      const ports = targets?.map((target) => ({ target, host_ip: '127.0.0.1', protocol: 'tcp' }));
      if (candidates.has(name)) {
        expect(service.tmpfs).toHaveLength(2);
        expect(service.userns_mode).toBe('host');
        expect(generated).toEqual({
          ...service,
          tmpfs: [
            '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
            '/run/aster:rw,noexec,nosuid,nodev,size=16m,mode=0777',
          ],
          userns_mode: 'keep-id',
          ...(ports ? { ports } : {}),
        });
      } else if (name === 'candidate-primary-postgres' || name === 'candidate-foreign-postgres') {
        expect(generated).toEqual({
          ...service,
          volumes: service.volumes?.map((mount) =>
            mount.startsWith('./.scripts/')
              ? `${path.join(repositoryRoot, mount.slice(2, mount.indexOf(':')))}${mount.slice(mount.indexOf(':'))}`
              : mount
          ),
        });
      } else {
        expect(generated).toEqual({ ...service, ...(ports ? { ports } : {}) });
      }
    }
    expect(await parse(source)).toEqual(baseline);
  } finally {
    await rm(runDirectory, { recursive: true, force: true });
  }
});

it('starts every Podman service after its healthy or completed dependencies', async () => {
  const [runner, topology] = await Promise.all([readFile(launcher, 'utf8'), parse(source)]);
  const start = runner.indexOf(
    'if [[ -n "${PODMAN_API_VERSION}" ]]; then\n  deadline=$((SECONDS + 600))'
  );
  const end = runner.indexOf('\nelse\n  compose up --detach "${SERVICES[@]}"', start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const stages = runner
    .slice(start, end)
    .split(/\n {2}start_podman_stage /u)
    .slice(1)
    .map((stage) =>
      stage
        .replaceAll(/\\\n\s*/gu, ' ')
        .trim()
        .split(/\s+/u)
    );
  expect(stages.map(([group]) => group)).toEqual([
    'dependencies',
    'init-and-oracle-core',
    'candidate-core',
    'fixture-coordinator',
  ]);
  const seen = new Set<string>();
  for (const [, ...services] of stages) {
    for (const name of services) {
      expect(seen.has(name)).toBe(false);
      expect(topology.services).toHaveProperty(name);
      for (const dependency of Object.keys(topology.services[name]?.depends_on ?? {})) {
        expect(seen.has(dependency)).toBe(true);
      }
    }
    for (const name of services) {
      seen.add(name);
    }
  }
  expect(seen).toEqual(new Set(Object.keys(topology.services)));
  expect(runner).toContain('compose up --no-deps --detach "${service}"');
  expect(runner).toContain(
    'if [[ -n "${ENGINE_SOCKET}" ]]; then\n    validate_engine_socket "${ENGINE_SOCKET}"'
  );
  expect(runner).toContain(
    '"${project}" == "${project_name}" && "${service_label}" == "${service}"'
  );
  expect(runner).toContain('/libpod/containers/${inspected_id}/healthcheck');
  expect(runner).toContain('http_status="$(podman_timeout');
  expect(runner).toContain('podman_timeout "${ENV_BIN}" -i');
  expect(runner).toContain('--max-time 20 --output /dev/null');
  expect(runner).toContain('wait_for_services "${SERVICES[@]}"');
  expect(runner).toContain(
    'else\n  compose up --detach "${SERVICES[@]}" >/dev/null || fail\n  deadline=$((SECONDS + 600))\nfi'
  );
  expect(runner).toContain('PODMAN_WAIT_DEADLINE=${deadline}');
  expect(runner).toContain('wait_for_services "${SERVICES[@]}"\nPODMAN_WAIT_DEADLINE=');
  expect(runner).toContain(
    'for port in "${PORTS[@]}"; do\n  failure_stage="http-readiness:${port}"'
  );
  expect(runner).toContain('done\nfailure_stage=topology-readiness\n[[ -S "${FIXTURE_SOCKET}" ]]');
});

it('resolves only a single owned Podman loopback port and leaves Docker direct-IP routing intact', async () => {
  const runner = await readFile(launcher, 'utf8');
  const start = runner.indexOf('container_published_port() {');
  expect(start).toBeGreaterThan(0);
  const resolver = runner.slice(start, runner.indexOf('\n}\n', start) + 3);
  const id = 'a'.repeat(64);
  const validPorts = { '3001/tcp': [{ HostIp: '127.0.0.1', HostPort: '49152' }] };
  const cases: ReadonlyArray<readonly [string, unknown, string, string, string]> = [
    ['valid', validPorts, id, 'fixture', 'candidate-primary-core'],
    ['wrong container', validPorts, 'b'.repeat(64), 'fixture', 'candidate-primary-core'],
    ['wrong project', validPorts, id, 'other', 'candidate-primary-core'],
    ['wrong service', validPorts, id, 'fixture', 'oracle-primary-core'],
    ['missing', {}, id, 'fixture', 'candidate-primary-core'],
    [
      'ambiguous',
      { '3001/tcp': [...validPorts['3001/tcp'], ...validPorts['3001/tcp']] },
      id,
      'fixture',
      'candidate-primary-core',
    ],
    [
      'nonloopback',
      { '3001/tcp': [{ HostIp: '0.0.0.0', HostPort: '49152' }] },
      id,
      'fixture',
      'candidate-primary-core',
    ],
    [
      'malformed port',
      { '3001/tcp': [{ HostIp: '127.0.0.1', HostPort: '49152x' }] },
      id,
      'fixture',
      'candidate-primary-core',
    ],
    [
      'port out of range',
      { '3001/tcp': [{ HostIp: '127.0.0.1', HostPort: '65536' }] },
      id,
      'fixture',
      'candidate-primary-core',
    ],
  ];
  await Promise.all(
    cases.map(async ([scenario, ports, inspectedId, project, service]) => {
      const metadata = `${JSON.stringify(ports)}|${inspectedId}|${project}|${service}`;
      const script = `set -euo pipefail
CLOSED_NODE_ENV=(env -i PATH=/usr/bin:/bin)
NODE_BIN=${JSON.stringify(process.execPath)}
project_name=fixture
compose() { printf '%s' '${id}'; }
docker_cli() { printf '%s\\n' '${metadata}'; }
${resolver}
container_published_port candidate-primary-core 3001`;
      return scenario === 'valid'
        ? expect(executeFile('/usr/bin/bash', ['-c', script])).resolves.toMatchObject({
            stdout: '49152',
            stderr: '',
          })
        : expect(executeFile('/usr/bin/bash', ['-c', script])).rejects.toMatchObject({
            code: 1,
            stdout: '',
            stderr: '',
          });
    })
  );
  await expect(
    executeFile('/usr/bin/bash', [
      '-c',
      `set -euo pipefail
${resolver}
container_published_port candidate-primary-core 65536`,
    ])
  ).rejects.toMatchObject({ code: 1, stderr: '' });
  expect(runner).toContain('if [[ -n "${PODMAN_API_VERSION}" ]]; then\n    target_ip=127.0.0.1');
  expect(runner).toContain('target_ip="$(container_network_ipv4 "${service}" "${network}")"');
  expect(runner).toContain('fail_service podman-published-port "${service}"');
  expect(runner).toContain('"TCP4-LISTEN:${host_port},bind=127.0.0.1,reuseaddr,fork"');
  expect(runner).toContain('"TCP4:${target_ip}:${target_port}"');
});

it('serializes Podman service creation while retaining the stage readiness barrier', async () => {
  const runner = await readFile(launcher, 'utf8');
  const start = runner.indexOf('start_podman_stage() {');
  const stageFunction = runner.slice(start, runner.indexOf('\n}\n', start) + 3);
  const { stdout } = await executeFile('/usr/bin/bash', [
    '-c',
    `set -euo pipefail
deadline=$((SECONDS + 10))
${stageFunction}
compose() { printf 'up:%s\n' "\${*: -1}" >&3; }
wait_for_services() { printf 'wait:%s\n' "$*" >&3; }
fail() { exit 1; }
start_podman_stage candidate-core candidate-primary-core candidate-foreign-core 3>&1`,
  ]);
  expect(stdout).toBe(
    'up:candidate-primary-core\nup:candidate-foreign-core\nwait:candidate-primary-core candidate-foreign-core\n'
  );
});

it('reports only fixed Podman failure stages, allowlisted services, and sanitized HTTP status', async () => {
  const runner = await readFile(launcher, 'utf8');
  const extract = (name: string): string => {
    const start = runner.indexOf(`${name}() {`);
    expect(start).toBeGreaterThan(0);
    return runner.slice(start, runner.indexOf('\n}\n', start) + 3);
  };
  const setup = `set -euo pipefail
RUNTIME_GATE=differential
failure_stage=compose-up
SERVICES=(candidate-primary-core)
PODMAN_API_VERSION=4.9.3
PODMAN_WAIT_DEADLINE=''
ENGINE_SOCKET=unused
ENV_BIN=env
PRIVATE_HOME=/tmp
CURL_BIN=curl
project_name=fixture
probe_id=${'a'.repeat(64)}
fail() { printf 'Aster runtime candidate gate failed (%s: %s)\\n' "$RUNTIME_GATE" "$failure_stage" >&2; exit 1; }
${extract('fail_service')}
${extract('wait_for_services')}
${extract('start_podman_stage')}
compose() { if [[ "$1" == up ]]; then return 1; fi; printf '%s' "$probe_id"; }
docker_cli() {
  [[ "$scenario" != inspect-failure ]] || return 1
  if [[ "$scenario" == container-exit ]]; then
    printf '%s|exited|1||fixture|candidate-primary-core' "$probe_id"
  else
    printf '%s|running|0|starting|fixture|candidate-primary-core' "$probe_id"
  fi
}
validate_engine_socket() { :; }
podman_timeout() { [[ "$scenario" != health-rpc ]] || return 124; printf '%s' "$health_http"; }
`;
  await Promise.all(
    [
      [
        'start',
        '',
        'deadline=$((SECONDS + 10)); start_podman_stage candidate-core candidate-primary-core',
        'podman-start:candidate-core',
      ],
      [
        'inspect-failure',
        '',
        'deadline=$((SECONDS + 10)); wait_for_services candidate-primary-core',
        'podman-inspect:candidate-primary-core',
      ],
      [
        'container-exit',
        '',
        'deadline=$((SECONDS + 10)); wait_for_services candidate-primary-core',
        'podman-container-exit:candidate-primary-core',
      ],
      [
        'health-rpc',
        '',
        'deadline=$((SECONDS + 10)); wait_for_services candidate-primary-core',
        'podman-health-rpc:candidate-primary-core',
      ],
      [
        'health',
        '503',
        'deadline=$((SECONDS + 10)); wait_for_services candidate-primary-core',
        'podman-health-http-503:candidate-primary-core',
      ],
      [
        'health',
        '503;private',
        'deadline=$((SECONDS + 10)); wait_for_services candidate-primary-core',
        'podman-health-http-invalid:candidate-primary-core',
      ],
      [
        'deadline',
        '',
        'deadline=0; wait_for_services candidate-primary-core',
        'podman-readiness-deadline:candidate-primary-core',
      ],
    ].map(async ([scenario, healthHttp, command, stage]) =>
      expect(
        executeFile('/usr/bin/bash', [
          '-c',
          `${setup}scenario=${scenario}; health_http='${healthHttp}'; ${command}`,
        ])
      ).rejects.toMatchObject({
        code: 1,
        stderr: `Aster runtime candidate gate failed (differential: ${stage})\n`,
      })
    )
  );
  await expect(
    executeFile('/usr/bin/bash', [
      '-c',
      `${setup}fail_service podman-inspect 'not-allowlisted:private'`,
    ])
  ).rejects.toMatchObject({
    code: 1,
    stderr: 'Aster runtime candidate gate failed (differential: podman-inspect)\n',
  });
});

it('bounds Podman RPCs by remaining startup time without extending later gate work', async () => {
  const runner = await readFile(launcher, 'utf8');
  const start = runner.indexOf('podman_timeout() {');
  const end = runner.indexOf('\n}\n', start) + 3;
  expect(start).toBeGreaterThan(0);
  const functionSource = runner.slice(start, end);
  const setup = `set -euo pipefail\nfail() { exit 42; }\nTIMEOUT_BIN=/usr/bin/timeout\n${functionSource}\n`;
  await executeFile('/usr/bin/bash', [
    '-c',
    `${setup}PODMAN_WAIT_DEADLINE=''; podman_timeout /usr/bin/true`,
  ]);
  await expect(
    executeFile('/usr/bin/bash', [
      '-c',
      `${setup}PODMAN_WAIT_DEADLINE=$((SECONDS + 1)); podman_timeout /usr/bin/sleep 10`,
    ])
  ).rejects.toMatchObject({ code: 124 });
  await expect(
    executeFile('/usr/bin/bash', [
      '-c',
      `${setup}PODMAN_WAIT_DEADLINE=$((SECONDS - 1)); podman_timeout /usr/bin/true`,
    ])
  ).rejects.toMatchObject({ code: 42 });
});
/* eslint-enable no-template-curly-in-string */
