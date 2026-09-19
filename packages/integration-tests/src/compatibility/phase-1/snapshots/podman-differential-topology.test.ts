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
}>;
type Topology = Readonly<{
  services: Readonly<Record<string, Service>>;
  networks: unknown;
  volumes: unknown;
}>;
const parse = async (file: string): Promise<Topology> =>
  JSON.parse(await readFile(file, 'utf8')) as Topology;

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

    for (const [name, service] of Object.entries(baseline.services)) {
      const generated = actual.services[name];
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
        expect(generated).toEqual(service);
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
  expect(stages).toHaveLength(4);
  const seen = new Set<string>();
  for (const stage of stages) {
    for (const name of stage) {
      expect(seen.has(name)).toBe(false);
      expect(topology.services).toHaveProperty(name);
      for (const dependency of Object.keys(topology.services[name]?.depends_on ?? {})) {
        expect(seen.has(dependency)).toBe(true);
      }
    }
    for (const name of stage) {
      seen.add(name);
    }
  }
  expect(seen).toEqual(new Set(Object.keys(topology.services)));
  expect(runner).toContain('compose up --no-deps --detach "$@"');
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
