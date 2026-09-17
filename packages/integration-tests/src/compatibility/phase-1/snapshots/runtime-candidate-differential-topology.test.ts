/* eslint-disable no-use-extend-native/no-use-extend-native -- Exact service, network, and volume authority comparisons use ES2023 non-mutating sorting. */
import { readFile } from 'node:fs/promises';
import path from 'node:path';

type ComposeService = Readonly<Record<string, unknown>>;
type ComposeDocument = Readonly<{
  services: Readonly<Record<string, ComposeService>>;
  networks: Readonly<Record<string, unknown>>;
  volumes: Readonly<Record<string, unknown>>;
}>;

const repositoryRoot = path.resolve(process.cwd(), '../..');
const topologyPath = path.join(
  repositoryRoot,
  'docker-compose.phase1-runtime-candidate-differential.yml'
);
const formalPath = path.join(repositoryRoot, 'docker-compose.phase1-compatibility.yml');
const candidatePath = path.join(repositoryRoot, 'docker-compose.phase1-aster-candidate.yml');
const runtimeRunnerPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase1-runtime-candidate.sh'
);
const differentialWrapperPath = path.join(
  repositoryRoot,
  '.scripts/compatibility/test-runtime-candidate-differential.sh'
);

const readCompose = async (filePath: string): Promise<ComposeDocument> =>
  JSON.parse(await readFile(filePath, 'utf8')) as ComposeDocument;

const oracleServices = [
  'oracle-primary-postgres',
  'oracle-primary-redis',
  'oracle-primary-core',
  'oracle-foreign-postgres',
  'oracle-foreign-redis',
  'oracle-foreign-core',
  'oracle-phase0-postgres',
  'oracle-phase0-redis',
  'oracle-phase0-core',
] as const;
const measuredCandidateServices = [
  'candidate-primary-postgres',
  'candidate-primary-init',
  'candidate-primary-core',
  'candidate-foreign-postgres',
  'candidate-foreign-init',
  'candidate-foreign-core',
  'candidate-fixture-coordinator',
  'candidate-connector-host',
  'candidate-saml-host',
  'candidate-script-host',
] as const;
const phase0CandidateServices = [
  'candidate-phase0-postgres',
  'candidate-phase0-redis',
  'candidate-phase0-core',
] as const;

describe('runtime-candidate differential topology', () => {
  it('copies reviewed Oracle and measured candidate services exactly', async () => {
    const [document, formal, candidate] = await Promise.all([
      readCompose(topologyPath),
      readCompose(formalPath),
      readCompose(candidatePath),
    ]);

    expect(Object.keys(document.services).toSorted()).toEqual(
      [...oracleServices, ...measuredCandidateServices, ...phase0CandidateServices].toSorted()
    );
    for (const service of oracleServices) {
      expect(document.services[service]).toEqual(formal.services[service]);
    }
    for (const service of measuredCandidateServices) {
      expect(document.services[service]).toEqual(candidate.services[service]);
    }
  });

  it('defines one isolated reference-mirror Phase 0 candidate stack', async () => {
    const document = await readCompose(topologyPath);
    const postgres = document.services['candidate-phase0-postgres'];
    const redis = document.services['candidate-phase0-redis'];
    const core = document.services['candidate-phase0-core'];

    expect(document.networks['candidate-phase0']).toEqual({
      internal: true,
      ipam: { config: [{ subnet: '172.30.243.0/24' }] },
    });
    expect(postgres).toMatchObject({
      image: ['$', '{ASTER_PHASE1_POSTGRES_IMAGE:?required}'].join(''),
      environment: {
        POSTGRES_USER: 'aster',
        POSTGRES_DB: 'aster',
      },
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.10' } },
      volumes: ['candidate-phase0-postgres:/var/lib/postgresql/data'],
    });
    expect(redis).toMatchObject({
      image: ['$', '{ASTER_PHASE1_REDIS_IMAGE:?required}'].join(''),
      command: ['redis-server', '--appendonly', 'yes'],
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.11' } },
      volumes: ['candidate-phase0-redis:/data'],
    });
    expect(core).toMatchObject({
      image: ['$', '{ASTER_PHASE1_PHASE0_CONTROL_IMAGE:?required}'].join(''),
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.12' } },
      environment: {
        ENDPOINT: 'http://localhost:3341',
        ADMIN_ENDPOINT: 'http://localhost:3441',
        ADMIN_PORT: '3441',
      },
    });
    expect(JSON.stringify(core)).not.toContain('ASTER_PHASE1_CANDIDATE_IMAGE');
    expect(JSON.stringify(document.services)).not.toContain('fixture-coordinator phase0');
  });

  it('uses exact closed networks volumes and rootless service policy', async () => {
    const [source, document] = await Promise.all([
      readFile(topologyPath, 'utf8'),
      readCompose(topologyPath),
    ]);

    expect(Object.keys(document.networks).toSorted()).toEqual(
      [
        'oracle-primary',
        'oracle-foreign',
        'oracle-phase0',
        'candidate-primary',
        'candidate-foreign',
        'candidate-phase0',
        'candidate-connector-boundary',
        'candidate-saml-boundary',
        'candidate-script-boundary',
      ].toSorted()
    );
    expect(Object.keys(document.volumes).toSorted()).toEqual(
      [
        'oracle-primary-postgres',
        'oracle-primary-redis',
        'oracle-foreign-postgres',
        'oracle-foreign-redis',
        'oracle-phase0-postgres',
        'oracle-phase0-redis',
        'candidate-primary-postgres',
        'candidate-foreign-postgres',
        'candidate-phase0-postgres',
        'candidate-primary-keyring',
        'candidate-foreign-keyring',
        'candidate-phase0-redis',
      ].toSorted()
    );
    for (const service of Object.values(document.services)) {
      expect(service).not.toHaveProperty('ports');
      expect(service).not.toHaveProperty('privileged');
      expect(service).not.toHaveProperty('cap_add');
      expect(service).not.toHaveProperty('network_mode');
      expect(JSON.stringify(service)).not.toContain('docker.sock');
    }
    expect(source).not.toMatch(/\b(?:anchors|extends|include|profiles):/u);
    expect(source).not.toContain('/dev/shm');
    expect(Object.keys(document.services)).toContain('candidate-phase0-redis');
  });

  it('runs only explicit non-publishable runtime gates with owned cleanup', async () => {
    const [source, wrapper] = await Promise.all([
      readFile(runtimeRunnerPath, 'utf8'),
      readFile(differentialWrapperPath, 'utf8'),
    ]);

    expect(source.startsWith('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n')).toBe(true);
    for (const required of [
      '/var/tmp/henry-build',
      'docker-compose.phase1-runtime-candidate-differential.yml',
      'prepare-review-profile',
      'run-differential',
      'run-candidate-invariants',
      "ASTER_PHASE1_MODE='runtime-candidate'",
      ['HOST_BIN_DIRECTORY="', '$', '{RUN_DIR}/host-bin"'].join(''),
      'docker_cli cp',
      '/usr/local/bin/aster-admin',
      ['PATH="', '$', '{HOST_BIN_DIRECTORY}:/usr/bin:/bin"'].join(''),
      ['FIXTURE_DIRECTORY="', '$', '{RUN_DIR}/fx"'].join(''),
      ['BROWSER_CACHE="', '$', '{BUILD_ROOT}/aster-playwright-browsers"'].join(''),
      ['PLAYWRIGHT_BROWSERS_PATH="', '$', '{BROWSER_CACHE}"'].join(''),
      ['require_private_root "', '$', '{BROWSER_CACHE}"'].join(''),
      ['[[ "', '$', '{#FIXTURE_SOCKET}" -le 107 ]] || fail'].join(''),
      'ASTER_FIXTURE_SOCKET=',
      'ASTER_PHASE1_PHASE0_CANDIDATE_IMAGE_DIGEST=',
      'phase-1-differential.json',
      'phase-1-candidate-invariants.json',
      'value.scenarios.length !== 22',
      'scenario.differences.length !== 0',
      'value.outcomes.length !== 18',
      'value.observationNegativeControls.length !== 6',
      'aster-phase1-candidate-invariant-evidence',
      'terminate_owned_process_group',
      ['container_id="$(compose ps --all -q "', '$', '{service}" 2>/dev/null || true)"'].join(''),
      ['container_id="$(compose ps --all -q "', '$', '{service}")"'].join(''),
      'label=com.docker.compose.project=',
      '^[A-Za-z0-9._/:-]+@sha256:',
      ['rm -rf -- "', '$', '{RUN_DIR}"'].join(''),
    ]) {
      expect(source).toContain(required);
    }
    for (const forbidden of [
      '--record-oracle',
      'evidence-manifest.json',
      'harness-result.json',
      'phase-1-browser.json',
      'phase-1-conformance.json',
      'docker.sock',
      '/dev/shm',
      'ASTER_PHASE1_PHASE0_CANDIDATE_FIXTURE_SOCKET=',
    ]) {
      expect(source).not.toContain(forbidden);
    }
    expect(wrapper).toContain("export ASTER_PHASE1_RUNTIME_GATE='differential'");
    expect(wrapper).toContain(
      ['exec "', '$', '{SCRIPT_DIR}/run-phase1-runtime-candidate.sh"'].join('')
    );
    expect(wrapper).not.toContain('run-candidate-invariants');
  });
});

/* eslint-enable no-use-extend-native/no-use-extend-native */
