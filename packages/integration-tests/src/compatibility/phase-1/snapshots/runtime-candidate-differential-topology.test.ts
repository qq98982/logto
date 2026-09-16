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
] as const;
const phase0CandidateServices = [
  'candidate-phase0-postgres',
  'candidate-phase0-init',
  'candidate-phase0-core',
  'candidate-phase0-fixture-coordinator',
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

  it('defines one primary-only Aster Phase 0 stack with exact isolated authority', async () => {
    const document = await readCompose(topologyPath);
    const postgres = document.services['candidate-phase0-postgres'];
    const init = document.services['candidate-phase0-init'];
    const core = document.services['candidate-phase0-core'];
    const coordinator = document.services['candidate-phase0-fixture-coordinator'];

    expect(document.networks['candidate-phase0']).toEqual({
      internal: true,
      ipam: { config: [{ subnet: '172.30.243.0/24' }] },
    });
    expect(postgres).toMatchObject({
      environment: {
        POSTGRES_USER: 'postgres',
        POSTGRES_DB: 'postgres',
        ASTER_PHASE1_INIT_CIDR: '172.30.243.11/32',
        ASTER_PHASE1_CORE_CIDR: '172.30.243.12/32',
        ASTER_PHASE1_COORDINATOR_CIDR: '172.30.243.13/32',
      },
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.10' } },
    });
    expect(init).toMatchObject({
      command: ['init', 'phase0'],
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.11' } },
      environment: {
        ASTER_PHASE1_PHASE0_CONFIG_FILE: ['$', '{ASTER_PHASE1_PHASE0_CONFIG_FILE:?required}'].join(
          ''
        ),
        ASTER_PHASE1_PHASE0_MASTER_KEY_FILE: '/var/lib/aster/phase0/aster-master-key.json',
      },
    });
    expect(core).toMatchObject({
      command: ['core', 'phase0'],
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.12' } },
      environment: {
        ASTER_PHASE1_DATA_ISSUER: 'http://localhost:3341/oidc',
        ASTER_PHASE1_ADMIN_ISSUER: 'http://localhost:3441/oidc',
        ASTER_PHASE1_ADMIN_ORIGIN: 'http://localhost:3441',
      },
    });
    expect(coordinator).toMatchObject({
      command: ['fixture-coordinator', 'phase0'],
      networks: { 'candidate-phase0': { ipv4_address: '172.30.243.13' } },
      environment: {
        ASTER_FIXTURE_SOCKET: ['$', '{ASTER_PHASE1_PHASE0_FIXTURE_SOCKET:?required}'].join(''),
      },
    });
    expect(JSON.stringify(core)).not.toMatch(/DB_URL|DATABASE_URL|POSTGRES|PASSWORD|SENTINEL/iu);
    expect(JSON.stringify(coordinator)).not.toMatch(/FOREIGN/iu);
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
        'candidate-phase0-keyring',
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
    expect(
      Object.keys(document.services).some((name) => name.includes('candidate-phase0-redis'))
    ).toBe(false);
  });
});

/* eslint-enable no-use-extend-native/no-use-extend-native */
