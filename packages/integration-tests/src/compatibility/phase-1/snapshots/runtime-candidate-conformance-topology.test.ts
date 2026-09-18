/* eslint-disable max-lines, no-template-curly-in-string -- This cohesive topology contract intentionally asserts literal shell interpolation syntax. */
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

type ComposeService = Readonly<{
  image?: string;
  build?: unknown;
  command?: readonly string[];
  depends_on?: Readonly<Record<string, Readonly<{ condition?: string }>>>;
  environment?: Readonly<Record<string, unknown>>;
  networks?: Readonly<Record<string, Readonly<{ aliases?: readonly string[] }>>>;
  volumes?: readonly string[];
  tmpfs?: readonly string[];
  user?: string;
  userns_mode?: string;
  read_only?: boolean;
  security_opt?: readonly string[];
  healthcheck?: Readonly<{ test?: readonly string[] }>;
  labels?: Readonly<Record<string, string>>;
  ports?: unknown;
  privileged?: unknown;
  cap_add?: unknown;
  network_mode?: unknown;
}>;
type ComposeDocument = Readonly<{
  'x-aster-project-name': string;
  services: Readonly<Record<string, ComposeService>>;
  networks: Readonly<
    Record<
      string,
      Readonly<{
        internal?: boolean;
        ipam?: Readonly<{ config?: ReadonlyArray<Readonly<{ subnet?: string }>> }>;
      }>
    >
  >;
  volumes: Readonly<Record<string, Readonly<{ labels?: Readonly<Record<string, string>> }>>>;
}>;

const executeFile = promisify(execFile);
const repositoryRoot = path.resolve(process.cwd(), '../..');
const topologyPath = path.join(
  repositoryRoot,
  'docker-compose.phase1-runtime-candidate-conformance.yml'
);
const pkiPath = path.join(repositoryRoot, '.scripts/compatibility/phase1-conformance-pki.sh');
const dockerfilePath = path.join(repositoryRoot, 'Dockerfile.phase1-oidf-suite');
const nginxPath = path.join(repositoryRoot, '.scripts/compatibility/phase1-conformance-nginx.conf');
const lifecyclePath = path.join(
  repositoryRoot,
  '.scripts/compatibility/run-phase1-runtime-candidate-conformance.sh'
);
const required = (name: string): string => ['$', `{${name}:?required}`].join('');
const serviceNames = Object.freeze([
  'candidate-primary-postgres',
  'candidate-primary-init',
  'candidate-conformance-core',
  'candidate-fixture-coordinator',
  'suite-mongo',
  'suite-server',
  'suite-nginx',
  'oidf-runner',
]);
const candidateHost = 'aster-server.aster-phase1-conformance.svc.cluster.local';
const suiteHost = 'conformance.aster-phase1-conformance.svc.cluster.local';
const cleanupLabels = Object.freeze({
  'com.aster.phase1.topology': 'runtime-candidate-conformance',
  'com.aster.phase1.cleanup': 'down-v',
});

const readCompose = async (): Promise<ComposeDocument> =>
  JSON.parse(await readFile(topologyPath, 'utf8')) as ComposeDocument;

describe('runtime-candidate official OIDF conformance topology', () => {
  it('defines the exact standalone services, isolated networks, aliases, and cleanup ownership', async () => {
    const document = await readCompose();

    expect(document['x-aster-project-name']).toBe(
      required('ASTER_PHASE1_CONFORMANCE_PROJECT_NAME')
    );
    expect(Object.keys(document.services)).toEqual(serviceNames);
    expect(document.networks).toEqual({
      db: { internal: true, ipam: { config: [{ subnet: '172.30.247.0/24' }] } },
      'suite-db': {
        internal: true,
        ipam: { config: [{ subnet: '172.30.248.0/24' }] },
      },
      'oidf-edge': {
        internal: true,
        ipam: { config: [{ subnet: '172.30.249.0/24' }] },
      },
    });
    expect(Object.keys(document.volumes)).toEqual([
      'candidate-primary-postgres',
      'candidate-primary-keyring',
      'candidate-fixture',
      'suite-mongo',
    ]);

    for (const service of Object.values(document.services)) {
      expect(service.labels).toEqual(expect.objectContaining(cleanupLabels));
      expect(service).not.toHaveProperty('ports');
      expect(service).not.toHaveProperty('privileged');
      expect(service).not.toHaveProperty('cap_add');
      expect(service).not.toHaveProperty('network_mode');
    }
    for (const volume of Object.values(document.volumes)) {
      expect(volume.labels).toEqual(cleanupLabels);
    }

    expect(document.services['candidate-conformance-core']?.networks).toEqual({
      db: { ipv4_address: '172.30.247.12' },
      'oidf-edge': { ipv4_address: '172.30.249.10', aliases: [candidateHost] },
    });
    expect(document.services['suite-nginx']?.networks).toEqual({
      'oidf-edge': { ipv4_address: '172.30.249.12', aliases: [suiteHost] },
    });
    expect(document.services['candidate-primary-postgres']?.networks).toEqual({
      db: { ipv4_address: '172.30.247.10' },
    });
    expect(document.services['suite-mongo']?.networks).toEqual({
      'suite-db': { ipv4_address: '172.30.248.10' },
    });
    expect(document.services['oidf-runner']?.networks).toEqual({
      'oidf-edge': { ipv4_address: '172.30.249.13' },
    });
    expect(document.services['candidate-primary-postgres']?.image).toBe(
      'docker.io/library/postgres:17-alpine@sha256:18cfe3ef5e6815560c98237d6216d1e5119702fb0f3894c8785dd58b8bbe5d73'
    );
    expect(document.services['oidf-runner']?.image).toBe(
      'docker.io/library/node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32'
    );
    for (const name of [
      'candidate-primary-init',
      'candidate-conformance-core',
      'candidate-fixture-coordinator',
    ]) {
      expect(document.services[name]?.image).toBe(required('ASTER_PHASE1_CANDIDATE_IMAGE_DIGEST'));
      expect(document.services[name]?.userns_mode).toBe('keep-id');
    }
  });

  it('keeps database and TLS material authority on the minimum services', async () => {
    const document = await readCompose();
    const { services } = document;
    const serialized = (name: string): string => JSON.stringify(services[name]);

    expect(services['candidate-primary-init']?.command).toEqual(['init', 'primary']);
    expect(services['candidate-conformance-core']?.command).toEqual([
      'conformance-core',
      'primary',
    ]);
    expect(services['candidate-fixture-coordinator']?.command).toEqual([
      'fixture-coordinator',
      'primary',
    ]);
    expect(services['candidate-conformance-core']?.environment).toMatchObject({
      ASTER_PHASE1_TLS_CERTIFICATE_FILE: '/etc/aster/pki/aster/tls.crt',
      ASTER_PHASE1_TLS_PRIVATE_KEY_FILE: '/etc/aster/pki/aster/tls.key',
      ASTER_PHASE1_TLS_CA_BUNDLE_FILE: '/etc/aster/pki/root-ca.crt',
    });

    for (const name of ['candidate-primary-init', 'candidate-conformance-core']) {
      expect(serialized(name)).not.toContain('/etc/aster/pki/suite/');
      expect(serialized(name)).not.toContain('suite-mongo');
      expect(serialized(name)).not.toMatch(/MONGODB|SPRING_MONGODB/iu);
    }
    expect(serialized('candidate-primary-init')).not.toContain('/etc/aster/pki/');
    expect(serialized('candidate-conformance-core')).toContain('/etc/aster/pki/root-ca.crt');
    expect(serialized('candidate-fixture-coordinator')).not.toContain('/etc/aster/pki/');
    expect(serialized('candidate-fixture-coordinator')).not.toContain('suite-mongo');

    expect(serialized('suite-nginx')).toContain('/etc/aster/pki/suite/tls.crt');
    expect(serialized('suite-nginx')).toContain('/etc/aster/pki/suite/tls.key');
    expect(serialized('suite-nginx')).not.toContain('root-ca.crt');
    expect(serialized('suite-nginx')).not.toContain('/etc/aster/pki/aster/');
    expect(services['suite-nginx']?.user).toBe(
      `${required('ASTER_PHASE1_RUNTIME_UID')}:${required('ASTER_PHASE1_RUNTIME_GID')}`
    );
    expect(services['suite-nginx']?.userns_mode).toBe('keep-id');
    expect(services['suite-nginx']?.tmpfs).toEqual(
      expect.arrayContaining([
        expect.stringContaining('/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777'),
        expect.stringContaining('/var/cache/nginx:rw,noexec,nosuid,nodev,size=32m,mode=0777'),
        expect.stringContaining('/var/run:rw,noexec,nosuid,nodev,size=8m,mode=0777'),
      ])
    );
    for (const name of ['suite-server', 'oidf-runner']) {
      expect(serialized(name)).toContain('/etc/aster/pki/root-ca.crt');
      expect(serialized(name)).not.toContain('/etc/aster/pki/aster/tls.key');
      expect(serialized(name)).not.toMatch(/POSTGRES|DATABASE_URL|MASTER_KEY/iu);
    }

    for (const [name, service] of Object.entries(services)) {
      const environment = JSON.stringify(service.environment ?? {});

      expect(environment).not.toMatch(/(?:PASSWORD|SECRET|TOKEN|KEY)":(?!"\/run\/secrets)/u);
      if (name !== 'candidate-primary-postgres') {
        expect(environment).not.toContain('POSTGRES_PASSWORD_FILE');
      }
    }
    expect(services['candidate-primary-postgres']?.environment).toMatchObject({
      POSTGRES_PASSWORD_FILE: '/run/secrets/postgres-password',
    });

    const runnerSecretMount = `${required(
      'ASTER_PHASE1_CONFORMANCE_SECRET_DIRECTORY'
    )}:/run/aster-secrets:ro`;
    const runnerDriverMount = `${required(
      'ASTER_PHASE1_CONFORMANCE_DRIVER_FILE'
    )}:/opt/aster/phase1-conformance-driver.sh:ro`;
    const runnerScriptMount = `${required(
      'ASTER_PHASE1_CONFORMANCE_RUNNER_FILE'
    )}:/opt/aster/phase1-conformance-runner.mjs:ro`;
    const topologySource = JSON.stringify(document);

    expect(services['oidf-runner']?.volumes).toContain(runnerSecretMount);
    expect(services['oidf-runner']?.volumes).toContain(runnerDriverMount);
    expect(services['oidf-runner']?.volumes).toContain(runnerScriptMount);
    expect(services['oidf-runner']?.userns_mode).toBe('keep-id');
    expect(topologySource.match(/ASTER_PHASE1_CONFORMANCE_SECRET_DIRECTORY/gu)).toHaveLength(1);
    for (const [name, service] of Object.entries(services)) {
      const runtimeAuthority = JSON.stringify({
        environment: service.environment,
        command: service.command,
      });

      expect(runtimeAuthority).not.toContain('ASTER_PHASE1_CONFORMANCE_SECRET_DIRECTORY');
      expect(runtimeAuthority).not.toContain('/run/aster-secrets');
      expect(runtimeAuthority).not.toMatch(/USER_PASSWORD|CLIENT_SECRET/iu);
      if (name !== 'oidf-runner') {
        expect(serialized(name)).not.toContain('/run/aster-secrets');
      }
    }
  });

  it('pins the suite source, image bases, runtime mode, and exact public URLs', async () => {
    const [document, dockerfile, nginx] = await Promise.all([
      readCompose(),
      readFile(dockerfilePath, 'utf8'),
      readFile(nginxPath, 'utf8'),
    ]);
    const suite = document.services['suite-server'];
    const runner = document.services['oidf-runner'];
    const source = JSON.stringify(document);

    expect(suite?.image).toBe(required('ASTER_PHASE1_OIDF_SUITE_IMAGE_DIGEST'));
    expect(suite).not.toHaveProperty('build');
    expect(suite?.environment).toMatchObject({
      BASE_URL: `https://${suiteHost}:8443`,
      BASE_MTLS_URL: `https://${suiteHost}:8443`,
      MONGODB_HOST: 'suite-mongo',
    });
    expect(suite?.labels).toMatchObject({
      'com.aster.phase1.oidf-suite-source-commit': '0dc0e3a21ec411e92c808e5b2e2258592c22b594',
      'com.aster.phase1.oidf-suite-image-id': required('ASTER_PHASE1_OIDF_SUITE_IMAGE_DIGEST'),
    });
    expect(suite?.environment).not.toHaveProperty('SPRING_PROFILES_ACTIVE');
    expect(runner?.command?.join(' ')).toContain('setInterval');
    expect(runner?.environment).toMatchObject({
      NODE_EXTRA_CA_CERTS: '/etc/aster/pki/root-ca.crt',
      ASTER_PHASE1_OIDF_RUNNER_MODE: 'wait-for-driver-exec',
    });
    expect(runner?.command?.join(' ')).not.toMatch(/plan|schedule|api/iu);
    expect(source).not.toMatch(/(?:^|["/:])latest(?:["/,]|$)/iu);
    expect(source).not.toContain('/dev/shm');
    expect(source).not.toMatch(/(?:^|,)uid=|(?:^|,)gid=/u);
    expect(source).not.toContain('root-ca.key');

    expect(dockerfile).toContain(
      'FROM docker.io/library/maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS builder'
    );
    expect(dockerfile).toContain(
      'FROM docker.io/library/eclipse-temurin:21-jre-jammy@sha256:61d6c7b34d36aee3f45d043101259f97f3c6d428dc2a6f75513789983c5e254f'
    );
    expect(dockerfile).toContain('mvn -B -Dmaven.test.skip=true -Dpmd.skip=true clean package');
    expect(dockerfile).toContain(
      ['org.opencontainers.image.revision="', '$', '{ASTER_PHASE1_OIDF_SUITE_COMMIT}"'].join('')
    );
    expect(dockerfile).toContain(
      'com.aster.phase1.maven-resolution="source-pom-not-fully-offline-locked"'
    );
    expect(dockerfile).toContain('COPY .git/HEAD /tmp/aster-phase1-oidf-suite-head');
    expect(dockerfile).toContain(
      'test "$(cat /tmp/aster-phase1-oidf-suite-head)" = "${ASTER_PHASE1_OIDF_SUITE_COMMIT}"'
    );
    expect(dockerfile).not.toMatch(/apt-get|curl/iu);
    expect(dockerfile).not.toMatch(/^FROM\s+[^\n]*:latest(?:\s|$)/gmu);

    expect(nginx).toContain(`server_name ${suiteHost};`);
    expect(nginx).toContain('ssl_certificate /etc/aster/pki/suite/tls.crt;');
    expect(nginx).toContain('ssl_certificate_key /etc/aster/pki/suite/tls.key;');
    expect(nginx).toContain('proxy_pass http://suite-server:8080;');
    expect(nginx).not.toMatch(/openssl|selfsigned|ssl_certificate\s+.*root-ca/iu);
  });

  it('applies read-only, no-new-privileges, health, and ephemeral storage policy', async () => {
    const document = await readCompose();

    for (const name of [
      'candidate-primary-init',
      'candidate-conformance-core',
      'candidate-fixture-coordinator',
      'suite-server',
      'suite-nginx',
      'oidf-runner',
    ]) {
      const service = document.services[name];

      expect(service?.read_only).toBe(true);
      expect(service?.security_opt).toEqual(['no-new-privileges:true']);
      expect(service?.user).toBeTruthy();
      expect(service?.tmpfs).toEqual(expect.arrayContaining([expect.stringContaining('/tmp:rw,')]));
    }
    for (const name of [
      'candidate-primary-postgres',
      'candidate-conformance-core',
      'candidate-fixture-coordinator',
      'suite-mongo',
      'suite-server',
      'suite-nginx',
      'oidf-runner',
    ]) {
      expect(document.services[name]?.healthcheck?.test).toBeTruthy();
    }
    expect(document.services['candidate-primary-init']?.depends_on).toEqual({
      'candidate-primary-postgres': { condition: 'service_healthy' },
    });
    expect(document.services['suite-server']?.depends_on).toEqual({
      'suite-mongo': { condition: 'service_healthy' },
    });
    expect(document.services['suite-nginx']?.depends_on).toEqual({
      'suite-server': { condition: 'service_healthy' },
    });
  });

  it('delegates the conformance runtime gate to the isolated lifecycle', async () => {
    const [dispatcher, lifecycle] = await Promise.all([
      readFile(
        path.join(repositoryRoot, '.scripts/compatibility/run-phase1-runtime-candidate.sh'),
        'utf8'
      ),
      readFile(lifecyclePath, 'utf8'),
    ]);

    expect(dispatcher).toContain(['[[ "', '$', "{RUNTIME_GATE}\" == 'conformance' ]]"].join(''));
    expect(dispatcher).toContain('run-phase1-runtime-candidate-conformance.sh');
    expect(lifecycle.startsWith('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n')).toBe(true);
    expect(lifecycle).toContain('readonly SERVICES=(');
    expect(lifecycle).toContain(
      'PODMAN_GRAPH_ROOT="${BUILD_ROOT}/aster-phase1-conformance-podman-graph"'
    );
    expect(lifecycle).toContain('system service --time=0');
    expect(lifecycle).toContain('run_owned_command 1800');
    expect(lifecycle).toContain('"${DOCKER_BIN}" image save --output');
    expect(lifecycle).toContain('SETUP_RUN_PGID');
    expect(lifecycle).toContain('compose config --quiet');
    expect(lifecycle).toContain('up --detach --no-build --no-deps');
    expect(lifecycle).toContain('compose_up_phase candidate-primary-postgres suite-mongo');
    expect(lifecycle).toContain('compose_up_phase candidate-primary-init suite-server');
    expect(lifecycle).toContain('compose_up_phase candidate-conformance-core');
    expect(lifecycle).toContain('compose_up_phase candidate-fixture-coordinator suite-nginx');
    expect(lifecycle).toContain('compose_up_phase oidf-runner');
    expect(lifecycle).toContain('compose ps --all -q');
    expect(lifecycle).not.toContain('/dev/shm');
    expect(lifecycle).not.toContain('/var/lib/docker');
    const wrapper = await readFile(
      path.join(repositoryRoot, '.scripts/compatibility/run-phase1-conformance.sh'),
      'utf8'
    );

    expect(wrapper).toContain('HOME="${root}"');
    expect(wrapper).toContain('DOCKER_HOST="unix://${engine_socket}"');
    expect(wrapper).toContain('"engineSocket", "topologyId"');
    expect(wrapper).toContain('"${engine_docker[@]}" ps -aq --no-trunc');
    expect(wrapper).toContain('"${runner_container_id}" "${driver_container_path}" "$@"');
    expect(wrapper).not.toContain('"${runner_container_id}" /usr/bin/node');
  });

  it('generates one short-lived CA and exact-host leaves without exposing material', async () => {
    const source = await readFile(pkiPath, 'utf8');
    const root = await mkdtemp('/var/tmp/henry-build/aster-phase1-conformance-pki.');

    await rm(root, { recursive: true, force: true });
    await executeFile('/usr/bin/mkdir', ['-m', '0700', root]);
    try {
      const result = await executeFile('/usr/bin/env', [
        '-i',
        'PATH=/usr/bin:/bin',
        pkiPath,
        root,
        String(process.getuid?.() ?? 0),
        String(process.getgid?.() ?? 0),
      ]);

      expect(result.stdout).toBe('');
      expect(result.stderr).toBe('');
      expect(source.startsWith('#!/usr/bin/env bash\nset -euo pipefail\numask 077\n')).toBe(true);
      for (const requiredSource of [
        "readonly OPENSSL_BIN='/usr/bin/openssl'",
        "readonly TIMEOUT_BIN='/usr/bin/timeout'",
        'require_trusted_tool "$OPENSSL_BIN"',
        'require_trusted_tool "$TIMEOUT_BIN"',
        'require_trusted_tool "$REALPATH_BIN"',
        'require_trusted_tool "$STAT_BIN"',
        'require_trusted_tool "$ID_BIN"',
        'require_trusted_tool "$MKDIR_BIN"',
        'require_trusted_tool "$MKTEMP_BIN"',
        'require_trusted_tool "$CHOWN_BIN"',
        'require_trusted_tool "$CHMOD_BIN"',
        'require_trusted_tool "$MV_BIN"',
        'require_trusted_tool "$RM_BIN"',
        '-days 2',
        `readonly CANDIDATE_HOST='${candidateHost}'`,
        `readonly SUITE_HOST='${suiteHost}'`,
        '"$CHMOD_BIN" 0400',
        '"$CHMOD_BIN" 0444',
      ]) {
        expect(source).toContain(requiredSource);
      }
      expect(source).toMatch(
        /"\$TIMEOUT_BIN"\s+--signal=TERM\s+--kill-after=5s\s+30s\s+"\$OPENSSL_BIN"/u
      );
      expect(source).toMatch(
        /"\$TIMEOUT_BIN"\s+--signal=TERM\s+--kill-after=5s\s+10s\s+"\$OPENSSL_BIN"/u
      );

      const rootCertificate = path.join(root, 'pki/root-ca.crt');
      const caKey = path.join(root, 'pki/host-only/root-ca.key');
      const candidateCertificate = path.join(root, 'pki/aster/tls.crt');
      const candidateKey = path.join(root, 'pki/aster/tls.key');
      const suiteCertificate = path.join(root, 'pki/suite/tls.crt');
      const suiteKey = path.join(root, 'pki/suite/tls.key');
      const document = await readCompose();

      const keyMetadata = await Promise.all(
        [caKey, candidateKey, suiteKey].map(async (key) => stat(key))
      );

      for (const metadata of keyMetadata) {
        expect(metadata.mode % 0o1000).toBe(0o400);
        expect(metadata.uid).toBe(process.getuid?.());
        expect(metadata.gid).toBe(process.getgid?.());
      }
      expect(document.services['suite-nginx']?.user).toBe(
        `${required('ASTER_PHASE1_RUNTIME_UID')}:${required('ASTER_PHASE1_RUNTIME_GID')}`
      );
      expect(keyMetadata.at(2)?.uid).toBe(process.getuid?.());
      expect(keyMetadata.at(2)?.gid).toBe(process.getgid?.());
      const certificateMetadata = await Promise.all(
        [rootCertificate, candidateCertificate, suiteCertificate].map(async (certificate) =>
          stat(certificate)
        )
      );

      for (const metadata of certificateMetadata) {
        expect(metadata.mode % 0o1000).toBe(0o444);
        expect(metadata.uid).toBe(process.getuid?.());
        expect(metadata.gid).toBe(process.getgid?.());
      }
      const candidateText = await executeFile('/usr/bin/openssl', [
        'x509',
        '-in',
        candidateCertificate,
        '-noout',
        '-ext',
        'subjectAltName',
      ]);
      const suiteText = await executeFile('/usr/bin/openssl', [
        'x509',
        '-in',
        suiteCertificate,
        '-noout',
        '-ext',
        'subjectAltName',
      ]);

      expect(candidateText.stdout).toContain(`DNS:${candidateHost}`);
      expect(candidateText.stdout).not.toContain(suiteHost);
      expect(suiteText.stdout).toContain(`DNS:${suiteHost}`);
      expect(suiteText.stdout).not.toContain(candidateHost);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

/* eslint-enable max-lines, no-template-curly-in-string */
