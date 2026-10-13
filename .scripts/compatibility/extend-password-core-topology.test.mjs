import assert from 'node:assert/strict';
import test from 'node:test';
import { extendPasswordCoreTopology } from './extend-password-core-topology.mjs';

const probe = (port) => `printf 'GET /readyz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 2 127.0.0.1 ${port} | grep -q ' 200 OK'`;
const base = (role) => ({
  services: {
    [`${role}-primary-core`]: {
      container_name: 'primary',
      depends_on: { db: { condition: 'service_healthy' } },
      environment: role === 'oracle'
        ? { ENDPOINT: 'http://localhost:3311', INTEGRATION_TEST: 'true', NODE_EXTRA_CA_CERTS: '/fixture/ca.pem' }
        : { ASTER_PHASE1_PRIMARY_CONFIG_FILE: '/private/primary.conf', ASTER_PHASE1_DATA_ISSUER: 'http://localhost:3321/oidc', ASTER_ISOLATED_IDENTITY_TRANSPORT_CONFIG: '/private/identity.json' },
      volumes: role === 'candidate' ? ['/private/primary.conf:/private/primary.conf:ro', '/private/identity.json:/private/identity.json:ro', 'keys:/keys:ro'] : ['/private/ca.pem:/fixture/ca.pem:ro'],
      healthcheck: { test: ['CMD-SHELL', role === 'oracle'
        ? 'nc -z localhost 3001 && nc -z localhost 3411'
        : `test -f /run/aster/maintainer-ready && ${probe(3001)} && ${probe(3421)}`] },
      networks: { [`${role}-primary`]: { ipv4_address: 'old' } },
    },
    ...(role === 'candidate' ? {
      'candidate-h5-core': {
        container_name: 'fixture-candidate-project-candidate-h5-core',
        image: 'candidate-image',
        userns_mode: 'keep-id',
      },
      'candidate-primary-postgres': { environment: {} },
      'candidate-primary-smtp': {
        container_name: 'primary-smtp',
        depends_on: { 'candidate-primary-core': { condition: 'service_healthy' } },
        environment: {
          ASTER_SMTP_BIND: '127.0.0.1',
          ASTER_SMTP_CONTROL_SOCKET: '/run/aster-smtp/verification-smtp.sock',
        },
        network_mode: 'service:candidate-primary-core',
        read_only: true,
        restart: 'no',
        userns_mode: 'container:fixture-candidate-project-candidate-primary-core',
        volumes: ['${ASTER_PHASE1_FIXTURE_DIRECTORY}:/run/aster-smtp:rw'],
      },
    } : {}),
  },
  networks: { [`${role}-primary`]: { internal: true } },
});

test('clones an isolated Reference production password authority without changing primary', () => {
  const output = extendPasswordCoreTopology(base('oracle'), { role: 'oracle' });
  assert.equal(output.services['oracle-primary-core'].environment.INTEGRATION_TEST, 'true');
  assert.equal(output.services['oracle-password-core'].environment.INTEGRATION_TEST, 'false');
  assert.equal(output.services['oracle-password-core'].environment.ENDPOINT, 'https://localhost:3361');
  assert.equal(output.services['oracle-password-core'].environment.NODE_EXTRA_CA_CERTS, '/fixture/ca.pem');
  assert.deepEqual(output.services['oracle-password-core'].volumes, ['/private/ca.pem:/fixture/ca.pem:ro']);
  assert.deepEqual(output.services['oracle-password-core'].networks, { 'oracle-primary': { ipv4_address: '172.30.231.15' } });
});

test('adds an owned Candidate password SMTP sink in the existing H5 core namespace', () => {
  const input = base('candidate');
  const output = extendPasswordCoreTopology(input, { role: 'candidate' });
  assert.deepEqual(output.services['candidate-primary-smtp'], input.services['candidate-primary-smtp']);
  assert.deepEqual(output.services['candidate-password-smtp'], {
    depends_on: { 'candidate-h5-core': { condition: 'service_healthy' } },
    environment: {
      ASTER_SMTP_BIND: '127.0.0.1',
      ASTER_SMTP_CONTROL_SOCKET: '/run/aster-smtp/password-verification-smtp.sock',
    },
    network_mode: 'service:candidate-h5-core',
    read_only: true,
    restart: 'no',
    userns_mode: 'container:fixture-candidate-project-candidate-h5-core',
    volumes: ['${ASTER_PHASE1_FIXTURE_DIRECTORY}:/run/aster-smtp:rw'],
  });
});

test('rejects a Candidate password sink without the bound H5 container identity', () => {
  const input = base('candidate');
  delete input.services['candidate-h5-core'].container_name;
  assert.throws(
    () => extendPasswordCoreTopology(input, { role: 'candidate' }),
    /Invalid Common206 password core topology/u
  );
});
