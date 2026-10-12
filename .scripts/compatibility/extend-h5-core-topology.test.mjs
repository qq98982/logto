import assert from 'node:assert/strict';
import test from 'node:test';
import { extendH5CoreTopology } from './extend-h5-core-topology.mjs';

const base = (role) => ({
  services: {
    [`${role}-primary-core`]: {
      container_name: 'original', image: 'sha256:abc',
      depends_on: { db: { condition: 'service_healthy' } },
      environment: role === 'oracle'
        ? { ENDPOINT: 'http://localhost:3311' }
        : { ASTER_PHASE1_PRIMARY_CONFIG_FILE: '/private/original.conf', ASTER_PHASE1_DATA_ISSUER: 'http://localhost:3321/oidc', NODE_EXTRA_CA_CERTS: '/run/aster/fetch-observer-ca.pem', SSL_CERT_FILE: '/run/aster/fetch-observer-ca.pem' },
      volumes: role === 'candidate' ? ['/private/original.conf:/private/original.conf:ro', 'keys:/keys:ro', '/private/bundle.pem:/run/aster/fetch-observer-ca.pem:ro'] : [],
      networks: { [`${role}-primary`]: { ipv4_address: 'old' } },
    },
    ...(role === 'candidate'
      ? { 'candidate-primary-postgres': { environment: { ASTER_PHASE1_CORE_CIDR: '172.30.241.12/32' } } }
      : {}),
  },
  networks: { [`${role}-primary`]: { internal: true } },
});

test('clones oracle authority with only an HTTPS public issuer and isolated listener', () => {
  const output=extendH5CoreTopology(base('oracle'),{role:'oracle',candidateConfigFile:'/private/h5.conf'});
  assert.equal(output.services['oracle-primary-core'].environment.ENDPOINT,'http://localhost:3311');
  assert.equal(output.services['oracle-h5-core'].environment.ENDPOINT,'https://localhost:3351');
  assert.deepEqual(output.services['oracle-h5-core'].ports,['127.0.0.1::3001']);
  assert.equal(output.services['oracle-h5-core'].container_name,undefined);
});

test('clones candidate authority with the H5 config and issuer while retaining keys', () => {
  const output=extendH5CoreTopology(base('candidate'),{role:'candidate',candidateConfigFile:'/private/h5.conf'});
  const service=output.services['candidate-h5-core'];
  assert.equal(service.environment.ASTER_PHASE1_DATA_ISSUER,'https://localhost:3352/oidc');
  assert.equal(service.environment.ASTER_PHASE1_PRIMARY_CONFIG_FILE,'/private/h5.conf');
  assert.deepEqual(service.volumes,['/private/h5.conf:/private/h5.conf:ro','keys:/keys:ro','/private/bundle.pem:/run/aster/fetch-observer-ca.pem:ro']);
  assert.equal(service.environment.NODE_EXTRA_CA_CERTS,'/run/aster/fetch-observer-ca.pem');
  assert.equal(service.environment.SSL_CERT_FILE,'/run/aster/fetch-observer-ca.pem');
  assert.equal(output.services['candidate-primary-postgres'].environment.ASTER_PHASE1_H5_CORE_CIDR,'172.30.241.14/32');
  assert.equal(output.services['candidate-primary-core'].environment.ASTER_PHASE1_DATA_ISSUER,'http://localhost:3321/oidc');
});
