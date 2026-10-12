import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import test from 'node:test';
import { promisify } from 'node:util';
import { extendH5CoreTopology } from './extend-h5-core-topology.mjs';

const execute = promisify(execFile);
const probe = (port) => `printf 'GET /readyz HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 2 127.0.0.1 ${port} | grep -q ' 200 OK'`;

const base = (role) => ({
  services: {
    [`${role}-primary-core`]: {
      container_name: 'original', image: 'sha256:abc',
      depends_on: { db: { condition: 'service_healthy' } },
      environment: role === 'oracle'
        ? { ENDPOINT: 'http://localhost:3311' }
        : { ASTER_PHASE1_PRIMARY_CONFIG_FILE: '/private/original.conf', ASTER_PHASE1_DATA_ISSUER: 'http://localhost:3321/oidc', NODE_EXTRA_CA_CERTS: '/run/aster/fetch-observer-ca.pem', SSL_CERT_FILE: '/run/aster/fetch-observer-ca.pem' },
      volumes: role === 'candidate' ? ['/private/original.conf:/private/original.conf:ro', 'keys:/keys:ro', '/private/bundle.pem:/run/aster/fetch-observer-ca.pem:ro'] : [],
      healthcheck: { test: ['CMD-SHELL', `test -f /run/aster/maintainer-ready && ${probe(3001)} && ${probe(role === 'oracle' ? 3411 : 3421)}`], interval: '0s', timeout: '3s', retries: 60 },
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
  assert.deepEqual(output.services['oracle-h5-core'].healthcheck.test,
    ['CMD-SHELL', `test -f /run/aster/maintainer-ready && ${probe(3001)}`]);
  assert.match(output.services['oracle-primary-core'].healthcheck.test[1],/3411/u);
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
  assert.deepEqual(service.healthcheck.test,
    ['CMD-SHELL', `test -f /run/aster/maintainer-ready && ${probe(3001)}`]);
  assert.match(output.services['candidate-primary-core'].healthcheck.test[1],/3421/u);
});

test('rejects an unknown primary healthcheck instead of weakening it', () => {
  const input=base('candidate');
  input.services['candidate-primary-core'].healthcheck.test[1]='true';
  assert.throws(() => extendH5CoreTopology(input,{role:'candidate',candidateConfigFile:'/private/h5.conf'}),
    /Invalid Common206 H5 core topology/u);
});

test('clone health requires maintainer readiness and a ready data authority', async () => {
  const root=await mkdtemp('/var/tmp/henry-build/h5-health-command.');
  const marker=`${root}/maintainer-ready`;
  const service=extendH5CoreTopology(base('candidate'),{
    role:'candidate',candidateConfigFile:'/private/h5.conf',
  }).services['candidate-h5-core'];
  const server=net.createServer();
  await new Promise((resolve,reject) => {
    server.once('error',reject);
    server.listen(0,'127.0.0.1',resolve);
  });
  const address=server.address();
  assert(address && typeof address==='object');
  const command=service.healthcheck.test[1]
    .replace('/run/aster/maintainer-ready',marker)
    .replace('127.0.0.1 3001',`127.0.0.1 ${address.port}`);
  let status='200 OK';
  server.on('connection',(socket) => socket.once('data',() => {
    socket.end(`HTTP/1.1 ${status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  }));
  try {
    await writeFile(marker,'ready\n',{mode:0o600});
    await execute('/bin/sh',['-c',command]);
    status='503 Service Unavailable';
    await assert.rejects(execute('/bin/sh',['-c',command]));
    await rm(marker);
    status='200 OK';
    await assert.rejects(execute('/bin/sh',['-c',command]));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(root,{recursive:true,force:true});
  }
});
