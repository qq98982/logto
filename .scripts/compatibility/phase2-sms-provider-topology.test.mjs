import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bindSmsProviderTopology, assertSmsProviderTopology } from './phase2-sms-provider-topology.mjs';
const options = { fixtureImage: `sha256:${'7'.repeat(64)}`, runtimeUid: 1000, runtimeGid: 1000,
  providerScript: '/private/sms/provider.mjs', caFile: '/private/sms/ca.pem',
  certificateFile: '/private/sms/cert.pem', privateKeyFile: '/private/sms/key.pem',
  oracleConfigurationFile: '/private/sms/o-config.json', oracleReceiptFile: '/private/sms/o-receipt.json',
  oracleControlDirectory: '/private/sms/o', candidateConfigurationFile: '/private/sms/c-config.json',
  candidateReceiptFile: '/private/sms/c-receipt.json', candidateControlDirectory: '/private/sms/c' };
const documents = () => Object.fromEntries(['oracle', 'candidate'].map((role) => [role, {
  services: { [`${role}-primary-core`]: {
    environment: { [role === 'oracle' ? 'NODE_EXTRA_CA_CERTS' : 'SSL_CERT_FILE']: '/run/aster/fetch-observer-ca.pem' },
    volumes: [`${options.caFile}:/run/aster/fetch-observer-ca.pem:ro`], extra_hosts: ['kept.test:127.0.0.1'] } },
  networks: { [`${role}-primary`]: { internal: true } }, volumes: {} }]));
test('binds isolated SMS transports with private control mounts and existing CA trust', () => {
  const before = documents(); const after = bindSmsProviderTopology(before.oracle, before.candidate, options);
  assertSmsProviderTopology(after.oracle, after.candidate, options);
  for (const role of ['oracle', 'candidate']) {
    const service = after[role].services[`${role}-sms-provider`];
    assert.equal(service.networks[`${role}-primary`].aliases[0], 'dysmsapi.aliyuncs.com');
    assert.equal(service.read_only, true); assert.deepEqual(service.cap_drop, ['ALL']);
    assert.equal(service.ports, undefined); assert.equal(service.network_mode, undefined);
    assert.equal(service.volumes.filter((value) => value.endsWith(':rw')).length, 2);
    assert.equal(before[role].services[`${role}-sms-provider`], undefined);
  }
});
test('rejects altered transport, network confinement and private authority mounts', () => {
  const mutations = [
    (x) => { x.oracle.networks['oracle-primary'].internal = false; },
    (x) => { x.candidate.services['candidate-primary-core'].extra_hosts = []; },
    (x) => { x.oracle.services['oracle-primary-core'].environment.NODE_EXTRA_CA_CERTS = '/wrong'; },
    (x) => { x.oracle.services['oracle-sms-provider'].volumes[3] += ':rw'; },
    (x) => { x.candidate.services['candidate-sms-provider'].ports = ['443:443']; },
    (x) => { x.candidate.services['candidate-sms-provider'].networks = x.oracle.services['oracle-sms-provider'].networks; },
    (x) => { x.oracle.services['oracle-sms-provider'].read_only = false; },
  ];
  for (const mutate of mutations) {
    const { oracle, candidate } = documents(); const bound = bindSmsProviderTopology(oracle, candidate, options);
    mutate(bound); assert.throws(() => assertSmsProviderTopology(bound.oracle, bound.candidate, options));
  }
});
test('rejects shared private paths, preexisting provider and ambiguous host mapping', () => {
  const { oracle, candidate } = documents();
  assert.throws(() => bindSmsProviderTopology(oracle, candidate, { ...options, candidateConfigurationFile: options.oracleConfigurationFile }));
  assert.throws(() => bindSmsProviderTopology(oracle, candidate, { ...options, oracleControlDirectory: `/${'a'.repeat(99)}` }));
  oracle.services['oracle-primary-core'].extra_hosts.push('dysmsapi.aliyuncs.com:1.2.3.4');
  assert.throws(() => bindSmsProviderTopology(oracle, candidate, options));
});
