import assert from 'node:assert/strict';
import test from 'node:test';

import { extendH5WechatTopology } from './extend-h5-wechat-topology.mjs';

const descriptor = {
  container: 'aster206-oracle-oracle-h5-wechat-provider-1',
  project: 'aster206-oracle',
  service: 'oracle-h5-wechat-provider',
  image: `sha256:${'a'.repeat(64)}`,
  configFile: '/private/config.json',
  receiptFile: '/private/receipt.json',
  healthDiagnosticFile: '/private/health.json',
  dockerHome: '/private/home',
  apiVersion: '4.9.4',
};
const options = {
  role: 'oracle',
  descriptor,
  script: '/source/provider.mjs',
  certificateFile: '/private/tls.pem',
  privateKeyFile: '/private/tls.key',
};

test('adds one stopped legacy H5 service at the shared provider address', () => {
  const result = extendH5WechatTopology(
    { services: {}, networks: { 'oracle-primary': { internal: true } } },
    options
  );
  assert.deepEqual(result.services['oracle-h5-wechat-provider'].networks, {
    'oracle-primary': { ipv4_address: '172.30.231.53' },
  });
  assert.equal(result.services['oracle-h5-wechat-provider'].mac_address, '02:42:ac:1e:e7:35');
  assert.equal(result.services['oracle-h5-wechat-provider'].restart, 'no');
});

test('uses the candidate stable peer identity without changing its shared address', () => {
  const candidateDescriptor = {
    ...descriptor,
    container: 'aster206-candidate-candidate-h5-wechat-provider-1',
    project: 'aster206-candidate',
    service: 'candidate-h5-wechat-provider',
  };
  const result = extendH5WechatTopology(
    { services: {}, networks: { 'candidate-primary': { internal: true } } },
    { ...options, role: 'candidate', descriptor: candidateDescriptor }
  );
  assert.deepEqual(result.services['candidate-h5-wechat-provider'].networks, {
    'candidate-primary': { ipv4_address: '172.30.241.53' },
  });
  assert.equal(result.services['candidate-h5-wechat-provider'].mac_address, '02:42:ac:1e:f1:35');
});

test('rejects foreign service ownership and unknown fields', () => {
  assert.throws(() =>
    extendH5WechatTopology(
      { services: {}, networks: { 'oracle-primary': { internal: true } } },
      { ...options, descriptor: { ...descriptor, project: 'foreign' } }
    )
  );
  assert.throws(() =>
    extendH5WechatTopology(
      { services: {}, networks: { 'oracle-primary': { internal: true } } },
      { ...options, extra: true }
    )
  );
});
