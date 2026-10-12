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
  assert.equal(result.services['oracle-h5-wechat-provider'].restart, 'no');
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
