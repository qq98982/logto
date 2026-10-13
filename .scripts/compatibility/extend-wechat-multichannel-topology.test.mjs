import assert from 'node:assert/strict';
import test from 'node:test';

import { extendWechatMultichannelTopology } from './extend-wechat-multichannel-topology.mjs';

test('uses the stable role peer identity when the multichannel provider assumes the shared address', () => {
  const result = extendWechatMultichannelTopology({
    services: { 'oracle-primary-core': { extra_hosts: [] } },
    networks: { 'oracle-primary': { internal: true } },
  }, {
    certificateFile: '/private/server.pem', configurationFile: '/private/config.json',
    fixtureImage: `sha256:${'a'.repeat(64)}`, privateKeyFile: '/private/server.key',
    receiptFile: '/private/receipt.ndjson', role: 'oracle', script: '/private/provider.mjs',
  });
  const provider = result.services['oracle-wechat-multichannel-provider'];
  assert.equal(provider.networks['oracle-primary'].ipv4_address, '172.30.231.53');
  assert.equal(provider.mac_address, '02:42:ac:1e:e7:35');
  assert.ok(result.services['oracle-primary-core'].extra_hosts.includes('api.weixin.qq.com:172.30.231.53'));
});

test('uses the candidate stable peer identity without changing its shared address', () => {
  const result = extendWechatMultichannelTopology({
    services: { 'candidate-primary-core': { extra_hosts: [] } },
    networks: { 'candidate-primary': { internal: true } },
  }, {
    certificateFile: '/private/server.pem', configurationFile: '/private/config.json',
    fixtureImage: `sha256:${'a'.repeat(64)}`, privateKeyFile: '/private/server.key',
    receiptFile: '/private/receipt.ndjson', role: 'candidate', script: '/private/provider.mjs',
  });
  const provider = result.services['candidate-wechat-multichannel-provider'];
  assert.equal(provider.networks['candidate-primary'].ipv4_address, '172.30.241.53');
  assert.equal(provider.mac_address, '02:42:ac:1e:f1:35');
});
