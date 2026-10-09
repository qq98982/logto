import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  assertWechatProviderTopology,
  bindWechatProviderTopology,
} from './phase2-wechat-provider-topology.mjs';

const options = Object.freeze({
  fixtureImage: `sha256:${'7'.repeat(64)}`,
  runtimeUid: 1000,
  runtimeGid: 1000,
  providerScript: '/private/run/phase2-wechat-provider.mjs',
  caFile: '/private/run/wechat-ca.pem',
  certificateFile: '/private/run/wechat-server.pem',
  privateKeyFile: '/private/run/wechat-server.key',
  oracleConfigurationFile: '/private/run/oracle-wechat-config.json',
  oracleReceiptFile: '/private/run/oracle-wechat-receipt.json',
  candidateConfigurationFile: '/private/run/candidate-wechat-config.json',
  candidateReceiptFile: '/private/run/candidate-wechat-receipt.json',
});

const documents = () => ({
  oracle: {
    services: {
      'oracle-primary-core': {
        environment: { NODE_EXTRA_CA_CERTS: '/run/aster/fetch-observer-ca.pem' },
        volumes: ['/private/run/wechat-ca.pem:/run/aster/fetch-observer-ca.pem:ro'],
      },
    },
    networks: { 'oracle-primary': { internal: true } },
    volumes: {},
  },
  candidate: {
    services: {
      'candidate-primary-core': {
        environment: { SSL_CERT_FILE: '/run/aster/fetch-observer-ca.pem' },
        volumes: ['/private/run/wechat-ca.pem:/run/aster/fetch-observer-ca.pem:ro'],
      },
    },
    networks: { 'candidate-primary': { internal: true } },
    volumes: {},
  },
});

test('binds two target-isolated confined providers to the fixed Wechat transport authorities', () => {
  const input = documents();
  const bound = bindWechatProviderTopology(input.oracle, input.candidate, options);
  assert.doesNotThrow(() => assertWechatProviderTopology(bound.oracle, bound.candidate, options));
  assert.deepEqual(
    bound.oracle.services['oracle-wechat-provider'].networks['oracle-primary'],
    {
      ipv4_address: '172.30.231.53',
      aliases: ['api.weixin.qq.com'],
    }
  );
  assert.deepEqual(
    bound.candidate.services['candidate-wechat-provider'].networks['candidate-primary'],
    {
      ipv4_address: '172.30.241.53',
      aliases: ['api.weixin.qq.com'],
    }
  );
  assert.equal(
    bound.oracle.services['oracle-wechat-provider'].mac_address,
    '02:42:ac:1e:e7:35'
  );
  assert.equal(
    bound.candidate.services['candidate-wechat-provider'].mac_address,
    '02:42:ac:1e:f1:35'
  );
  for (const service of [
    bound.oracle.services['oracle-wechat-provider'],
    bound.candidate.services['candidate-wechat-provider'],
  ]) {
    assert.equal(service.image, options.fixtureImage);
    assert.equal(service.user, '1000:1000');
    assert.equal(service.userns_mode, 'keep-id');
    assert.equal(service.read_only, true);
    assert.deepEqual(service.cap_drop, ['ALL']);
    assert.deepEqual(service.security_opt, ['no-new-privileges:true']);
    assert.equal(service.restart, 'no');
    assert.equal(service.environment.ASTER_WECHAT_PROVIDER_PORT, '443');
    assert.equal(service.volumes.every((volume) => volume.endsWith(':ro') || volume.endsWith(':rw')), true);
    assert.equal(service.volumes.filter((volume) => volume.endsWith(':rw')).length, 1);
  }
  assert.equal(
    bound.oracle.services['oracle-primary-core'].environment.NODE_EXTRA_CA_CERTS,
    '/run/aster/fetch-observer-ca.pem'
  );
  assert.equal(
    bound.candidate.services['candidate-primary-core'].environment.SSL_CERT_FILE,
    '/run/aster/fetch-observer-ca.pem'
  );
  assert.equal(input.oracle.services['oracle-wechat-provider'], undefined);
  assert.equal(input.candidate.services['candidate-wechat-provider'], undefined);
});

test('rejects altered image, alias, MAC, trust, mount, user, capability, rootfs, or network confinement', () => {
  const mutations = [
    (value) => {
      value.oracle.services['oracle-wechat-provider'].image = `sha256:${'8'.repeat(64)}`;
    },
    (value) => {
      value.candidate.services['candidate-wechat-provider'].networks[
        'candidate-primary'
      ].aliases = [];
    },
    (value) => {
      value.oracle.services['oracle-wechat-provider'].mac_address = '02:42:ac:1e:e7:36';
    },
    (value) => {
      value.candidate.services['candidate-primary-core'].environment.SSL_CERT_FILE =
        '/private/other-ca.pem';
    },
    (value) => {
      value.oracle.services['oracle-primary-core'].volumes = [];
    },
    (value) => {
      value.oracle.services['oracle-wechat-provider'].volumes[3] =
        '/private/run/wechat-server.key:/run/aster-wechat-provider/tls/server.key:rw';
    },
    (value) => {
      value.oracle.services['oracle-wechat-provider'].user = '0:0';
    },
    (value) => {
      value.candidate.services['candidate-wechat-provider'].cap_drop = [];
    },
    (value) => {
      value.oracle.services['oracle-wechat-provider'].read_only = false;
    },
    (value) => {
      value.oracle.networks['oracle-primary'].internal = false;
    },
    (value) => {
      value.candidate.services['candidate-wechat-provider'].networks = {
        'oracle-primary': {
          ipv4_address: '172.30.231.53',
          aliases: ['api.weixin.qq.com'],
        },
      };
    },
  ];
  for (const mutate of mutations) {
    const input = documents();
    const bound = bindWechatProviderTopology(input.oracle, input.candidate, options);
    const changed = structuredClone(bound);
    mutate(changed);
    assert.throws(
      () => assertWechatProviderTopology(changed.oracle, changed.candidate, options),
      /Invalid Phase 2 WeChat provider topology/u
    );
  }
});

test('rejects shared private state paths and unbounded topology inputs', () => {
  assert.throws(
    () =>
      bindWechatProviderTopology(documents().oracle, documents().candidate, {
        ...options,
        candidateConfigurationFile: options.oracleConfigurationFile,
      }),
    /Invalid Phase 2 WeChat provider topology/u
  );
  for (const providerScript of [
    '/private/run/provider:bad.mjs',
    '/private/run/provider,bad.mjs',
    '/private/run//provider.mjs',
    '/private/run/../provider.mjs',
  ]) {
    assert.throws(
      () =>
        bindWechatProviderTopology(documents().oracle, documents().candidate, {
          ...options,
          providerScript,
        }),
        /Invalid Phase 2 WeChat provider topology/u
    );
  }
  assert.throws(
    () =>
      bindWechatProviderTopology(documents().oracle, documents().candidate, {
        ...options,
        providerScript: 'relative/provider.mjs',
      }),
      /Invalid Phase 2 WeChat provider topology/u
  );
  assert.throws(
    () =>
      bindWechatProviderTopology(documents().oracle, documents().candidate, {
        ...options,
        fixtureImage: 'latest',
      }),
    /Invalid Phase 2 WeChat provider topology/u
  );
});
