import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  assertGoogleProviderTopology,
  bindGoogleProviderTopology,
} from './phase2-google-provider-topology.mjs';

const options = Object.freeze({
  fixtureImage: `sha256:${'7'.repeat(64)}`,
  runtimeUid: 1000,
  runtimeGid: 1000,
  providerScript: '/private/run/phase2-google-provider.mjs',
  caFile: '/private/run/google-ca.pem',
  certificateFile: '/private/run/google-server.pem',
  privateKeyFile: '/private/run/google-server.key',
  oracleConfigurationFile: '/private/run/oracle-google-config.json',
  oracleReceiptFile: '/private/run/oracle-google-receipt.json',
  candidateConfigurationFile: '/private/run/candidate-google-config.json',
  candidateReceiptFile: '/private/run/candidate-google-receipt.json',
});

const documents = () => ({
  oracle: {
    services: {
      'oracle-primary-core': {
        environment: { NODE_EXTRA_CA_CERTS: '/run/aster/fetch-observer-ca.pem' },
        volumes: ['/private/run/google-ca.pem:/run/aster/fetch-observer-ca.pem:ro'],
      },
    },
    networks: { 'oracle-primary': { internal: true } },
    volumes: {},
  },
  candidate: {
    services: {
      'candidate-primary-core': {
        environment: { SSL_CERT_FILE: '/run/aster/fetch-observer-ca.pem' },
        volumes: ['/private/run/google-ca.pem:/run/aster/fetch-observer-ca.pem:ro'],
      },
    },
    networks: { 'candidate-primary': { internal: true } },
    volumes: {},
  },
});

test('binds two target-isolated confined providers to the fixed Google transport authorities', () => {
  const input = documents();
  const bound = bindGoogleProviderTopology(input.oracle, input.candidate, options);
  assert.doesNotThrow(() => assertGoogleProviderTopology(bound.oracle, bound.candidate, options));
  assert.deepEqual(
    bound.oracle.services['oracle-google-provider'].networks['oracle-primary'],
    {
      ipv4_address: '172.30.231.52',
      mac_address: '02:42:ac:1e:e7:34',
      aliases: ['oauth2.googleapis.com', 'openidconnect.googleapis.com'],
    }
  );
  assert.deepEqual(
    bound.candidate.services['candidate-google-provider'].networks['candidate-primary'],
    {
      ipv4_address: '172.30.241.52',
      mac_address: '02:42:ac:1e:f1:34',
      aliases: ['oauth2.googleapis.com', 'openidconnect.googleapis.com'],
    }
  );
  for (const service of [
    bound.oracle.services['oracle-google-provider'],
    bound.candidate.services['candidate-google-provider'],
  ]) {
    assert.equal(service.image, options.fixtureImage);
    assert.equal(service.user, '1000:1000');
    assert.equal(service.userns_mode, 'keep-id');
    assert.equal(service.read_only, true);
    assert.deepEqual(service.cap_drop, ['ALL']);
    assert.deepEqual(service.security_opt, ['no-new-privileges:true']);
    assert.equal(service.restart, 'no');
    assert.equal(service.environment.ASTER_GOOGLE_PROVIDER_PORT, '443');
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
  assert.equal(input.oracle.services['oracle-google-provider'], undefined);
  assert.equal(input.candidate.services['candidate-google-provider'], undefined);
});

test('rejects altered image, alias, MAC, trust, mount, user, capability, rootfs, or network confinement', () => {
  const mutations = [
    (value) => {
      value.oracle.services['oracle-google-provider'].image = `sha256:${'8'.repeat(64)}`;
    },
    (value) => {
      value.candidate.services['candidate-google-provider'].networks[
        'candidate-primary'
      ].aliases = ['oauth2.googleapis.com'];
    },
    (value) => {
      value.oracle.services['oracle-google-provider'].networks[
        'oracle-primary'
      ].mac_address = '02:42:ac:1e:e7:35';
    },
    (value) => {
      value.candidate.services['candidate-primary-core'].environment.SSL_CERT_FILE =
        '/private/other-ca.pem';
    },
    (value) => {
      value.oracle.services['oracle-primary-core'].volumes = [];
    },
    (value) => {
      value.oracle.services['oracle-google-provider'].volumes[3] =
        '/private/run/google-server.key:/run/aster-google-provider/tls/server.key:rw';
    },
    (value) => {
      value.oracle.services['oracle-google-provider'].user = '0:0';
    },
    (value) => {
      value.candidate.services['candidate-google-provider'].cap_drop = [];
    },
    (value) => {
      value.oracle.services['oracle-google-provider'].read_only = false;
    },
    (value) => {
      value.oracle.networks['oracle-primary'].internal = false;
    },
    (value) => {
      value.candidate.services['candidate-google-provider'].networks = {
        'oracle-primary': {
          ipv4_address: '172.30.231.52',
          aliases: ['oauth2.googleapis.com', 'openidconnect.googleapis.com'],
        },
      };
    },
  ];
  for (const mutate of mutations) {
    const input = documents();
    const bound = bindGoogleProviderTopology(input.oracle, input.candidate, options);
    const changed = structuredClone(bound);
    mutate(changed);
    assert.throws(
      () => assertGoogleProviderTopology(changed.oracle, changed.candidate, options),
      /Invalid Phase 2 Google provider topology/u
    );
  }
});

test('rejects shared private state paths and unbounded topology inputs', () => {
  assert.throws(
    () =>
      bindGoogleProviderTopology(documents().oracle, documents().candidate, {
        ...options,
        candidateConfigurationFile: options.oracleConfigurationFile,
      }),
    /Invalid Phase 2 Google provider topology/u
  );
  for (const providerScript of [
    '/private/run/provider:bad.mjs',
    '/private/run/provider,bad.mjs',
    '/private/run//provider.mjs',
    '/private/run/../provider.mjs',
  ]) {
    assert.throws(
      () =>
        bindGoogleProviderTopology(documents().oracle, documents().candidate, {
          ...options,
          providerScript,
        }),
      /Invalid Phase 2 Google provider topology/u
    );
  }
  assert.throws(
    () =>
      bindGoogleProviderTopology(documents().oracle, documents().candidate, {
        ...options,
        providerScript: 'relative/provider.mjs',
      }),
    /Invalid Phase 2 Google provider topology/u
  );
  assert.throws(
    () =>
      bindGoogleProviderTopology(documents().oracle, documents().candidate, {
        ...options,
        fixtureImage: 'latest',
      }),
    /Invalid Phase 2 Google provider topology/u
  );
});
