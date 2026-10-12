import assert from 'node:assert/strict';
import test from 'node:test';

import { applyCandidateIdentityConfig } from './apply-candidate-identity-config.mjs';

test('keeps the core trust bundle separate from the isolated identity CA', () => {
  const result = applyCandidateIdentityConfig({ services: {
    'candidate-primary-core': {
      environment: {
        NODE_EXTRA_CA_CERTS: '/run/aster/core-extra-ca-bundle.pem',
        SSL_CERT_FILE: '/run/aster/core-extra-ca-bundle.pem',
      },
      volumes: ['/private/bundle.pem:/run/aster/core-extra-ca-bundle.pem:ro'],
    },
  } }, {
    configurationFile: '/private/identity-transports.json',
    caFile: '/private/identity-ca.pem',
  });
  const core = result.services['candidate-primary-core'];
  assert.equal(core.environment.NODE_EXTRA_CA_CERTS, '/run/aster/core-extra-ca-bundle.pem');
  assert.equal(core.environment.SSL_CERT_FILE, '/run/aster/core-extra-ca-bundle.pem');
  assert.equal(core.environment.ASTER_ISOLATED_IDENTITY_TRANSPORT_CONFIG, '/run/aster/identity-transports.json');
  assert.deepEqual(core.volumes, [
    '/private/bundle.pem:/run/aster/core-extra-ca-bundle.pem:ro',
    '/private/identity-transports.json:/run/aster/identity-transports.json:ro',
    '/private/identity-ca.pem:/run/aster/identity-fixture-ca.pem:ro',
  ]);
});
