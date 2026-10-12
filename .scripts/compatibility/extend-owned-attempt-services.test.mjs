import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { extendOwnedAttemptServices } from './extend-owned-attempt-services.mjs';

const image = `sha256:${'a'.repeat(64)}`;
const descriptorFor = (root) => ({
  target: { label: 'oracle', coreUrl: 'http://localhost:3311', adminUrl: 'http://localhost:3411' },
  pwned: Object.fromEntries(
    ['clear', 'compromised', 'unavailable'].map((name) => [name, {
      container: `project-oracle-pwned-${name}-1`, project: 'project',
      service: `oracle-pwned-${name}`, image, receiptFile: `${root}/${name}.receipt`,
      configFile: `${root}/${name}.config`, dockerHome: `${root}/docker`, apiVersion: '4.9.4',
    }])
  ),
  backchannel: Object.fromEntries(
    ['accepted', 'rejected'].map((name) => [name, {
      container: `project-oracle-backchannel-${name}-1`, project: 'project',
      service: `oracle-backchannel-${name}`, image, receiptFile: `${root}/${name}.receipt`,
      socketFile: `${root}/${name}.sock`, dockerHome: `${root}/docker`, apiVersion: '4.9.4',
    }])
  ),
});
const optionsFor = (root, descriptorFile) => ({
  backchannelScript: `${root}/backchannel.mjs`, caFile: `${root}/ca.pem`,
  certificateFile: `${root}/server.pem`, descriptorFile,
  privateKeyFile: `${root}/server.key`, pwnedScript: `${root}/pwned.mjs`,
});
const topology = () => ({
  services: {
    'oracle-primary-core': {
      environment: { NODE_EXTRA_CA_CERTS: '/run/aster/fetch-observer-ca.pem' },
      extra_hosts: ['dysmsapi.aliyuncs.com:172.30.231.54'], volumes: [],
    },
    'oracle-sms-provider': {
      networks: { 'oracle-primary': { ipv4_address: '172.30.231.54', aliases: ['dysmsapi.aliyuncs.com'] } },
    },
  },
  networks: { 'oracle-primary': { internal: true } },
});

test('keeps the Common SMS fixture stable and assigns the isolated Pwned peer separately', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'aster-owned-attempt-'));
  const descriptorFile = `${root}/descriptor.json`;
  await writeFile(descriptorFile, JSON.stringify(descriptorFor(root)));
  const result = await extendOwnedAttemptServices(topology(), optionsFor(root, descriptorFile));
  assert.equal(result.services['oracle-sms-provider'].networks['oracle-primary'].ipv4_address, '172.30.231.54');
  assert.ok(result.services['oracle-primary-core'].extra_hosts.includes('dysmsapi.aliyuncs.com:172.30.231.54'));
  assert.ok(result.services['oracle-primary-core'].extra_hosts.includes('api.pwnedpasswords.com:172.30.231.56'));
  assert.equal(result.services['oracle-primary-core'].environment.NODE_EXTRA_CA_CERTS, '/run/aster/core-extra-ca-bundle.pem');
  assert.ok(result.services['oracle-primary-core'].volumes.includes(`${root}/ca.pem:/run/aster/core-extra-ca-bundle.pem:ro`));
  assert.equal(result.services['oracle-pwned-clear'].networks['oracle-primary'].ipv4_address, '172.30.231.56');
});

test('accepts the topology independently of the existing SMS fixture details', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'aster-owned-attempt-'));
  const descriptorFile = `${root}/descriptor.json`;
  await writeFile(descriptorFile, JSON.stringify(descriptorFor(root)));
  const input = topology();
  delete input.services['oracle-sms-provider'];
  await assert.doesNotReject(extendOwnedAttemptServices(input, optionsFor(root, descriptorFile)));
});
