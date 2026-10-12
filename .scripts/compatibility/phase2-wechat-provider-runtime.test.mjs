import assert from 'node:assert/strict';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
} from 'node:fs/promises';
import { test } from 'node:test';

import {
  clearWechatProviderHealthProbeFiles,
  prepareWechatProviderRuntimeFiles,
  writeWechatProviderHealthProbeConfigurations,
  writeWechatProviderRuntimeInputs,
} from './phase2-wechat-provider-runtime.mjs';
import { parseWechatProviderConfiguration } from './phase2-wechat-provider.mjs';

const createRoot = async () => {
  const parent = await mkdtemp('/var/tmp/henry-build/phase2-Wechat-provider-runtime-');
  await chmod(parent, 0o700);
  const home = `${parent}/home`;
  await mkdir(home, { mode: 0o700 });
  return { parent, root: `${parent}/provider`, home };
};

const targetInput = (root, home) => ({
  root,
  oracle: {
    container: 'oracle-project-oracle-Wechat-provider-1',
    project: 'oracle-project',
    service: 'oracle-wechat-provider',
    image: `sha256:${'7'.repeat(64)}`,
  },
  candidate: {
    container: 'candidate-project-candidate-Wechat-provider-1',
    project: 'candidate-project',
    service: 'candidate-wechat-provider',
    image: `sha256:${'7'.repeat(64)}`,
  },
  dockerHome: home,
  apiVersion: '5.5.2',
});

test('prepares isolated private files and exact target-specific provider inputs', async () => {
  const fixture = await createRoot();
  try {
    const prepared = await prepareWechatProviderRuntimeFiles(fixture.root);
    const paths = await writeWechatProviderRuntimeInputs(targetInput(fixture.root, fixture.home));
    assert.deepEqual(paths, prepared);
    const oracle = JSON.parse(await readFile(paths.oracleInputFile, 'utf8'));
    const candidate = JSON.parse(await readFile(paths.candidateInputFile, 'utf8'));
    const keys = [
      'schemaVersion', 'container', 'project', 'service', 'image', 'configFile', 'receiptFile',
      'healthDiagnosticFile', 'dockerHome', 'apiVersion', 'wechatSubject', 'originalOwnerEmail',
      'unionId', 'channel', 'clientId', 'clientSecret',
    ].toSorted();
    assert.deepEqual(Object.keys(oracle).toSorted(), keys);
    assert.deepEqual(Object.keys(candidate).toSorted(), keys);
    assert.equal(oracle.channel, 'web');
    assert.equal(candidate.channel, 'web');
    assert.equal(oracle.wechatSubject, candidate.wechatSubject);
    assert.equal(oracle.wechatSubject, oracle.unionId);
    assert.equal(candidate.wechatSubject, candidate.unionId);
    assert.equal(oracle.originalOwnerEmail, candidate.originalOwnerEmail);
    assert.equal(oracle.unionId, candidate.unionId);
    assert.notEqual(oracle.clientId, candidate.clientId);
    assert.notEqual(oracle.clientSecret, candidate.clientSecret);
    for (const file of [
      paths.oracleInputFile,
      paths.candidateInputFile,
      oracle.configFile,
      oracle.receiptFile,
      oracle.healthDiagnosticFile,
      candidate.configFile,
      candidate.receiptFile,
      candidate.healthDiagnosticFile,
    ]) {
      const state = await lstat(file);
      assert.equal(state.isFile(), true);
      assert.equal(state.isSymbolicLink(), false);
      assert.equal(state.nlink, 1);
      assert.equal(state.mode & 0o777, 0o600);
    }
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test('rejects reused targets, malformed API versions, and repeated preparation', async () => {
  const fixture = await createRoot();
  try {
    await prepareWechatProviderRuntimeFiles(fixture.root);
    const valid = targetInput(fixture.root, fixture.home);
    await assert.rejects(
      writeWechatProviderRuntimeInputs({ ...valid, apiVersion: 'latest' }),
      /Invalid Phase 2 WeChat provider runtime preparation/u
    );
    await assert.rejects(
      writeWechatProviderRuntimeInputs({
        ...valid,
        candidate: { ...valid.candidate, project: valid.oracle.project },
      }),
      /Invalid Phase 2 WeChat provider runtime preparation/u
    );
    await assert.rejects(
      prepareWechatProviderRuntimeFiles(fixture.root),
      /EEXIST|Invalid Phase 2 WeChat provider runtime preparation/u
    );
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test('writes a valid non-authenticating health probe in place and clears every mutable file', async () => {
  const fixture = await createRoot();
  try {
    await prepareWechatProviderRuntimeFiles(fixture.root);
    const files = ['oracle', 'candidate'].flatMap((role) => [
      `${fixture.root}/${role}/configuration/configuration.json`,
      `${fixture.root}/${role}/receipts/observations.json`,
      `${fixture.root}/${role}/diagnostics/health.json`,
    ]);
    const identities = await Promise.all(files.map(async (file) => lstat(file)));
    await writeWechatProviderHealthProbeConfigurations(fixture.root);
    for (const role of ['oracle', 'candidate']) {
      const file = `${fixture.root}/${role}/configuration/configuration.json`;
      const value = JSON.parse(await readFile(file, 'utf8'));
      assert.deepEqual(Object.keys(value).toSorted(), [
        'schemaVersion', 'appId', 'appSecret', 'unionId', 'codes',
      ].toSorted());
      assert.equal(value.schemaVersion, 1);
      assert.deepEqual(Object.keys(value.codes).toSorted(), [
        'setup', 'browser', 'account', 'foreignAccount', 'noUnionId', 'invalidCode', 'replay', 'malformedProvider',
      ].toSorted());
      assert.equal(new Set(Object.values(value.codes)).size, 8);
      assert.match(value.unionId, /^common-wechat-health-/u);
      assert.doesNotThrow(() => parseWechatProviderConfiguration(value));
    }
    await clearWechatProviderHealthProbeFiles(fixture.root);
    for (const [index, file] of files.entries()) {
      const state = await lstat(file);
      assert.equal(state.dev, identities[index].dev);
      assert.equal(state.ino, identities[index].ino);
      assert.equal(state.size, 0);
      assert.equal(state.mode & 0o777, 0o600);
    }
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test('rejects a symlinked or replaced known provider configuration file', async () => {
  const fixture = await createRoot();
  try {
    await prepareWechatProviderRuntimeFiles(fixture.root);
    const configuration = `${fixture.root}/oracle/configuration/configuration.json`;
    const moved = `${fixture.root}/oracle/configuration/original.json`;
    await rename(configuration, moved);
    await symlink(moved, configuration);
    await assert.rejects(
      writeWechatProviderHealthProbeConfigurations(fixture.root),
      /Invalid Phase 2 WeChat provider runtime preparation/u
    );
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});
