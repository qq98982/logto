import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { test } from 'node:test';
import { promisify } from 'node:util';

import {
  clearGoogleProviderHealthProbeFiles,
  prepareGoogleProviderRuntimeFiles,
  writeGoogleProviderHealthProbeConfigurations,
  writeGoogleProviderRuntimeInputs,
} from './phase2-google-provider-runtime.mjs';

const execute = promisify(execFile);

const createRoot = async () => {
  const parent = await mkdtemp('/var/tmp/henry-build/phase2-google-provider-runtime-');
  await chmod(parent, 0o700);
  const home = `${parent}/home`;
  await mkdir(home, { mode: 0o700 });
  return { parent, root: `${parent}/provider`, home };
};

const targetInput = (root, home) => ({
  root,
  oracle: {
    container: 'oracle-project-oracle-google-provider-1',
    project: 'oracle-project',
    service: 'oracle-google-provider',
    image: `sha256:${'7'.repeat(64)}`,
  },
  candidate: {
    container: 'candidate-project-candidate-google-provider-1',
    project: 'candidate-project',
    service: 'candidate-google-provider',
    image: `sha256:${'7'.repeat(64)}`,
  },
  dockerHome: home,
  apiVersion: '5.5.2',
});

test('prepares isolated provider inputs accepted by the pinned Google provisioner', async () => {
  const fixture = await createRoot();
  try {
    const prepared = await prepareGoogleProviderRuntimeFiles(fixture.root);
    const paths = await writeGoogleProviderRuntimeInputs(targetInput(fixture.root, fixture.home));
    assert.deepEqual(paths, prepared);
    const oracle = JSON.parse(await readFile(paths.oracleInputFile, 'utf8'));
    const candidate = JSON.parse(await readFile(paths.candidateInputFile, 'utf8'));
    const keys = [
      'schemaVersion', 'container', 'project', 'service', 'image', 'configFile', 'receiptFile',
      'healthDiagnosticFile', 'dockerHome', 'apiVersion', 'googleSubject', 'originalOwnerEmail',
      'changedProviderEmail', 'expectedUserinfoMethod', 'clientId', 'clientSecret',
    ].toSorted();
    assert.deepEqual(Object.keys(oracle).toSorted(), keys);
    assert.deepEqual(Object.keys(candidate).toSorted(), keys);
    assert.equal(oracle.expectedUserinfoMethod, 'POST');
    assert.equal(candidate.expectedUserinfoMethod, 'GET');
    assert.equal(oracle.googleSubject, candidate.googleSubject);
    assert.equal(oracle.originalOwnerEmail, candidate.originalOwnerEmail);
    assert.equal(oracle.changedProviderEmail, candidate.changedProviderEmail);
    assert.notEqual(oracle.clientId, candidate.clientId);
    assert.notEqual(oracle.clientSecret, candidate.clientSecret);
    for (const input of [oracle, candidate]) {
      assert.match(input.clientId, /^[0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com$/u);
      assert.match(input.clientSecret, /^[!-~]{8,100}$/u);
    }
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
    await prepareGoogleProviderRuntimeFiles(fixture.root);
    const valid = targetInput(fixture.root, fixture.home);
    await assert.rejects(
      writeGoogleProviderRuntimeInputs({ ...valid, apiVersion: 'latest' }),
      /Invalid Phase 2 Google provider runtime preparation/u
    );
    await assert.rejects(
      writeGoogleProviderRuntimeInputs({
        ...valid,
        candidate: { ...valid.candidate, project: valid.oracle.project },
      }),
      /Invalid Phase 2 Google provider runtime preparation/u
    );
    await assert.rejects(
      prepareGoogleProviderRuntimeFiles(fixture.root),
      /EEXIST|Invalid Phase 2 Google provider runtime preparation/u
    );
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test('runner forwards exact Common failures and ignores other diagnostic text', async () => {
  const fixture = await createRoot();
  try {
    const stderrFile = `${fixture.parent}/rows.stderr`;
    const accepted = [
      'common.email.password-registration',
      'common.password.recovery',
      'common.google.existing-owner',
      'common.wechat.h5',
    ].flatMap((id) =>
      ['oracle', 'candidate'].map(
        (target) => `Phase 2 client credentials command failed (${target}/${id}).`
      )
    );
    accepted.push('Phase 2 client credentials command failed (oracle/common.password.policy/compromise-clear).');
    accepted.push('Phase 2 client credentials command failed (oracle/common.password.policy/local-policy-readback).');
    accepted.push('Phase 2 client credentials command failed (candidate-completion-fixture).');
    accepted.push('Phase 2 client credentials command failed (oracle-completion-runtime-read).');
    accepted.push('Phase 2 client credentials command failed (candidate-completion-owned-app-cleanup/common.account.wechat-link).');
    await writeFile(
      stderrFile,
      `${[
        ...accepted,
        'Phase 2 client credentials command failed (oracle/common.google.unknown).',
        'Phase 2 client credentials command failed (candidate/common.google.existing-owner): private-secret.',
        'Phase 2 client credentials command failed (oracle-completion-runtime-read/private-secret).',
        'Phase 2 client credentials command failed (candidate-completion-owned-app-cleanup/common.unknown).',
        'Phase 2 client credentials command failed (oracle/common.password.policy/private).',
        'Phase 2 client credentials command failed (oracle/common.password.policy/local-policy-read-secret).',
      ].join('\n')}\n`,
      { mode: 0o600 }
    );
    const runner = new URL('./run-phase2-client-credentials.sh', import.meta.url).pathname;
    const { stderr } = await execute('/usr/bin/bash', [
      '-c',
      'source "$1"; forward_closed_common_row_failures "$2"',
      'phase2-google-provider-runtime-test',
      runner,
      stderrFile,
    ]);
    assert.deepEqual(stderr.trim().split('\n'), accepted);
    assert.equal(stderr.includes('unknown'), false);
    assert.equal(stderr.includes('private-secret'), false);
    await writeFile(stderrFile, 'unrecognized diagnostic\n', { mode: 0o600 });
    const empty = await execute('/usr/bin/bash', [
      '-c',
      'source "$1"; forward_closed_common_row_failures "$2"',
      'phase2-google-provider-runtime-test',
      runner,
      stderrFile,
    ]);
    assert.equal(empty.stderr, '');
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});

test('writes a valid non-authenticating health probe in place and clears every mutable file', async () => {
  const fixture = await createRoot();
  try {
    await prepareGoogleProviderRuntimeFiles(fixture.root);
    const files = ['oracle', 'candidate'].flatMap((role) => [
      `${fixture.root}/${role}/configuration/configuration.json`,
      `${fixture.root}/${role}/receipts/observations.json`,
      `${fixture.root}/${role}/diagnostics/health.json`,
    ]);
    const identities = await Promise.all(files.map(async (file) => lstat(file)));
    await writeGoogleProviderHealthProbeConfigurations(fixture.root);
    for (const role of ['oracle', 'candidate']) {
      const file = `${fixture.root}/${role}/configuration/configuration.json`;
      const value = JSON.parse(await readFile(file, 'utf8'));
      assert.deepEqual(Object.keys(value).toSorted(), [
        'schemaVersion',
        'clientId',
        'clientSecret',
        'targetOrigin',
        'connectorId',
        'callbackUri',
        'stable',
        'changedEmail',
        'wrongStateControl',
        'unverifiedEmailControl',
        'occupiedEmailControl',
      ].toSorted());
      assert.equal(value.schemaVersion, 1);
      assert.equal(value.callbackUri, `${value.targetOrigin}/callback/${value.connectorId}`);
      assert.equal(value.stable.profile.sub, value.changedEmail.profile.sub);
      assert.equal(value.stable.profile.sub, value.wrongStateControl.profile.sub);
      assert.notEqual(value.stable.code, value.changedEmail.code);
      assert.notEqual(value.changedEmail.code, value.wrongStateControl.code);
    }
    await clearGoogleProviderHealthProbeFiles(fixture.root);
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
    await prepareGoogleProviderRuntimeFiles(fixture.root);
    const configuration = `${fixture.root}/oracle/configuration/configuration.json`;
    const moved = `${fixture.root}/oracle/configuration/original.json`;
    await rename(configuration, moved);
    await symlink(moved, configuration);
    await assert.rejects(
      writeGoogleProviderHealthProbeConfigurations(fixture.root),
      /Invalid Phase 2 Google provider runtime preparation/u
    );
  } finally {
    await rm(fixture.parent, { recursive: true, force: true });
  }
});
