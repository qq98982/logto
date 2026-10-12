import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { promisify } from 'node:util';
import assert from 'node:assert/strict';
import test from 'node:test';

const execute = promisify(execFile);

test('binds public targets to core ports while reserving HTTPS ports for H5', async () => {
  const root = await mkdtemp('/var/tmp/henry-build/common206-descriptor-test.');
  try {
    const sms = `${root}/sms`;
    await Promise.all(['o', 'c'].map(async (role) => {
      await mkdir(`${sms}/${role}`, { recursive: true, mode: 0o700 });
      await writeFile(`${sms}/${role}/configuration.json`, JSON.stringify({
        accessKeyId: `${role}-id`,
        accessKeySecret: `${role}-private`,
        signName: `${role}-sign`,
        templates: { Register: `${role}-register-template` },
      }), { mode: 0o600 });
    }));
    const script = new URL('./generate-runtime-descriptors.mjs', import.meta.url).pathname;
    await execute(process.execPath, [script, root, `sha256:${'a'.repeat(64)}`, 'oracle-project',
      'candidate-project', `${root}/oracle-google.json`, `${root}/candidate-google.json`,
      `${root}/oracle-web.json`, `${root}/candidate-web.json`, sms]);
    const [oracle, candidate] = await Promise.all(['oracle', 'candidate'].map(async (role) =>
      JSON.parse(await readFile(`${root}/runtime-common/${role}-descriptor.json`, 'utf8'))));
    assert.deepEqual(oracle.target, { label: 'oracle', coreUrl: 'http://localhost:3311/', adminUrl: 'http://localhost:3411/' });
    assert.equal(oracle.h5.listenUrl, 'https://localhost:3351');
    assert.deepEqual(candidate.target, { label: 'candidate', coreUrl: 'http://localhost:3321/', adminUrl: 'http://localhost:3421/' });
    assert.equal(candidate.h5.listenUrl, 'https://localhost:3352');
    assert.equal(oracle.wechat.service, 'oracle-wechat-multichannel-provider');
    assert.equal(candidate.wechat.service, 'candidate-wechat-multichannel-provider');
    assert.match(oracle.wechat.phone, /^\d+$/u);
    assert.match(candidate.wechat.phone, /^\d+$/u);
    assert.notEqual(oracle.wechat.phone, candidate.wechat.phone);
    assert.deepEqual(
      [oracle.wechat.smsAccessKeyId, oracle.wechat.smsAccessSecret, oracle.wechat.smsSignName,
        oracle.wechat.smsTemplateCode],
      ['o-id', 'o-private', 'o-sign', 'o-register-template']
    );
    assert.equal(oracle.wechat.dockerHome, candidate.wechat.dockerHome);
    const dockerHome = await stat(oracle.wechat.dockerHome);
    assert.equal(dockerHome.isDirectory(), true);
    assert.equal(dockerHome.mode & 0o777, 0o700);
    for (const descriptor of [oracle, candidate]) {
      const configuration = await stat(descriptor.wechat.configFile);
      assert.equal(configuration.size, 0);
      assert.equal(configuration.mode & 0o777, 0o600);
      assert.equal(await readFile(descriptor.wechat.configFile, 'utf8'), '');
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
