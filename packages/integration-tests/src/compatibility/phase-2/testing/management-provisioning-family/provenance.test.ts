/* eslint-disable no-await-in-loop -- Each pinned fixture is read and hashed independently. */
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const expected = Object.freeze({
  'provision-client.mjs': 'c057f7300db270a1fa6c22f043304d25c10fbc9097118097352b614c29f419e3',
  'provision-email-connector.mjs':
    '5bad4703931bbf59bcf06c7c11271e83f91a163c1c8323598babde389b81bac7',
  'provision-google-connector.mjs':
    '41dda3bf0d627dc6ab12436c467ee312b4a05bb786998972cc5e67da7fdb200b',
  'provision-sms-connector.mjs': '0ee786ee8475486d1eca4a0c10dd3907b8aa278782efa0fe9b12e214081de0de',
  'provision-wechat-connectors.mjs':
    'a05a82c052682dbc3aab1cda07891a551a7e0b3b02efc83976ffac7debf57659',
});
test('pins the reviewed synthetic provisioner copies from Aster c5d9ed6', async () => {
  for (const [name, digest] of Object.entries(expected)) {
    const source = await readFile(
      new URL(
        `../../../../../src/compatibility/phase-2/testing/management-provisioning-family/${name}`,
        import.meta.url
      )
    );
    expect(createHash('sha256').update(source).digest('hex')).toBe(digest);
    expect(source.toString('utf8')).toContain('BOX_AI_LOGTO_MANAGEMENT_TOKEN');
  }
});
/* eslint-enable no-await-in-loop */
