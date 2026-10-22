/** @jest-environment node */

import { spawnSync } from 'node:child_process';
import path from 'node:path';

import { hasExperienceModuleSideEffects } from './bundle-module-side-effects';

const viteBuildScript = String.raw`
import { pathToFileURL } from 'node:url';
import { build } from 'vite';

const helperPath = process.env.ASTER_EXPERIENCE_MODULE_SIDE_EFFECTS_HELPER;
if (!helperPath) throw new Error('Missing helper path');

const { hasExperienceModuleSideEffects } = await import(pathToFileURL(helperPath).href);
const modules = new Map([
  ['/virtual/experience-entry.js', "import { requiredValue } from '/workspace/packages/schemas/lib/index.js'; import '/virtual/application-side-effect.js'; globalThis.__result = requiredValue;"],
  ['/workspace/packages/schemas/lib/index.js', "export { requiredValue } from '/workspace/packages/schemas/lib/db-entries/sign-in-experience.js'; export * from '/workspace/packages/schemas/lib/types/custom-profile-fields.js';"],
  ['/workspace/packages/schemas/lib/db-entries/sign-in-experience.js', "export const requiredValue = 'retained-required-export';"],
  ['/workspace/packages/schemas/lib/types/custom-profile-fields.js', "globalThis.__unusedServerDefinition = 'forbidden-unused-server-definition'; export const unusedValue = true;"],
  ['/virtual/application-side-effect.js', "globalThis.__externalEffect = 'retained-external-effect';"],
]);
const result = await build({
  configFile: false,
  logLevel: 'silent',
  build: {
    minify: false,
    write: false,
    rollupOptions: {
      input: '/virtual/experience-entry.js',
      treeshake: { moduleSideEffects: hasExperienceModuleSideEffects },
    },
  },
  plugins: [{
    name: 'experience-module-side-effects-test',
    resolveId: (id) => modules.has(id) ? id : undefined,
    load: (id) => modules.get(id),
  }],
});
if (!Array.isArray(result) && !('output' in result)) throw new Error('Missing build output');
const outputs = Array.isArray(result) ? result : [result];
const code = outputs.flatMap(({ output }) => output).map((item) => item.type === 'chunk' ? item.code : '').join('\n');
process.stdout.write(JSON.stringify({
  requiredExportRetained: code.includes('retained-required-export'),
  externalEffectRetained: code.includes('retained-external-effect'),
  unusedServerDefinitionRemoved: !code.includes('forbidden-unused-server-definition'),
}));
`;

describe('Experience bundle module side effects', () => {
  it('removes unused declarative server exports while retaining used exports and external effects', () => {
    const result = spawnSync(
      process.execPath,
      [
        '--no-warnings',
        '--experimental-strip-types',
        '--input-type=module',
        '--eval',
        viteBuildScript,
      ],
      {
        // Jest transforms this test as CommonJS and provides its containing directory here.
        // eslint-disable-next-line unicorn/prefer-module
        cwd: path.resolve(__dirname, '../..'),
        encoding: 'utf8',
        env: {
          ...process.env,
          ASTER_EXPERIENCE_MODULE_SIDE_EFFECTS_HELPER: path.resolve(
            // Jest transforms this test as CommonJS and provides its containing directory here.
            // eslint-disable-next-line unicorn/prefer-module
            __dirname,
            'bundle-module-side-effects.ts'
          ),
        },
        maxBuffer: 1024 * 1024,
        timeout: 30_000,
      }
    );

    expect({
      error: result.error?.message,
      signal: result.signal,
      status: result.status,
      stderr: result.stderr,
    }).toEqual({
      error: undefined,
      signal: null,
      status: 0,
      stderr: '',
    });
    expect(JSON.parse(result.stdout)).toEqual({
      requiredExportRetained: true,
      externalEffectRetained: true,
      unusedServerDefinitionRemoved: true,
    });
  });

  it.each([
    '/repo/packages/toolkit/connector-kit/lib/index.js',
    '/repo/packages/toolkit/connector-kit/lib/types/index.js',
    '/repo/packages/schemas/lib/index.js',
    '/repo/packages/schemas/lib/db-entries/logto-config.js',
    '/repo/packages/schemas/lib/db-entries/sign-in-experience.js',
    '/repo/packages/schemas/lib/db-entries/user.js',
    '/repo/packages/schemas/lib/types/custom-profile-fields.js',
    '/repo/packages/schemas/lib/types/onboarding.js',
  ])('treats the reviewed declarative module as side-effect free: %s', (id) => {
    expect(hasExperienceModuleSideEffects(id)).toBe(false);
  });

  it('does not mark application modules or similarly named external modules as pure', () => {
    expect(hasExperienceModuleSideEffects('/repo/packages/experience/src/App.tsx')).toBe(true);
    expect(hasExperienceModuleSideEffects('/vendor/schemas/lib/db-entries/user.js')).toBe(true);
    expect(
      hasExperienceModuleSideEffects(
        '/repo/packages/schemas/lib/db-entries/sign-in-experience.js?commonjs-proxy'
      )
    ).toBe(false);
  });
});
