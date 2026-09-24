import { defineConfig, type Options } from 'tsup';

import { defaultConfig } from '../../tsup.shared.config.js';

export const config = Object.freeze({
  ...defaultConfig,
  entry: ['src/index.ts', 'src/runtime-probes/aliyun-captcha.ts', 'src/workers/tasks/**/*.ts'],
  noExternal: ['@alicloud/captcha20230305', '@alicloud/openapi-core', '@darabonba/typescript'],
  banner: {
    js: [
      "import { createRequire as __boxAiCreateRequire } from 'node:module';",
      'const require = __boxAiCreateRequire(import.meta.url);',
    ].join(' '),
  },
  outDir: 'build',
  onSuccess: 'pnpm run copy:apidocs',
} satisfies Options);

export default defineConfig(config);
