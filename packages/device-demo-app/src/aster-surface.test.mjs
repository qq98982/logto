import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const sourceRoot = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.dirname(sourceRoot);

test('device demo exposes only Aster product-owned markers', () => {
  const runtimeSource = ['App.tsx', 'DevPanel.tsx', 'Footer.tsx']
    .map((file) => fs.readFileSync(path.join(sourceRoot, file), 'utf8'))
    .join('\n');
  const html = fs.readFileSync(path.join(packageRoot, 'index.html'), 'utf8');
  const productBearingAssets = fs
    .readdirSync(path.join(sourceRoot, 'assets'))
    .filter((file) => /logto/iu.test(file));

  assert.doesNotMatch(
    runtimeSource,
    /\bLogto\b|logto\.io|logto:device-demo-app|Powered By Logto/u
  );
  assert.match(runtimeSource, /aster:device-demo-app:dev:/u);
  assert.match(runtimeSource, />Aster</u);
  assert.match(html, /<title>Aster Device Flow Demo<\/title>/u);
  assert.deepEqual(productBearingAssets, []);
});
