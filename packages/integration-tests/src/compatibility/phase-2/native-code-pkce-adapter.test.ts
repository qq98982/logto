import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import {
  nativeCodePkceAdapter,
  nativeCodePkceAdapterAuthority,
} from './native-code-pkce-adapter.js';

const sourcePath = path.resolve('src/compatibility/phase-2/testing/native-code-pkce-adapter.mjs');
const fixedEntropy = () => Buffer.alloc(32, 7);

describe('reviewed Native code PKCE adapter input', () => {
  it('binds the exact reviewed source and archive authority', async () => {
    const sourceSha256 = createHash('sha256')
      .update(await readFile(sourcePath))
      .digest('hex');

    expect(sourceSha256).toBe(nativeCodePkceAdapterAuthority.sourceSha256);
    expect(nativeCodePkceAdapterAuthority).toEqual({
      privateCommit: '0d9f6b8836d7356d50fc0a2fe13e9cfc68264c26',
      archiveSha256: 'be8688a2e0b63dd52a3a9286ff68a9c357ecdae64068abd21af9b0649bc7c1f0',
      sourceSha256: '2c68bdaa149b53b58a8eee1501c0a78513dbacbdeca408b86545db4e05348bc8',
    });
    expect(Object.isFrozen(nativeCodePkceAdapterAuthority)).toBe(true);
  });

  it('admits only the reviewed ES384 selection before network use', () => {
    const config = {
      issuer: 'https://identity.example/oidc',
      clientId: 'native-client',
      redirectUri: 'https://app.example/callback',
      resource: 'https://app.example/api',
      resourceScope: 'session:exchange' as const,
      idTokenAlgorithm: 'ES384' as const,
    };
    const attempt = nativeCodePkceAdapter.startNativeAuthorization(config, fixedEntropy);

    expect(new URL(attempt.authorizationUrl).searchParams.get('code_challenge_method')).toBe(
      'S256'
    );
    expect(() =>
      nativeCodePkceAdapter.startNativeAuthorization(
        { ...config, idTokenAlgorithm: 'RS256' as 'ES384' },
        fixedEntropy
      )
    ).toThrow('callback rejected (id-token-algorithm)');
  });
});
