import type { JSONWebKeySet } from 'jose';

import * as reviewedModule from './testing/native-code-pkce-adapter.mjs';

export const nativeCodePkceAdapterAuthority = Object.freeze({
  privateCommit: '0d9f6b8836d7356d50fc0a2fe13e9cfc68264c26',
  archiveSha256: 'be8688a2e0b63dd52a3a9286ff68a9c357ecdae64068abd21af9b0649bc7c1f0',
  sourceSha256: '2c68bdaa149b53b58a8eee1501c0a78513dbacbdeca408b86545db4e05348bc8',
});

export type NativeCodePkceAttempt = Readonly<{
  authorizationUrl: string;
  getVerifier(): string;
  getState(): string;
  getNonce(): string;
  toJSON(): never;
}>;

export type NativeCodePkceCompletionAttempt = Pick<
  NativeCodePkceAttempt,
  'getVerifier' | 'getState' | 'getNonce' | 'toJSON'
>;

export type NativeCodePkceCredentials = Readonly<{
  subject: string;
  profile: Readonly<Record<string, unknown>>;
  getResourceAccessToken(): string;
  getProfileAccessToken(): string;
  toJSON(): never;
}>;

export type NativeCodePkceAdapter = Readonly<{
  startNativeAuthorization(
    config: Readonly<{
      issuer: string;
      clientId: string;
      redirectUri: string;
      resource: string;
      resourceScope: 'session:exchange';
      idTokenAlgorithm: 'ES384';
    }>,
    entropy?: (size: number) => Uint8Array
  ): NativeCodePkceAttempt;
  completeNativeCallback(
    input: Readonly<{
      callbackUrl: string;
      attempt: NativeCodePkceCompletionAttempt;
      config: Readonly<{
        issuer: string;
        clientId: string;
        redirectUri: string;
        resource: string;
        resourceScope: 'session:exchange';
        idTokenAlgorithm: 'ES384';
      }>;
      jwks: JSONWebKeySet;
      fetcher: typeof fetch;
      now: number;
    }>
  ): Promise<NativeCodePkceCredentials>;
}>;

export const nativeCodePkceAdapter: NativeCodePkceAdapter = Object.freeze({
  startNativeAuthorization: reviewedModule.startNativeAuthorization,
  completeNativeCallback: reviewedModule.completeNativeCallback,
});
