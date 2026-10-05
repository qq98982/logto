import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import type { CommonEmailPasswordProjection } from '../browser/common-email-password-sign-in.js';
import { runCommonEmailPasswordForTarget } from '../browser/common-email-password-target-driver.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonEmailPasswordScenarioIds = Object.freeze([
  'common.email.password-sign-in',
] as const);

export const commonEmailPasswordExpectedProjection = Object.freeze({
  identifier: 'email' as const,
  casing: 'canonical-owner' as const,
  passwordOutcome: 'accepted' as const,
  consent: true as const,
  callback: 'state-issuer-code-bound' as const,
  pkce: 'S256' as const,
  profileSubject: true as const,
  emailVerified: true as const,
  refreshRotated: true as const,
  invalidPassword: 'rejected' as const,
  suspended: 'rejected' as const,
  usernamePreserved: true as const,
});

export type CommonEmailPasswordScenarioResult = Readonly<{
  id: (typeof commonEmailPasswordScenarioIds)[number];
  projection: CommonEmailPasswordProjection;
}>;

export const compareCommonEmailPasswordProjections = (
  oracle: CommonEmailPasswordProjection,
  candidate: CommonEmailPasswordProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonEmailPasswordExpectedProjection) &&
  isDeepStrictEqual(candidate, commonEmailPasswordExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runCommonEmailPasswordScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonEmailPasswordScenarioResult> => {
  const { status } = input.fixture;
  if (!status) {
    throw new TypeError('Invalid Common email password scenario fixture');
  }
  const projection = await runCommonEmailPasswordForTarget({
    ...input,
    browser: {
      storageKey:
        input.target.label === 'oracle'
          ? asterNativeSurfaceContract.markers.demoConfigStorageKey.reference
          : asterNativeSurfaceContract.markers.demoConfigStorageKey.candidate,
      demo: {
        appId: status.client.id,
        prompt: 'consent',
        scope: `openid offline_access profile email ${status.resource.scopeName}`,
        resource: status.resource.indicator,
      },
      redirectUri: new URL('/demo-app', input.target.coreUrl).href,
      initialResponseScope: 'openid offline_access profile email',
      resourceScope: status.resource.scopeName,
    },
  });
  return Object.freeze({
    id: commonEmailPasswordScenarioIds[0],
    projection,
  });
};
