import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  commonEmailPasswordRegistrationExpectedProjection,
  runCommonEmailPasswordRegistrationForTarget,
  type CommonEmailPasswordRegistrationTargetProjection,
} from '../browser/common-email-password-registration-target-driver.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonEmailPasswordRegistrationScenarioIds = Object.freeze([
  'common.email.password-registration',
] as const);

export type CommonEmailPasswordRegistrationScenarioResult = Readonly<{
  id: (typeof commonEmailPasswordRegistrationScenarioIds)[number];
  projection: CommonEmailPasswordRegistrationTargetProjection;
}>;

export const compareCommonEmailPasswordRegistrationProjections = (
  oracle: CommonEmailPasswordRegistrationTargetProjection,
  candidate: CommonEmailPasswordRegistrationTargetProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonEmailPasswordRegistrationExpectedProjection) &&
  isDeepStrictEqual(candidate, commonEmailPasswordRegistrationExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runCommonEmailPasswordRegistrationScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonEmailPasswordRegistrationScenarioResult> => {
  const { status } = input.fixture;
  if (!status) {
    throw new TypeError('Invalid Common email password registration scenario fixture');
  }
  const projection = await runCommonEmailPasswordRegistrationForTarget({
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
  return Object.freeze({ id: commonEmailPasswordRegistrationScenarioIds[0], projection });
};
