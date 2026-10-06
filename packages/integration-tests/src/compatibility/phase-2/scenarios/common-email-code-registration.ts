import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  commonEmailCodeRegistrationExpectedProjection,
  runCommonEmailCodeRegistrationForTarget,
  type CommonEmailCodeRegistrationTargetProjection,
} from '../browser/common-email-code-registration-target-driver.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonEmailCodeRegistrationScenarioIds = Object.freeze([
  'common.email.code-registration',
] as const);

export type CommonEmailCodeRegistrationScenarioResult = Readonly<{
  id: (typeof commonEmailCodeRegistrationScenarioIds)[number];
  projection: CommonEmailCodeRegistrationTargetProjection;
}>;

export const compareCommonEmailCodeRegistrationProjections = (
  oracle: CommonEmailCodeRegistrationTargetProjection,
  candidate: CommonEmailCodeRegistrationTargetProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonEmailCodeRegistrationExpectedProjection) &&
  isDeepStrictEqual(candidate, commonEmailCodeRegistrationExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runCommonEmailCodeRegistrationScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonEmailCodeRegistrationScenarioResult> => {
  const { status } = input.fixture;
  if (!status) {
    throw new TypeError('Invalid Common email code registration scenario fixture');
  }
  const projection = await runCommonEmailCodeRegistrationForTarget({
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
  return Object.freeze({ id: commonEmailCodeRegistrationScenarioIds[0], projection });
};
