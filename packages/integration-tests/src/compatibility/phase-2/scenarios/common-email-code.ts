import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  commonEmailCodeExpectedProjection,
  commonEmailCodeScenarioId,
  type CommonEmailCodeProjection,
} from '../browser/common-email-code-sign-in.js';
import { runCommonEmailCodeForTarget } from '../browser/common-email-code-target-driver.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonEmailCodeScenarioIds = Object.freeze([commonEmailCodeScenarioId] as const);

export type CommonEmailCodeScenarioResult = Readonly<{
  id: (typeof commonEmailCodeScenarioIds)[number];
  projection: CommonEmailCodeProjection;
}>;

export const compareCommonEmailCodeProjections = (
  oracle: CommonEmailCodeProjection,
  candidate: CommonEmailCodeProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonEmailCodeExpectedProjection) &&
  isDeepStrictEqual(candidate, commonEmailCodeExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runCommonEmailCodeScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonEmailCodeScenarioResult> => {
  const { status } = input.fixture;
  if (!status) {
    throw new TypeError('Invalid Common email code scenario fixture');
  }
  const projection = await runCommonEmailCodeForTarget({
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
  return Object.freeze({ id: commonEmailCodeScenarioId, projection });
};
