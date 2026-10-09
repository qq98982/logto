import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  commonEmailRecoveryExpectedProjection,
  runCommonEmailRecoveryForTarget,
  type CommonEmailRecoveryTargetProjection,
} from '../browser/common-email-recovery-target-driver.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonPasswordRecoveryScenarioIds = Object.freeze([
  'common.password.recovery',
] as const);

export type CommonPasswordRecoveryScenarioResult = Readonly<{
  id: (typeof commonPasswordRecoveryScenarioIds)[number];
  projection: CommonEmailRecoveryTargetProjection;
}>;

export const compareCommonPasswordRecoveryProjections = (
  oracle: CommonEmailRecoveryTargetProjection,
  candidate: CommonEmailRecoveryTargetProjection
): readonly string[] =>
  isDeepStrictEqual(oracle, commonEmailRecoveryExpectedProjection) &&
  isDeepStrictEqual(candidate, commonEmailRecoveryExpectedProjection) &&
  isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export const runCommonPasswordRecoveryScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonPasswordRecoveryScenarioResult> => {
  const { status } = input.fixture;
  if (!status) {
    throw new TypeError('Invalid Common password recovery scenario fixture');
  }
  const projection = await runCommonEmailRecoveryForTarget({
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
  return Object.freeze({ id: commonPasswordRecoveryScenarioIds[0], projection });
};
