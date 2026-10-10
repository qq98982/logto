import { isDeepStrictEqual } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  runCommonPhoneCodeForTarget,
  type CommonPhoneCodeTargetInput,
  type CommonPhoneCodeScenarioProjection,
} from '../browser/common-phone-code-target-driver.js';
import { assertCommonPhoneCodeControls } from '../browser/common-phone-code.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonPhoneCodeScenarioIds = Object.freeze([
  'common.phone.code-registration',
  'common.phone.code-sign-in',
] as const);
export type CommonPhoneCodeScenarioResult = Readonly<{
  id: (typeof commonPhoneCodeScenarioIds)[number];
  projection: CommonPhoneCodeScenarioProjection;
}>;
export const compareCommonPhoneCodeProjections = (
  id: CommonPhoneCodeScenarioResult['id'],
  oracle: CommonPhoneCodeScenarioProjection,
  candidate: CommonPhoneCodeScenarioProjection
): readonly string[] => {
  const outcome = id === commonPhoneCodeScenarioIds[0] ? 'created' : 'accepted';
  try {
    assertCommonPhoneCodeControls(oracle.controls);
    assertCommonPhoneCodeControls(candidate.controls);
    const expectedFlow = {
      identifier: 'phone',
      outcome,
      consent: true,
      callback: 'state-issuer-code-bound',
      pkce: 'S256',
      profileSubject: true,
      phoneVerified: true,
      refreshRotated: true,
    };
    const expected = { flow: expectedFlow, controls: oracle.controls };
    return isDeepStrictEqual(oracle, expected) && isDeepStrictEqual(candidate, expected)
      ? []
      : ['/projection'];
  } catch {
    return ['/projection'];
  }
};
export const runCommonPhoneCodeScenarioRow = async (
  input: Readonly<{
    scenario: CommonPhoneCodeTargetInput['scenario'];
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
    withProviderLease: CommonPhoneCodeTargetInput['withProviderLease'];
  }>
): Promise<CommonPhoneCodeScenarioResult> => {
  const { status } = input.fixture;
  if (!status) {
    throw new TypeError('Invalid Common phone code scenario fixture');
  }
  const projection = await runCommonPhoneCodeForTarget({
    ...input,
    browser: {
      storageKey:
        input.target.label === 'oracle'
          ? asterNativeSurfaceContract.markers.demoConfigStorageKey.reference
          : asterNativeSurfaceContract.markers.demoConfigStorageKey.candidate,
      demo: {
        appId: status.client.id,
        prompt: 'consent',
        scope: `openid offline_access profile phone ${status.resource.scopeName}`,
        resource: status.resource.indicator,
      },
      redirectUri: new URL('/demo-app', input.target.coreUrl).href,
      initialResponseScope: 'openid offline_access profile phone',
      resourceScope: status.resource.scopeName,
    },
  });
  return Object.freeze({
    id: commonPhoneCodeScenarioIds[input.scenario === 'registration' ? 0 : 1],
    projection,
  });
};
