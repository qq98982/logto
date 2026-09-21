/* eslint-disable complexity -- This boundary validates the exact pinned profile projection before releasing public config. */
import { cloneAndDeepFreeze, snapshotClosedDataGraph } from '../model.js';
import { assertConformanceSemantics } from '../profile-semantics/conformance.js';
import type { Phase1Profile } from '../profile-types.js';

export const phase1ConformanceSuiteRepository = 'https://gitlab.com/openid/conformance-suite.git';
export const phase1ConformanceSuiteCommit = '0dc0e3a21ec411e92c808e5b2e2258592c22b594';

export type Phase1ConformancePlanId =
  | 'oidcc-basic-certification-test-plan'
  | 'oidcc-config-certification-test-plan';

export type Phase1ConformancePublicPlan = Readonly<{
  id: Phase1ConformancePlanId;
  displayName: string;
  variant: Readonly<Record<string, unknown>>;
}>;

export type Phase1ConformancePublicConfig = Readonly<{
  schemaVersion: 1;
  suite: Readonly<{
    repository: typeof phase1ConformanceSuiteRepository;
    commit: typeof phase1ConformanceSuiteCommit;
  }>;
  target: Readonly<{
    issuer: string;
    discoveryUrl: string;
    suiteBaseUrl: string;
    alias: string;
    callbackUri: string;
  }>;
  staticClients: ReadonlyArray<
    Readonly<{
      id: 'oidf-basic-1' | 'oidf-basic-2' | 'oidf-post-1';
      tokenEndpointAuthMethod: 'client_secret_basic' | 'client_secret_post';
      redirectUris: readonly string[];
    }>
  >;
  plans: readonly Phase1ConformancePublicPlan[];
}>;

const diagnostic = 'Invalid phase 1 conformance config';
const expectedClientIds = Object.freeze(['oidf-basic-1', 'oidf-basic-2', 'oidf-post-1'] as const);
const expectedClientMethods = Object.freeze([
  'client_secret_basic',
  'client_secret_basic',
  'client_secret_post',
] as const);
const expectedPlanIds = Object.freeze([
  'oidcc-basic-certification-test-plan',
  'oidcc-config-certification-test-plan',
] as const);

const publicPlan = (
  plan: Phase1Profile['conformance']['plans'][number]
): Phase1ConformancePublicPlan =>
  Object.freeze({
    id: plan.testPlanName,
    displayName: plan.displayName,
    variant: cloneAndDeepFreeze({ ...plan.variants }),
  });

export const createPhase1ConformanceConfig = (
  profile: Readonly<Phase1Profile>
): Phase1ConformancePublicConfig => {
  try {
    assertConformanceSemantics(profile);
    if (
      profile.conformance.suiteRepository !== phase1ConformanceSuiteRepository ||
      profile.conformance.suiteCommit !== phase1ConformanceSuiteCommit ||
      profile.conformance.staticClients.length !== expectedClientIds.length ||
      profile.conformance.plans.length !== expectedPlanIds.length
    ) {
      throw new TypeError(diagnostic);
    }
    for (const [index, client] of profile.conformance.staticClients.entries()) {
      if (
        client.id !== expectedClientIds[index] ||
        client.tokenEndpointAuthMethod !== expectedClientMethods[index] ||
        client.redirectUris.length !== 1 ||
        client.redirectUris[0] !== profile.conformance.target.callbackUri
      ) {
        throw new TypeError(diagnostic);
      }
    }
    for (const [index, plan] of profile.conformance.plans.entries()) {
      if (plan.testPlanName !== expectedPlanIds[index]) {
        throw new TypeError(diagnostic);
      }
    }
    const config = {
      schemaVersion: 1 as const,
      suite: {
        repository: phase1ConformanceSuiteRepository,
        commit: phase1ConformanceSuiteCommit,
      },
      target: {
        issuer: profile.conformance.target.issuer,
        discoveryUrl: profile.conformance.target.discoveryUrl,
        suiteBaseUrl: profile.conformance.target.suiteBaseUrl,
        alias: profile.conformance.target.alias,
        callbackUri: profile.conformance.target.callbackUri,
      },
      staticClients: profile.conformance.staticClients.map((client) => ({
        id: client.id,
        tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
        redirectUris: [...client.redirectUris],
      })),
      plans: profile.conformance.plans.map((plan) => publicPlan(plan)),
    };
    const snapshot = snapshotClosedDataGraph<Phase1ConformancePublicConfig>(config);

    if (snapshot === undefined) {
      throw new TypeError(diagnostic);
    }

    return cloneAndDeepFreeze(snapshot);
  } catch {
    throw new TypeError(diagnostic);
  }
};

/* eslint-enable complexity */
