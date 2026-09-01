import { isDeepStrictEqual } from 'node:util';

import { userClaims, UserScope } from '@logto/core-kit';

import type { JsonObject } from '../../normalize.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimePhone,
  getPhase1FixtureRuntimeUsername,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { projectUserInfoObservation } from '../projections/userinfo.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  exchangePositiveAuthorizationCode,
  withPositiveOidcFlow,
  type PositiveOidcFlowOptions,
} from './positive-oidc-flow.js';
import {
  positiveOidcDataNormalizationContext,
  projectPositiveScenarioState,
  readPositiveUserInfo,
  revokePositiveTokenGrant,
  verifyPositiveTokenGrant,
} from './positive-oidc-token.js';

const scenarioId = 'userinfo.openid';
const requestedScopes = [
  UserScope.Profile,
  UserScope.Email,
  UserScope.Address,
  UserScope.Phone,
] as const;
const allowedClaims = new Set(['sub', ...requestedScopes.flatMap((scope) => userClaims[scope])]);

export type UserInfoOpenIdDependencies = Readonly<{
  flowOptions?: PositiveOidcFlowOptions;
  withPositiveOidcFlow?: typeof withPositiveOidcFlow;
}>;

const assertSeededClaims = (context: Phase1ScenarioRunContext, body: JsonObject): void => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');

  if (!allocation) {
    throw new Error('Phase 1 UserInfo fixture is invalid');
  }
  const { subject } = context.profile.fixtures.dataTenant;
  const runtimeSubjectId = getPhase1FixtureRuntimeId(
    context.fixture.public,
    allocation.allocationId,
    'user',
    subject.id
  );
  const runtimeUsername = getPhase1FixtureRuntimeUsername(
    subject.username,
    allocation.allocationId
  );
  const expected: Readonly<Record<string, unknown>> = {
    sub: runtimeSubjectId,
    name: subject.name,
    preferred_username: runtimeUsername,
    username: runtimeUsername,
    email: getPhase1FixtureRuntimeEmail(subject.primaryEmail, allocation.allocationId),
    email_verified: true,
    phone_number: getPhase1FixtureRuntimePhone(allocation.allocationId),
    phone_number_verified: true,
    address: subject.profile.address,
  };

  if (
    Object.keys(body).some((claim) => !allowedClaims.has(claim)) ||
    Object.entries(expected).some(([claim, value]) => !isDeepStrictEqual(body[claim], value)) ||
    typeof body.created_at !== 'number' ||
    !Number.isSafeInteger(body.created_at) ||
    body.created_at < 100_000_000_000 ||
    typeof body.updated_at !== 'number' ||
    !Number.isSafeInteger(body.updated_at) ||
    body.updated_at < body.created_at
  ) {
    throw new Error('Phase 1 UserInfo claims are invalid');
  }
};

const assertUserInfoState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.persistedState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 UserInfo state is invalid');
  }
};

export const runUserInfoOpenId = async (
  context: Phase1ScenarioRunContext,
  dependencies: UserInfoOpenIdDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const { userinfoPath } = context.profile.oidc;

  if (!userinfoPath.startsWith('/') || userinfoPath.slice(1).startsWith('/')) {
    throw new Error('Phase 1 UserInfo path is invalid');
  }
  const { result } = await (dependencies.withPositiveOidcFlow ?? withPositiveOidcFlow)(
    context,
    { ...dependencies.flowOptions, captureSteps: false, includeResource: false },
    async (credentials) => {
      const normalizationContext = positiveOidcDataNormalizationContext(context);
      const grant = await exchangePositiveAuthorizationCode(context, credentials);
      try {
        await verifyPositiveTokenGrant(context, grant, false);
        const before = await context.projectFixtureState();
        const userInfoResponse = await readPositiveUserInfo(context, grant, userinfoPath.slice(1));
        const userInfoBody = userInfoResponse.body;
        assertSeededClaims(context, userInfoBody);
        const userInfoState = await context.projectScenarioState({
          scenarioId,
          stepId: 'userinfo',
          fixture: context.fixture,
        });
        const userinfo = projectUserInfoObservation(
          {
            ...userInfoState,
            status: userInfoResponse.status,
            headers: userInfoResponse.headers,
            body: userInfoBody,
          },
          normalizationContext,
          { scenarioId, stepId: 'userinfo' }
        );
        const state = await projectPositiveScenarioState(context, {
          scenarioId,
          stepId: 'state',
          normalizationContext,
          validate: assertUserInfoState,
        });
        const after = await context.projectFixtureState();

        if (!isDeepStrictEqual(before, after)) {
          throw new Error('Phase 1 UserInfo mutated fixture state');
        }

        return Object.freeze([
          Object.freeze({ stepId: 'userinfo', value: userinfo }),
          Object.freeze({ stepId: 'state', value: state }),
        ]);
      } finally {
        revokePositiveTokenGrant(grant);
      }
    }
  );

  return result;
};
