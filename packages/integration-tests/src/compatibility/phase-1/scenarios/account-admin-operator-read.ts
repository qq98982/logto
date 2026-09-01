import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject } from '../../normalize.js';
import type { RawProtocolResponse } from '../clients/oidc.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeUsername,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import {
  projectAccountObservation,
  projectSemanticStateObservation,
} from '../projections/index.js';

import {
  withPositiveAdminSession,
  type PositiveAdminSessionOptions,
} from './positive-admin-flow.js';
import {
  installPositiveAdminAccountToken,
  positiveAdminNormalizationContext,
} from './positive-admin-token.js';

const scenarioId = 'account.admin-operator-read';
const minimumEpochMilliseconds = 100_000_000_000;

export type AccountAdminOperatorReadDependencies = Readonly<{
  sessionOptions?: PositiveAdminSessionOptions;
  withPositiveAdminSession?: typeof withPositiveAdminSession;
  installPositiveAdminAccountToken?: typeof installPositiveAdminAccountToken;
  positiveAdminNormalizationContext?: typeof positiveAdminNormalizationContext;
}>;

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  jsonValueGuard.safeParse(value).success;

const requireJsonResponse = (response: RawProtocolResponse): JsonObject => {
  try {
    const mediaTypes = response.headers
      .filter(([name]) => name.toLowerCase() === 'content-type')
      .map(([, value]) => value.split(';', 1)[0]?.trim().toLowerCase());
    const body: unknown = JSON.parse(response.body);

    if (
      response.status !== 200 ||
      mediaTypes.length !== 1 ||
      mediaTypes[0] !== 'application/json' ||
      !isJsonObject(body)
    ) {
      throw new TypeError('invalid response');
    }

    return body;
  } catch {
    throw new Error('Phase 1 Account response is invalid');
  }
};

const assertOperator = (context: Phase1ScenarioRunContext, body: JsonObject): void => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'admin');

  if (!allocation) {
    throw new Error('Phase 1 Account fixture is invalid');
  }
  const { operator } = context.profile.fixtures.adminTenant;
  const expected = {
    id: getPhase1FixtureRuntimeId(
      context.fixture.public,
      allocation.allocationId,
      'user',
      operator.id
    ),
    username: getPhase1FixtureRuntimeUsername(operator.username, allocation.allocationId),
    primaryEmail: getPhase1FixtureRuntimeEmail(operator.primaryEmail, allocation.allocationId),
  };
  const { createdAt, updatedAt } = body;

  if (
    Object.entries(expected).some(([key, value]) => body[key] !== value) ||
    typeof createdAt !== 'number' ||
    !Number.isSafeInteger(createdAt) ||
    createdAt < minimumEpochMilliseconds ||
    typeof updatedAt !== 'number' ||
    !Number.isSafeInteger(updatedAt) ||
    updatedAt < minimumEpochMilliseconds ||
    updatedAt < createdAt
  ) {
    throw new Error('Phase 1 Account operator is invalid');
  }
};

const assertNoMutationState = (
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>
): void => {
  if (
    !isDeepStrictEqual(state.persistedState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 Account state is invalid');
  }
};

export const runAccountAdminOperatorRead = async (
  context: Phase1ScenarioRunContext,
  dependencies: AccountAdminOperatorReadDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const runSession = dependencies.withPositiveAdminSession ?? withPositiveAdminSession;
  const installAccount =
    dependencies.installPositiveAdminAccountToken ?? installPositiveAdminAccountToken;
  const { result } = await runSession(
    context,
    { ...dependencies.sessionOptions, captureAuthorize: false, captureCodeToken: false },
    async (session) => {
      installAccount(context, session);
      const normalizationContext = (
        dependencies.positiveAdminNormalizationContext ?? positiveAdminNormalizationContext
      )(context);
      const before = await context.projectFixtureState();
      const response = await context.protocol
        .forAllocation('admin')
        .account.requestAccount('account-admin-operator-read', 'my-account/', {
          method: 'GET',
          includeCookies: false,
        });
      const body = requireJsonResponse(response);
      assertOperator(context, body);
      const accountState = await context.projectScenarioState({
        scenarioId,
        stepId: 'account',
        fixture: context.fixture,
      });
      assertNoMutationState(accountState);
      const account = projectAccountObservation(
        { ...accountState, status: response.status, headers: response.headers, body },
        normalizationContext,
        { scenarioId, stepId: 'account' }
      );
      const finalState = await context.projectScenarioState({
        scenarioId,
        stepId: 'state',
        fixture: context.fixture,
      });
      assertNoMutationState(finalState);
      const state = projectSemanticStateObservation(
        { ...finalState, status: 200, headers: [] },
        normalizationContext,
        { scenarioId, stepId: 'state' }
      );
      const after = await context.projectFixtureState();

      if (!isDeepStrictEqual(before, after)) {
        throw new Error('Phase 1 Account read mutated fixture state');
      }

      return Object.freeze([
        Object.freeze({ stepId: 'account', value: account }),
        Object.freeze({ stepId: 'state', value: state }),
      ]);
    }
  );

  return result;
};
