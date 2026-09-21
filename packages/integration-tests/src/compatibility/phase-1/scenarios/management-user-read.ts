/* eslint-disable complexity, no-restricted-syntax, @typescript-eslint/no-unsafe-assignment -- The exact seeded-user response predicate and guarded JSON publication are intentionally kept together. */
import { isDeepStrictEqual } from 'node:util';

import type { JsonValue, NormalizationContext } from '../../normalize.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimePhone,
  getPhase1FixtureRuntimeUsername,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { createPhase1NormalizationContext } from '../native-surface-profile.js';
import type { Phase1ConsoleReadRequest } from '../profile-types.js';
import { projectManagementObservation } from '../projections/management.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import { withPositiveAdminSession } from './positive-admin-flow.js';
import { refreshPositiveAdminManagementToken } from './positive-admin-token.js';
import { projectPositiveScenarioState } from './positive-oidc-token.js';

const scenarioId = 'management.user-read';
const jsonMediaType = 'application/json';

type UserReadRequest = Extract<Phase1ConsoleReadRequest, Readonly<{ path: '/api/users' }>>;

export type ManagementUserReadDependencies = Readonly<{
  withPositiveAdminSession?: typeof withPositiveAdminSession;
  refreshPositiveAdminManagementToken?: typeof refreshPositiveAdminManagementToken;
}>;

const isPlainObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

const headerValues = (
  headers: ReadonlyArray<readonly [string, string]>,
  name: string
): readonly string[] =>
  headers
    .filter(([candidate]) => candidate.toLowerCase() === name.toLowerCase())
    .map(([, value]) => value);

const requireUserRequest = (context: Phase1ScenarioRunContext): UserReadRequest => {
  const requests = context.profile.consoleReadRequests.filter(
    (request): request is UserReadRequest => request.path === '/api/users'
  );

  if (requests.length !== 1 || !requests[0]) {
    throw new Error('Phase 1 Management user request profile is invalid');
  }

  return requests[0];
};

const dataNormalizationContext = (context: Phase1ScenarioRunContext): NormalizationContext => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');
  const symbols = allocation && context.protocol.symbolsFor(allocation.allocationId);

  if (!allocation || !symbols) {
    throw new Error('Phase 1 Management user fixture is invalid');
  }
  const { subject } = context.profile.fixtures.dataTenant;
  symbols.bind(
    'fixture.data.username',
    getPhase1FixtureRuntimeUsername(subject.username, allocation.allocationId)
  );
  symbols.bind(
    'fixture.data.email',
    getPhase1FixtureRuntimeEmail(subject.primaryEmail, allocation.allocationId)
  );
  symbols.bind('fixture.data.phone', getPhase1FixtureRuntimePhone(allocation.allocationId));

  return createPhase1NormalizationContext(context.profile, context.target, symbols);
};

const requestPath = (request: UserReadRequest): string =>
  `users?${new URLSearchParams(Object.entries(request.query)).toString()}`;

const requireResponseBody = (
  context: Phase1ScenarioRunContext,
  request: UserReadRequest,
  response: Readonly<{
    status: number;
    headers: ReadonlyArray<readonly [string, string]>;
    body: string;
  }>
): readonly JsonValue[] => {
  try {
    const mediaTypes = headerValues(response.headers, 'content-type').map((value) =>
      value.split(';', 1)[0]?.trim().toLowerCase()
    );
    const totalNumbers = headerValues(response.headers, 'total-number');
    const parsed: unknown = JSON.parse(response.body);

    if (
      response.status !== request.expectedStatus ||
      mediaTypes.length !== 1 ||
      mediaTypes[0] !== jsonMediaType ||
      totalNumbers.length !== 1 ||
      totalNumbers[0] !== request.requiredHeaderValues['Total-Number'] ||
      !Array.isArray(parsed) ||
      parsed.length !== request.requiredBodyLength ||
      parsed.length !== request.requiredProjection.length
    ) {
      throw new TypeError('invalid response');
    }
    const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');
    const expected = request.requiredProjection[0];
    const actual = parsed[0];
    const { subject } = context.profile.fixtures.dataTenant;

    if (
      !allocation ||
      !expected ||
      !isPlainObject(actual) ||
      actual.id !==
        getPhase1FixtureRuntimeId(
          context.fixture.public,
          allocation.allocationId,
          'user',
          subject.id
        ) ||
      actual.username !==
        getPhase1FixtureRuntimeUsername(subject.username, allocation.allocationId) ||
      actual.name !== expected.name ||
      actual.primaryEmail !==
        getPhase1FixtureRuntimeEmail(subject.primaryEmail, allocation.allocationId) ||
      actual.primaryPhone !== getPhase1FixtureRuntimePhone(allocation.allocationId) ||
      actual.avatar !== expected.avatar ||
      actual.applicationId !== expected.applicationId ||
      actual.lastSignInAt !== null ||
      actual.isSuspended !== expected.isSuspended ||
      actual.hasPassword !== expected.hasPassword ||
      typeof actual.createdAt !== 'number' ||
      !Number.isSafeInteger(actual.createdAt) ||
      actual.createdAt < 100_000_000_000 ||
      typeof actual.updatedAt !== 'number' ||
      !Number.isSafeInteger(actual.updatedAt) ||
      actual.updatedAt < actual.createdAt
    ) {
      throw new TypeError('invalid user');
    }

    return parsed as readonly JsonValue[];
  } catch {
    throw new Error('Phase 1 Management user response is invalid');
  }
};

const assertNoMutationState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.persistedState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 Management user state is invalid');
  }
};

export const runManagementUserRead = async (
  context: Phase1ScenarioRunContext,
  dependencies: ManagementUserReadDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const runAdminSession = dependencies.withPositiveAdminSession ?? withPositiveAdminSession;
  const refreshManagement =
    dependencies.refreshPositiveAdminManagementToken ?? refreshPositiveAdminManagementToken;
  const { result } = await runAdminSession<readonly Phase1ScenarioStepResult[]>(
    context,
    { captureAuthorize: false, captureCodeToken: false },
    async (session) => {
      await refreshManagement(context, session);
      const request = requireUserRequest(context);
      const normalizationContext = dataNormalizationContext(context);
      const before = await context.projectFixtureState();
      const response = await context.protocol
        .forAllocation('data')
        .management.requestManagement('users', requestPath(request), {
          method: request.method,
          headers: [
            ['Origin', request.origin],
            ['Accept-Language', request.headers['Accept-Language']],
          ],
        });
      const body = requireResponseBody(context, request, response);
      const userState = await context.projectScenarioState({
        scenarioId,
        stepId: 'users',
        fixture: context.fixture,
      });
      assertNoMutationState(userState);
      const users = projectManagementObservation(
        { ...userState, status: response.status, headers: response.headers, body },
        normalizationContext,
        { scenarioId, stepId: 'users' }
      );
      const state = await projectPositiveScenarioState(context, {
        scenarioId,
        stepId: 'state',
        normalizationContext,
        validate: assertNoMutationState,
      });
      const after = await context.projectFixtureState();

      if (!isDeepStrictEqual(before, after)) {
        throw new Error('Phase 1 Management user read mutated fixture state');
      }

      return Object.freeze([
        Object.freeze({ stepId: 'users', value: users }),
        Object.freeze({ stepId: 'state', value: state }),
      ]);
    }
  );

  return result;
};

/* eslint-enable complexity, no-restricted-syntax, @typescript-eslint/no-unsafe-assignment */
