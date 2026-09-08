/* eslint-disable complexity, no-await-in-loop, no-restricted-syntax, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutating-methods -- The exact ordered read matrix, JSON boundary, and immutable published results stay in one auditable scenario. */
import { isDeepStrictEqual } from 'node:util';

import type { JsonValue, NormalizationContext } from '../../normalize.js';
import { getPhase1FixtureRuntimeId, getPhase1FixtureRuntimeText } from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { createPhase1NormalizationContext } from '../native-surface-profile.js';
import type { Phase1ConsoleReadRequest } from '../profile-types.js';
import { projectManagementObservation } from '../projections/management.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import { withPositiveAdminSession } from './positive-admin-flow.js';
import { refreshPositiveAdminManagementToken } from './positive-admin-token.js';
import { projectPositiveScenarioState } from './positive-oidc-token.js';

const scenarioId = 'management.application-read';
const applicationJsonMediaType = 'application/json';
const applicationStepIds = ['first-party', 'third-party', 'saml'] as const;

type ApplicationReadRequest = Extract<
  Phase1ConsoleReadRequest,
  Readonly<{ path: '/api/applications' }>
>;

export type ManagementApplicationReadDependencies = Readonly<{
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

const requireApplicationRequests = (
  context: Phase1ScenarioRunContext
): readonly ApplicationReadRequest[] => {
  const requests = context.profile.consoleReadRequests.filter(
    (request): request is ApplicationReadRequest => request.path === '/api/applications'
  );

  if (requests.length !== applicationStepIds.length) {
    throw new Error('Phase 1 Management application request profile is invalid');
  }

  return requests;
};

const dataNormalizationContext = (context: Phase1ScenarioRunContext): NormalizationContext => {
  const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');
  const symbols = allocation && context.protocol.symbolsFor(allocation.allocationId);

  if (!allocation || !symbols) {
    throw new Error('Phase 1 Management application fixture is invalid');
  }
  const { applications } = context.profile.fixtures.dataTenant;

  if (applications.length !== 2) {
    throw new Error('Phase 1 Management application fixture is invalid');
  }
  for (const application of applications) {
    const kind = application.isThirdParty ? 'third-party' : 'first-party';
    symbols.bind(
      `fixture.data.application-name.${kind}`,
      getPhase1FixtureRuntimeText(application.name, allocation.allocationId)
    );
  }

  return createPhase1NormalizationContext(context.profile, context.target, symbols);
};

const requestPath = (request: ApplicationReadRequest): string => {
  const query = new URLSearchParams(Object.entries(request.query));

  return `applications?${query.toString()}`;
};

const requireResponseBody = (
  context: Phase1ScenarioRunContext,
  request: ApplicationReadRequest,
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
      mediaTypes[0] !== applicationJsonMediaType ||
      totalNumbers.length !== 1 ||
      totalNumbers[0] !== request.requiredHeaderValues['Total-Number'] ||
      !Array.isArray(parsed) ||
      parsed.length !== request.requiredBodyLength ||
      parsed.length !== request.requiredProjection.length
    ) {
      throw new TypeError('invalid response');
    }
    const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');

    if (!allocation) {
      throw new TypeError('invalid fixture');
    }
    for (const [index, expected] of request.requiredProjection.entries()) {
      const actual = parsed[index];
      const application = context.profile.fixtures.dataTenant.applications.find(
        ({ id }) => id === expected.id
      );

      if (
        !application ||
        !isPlainObject(actual) ||
        actual.id !==
          getPhase1FixtureRuntimeId(
            context.fixture.public,
            allocation.allocationId,
            'application',
            application.id
          ) ||
        actual.name !== getPhase1FixtureRuntimeText(application.name, allocation.allocationId) ||
        actual.type !== expected.type ||
        actual.isThirdParty !== expected.isThirdParty ||
        !isDeepStrictEqual(actual.customClientMetadata, expected.customClientMetadata) ||
        typeof actual.createdAt !== 'number' ||
        !Number.isSafeInteger(actual.createdAt) ||
        actual.createdAt < 100_000_000_000
      ) {
        throw new TypeError('invalid application');
      }
    }

    return parsed as readonly JsonValue[];
  } catch {
    throw new Error('Phase 1 Management application response is invalid');
  }
};

const assertNoMutationState = (state: Phase1ScenarioStateProjectionInput): void => {
  if (
    !isDeepStrictEqual(state.persistedState, { unrelatedMutation: false }) ||
    !isDeepStrictEqual(state.sideEffects, { unrelatedMutation: false })
  ) {
    throw new Error('Phase 1 Management application state is invalid');
  }
};

export const runManagementApplicationRead = async (
  context: Phase1ScenarioRunContext,
  dependencies: ManagementApplicationReadDependencies = {}
): Promise<readonly Phase1ScenarioStepResult[]> => {
  const runAdminSession = dependencies.withPositiveAdminSession ?? withPositiveAdminSession;
  const refreshManagement =
    dependencies.refreshPositiveAdminManagementToken ?? refreshPositiveAdminManagementToken;
  const { result } = await runAdminSession<readonly Phase1ScenarioStepResult[]>(
    context,
    { captureAuthorize: false, captureCodeToken: false },
    async (session) => {
      await refreshManagement(context, session);
      const requests = requireApplicationRequests(context);
      const normalizationContext = dataNormalizationContext(context);
      const { management } = context.protocol.forAllocation('data');
      const before = await context.projectFixtureState();
      const visibleSteps: Phase1ScenarioStepResult[] = [];

      for (const [index, request] of requests.entries()) {
        const stepId = applicationStepIds[index];

        if (!stepId) {
          throw new Error('Phase 1 Management application request profile is invalid');
        }
        const response = await management.requestManagement(stepId, requestPath(request), {
          method: request.method,
          headers: [
            ['Origin', request.origin],
            ['Accept-Language', request.headers['Accept-Language']],
          ],
        });
        const body = requireResponseBody(context, request, response);
        const state = await context.projectScenarioState({
          scenarioId,
          stepId,
          fixture: context.fixture,
        });
        assertNoMutationState(state);
        visibleSteps.push(
          Object.freeze({
            stepId,
            value: projectManagementObservation(
              { ...state, status: response.status, headers: response.headers, body },
              normalizationContext,
              { scenarioId, stepId }
            ),
          })
        );
      }
      const state = await projectPositiveScenarioState(context, {
        scenarioId,
        stepId: 'state',
        normalizationContext,
        validate: assertNoMutationState,
      });
      const after = await context.projectFixtureState();

      if (!isDeepStrictEqual(before, after)) {
        throw new Error('Phase 1 Management application read mutated fixture state');
      }

      return Object.freeze([...visibleSteps, Object.freeze({ stepId: 'state', value: state })]);
    }
  );

  return result;
};

/* eslint-enable complexity, no-await-in-loop, no-restricted-syntax, @typescript-eslint/no-unsafe-assignment, @silverhand/fp/no-mutating-methods */
