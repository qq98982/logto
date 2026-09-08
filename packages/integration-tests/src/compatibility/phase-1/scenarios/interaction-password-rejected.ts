import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, NormalizationContext } from '../../normalize.js';
import { getPhase1FixtureRuntimeId, getPhase1FixtureRuntimeUsername } from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { createPhase1NormalizationContext } from '../native-surface-profile.js';
import {
  projectAuthorizationObservation,
  projectExperienceErrorObservation,
  projectSemanticStateObservation,
  type RawHttpObservation,
} from '../projections/index.js';

const scenarioId = 'interaction.password-rejected';
const jsonHeaders = Object.freeze([Object.freeze(['content-type', 'application/json'] as const)]);
const expectedError = Object.freeze({
  code: 'session.invalid_credentials',
  message: 'Incorrect account or password. Please check your input.',
});
const expectedState = Object.freeze({
  body: Object.freeze({ observed: true }),
  semanticState: Object.freeze({ interactionStatus: 'present' }),
  persistedState: Object.freeze({
    verificationRecords: 0,
    identifiedUsers: 0,
    grants: 0,
    issuances: 0,
    sessionExtensions: 0,
  }),
  sideEffects: Object.freeze({ authenticationState: 'unchanged' }),
});

export type PasswordRejectedRandomSource = Readonly<{
  codeVerifier(): string;
  state(): string;
}>;

const defaultRandom: PasswordRejectedRandomSource = Object.freeze({
  codeVerifier: () => randomBytes(48).toString('base64url'),
  state: () => randomBytes(32).toString('base64url'),
});

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const parseJsonObject = (value: string, diagnostic: string): JsonObject => {
  try {
    const parsed: unknown = JSON.parse(value);

    const result = jsonValueGuard.safeParse(parsed);

    if (!result.success || !isJsonObject(result.data)) {
      throw new TypeError('Invalid JSON object');
    }

    return result.data;
  } catch {
    throw new Error(diagnostic);
  }
};

const assertStatus = (status: number, expected: number, diagnostic: string): void => {
  if (status !== expected) {
    throw new Error(diagnostic);
  }
};

const assertNoSetCookie = (
  headers: ReadonlyArray<readonly [string, string]>,
  diagnostic: string
) => {
  if (headers.some(([name]) => name.toLowerCase() === 'set-cookie')) {
    throw new Error(diagnostic);
  }
};

const assertJsonResponse = (
  headers: ReadonlyArray<readonly [string, string]>,
  diagnostic: string
) => {
  const values = headers
    .filter(([name]) => name.toLowerCase() === 'content-type')
    .map(([, value]) => value.split(';', 1)[0]?.trim().toLowerCase());

  if (values.length !== 1 || values[0] !== 'application/json') {
    throw new Error(diagnostic);
  }
};

const assertClosedState = (
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>
): void => {
  if (
    !isDeepStrictEqual(state.body, expectedState.body) ||
    !isDeepStrictEqual(state.semanticState, expectedState.semanticState) ||
    !isDeepStrictEqual(state.persistedState, expectedState.persistedState) ||
    !isDeepStrictEqual(state.sideEffects, expectedState.sideEffects)
  ) {
    throw new Error('Phase 1 rejected password state is invalid');
  }
};

const observation = (
  response: Readonly<{
    status: number;
    headers: ReadonlyArray<readonly [string, string]>;
  }>,
  body: unknown,
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>
): RawHttpObservation => ({ ...state, ...response, body });

export const runInteractionPasswordRejected = async (
  context: Phase1ScenarioRunContext,
  random: PasswordRejectedRandomSource = defaultRandom
): Promise<readonly Phase1ScenarioStepResult[]> =>
  context.fixture.withSecretLease(async (lease) => {
    const allocation = context.fixture.public.allocations.find(({ role }) => role === 'data');
    const application = context.profile.fixtures.dataTenant.applications.find(
      ({ isThirdParty }) => isThirdParty
    );

    if (!allocation || !application?.isThirdParty) {
      throw new Error('Phase 1 rejected password fixture is invalid');
    }
    const [redirectUri] = application.oidcClientMetadata.redirectUris;

    if (!redirectUri) {
      throw new Error('Phase 1 rejected password fixture is invalid');
    }
    const clients = context.protocol.forAllocation('data');
    const clientId = getPhase1FixtureRuntimeId(
      context.fixture.public,
      allocation.allocationId,
      'application',
      application.id
    );
    const username = getPhase1FixtureRuntimeUsername(
      context.profile.fixtures.dataTenant.subject.username,
      allocation.allocationId
    );
    const symbols = context.protocol.symbolsFor(allocation.allocationId);

    if (!symbols || clients.oidc.store !== clients.experience.store) {
      throw new Error('Phase 1 rejected password protocol session is invalid');
    }
    symbols.bind('fixture.data.username', username);
    const projectionContext: NormalizationContext = createPhase1NormalizationContext(
      context.profile,
      context.target,
      symbols
    );
    const verifier = random.codeVerifier();
    const stateSecret = random.state();
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const { authorizationPath } = context.profile.oidc;
    const query = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: stateSecret,
      response_type: 'code',
      prompt: 'login',
      scope: 'openid',
    });
    clients.oidc.store.registerSecret(verifier);
    clients.oidc.store.registerSecret(stateSecret);
    const authorize = await clients.oidc.request(
      'password-rejected-authorization-start',
      `${authorizationPath.replace(/^\//u, '')}?${query.toString()}`,
      { includeCookies: true }
    );
    assertStatus(authorize.status, 303, 'Phase 1 rejected password authorization failed');

    const bootstrap = await clients.experience.requestExperience(
      'password-rejected-bootstrap',
      'experience',
      { method: 'PUT', headers: jsonHeaders, body: JSON.stringify({ interactionEvent: 'SignIn' }) }
    );
    assertStatus(bootstrap.status, 204, 'Phase 1 rejected password bootstrap failed');
    assertNoSetCookie(bootstrap.headers, 'Phase 1 rejected password bootstrap mutated cookies');
    if (bootstrap.body.length > 0) {
      throw new Error('Phase 1 rejected password bootstrap body is invalid');
    }
    const bootstrapState = await context.projectScenarioState({
      scenarioId,
      stepId: 'experience-bootstrap',
      fixture: context.fixture,
    });
    assertClosedState(bootstrapState);
    const bootstrapStep = Object.freeze({
      stepId: 'experience-bootstrap',
      value: projectAuthorizationObservation(
        observation(bootstrap, null, bootstrapState),
        projectionContext
      ),
    });

    const password = lease.getPassword(context.profile.fixtures.dataTenant.subject.id);
    const rejectedPassword = `${password}.rejected`;
    clients.experience.store.registerSecret(password);
    clients.experience.store.registerSecret(rejectedPassword);
    const rejected = await clients.experience.requestExperience(
      'password-rejected-verification',
      'experience/verification/password',
      {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({
          identifier: { type: 'username', value: username },
          password: rejectedPassword,
        }),
      }
    );
    assertStatus(rejected.status, 422, 'Phase 1 rejected password response is invalid');
    assertJsonResponse(rejected.headers, 'Phase 1 rejected password response is invalid');
    assertNoSetCookie(rejected.headers, 'Phase 1 rejected password mutated cookies');
    const rejectedBody = parseJsonObject(
      rejected.body,
      'Phase 1 rejected password response is invalid'
    );

    if (!isDeepStrictEqual(rejectedBody, expectedError)) {
      throw new Error('Phase 1 rejected password response is invalid');
    }
    const rejectedState = await context.projectScenarioState({
      scenarioId,
      stepId: 'password',
      fixture: context.fixture,
    });
    assertClosedState(rejectedState);
    const passwordStep = Object.freeze({
      stepId: 'password',
      value: projectExperienceErrorObservation(
        observation(rejected, rejectedBody, rejectedState),
        projectionContext
      ),
    });
    const finalState = await context.projectScenarioState({
      scenarioId,
      stepId: 'state',
      fixture: context.fixture,
    });
    assertClosedState(finalState);
    const stateStep = Object.freeze({
      stepId: 'state',
      value: projectSemanticStateObservation(
        { ...finalState, status: 200, headers: [] },
        projectionContext,
        { scenarioId, stepId: 'state' }
      ),
    });
    const steps = Object.freeze([bootstrapStep, passwordStep, stateStep]);
    clients.oidc.store.assertNoCredentialMaterial(steps);

    return steps;
  });
