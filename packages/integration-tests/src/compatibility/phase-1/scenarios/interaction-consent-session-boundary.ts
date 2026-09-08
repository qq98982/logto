/* eslint-disable max-lines, complexity, no-control-regex, no-await-in-loop, @silverhand/fp/no-mutating-methods, id-length -- The complete ordered 14-request consent boundary, opaque A/B labels, and bounded JSON guards stay in one auditable scenario. */
import { createHash, randomBytes } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { jsonValueGuard, type TargetConfig } from '../../model.js';
import type { JsonObject, NormalizationContext } from '../../normalize.js';
import { ConsentClient } from '../clients/consent.js';
import { ExperienceClient } from '../clients/experience.js';
import {
  MemoryProtocolSecretStore,
  OidcClient,
  type ProtocolRequestOptions,
  type RawProtocolResponse,
} from '../clients/oidc.js';
import {
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
  type Phase1FixtureAllocationRole,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext, Phase1ScenarioStepResult } from '../model.js';
import { createPhase1NormalizationContext } from '../native-surface-profile.js';
import {
  projectConsentErrorObservation,
  projectConsentObservation,
  projectSemanticStateObservation,
  type RawHttpObservation,
} from '../projections/index.js';

const scenarioId = 'interaction.consent-session-boundary';
const jsonHeaders = Object.freeze([Object.freeze(['content-type', 'application/json'] as const)]);
const cookieFailureDescription = 'interaction session id cookie not found';
const replayFailureDescription = 'interaction session not found';

type BoundaryLabel = 'a' | 'b' | 'foreign';
type BoundaryClients = Readonly<{
  oidc: Pick<OidcClient, 'request' | 'store'>;
  experience: Pick<ExperienceClient, 'requestExperience' | 'store'>;
  consent: Pick<ConsentClient, 'requestConsent' | 'store'>;
}>;
type BoundarySession = Readonly<{
  label: BoundaryLabel;
  target: TargetConfig;
  role: Phase1FixtureAllocationRole;
  store: MemoryProtocolSecretStore;
  clients: BoundaryClients;
  clientId: string;
  userId: string;
  redirectUri: string;
  authorizationState: string;
}>;

export type ConsentBoundaryScenarioOptions = Readonly<{
  createClients?: (
    input: Readonly<{
      label: BoundaryLabel;
      target: TargetConfig;
      role: Phase1FixtureAllocationRole;
      store: MemoryProtocolSecretStore;
      context: Phase1ScenarioRunContext;
    }>
  ) => BoundaryClients;
  requestDerivedConsent?: (
    input: Readonly<{
      operation: string;
      store: MemoryProtocolSecretStore;
      options: ProtocolRequestOptions;
      context: Phase1ScenarioRunContext;
    }>
  ) => Promise<RawProtocolResponse>;
}>;

const baselineState = Object.freeze({
  body: Object.freeze({ observed: true }),
  semanticState: Object.freeze({
    interactions: Object.freeze({ a: 'missing', b: 'present', foreign: 'present' }),
    principals: Object.freeze({ a: 'active', b: 'active', foreign: 'active' }),
  }),
  persistedState: Object.freeze({
    a: Object.freeze({ grants: 1, issuances: 1, sessionExtensions: 1, firstConsentBindings: 1 }),
    b: Object.freeze({ grants: 0, issuances: 0, sessionExtensions: 0, firstConsentBindings: 0 }),
    foreign: Object.freeze({
      grants: 0,
      issuances: 0,
      sessionExtensions: 0,
      firstConsentBindings: 0,
    }),
  }),
  sideEffects: Object.freeze({
    grantDelta: 0,
    issuanceDelta: 0,
    sessionExtensionDelta: 0,
    firstConsentBindingDelta: 0,
  }),
});
const acceptedBState = Object.freeze({
  ...baselineState,
  persistedState: Object.freeze({
    ...baselineState.persistedState,
    b: Object.freeze({ grants: 1, issuances: 0, sessionExtensions: 1, firstConsentBindings: 1 }),
  }),
  sideEffects: Object.freeze({
    grantDelta: 1,
    issuanceDelta: 0,
    sessionExtensionDelta: 1,
    firstConsentBindingDelta: 1,
  }),
});
const resumedBState = Object.freeze({
  ...acceptedBState,
  semanticState: Object.freeze({
    ...acceptedBState.semanticState,
    interactions: Object.freeze({ a: 'missing', b: 'missing', foreign: 'present' }),
  }),
  persistedState: Object.freeze({
    ...acceptedBState.persistedState,
    b: Object.freeze({ ...acceptedBState.persistedState.b, issuances: 1 }),
  }),
  sideEffects: Object.freeze({ ...acceptedBState.sideEffects, issuanceDelta: 1 }),
});

const defaultCreateClients = ({
  target,
  role,
  store,
  context,
}: Parameters<
  NonNullable<ConsentBoundaryScenarioOptions['createClients']>
>[0]): BoundaryClients => {
  const clientOptions = {
    target,
    fixture: context.fixture,
    allocationRole: role,
    store,
    signal: context.signal,
  };

  return Object.freeze({
    oidc: new OidcClient(clientOptions),
    experience: new ExperienceClient(clientOptions),
    consent: new ConsentClient(clientOptions),
  });
};

const isJsonObject = (value: unknown): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const parseObject = (value: string, diagnostic: string): JsonObject => {
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

const requireText = (value: unknown, diagnostic: string): string => {
  if (typeof value !== 'string' || value.length === 0 || /[\u0000-\u001F\u007F]/u.test(value)) {
    throw new Error(diagnostic);
  }

  return value;
};

const requireStatus = (response: RawProtocolResponse, expected: number, diagnostic: string) => {
  if (response.status !== expected) {
    throw new Error(diagnostic);
  }

  return response;
};

const headerValues = (response: RawProtocolResponse, name: string) =>
  response.headers
    .filter(([candidate]) => candidate.toLowerCase() === name)
    .map(([, value]) => value);

const requireJson = (response: RawProtocolResponse, diagnostic: string): JsonObject => {
  const types = headerValues(response, 'content-type').map((value) =>
    value.split(';', 1)[0]?.trim().toLowerCase()
  );

  if (types.length !== 1 || types[0] !== 'application/json') {
    throw new Error(diagnostic);
  }

  return parseObject(response.body, diagnostic);
};

const relativeResumePath = (value: unknown, target: TargetConfig, diagnostic: string): string => {
  try {
    const url = new URL(requireText(value, diagnostic));
    const segments = url.pathname.split('/');

    if (
      url.origin !== new URL(target.coreUrl).origin ||
      segments.length !== 4 ||
      segments[1] !== 'oidc' ||
      segments[2] !== 'auth' ||
      !segments[3] ||
      url.search.length > 0 ||
      url.hash.length > 0
    ) {
      throw new TypeError('Invalid resume path');
    }

    return `oidc/auth/${segments[3]}`;
  } catch {
    throw new Error(diagnostic);
  }
};

const requireAuthorizationCallback = (
  response: RawProtocolResponse,
  session: BoundarySession,
  expectedIssuer: string
): string => {
  requireStatus(response, 303, 'Phase 1 consent boundary B resume failed');
  const locations = headerValues(response, 'location');
  const [location] = locations;

  if (!location || locations.length !== 1) {
    throw new Error('Phase 1 consent boundary B callback is invalid');
  }
  try {
    const callback = new URL(location, session.redirectUri);
    const registered = new URL(session.redirectUri);
    const codes = callback.searchParams.getAll('code');
    const states = callback.searchParams.getAll('state');
    const issuers = callback.searchParams.getAll('iss');

    if (
      callback.origin !== registered.origin ||
      callback.pathname !== registered.pathname ||
      callback.hash !== registered.hash ||
      codes.length !== 1 ||
      !codes[0] ||
      states.length !== 1 ||
      states[0] !== session.authorizationState ||
      issuers.length !== 1 ||
      issuers[0] !== expectedIssuer ||
      callback.searchParams.has('error')
    ) {
      throw new TypeError('Invalid authorization callback');
    }

    return codes[0];
  } catch {
    throw new Error('Phase 1 consent boundary B callback is invalid');
  }
};

const stateEquals = (
  value: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>,
  expected: typeof baselineState | typeof acceptedBState | typeof resumedBState
) =>
  isDeepStrictEqual(value.body, expected.body) &&
  isDeepStrictEqual(value.semanticState, expected.semanticState) &&
  isDeepStrictEqual(value.persistedState, expected.persistedState) &&
  isDeepStrictEqual(value.sideEffects, expected.sideEffects);

const requireState = async (
  context: Phase1ScenarioRunContext,
  stepId: string,
  phase: 'baseline' | 'accepted-b' | 'resumed-b'
) => {
  const state = await context.projectScenarioState({
    scenarioId,
    stepId,
    fixture: context.fixture,
  });

  const expected =
    phase === 'baseline' ? baselineState : phase === 'accepted-b' ? acceptedBState : resumedBState;

  if (!stateEquals(state, expected)) {
    throw new Error('Phase 1 consent boundary state is invalid');
  }

  return state;
};

const rawObservation = (
  response: RawProtocolResponse,
  body: unknown,
  state: Awaited<ReturnType<Phase1ScenarioRunContext['projectScenarioState']>>,
  overrides: Partial<RawHttpObservation> = {}
): RawHttpObservation => ({ ...state, ...response, body, ...overrides });

const getLogicalIdentity = (label: BoundaryLabel, context: Phase1ScenarioRunContext) => {
  const thirdParty = context.profile.fixtures.dataTenant.applications.find(
    ({ isThirdParty }) => isThirdParty
  );

  if (!thirdParty?.isThirdParty) {
    throw new Error('Phase 1 consent boundary fixture is invalid');
  }

  return label === 'a'
    ? Object.freeze({
        user: context.profile.fixtures.dataTenant.subject.id,
        username: context.profile.fixtures.dataTenant.subject.username,
        application: thirdParty.id,
        redirectUri: thirdParty.oidcClientMetadata.redirectUris[0],
        scopes: 'openid profile',
      })
    : Object.freeze({
        user: `consent.${label === 'b' ? 'primary' : 'foreign'}.user-b`,
        username: `${context.profile.fixtures.dataTenant.subject.username}_boundary_b`,
        application: `consent.${label === 'b' ? 'primary' : 'foreign'}.client-b`,
        redirectUri: thirdParty.oidcClientMetadata.redirectUris[0],
        scopes: 'openid',
      });
};

const advanceToConsent = async (
  label: BoundaryLabel,
  context: Phase1ScenarioRunContext,
  password: string,
  createClients: NonNullable<ConsentBoundaryScenarioOptions['createClients']>
): Promise<BoundarySession> => {
  const role: Phase1FixtureAllocationRole = label === 'foreign' ? 'foreign' : 'data';
  const allocation = context.fixture.public.allocations.find(
    (candidate) => candidate.role === role
  );
  const target = label === 'foreign' ? context.fixture.foreignTarget : context.target;
  const identity = getLogicalIdentity(label, context);

  if (!allocation || !target || !identity.redirectUri) {
    throw new Error('Phase 1 consent boundary fixture is invalid');
  }
  const clientId = getPhase1FixtureRuntimeId(
    context.fixture.public,
    allocation.allocationId,
    'application',
    identity.application
  );
  const userId = getPhase1FixtureRuntimeId(
    context.fixture.public,
    allocation.allocationId,
    'user',
    identity.user
  );
  const username = getPhase1FixtureRuntimeUsername(identity.username, allocation.allocationId);
  const store = new MemoryProtocolSecretStore();
  const clients = createClients({ label, target, role, store, context });

  if (
    clients.oidc.store !== store ||
    clients.experience.store !== store ||
    clients.consent.store !== store
  ) {
    throw new Error('Phase 1 consent boundary protocol session is invalid');
  }
  const verifier = randomBytes(48).toString('base64url');
  const authorizationState = randomBytes(32).toString('base64url');
  store.registerSecret(verifier);
  store.registerSecret(authorizationState);
  store.registerSecret(password);
  const query = new URLSearchParams({
    client_id: clientId,
    redirect_uri: identity.redirectUri,
    code_challenge: createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
    state: authorizationState,
    response_type: 'code',
    prompt: 'login consent',
    scope: identity.scopes,
  });
  requireStatus(
    await clients.oidc.request(
      `consent-boundary-${label}-authorization`,
      `${context.profile.oidc.authorizationPath.replace(/^\//u, '')}?${query.toString()}`,
      { includeCookies: true }
    ),
    303,
    'Phase 1 consent boundary authorization failed'
  );
  requireStatus(
    await clients.experience.requestExperience(
      `consent-boundary-${label}-bootstrap`,
      'experience',
      { method: 'PUT', headers: jsonHeaders, body: JSON.stringify({ interactionEvent: 'SignIn' }) }
    ),
    204,
    'Phase 1 consent boundary bootstrap failed'
  );
  const verification = requireJson(
    requireStatus(
      await clients.experience.requestExperience(
        `consent-boundary-${label}-password`,
        'experience/verification/password',
        {
          method: 'POST',
          headers: jsonHeaders,
          body: JSON.stringify({ identifier: { type: 'username', value: username }, password }),
        }
      ),
      200,
      'Phase 1 consent boundary password failed'
    ),
    'Phase 1 consent boundary password failed'
  );
  const verificationId = requireText(
    verification.verificationId,
    'Phase 1 consent boundary password failed'
  );
  store.registerSecret(verificationId);
  requireStatus(
    await clients.experience.requestExperience(
      `consent-boundary-${label}-identify`,
      'experience/identification',
      { method: 'POST', headers: jsonHeaders, body: JSON.stringify({ verificationId }) }
    ),
    204,
    'Phase 1 consent boundary identification failed'
  );
  const submit = requireJson(
    requireStatus(
      await clients.experience.requestExperience(
        `consent-boundary-${label}-submit`,
        'experience/submit',
        { method: 'POST' }
      ),
      200,
      'Phase 1 consent boundary submission failed'
    ),
    'Phase 1 consent boundary submission failed'
  );
  const bridgePath = relativeResumePath(
    submit.redirectTo,
    target,
    'Phase 1 consent boundary bridge is invalid'
  );
  const bridge = requireStatus(
    await clients.oidc.request(`consent-boundary-${label}-bridge`, bridgePath),
    303,
    'Phase 1 consent boundary bridge failed'
  );
  const locations = headerValues(bridge, 'location');

  const [location] = locations;

  if (
    !location ||
    locations.length !== 1 ||
    new URL(location, target.coreUrl).pathname !== '/consent'
  ) {
    throw new Error('Phase 1 consent boundary bridge failed');
  }

  return Object.freeze({
    label,
    target,
    role,
    store,
    clients,
    clientId,
    userId,
    redirectUri: identity.redirectUri,
    authorizationState,
  });
};

const completeAndReplay = async (session: BoundarySession): Promise<void> => {
  const consent = requireJson(
    requireStatus(
      await session.clients.consent.requestConsent('consent-boundary-a-accept', 'consent', {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({}),
      }),
      200,
      'Phase 1 consent boundary replay setup failed'
    ),
    'Phase 1 consent boundary replay setup failed'
  );
  const resumePath = relativeResumePath(
    consent.redirectTo,
    session.target,
    'Phase 1 consent boundary replay setup failed'
  );
  requireStatus(
    await session.clients.oidc.request('consent-boundary-a-resume', resumePath),
    303,
    'Phase 1 consent boundary replay setup failed'
  );
};

const assertRejectedResponse = (
  response: RawProtocolResponse,
  replayed: boolean,
  clearsInvalidSignature: boolean
): JsonObject => {
  requireStatus(response, 400, 'Phase 1 consent rejection response is invalid');
  const body = requireJson(response, 'Phase 1 consent rejection response is invalid');
  const expected = {
    code: 'session.not_found',
    message: 'Session not found. Please go back and sign in again.',
    error: 'invalid_request',
    error_description: replayed ? replayFailureDescription : cookieFailureDescription,
  };

  if (!isDeepStrictEqual(body, expected) || headerValues(response, 'location').length > 0) {
    throw new Error('Phase 1 consent rejection response is invalid');
  }
  const setCookies = headerValues(response, 'set-cookie');
  const deletionCookiePattern =
    /^_interaction\.sig=;\s*path=\/;\s*expires=Thu, 01 Jan 1970 00:00:00 GMT;(?:\s*secure;)?\s*httponly$/iu;
  const clearsSignature =
    setCookies.length === 1 && deletionCookiePattern.test(setCookies[0] ?? '');

  if (
    clearsSignature !== clearsInvalidSignature ||
    setCookies.length !== (clearsInvalidSignature ? 1 : 0)
  ) {
    throw new Error('Phase 1 consent rejection cookie response is invalid');
  }

  return body;
};

const canonicalizeSignatureDeletion = (response: RawProtocolResponse): RawProtocolResponse => ({
  ...response,
  headers: Object.freeze(
    response.headers.map(([name, value]) =>
      name.toLowerCase() === 'set-cookie' && value.startsWith('_interaction.sig=;')
        ? Object.freeze([
            name,
            `_interaction.sig=; Path=/; Max-Age=0;${/;\s*secure(?:;|$)/iu.test(value) ? ' Secure;' : ''} HttpOnly`,
          ] as const)
        : Object.freeze([name, value] as const)
    )
  ),
});

export const runInteractionConsentSessionBoundary = async (
  context: Phase1ScenarioRunContext,
  options: ConsentBoundaryScenarioOptions = {}
): Promise<readonly Phase1ScenarioStepResult[]> =>
  context.fixture.withSecretLease(async (lease) => {
    const createClients = options.createClients ?? defaultCreateClients;
    const a = await advanceToConsent(
      'a',
      context,
      lease.getPassword(context.profile.fixtures.dataTenant.subject.id),
      createClients
    );
    const b = await advanceToConsent(
      'b',
      context,
      lease.getPassword('consent.primary.user-b'),
      createClients
    );
    const foreign = await advanceToConsent(
      'foreign',
      context,
      lease.getPassword('consent.foreign.user-b'),
      createClients
    );
    await completeAndReplay(a);
    const dataAllocation = context.fixture.public.allocations.find(({ role }) => role === 'data');
    const symbols = dataAllocation && context.protocol.symbolsFor(dataAllocation.allocationId);

    if (!dataAllocation || !symbols) {
      throw new Error('Phase 1 consent boundary symbols are unavailable');
    }
    symbols.bind(
      'fixture.consent.primary.user-b.username',
      getPhase1FixtureRuntimeUsername(
        `${context.profile.fixtures.dataTenant.subject.username}_boundary_b`,
        dataAllocation.allocationId
      )
    );
    symbols.bind(
      'fixture.consent.primary.client-b.name',
      getPhase1FixtureRuntimeText('consent.primary client B', dataAllocation.allocationId)
    );
    const projectionContext: NormalizationContext = createPhase1NormalizationContext(
      context.profile,
      context.target,
      symbols
    );
    const primaryConsentUrl = new URL('/api/interaction/consent', context.target.coreUrl);
    const aConsentUrl = new URL('/api/interaction/consent', a.target.coreUrl);
    const bConsentUrl = new URL('/api/interaction/consent', b.target.coreUrl);
    const foreignConsentUrl = new URL('/api/interaction/consent', foreign.target.coreUrl);
    const requestDerived =
      options.requestDerivedConsent ??
      (async ({ operation, store, options }) =>
        new ConsentClient({
          target: context.target,
          fixture: context.fixture,
          allocationRole: 'data',
          store,
          signal: context.signal,
        }).requestConsent(operation, 'consent', options));
    const steps: Phase1ScenarioStepResult[] = [];
    const variants = [
      {
        name: 'absent',
        derive: () => new MemoryProtocolSecretStore(),
        replayed: false,
        clears: false,
      },
      {
        name: 'partial',
        derive: () =>
          a.store.deriveInteractionCookieStore(aConsentUrl, primaryConsentUrl, 'partial'),
        replayed: false,
        clears: false,
      },
      {
        name: 'tampered',
        derive: () =>
          a.store.deriveInteractionCookieStore(aConsentUrl, primaryConsentUrl, 'tampered'),
        replayed: false,
        clears: true,
      },
      {
        name: 'spliced',
        derive: () =>
          a.store.deriveInteractionCookieStore(aConsentUrl, primaryConsentUrl, 'spliced', b.store),
        replayed: false,
        clears: true,
      },
      {
        name: 'replayed',
        derive: () => a.store.deriveInteractionCookieStore(aConsentUrl, primaryConsentUrl, 'exact'),
        replayed: true,
        clears: false,
      },
      {
        name: 'foreign',
        derive: () =>
          foreign.store.deriveInteractionCookieStore(foreignConsentUrl, primaryConsentUrl, 'exact'),
        replayed: false,
        clears: true,
      },
    ] as const;

    for (const method of ['GET', 'POST'] as const) {
      for (const variant of variants) {
        const stepId = `${method.toLowerCase()}-${variant.name}`;
        const store = variant.derive();
        const response = await requestDerived({
          operation: `consent-boundary-${stepId}`,
          store,
          options: {
            method,
            ...(method === 'POST' ? { headers: jsonHeaders, body: JSON.stringify({}) } : {}),
          },
          context,
        });
        const body = assertRejectedResponse(response, variant.replayed, variant.clears);
        const state = await requireState(context, stepId, 'baseline');
        const projectedResponse = canonicalizeSignatureDeletion(response);
        const value = (() => {
          try {
            return projectConsentErrorObservation(
              rawObservation(projectedResponse, body, state),
              projectionContext
            );
          } catch {
            throw new Error(`Phase 1 consent rejection projection failed: ${stepId}`);
          }
        })();
        store.assertNoCredentialMaterial(value);
        steps.push(Object.freeze({ stepId, value }));
      }
    }

    const validGet = requireStatus(
      await b.clients.consent.requestConsent('consent-boundary-get-valid-b', 'consent', {
        method: 'GET',
      }),
      200,
      'Phase 1 consent boundary valid read failed'
    );
    const validGetBody = requireJson(validGet, 'Phase 1 consent boundary valid read failed');

    const { application } = validGetBody;
    const { user } = validGetBody;

    if (
      typeof application !== 'object' ||
      application === null ||
      Array.isArray(application) ||
      application.id !== b.clientId ||
      typeof user !== 'object' ||
      user === null ||
      Array.isArray(user) ||
      user.id !== b.userId
    ) {
      throw new Error('Phase 1 consent boundary valid read failed');
    }
    const validGetState = await requireState(context, 'get-valid-b', 'baseline');
    steps.push(
      Object.freeze({
        stepId: 'get-valid-b',
        value: projectConsentObservation(
          rawObservation(validGet, validGetBody, validGetState),
          projectionContext
        ),
      })
    );

    const validPost = requireStatus(
      await b.clients.consent.requestConsent('consent-boundary-post-valid-b', 'consent', {
        method: 'POST',
        headers: jsonHeaders,
        body: JSON.stringify({}),
      }),
      200,
      'Phase 1 consent boundary valid submission failed'
    );
    const validPostBody = requireJson(
      validPost,
      'Phase 1 consent boundary valid submission failed'
    );
    const resumePath = relativeResumePath(
      validPostBody.redirectTo,
      b.target,
      'Phase 1 consent boundary valid submission failed'
    );
    b.store.registerSecret(decodeURIComponent(resumePath.split('/').at(-1) ?? ''));
    const validPostState = await requireState(context, 'post-valid-b', 'accepted-b');
    steps.push(
      Object.freeze({
        stepId: 'post-valid-b',
        value: projectConsentObservation(
          rawObservation(validPost, validPostBody, validPostState),
          projectionContext
        ),
      })
    );
    const resumeResponse = await b.clients.oidc.request('consent-boundary-b-resume', resumePath);
    const expectedIssuer = new URL(context.profile.oidc.issuerPath, b.target.coreUrl).href.replace(
      /\/$/u,
      ''
    );
    const code = requireAuthorizationCallback(resumeResponse, b, expectedIssuer);
    b.store.registerSecret(code);
    const finalState = await requireState(context, 'state', 'resumed-b');
    steps.push(
      Object.freeze({
        stepId: 'state',
        value: projectSemanticStateObservation(
          { ...finalState, status: 200, headers: [] },
          projectionContext,
          { scenarioId, stepId: 'state' }
        ),
      })
    );
    const frozen = Object.freeze(steps);

    for (const session of [a, b, foreign]) {
      session.store.assertNoCredentialMaterial(frozen);
    }

    return frozen;
  });

/* eslint-enable max-lines, complexity, no-control-regex, no-await-in-loop, @silverhand/fp/no-mutating-methods, id-length */
