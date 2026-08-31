/* eslint-disable max-lines, no-restricted-syntax, unicorn/no-array-for-each, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-confusing-void-expression -- The relational validator preserves exact request and SDK order while tracking subset positions. */
import { ReservedResource, UserScope, withReservedScopes } from '@logto/js';

import type {
  Phase1ConsoleReadRequest,
  Phase1ExperienceBootstrapRequest,
  Phase1InteractionOperation,
  Phase1Profile,
} from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

const expectedManagementOperations = [
  'http.management-api.get./api/applications',
  'http.management-api.get./api/users',
] as const;
const expectedAccountOperations = ['http.user-api.get./api/my-account'] as const;
const expectedExperienceBootstrapOperations = [
  'http.management-api.get./api/.well-known/phrases',
  'http.management-api.get./api/.well-known/sign-in-exp',
] as const;
const expectedExperienceOperations = [
  'http.experience-api.get./api/experience/interaction',
  'http.experience-api.post./api/experience/identification',
  'http.experience-api.post./api/experience/submit',
  'http.experience-api.post./api/experience/verification/password',
  'http.experience-api.put./api/experience',
  'http.experience-api.put./api/experience/interaction-event',
] as const;
const expectedConsentGetAuthorization =
  'active interaction cookies for phase1-browser and phase1-user';
const expectedConsentGetContinuity =
  'same in-memory jar from authorization and password interaction; raw values never enter evidence';
const expectedConsentPostAuthorization =
  'the same active interaction cookies returned by the GET operation';
const expectedConsentPostContinuity =
  'reuse the exact GET jar and then the exact resulting jar for the resume request';
const expectedOrganizationTokenTrigger =
  'useTenantScopeListener after the authenticated default-tenant Console mounts';
const expectedOrganizationTokenPersistedOutcome =
  'reference-compatible refresh rotation with no tenant, membership, role, or consent mutation';
const expectedRefreshCredentialPlaceholder = 'in-memory credential omitted from evidence';

const fail = (pointer: string, rule: string): never => {
  throw new Phase1ProfileValidationError('semantic', [pointer], [rule]);
};

const requireValue = <Value>(value: Value, pointer: string, rule: string): NonNullable<Value> =>
  value === undefined || value === null ? fail(pointer, rule) : (value as NonNullable<Value>);

const assertEqual = (actual: unknown, expected: unknown, pointer: string, rule: string): void => {
  if (actual !== expected) {
    fail(pointer, rule);
  }
};

const assertExactRecord = (
  actual: Readonly<Record<string, unknown>>,
  expected: Readonly<Record<string, unknown>>,
  pointer: string,
  rule: string
): void => {
  const actualKeys = Object.keys(actual).toSorted();
  const expectedKeys = Object.keys(expected).toSorted();

  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    fail(pointer, rule);
  }

  for (const [key, expectedValue] of Object.entries(expected)) {
    if (actual[key] !== expectedValue) {
      fail(`${pointer}/${key}`, rule);
    }
  }
};

const assertExactOrder = (
  actual: readonly string[],
  expected: readonly string[],
  pointer: string,
  rule: string
): void => {
  const firstDifference = Array.from(
    { length: Math.max(actual.length, expected.length) },
    (_, index) => index
  ).find((index) => actual[index] !== expected[index]);

  if (firstDifference !== undefined) {
    fail(`${pointer}/${firstDifference}`, rule);
  }
};

const assertOrderedSubset = (
  subset: readonly string[],
  sequence: readonly string[],
  pointer: string
): void => {
  let previousIndex = -1;

  subset.forEach((value, index) => {
    const resolvedIndex = sequence.indexOf(value, previousIndex + 1);

    if (resolvedIndex === -1) {
      fail(`${pointer}/${index}`, 'consent-scope-ordered-subset');
    }

    previousIndex = resolvedIndex;
  });
};

const assertUiRoutes = (profile: Phase1Profile): void => {
  const expectedBases = {
    'experience-user': profile.routing.userEndpoint,
    'experience-admin': profile.routing.adminEndpoint,
    'demo-app': profile.routing.userEndpoint,
    console: profile.routing.adminEndpoint,
  } as const;
  const expectedTenants = {
    'experience-user': profile.fixtures.dataTenant.id,
    'experience-admin': profile.fixtures.adminTenant.id,
  } as const;

  profile.uiAssetContracts.forEach((asset, index) => {
    const pointer = `/uiAssetContracts/${index}`;
    assertEqual(
      asset.baseUrl,
      expectedBases[asset.application],
      `${pointer}/baseUrl`,
      'asset-route'
    );

    if ('tenant' in asset) {
      assertEqual(
        asset.tenant,
        expectedTenants[asset.application],
        `${pointer}/tenant`,
        'asset-route'
      );
    }

    const expectedPrefix =
      asset.application === 'demo-app'
        ? '/demo-app/assets/'
        : asset.application === 'console'
          ? '/console/assets/'
          : '/assets/';
    assertEqual(asset.assetPrefix, expectedPrefix, `${pointer}/assetPrefix`, 'asset-route');
  });
};

const assertEndpointBootstrap = (
  profile: Phase1Profile,
  request: Phase1ConsoleReadRequest,
  index: number
): void => {
  const pointer = `/consoleReadRequests/${index}`;
  assertEqual(request.method, 'GET', `${pointer}/method`, 'operation-route');
  assertEqual(
    request.baseUrl,
    profile.routing.adminEndpoint,
    `${pointer}/baseUrl`,
    'operation-route'
  );
  assertEqual(request.authorization, null, `${pointer}/authorization`, 'operation-authorization');
  assertEqual(request.expectedStatus, 200, `${pointer}/expectedStatus`, 'operation-status');

  if (request.path === '/api/.well-known/endpoints/default') {
    assertEqual(
      request.requiredProjection.user,
      profile.routing.userEndpoint,
      `${pointer}/requiredProjection/user`,
      'operation-projection'
    );
  }
};

const assertManagementRead = (
  profile: Phase1Profile,
  request: Extract<
    Phase1ConsoleReadRequest,
    Readonly<{ path: '/api/applications' | '/api/users' }>
  >,
  index: number
): void => {
  const pointer = `/consoleReadRequests/${index}`;
  assertEqual(request.method, 'GET', `${pointer}/method`, 'operation-route');
  assertEqual(
    request.baseUrl,
    profile.routing.userEndpoint,
    `${pointer}/baseUrl`,
    'operation-route'
  );
  assertEqual(
    request.baseUrlField,
    'routing.userEndpoint',
    `${pointer}/baseUrlField`,
    'operation-route'
  );
  assertEqual(request.origin, profile.routing.adminEndpoint, `${pointer}/origin`, 'operation-cors');
  assertEqual(
    request.headers['Accept-Language'],
    'en',
    `${pointer}/headers/Accept-Language`,
    'operation-header'
  );
  assertEqual(
    request.authorization.issuer,
    profile.consoleAuthentication.issuer,
    `${pointer}/authorization/issuer`,
    'operation-authorization'
  );
  assertEqual(
    request.authorization.resource,
    profile.consoleAuthentication.configuredResources.at(0),
    `${pointer}/authorization/resource`,
    'operation-authorization'
  );

  const resource = profile.fixtures.adminTenant.resources.find(
    ({ indicator }) => indicator === request.authorization.resource
  );

  if (!resource?.scopes.includes(request.authorization.scope)) {
    fail(`${pointer}/authorization/scope`, 'operation-authorization');
  }

  assertEqual(request.expectedStatus, 200, `${pointer}/expectedStatus`, 'operation-status');
  assertEqual(
    request.requiredBodyLength,
    request.requiredProjection.length,
    `${pointer}/requiredBodyLength`,
    'operation-projection'
  );
  assertExactOrder(
    request.requiredResponseHeaders,
    ['Total-Number'],
    `${pointer}/requiredResponseHeaders`,
    'operation-header'
  );
  assertExactRecord(
    request.requiredHeaderValues,
    { 'Total-Number': String(request.requiredBodyLength) },
    `${pointer}/requiredHeaderValues`,
    'operation-header'
  );
};

const assertConsoleReads = (profile: Phase1Profile): void => {
  const firstPartyApplication = requireValue(
    profile.fixtures.dataTenant.applications.find(({ isThirdParty }) => !isThirdParty),
    '/fixtures/dataTenant/applications',
    'console-projection-matrix'
  );
  const browserApplicationId =
    profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue.appId;
  const expectedMatrix = [
    { path: '/api/.well-known/endpoints/default', query: {}, projectionIds: null },
    {
      path: '/api/applications',
      query: { page: '1', page_size: '20', isThirdParty: 'false' },
      projectionIds: [firstPartyApplication.id],
    },
    {
      path: '/api/applications',
      query: { page: '1', page_size: '20', isThirdParty: 'true' },
      projectionIds: [browserApplicationId],
    },
    {
      path: '/api/applications',
      query: { page: '1', page_size: '1', isThirdParty: 'false', types: 'SAML' },
      projectionIds: [],
    },
    {
      path: '/api/users',
      query: { page: '1', page_size: '20' },
      projectionIds: [profile.fixtures.dataTenant.subject.id],
    },
  ] as const;

  if (profile.consoleReadRequests.length !== expectedMatrix.length) {
    fail('/consoleReadRequests', 'console-request-matrix');
  }

  expectedMatrix.forEach((expected, index) => {
    const request = requireValue(
      profile.consoleReadRequests.at(index),
      '/consoleReadRequests',
      'console-request-matrix'
    );
    assertEqual(
      request.path,
      expected.path,
      `/consoleReadRequests/${index}/path`,
      'console-request-matrix'
    );
    assertExactRecord(
      request.query,
      expected.query,
      `/consoleReadRequests/${index}/query`,
      'console-request-matrix'
    );

    if (expected.projectionIds !== null) {
      if (request.path === '/api/.well-known/endpoints/default') {
        fail(`/consoleReadRequests/${index}/requiredProjection`, 'console-projection-matrix');
      }
      const projectionRequest = request as Exclude<
        Phase1ConsoleReadRequest,
        Readonly<{ path: '/api/.well-known/endpoints/default' }>
      >;
      const projections = projectionRequest.requiredProjection;

      const maximumProjectionLength = Math.max(projections.length, expected.projectionIds.length);

      for (const projectionIndex of Array.from(
        { length: maximumProjectionLength },
        (_, candidateIndex) => candidateIndex
      )) {
        if (projections[projectionIndex]?.id !== expected.projectionIds[projectionIndex]) {
          fail(
            `/consoleReadRequests/${index}/requiredProjection/${projectionIndex}/id`,
            'console-projection-matrix'
          );
        }
      }
    }
  });

  profile.consoleReadRequests.forEach((request, index) => {
    if (request.path === '/api/.well-known/endpoints/default') {
      assertEndpointBootstrap(profile, request, index);
    } else {
      assertManagementRead(profile, request, index);
    }
  });

  const endpointBootstrap = profile.consoleReadRequests.find(
    ({ path }) => path === '/api/.well-known/endpoints/default'
  );

  if (!endpointBootstrap) {
    fail('/consoleReadRequests', 'operation-route');
  }

  const expectedBootstrapOperation = `GET ${profile.routing.adminEndpoint}/api/.well-known/endpoints/default`;
  assertExactOrder(
    profile.consoleBootstrapOperations,
    [expectedBootstrapOperation],
    '/consoleBootstrapOperations',
    'operation-registry'
  );

  const readPaths = new Set(profile.consoleReadRequests.map(({ path }) => path));
  const expectedRequestOperations = [
    ['/api/applications', 'http.management-api.get./api/applications'],
    ['/api/users', 'http.management-api.get./api/users'],
  ] as const;

  expectedRequestOperations.forEach(([path, operation]) => {
    if (!readPaths.has(path) || !profile.managementOperations.includes(operation)) {
      fail('/managementOperations', 'operation-registry');
    }
  });
};

const assertOperationRegistries = (profile: Phase1Profile): void => {
  assertExactOrder(
    profile.managementOperations,
    expectedManagementOperations,
    '/managementOperations',
    'operation-registry'
  );
  assertExactOrder(
    profile.accountOperations,
    expectedAccountOperations,
    '/accountOperations',
    'operation-registry'
  );
  assertExactOrder(
    profile.experienceBootstrapOperations,
    expectedExperienceBootstrapOperations,
    '/experienceBootstrapOperations',
    'operation-registry'
  );
  assertExactOrder(
    profile.experienceOperations,
    expectedExperienceOperations,
    '/experienceOperations',
    'operation-registry'
  );
};

const assertExperienceBootstrap = (
  profile: Phase1Profile,
  request: Phase1ExperienceBootstrapRequest,
  index: number
): void => {
  const pointer = `/experienceBootstrapRequests/${index}`;
  const browserAppId =
    profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue.appId;
  const adminAppId = profile.fixtures.adminTenant.application.id;
  const expectedMatrix = [
    {
      kind: 'sign-in',
      baseUrl: profile.routing.userEndpoint,
      appId: browserAppId,
      projection: `username/password sign-in settings for ${browserAppId}`,
    },
    {
      kind: 'phrases',
      baseUrl: profile.routing.userEndpoint,
      projection: 'English phrase payload used by the pinned Experience tree',
    },
    {
      kind: 'sign-in',
      baseUrl: profile.routing.adminEndpoint,
      appId: adminAppId,
      projection: `username/password sign-in settings for ${adminAppId}`,
    },
    {
      kind: 'phrases',
      baseUrl: profile.routing.adminEndpoint,
      projection: 'English admin-tenant phrase payload used by the pinned Experience tree',
    },
  ] as const;
  const expected = requireValue(
    expectedMatrix.at(index),
    '/experienceBootstrapRequests',
    'bootstrap-request-matrix'
  );
  assertEqual(request.method, 'GET', `${pointer}/method`, 'operation-route');
  assertEqual(request.expectedStatus, 200, `${pointer}/expectedStatus`, 'operation-status');
  assertEqual(request.baseUrl, expected.baseUrl, `${pointer}/baseUrl`, 'operation-route');

  if (expected.kind === 'sign-in') {
    if (request.path !== '/api/.well-known/sign-in-exp') {
      fail(`${pointer}/path`, 'bootstrap-request-matrix');
    }

    assertExactRecord(
      request.query,
      { appId: expected.appId, uiLocales: 'en' },
      `${pointer}/query`,
      'bootstrap-request-matrix'
    );
  } else {
    if (request.path !== '/api/.well-known/phrases' || !('headers' in request)) {
      fail(`${pointer}/path`, 'bootstrap-request-matrix');
    }

    assertExactRecord(request.query, { lng: 'en' }, `${pointer}/query`, 'bootstrap-request-matrix');
    const phraseRequest = request as Extract<
      Phase1ExperienceBootstrapRequest,
      Readonly<{ path: '/api/.well-known/phrases' }>
    >;
    assertExactRecord(
      phraseRequest.headers,
      { 'Accept-Language': 'en' },
      `${pointer}/headers`,
      'bootstrap-request-matrix'
    );
  }
  assertEqual(
    request.requiredProjection,
    expected.projection,
    `${pointer}/requiredProjection`,
    'operation-projection'
  );
};

const assertBootstrapAndAccountOperations = (profile: Phase1Profile): void => {
  if (profile.experienceBootstrapRequests.length !== 4) {
    fail('/experienceBootstrapRequests', 'bootstrap-request-matrix');
  }

  profile.experienceBootstrapRequests.forEach((request, index) =>
    assertExperienceBootstrap(profile, request, index)
  );

  if (profile.consoleAccountRequests.length !== 1) {
    fail('/consoleAccountRequests', 'account-request-matrix');
  }

  profile.consoleAccountRequests.forEach((request, index) => {
    const pointer = `/consoleAccountRequests/${index}`;
    assertEqual(request.method, 'GET', `${pointer}/method`, 'operation-route');
    assertEqual(
      request.url,
      `${profile.routing.adminEndpoint}/api/my-account/`,
      `${pointer}/url`,
      'operation-route'
    );
    assertEqual(
      request.authorization.issuer,
      profile.consoleAuthentication.issuer,
      `${pointer}/authorization/issuer`,
      'operation-authorization'
    );
    assertEqual(
      request.authorization.resource,
      null,
      `${pointer}/authorization/resource`,
      'operation-authorization'
    );
    assertEqual(
      request.authorization.tokenFormat,
      'opaque',
      `${pointer}/authorization/tokenFormat`,
      'operation-authorization'
    );
    assertEqual(request.expectedStatus, 200, `${pointer}/expectedStatus`, 'operation-status');
  });

  if (!profile.accountOperations.includes('http.user-api.get./api/my-account')) {
    fail('/accountOperations', 'operation-registry');
  }
};

const assertCors = (profile: Phase1Profile): void => {
  assertEqual(profile.cors.origin, profile.routing.adminEndpoint, '/cors/origin', 'operation-cors');
  assertEqual(profile.cors.target, profile.routing.userEndpoint, '/cors/target', 'operation-cors');
  assertEqual(
    profile.cors.allowOriginResponse,
    profile.cors.origin,
    '/cors/allowOriginResponse',
    'operation-cors'
  );

  assertExactOrder(profile.cors.methods, ['OPTIONS', 'GET'], '/cors/methods', 'operation-cors');
  assertExactOrder(
    profile.cors.allowedRequestHeaders,
    ['Authorization', 'Accept-Language', 'Content-Type'],
    '/cors/allowedRequestHeaders',
    'operation-cors'
  );
  assertEqual(
    profile.cors.exposeHeadersResponse,
    '*',
    '/cors/exposeHeadersResponse',
    'operation-cors'
  );
  assertEqual(
    profile.cors.browserReadableHeader,
    'Total-Number',
    '/cors/browserReadableHeader',
    'operation-cors'
  );
  assertEqual(profile.cors.preflightStatus, 204, '/cors/preflightStatus', 'operation-status');

  const profiledCrossOriginPaths = profile.consoleReadRequests
    .filter(
      (
        request
      ): request is Extract<
        Phase1ConsoleReadRequest,
        Readonly<{ path: '/api/applications' | '/api/users' }>
      > => request.path !== '/api/.well-known/endpoints/default'
    )
    .map(({ path }) => path)
    .filter((path, index, paths) => paths.indexOf(path) === index);
  assertExactOrder(
    profile.cors.preflightPaths,
    profiledCrossOriginPaths,
    '/cors/preflightPaths',
    'cors-preflight-exact-set'
  );
};

const assertConsentPair = (profile: Phase1Profile): void => {
  const getOperations = profile.interactionOperations.filter(
    (operation): operation is Extract<Phase1InteractionOperation, Readonly<{ method: 'GET' }>> =>
      operation.method === 'GET'
  );
  const postOperations = profile.interactionOperations.filter(
    (operation): operation is Extract<Phase1InteractionOperation, Readonly<{ method: 'POST' }>> =>
      operation.method === 'POST'
  );

  if (getOperations.length !== 1 || postOperations.length !== 1) {
    fail('/interactionOperations', 'consent-operation-pair');
  }

  const get = requireValue(getOperations.at(0), '/interactionOperations', 'consent-operation-pair');
  const post = requireValue(
    postOperations.at(0),
    '/interactionOperations',
    'consent-operation-pair'
  );

  const getIndex = profile.interactionOperations.indexOf(get);
  const postIndex = profile.interactionOperations.indexOf(post);
  const postPointer = `/interactionOperations/${postIndex}`;

  if (get.id === post.id) {
    fail(`/interactionOperations/${postIndex}/id`, 'consent-operation-pair');
  }

  assertEqual(
    get.baseUrl,
    profile.routing.userEndpoint,
    `/interactionOperations/${getIndex}/baseUrl`,
    'operation-route'
  );
  assertEqual(
    get.path,
    '/api/interaction/consent',
    `/interactionOperations/${getIndex}/path`,
    'operation-route'
  );
  assertEqual(post.baseUrl, get.baseUrl, `${postPointer}/baseUrl`, 'consent-operation-pair');
  assertEqual(post.path, get.path, `${postPointer}/path`, 'consent-operation-pair');
  assertEqual(
    get.expectedStatus,
    200,
    `/interactionOperations/${getIndex}/expectedStatus`,
    'operation-status'
  );
  assertExactOrder(
    get.errorStatuses.map(String),
    ['400'],
    `/interactionOperations/${getIndex}/errorStatuses`,
    'operation-status'
  );
  assertEqual(post.expectedStatus, 200, `${postPointer}/expectedStatus`, 'operation-status');
  assertExactOrder(
    post.errorStatuses.map(String),
    ['400'],
    `${postPointer}/errorStatuses`,
    'operation-status'
  );

  for (const [index, operation] of profile.interactionOperations.entries()) {
    const expectedId = `phase1.http.interaction.${operation.method.toLowerCase()}.${operation.path}`;

    if (operation.id !== expectedId) {
      fail(`/interactionOperations/${index}/id`, 'consent-operation-id');
    }
  }
  assertEqual(
    get.authorization,
    expectedConsentGetAuthorization,
    `/interactionOperations/${getIndex}/authorization`,
    'consent-cookie-continuity'
  );
  assertEqual(
    get.cookieJarContinuity,
    expectedConsentGetContinuity,
    `/interactionOperations/${getIndex}/cookieJarContinuity`,
    'consent-cookie-continuity'
  );
  assertEqual(
    post.authorization,
    expectedConsentPostAuthorization,
    `${postPointer}/authorization`,
    'consent-cookie-continuity'
  );
  assertEqual(
    post.cookieJarContinuity,
    expectedConsentPostContinuity,
    `${postPointer}/cookieJarContinuity`,
    'consent-cookie-continuity'
  );

  if (Object.keys(post.body).length > 0) {
    fail(`${postPointer}/body`, 'consent-body');
  }

  const consentBase = new URL(profile.routing.userEndpoint);
  assertEqual(
    post.requiredProjection.redirectTo.scheme,
    consentBase.protocol.slice(0, -1),
    `${postPointer}/requiredProjection/redirectTo/scheme`,
    'consent-redirect-route'
  );
  assertEqual(
    post.requiredProjection.redirectTo.origin,
    consentBase.origin,
    `${postPointer}/requiredProjection/redirectTo/origin`,
    'consent-redirect-route'
  );
  assertEqual(
    post.requiredProjection.redirectTo.pathTemplate,
    '/oidc/auth/{one-time-resume-credential}',
    `${postPointer}/requiredProjection/redirectTo/pathTemplate`,
    'consent-redirect-route'
  );
  assertExactOrder(
    post.requiredProjection.redirectTo.queryKeys,
    [],
    `${postPointer}/requiredProjection/redirectTo/queryKeys`,
    'consent-redirect-route'
  );
  assertEqual(
    post.requiredProjection.redirectTo.fragment,
    '',
    `${postPointer}/requiredProjection/redirectTo/fragment`,
    'consent-redirect-route'
  );

  if (!profile.differentialScenarios.includes(profile.consentSessionBoundaryContract.scenarioId)) {
    fail('/consentSessionBoundaryContract/scenarioId', 'differential-scenario-reference');
  }
};

const assertOrganizationTokenRequest = (profile: Phase1Profile): void => {
  const request = profile.consoleOrganizationTokenRequest;
  const formKeys = Object.keys(request.form);
  const expectedFormKeys = new Set([
    'client_id',
    'grant_type',
    'organization_id',
    'refresh_token',
    'resource',
    'scope',
  ]);

  if (
    formKeys.length !== expectedFormKeys.size ||
    formKeys.some((key) => !expectedFormKeys.has(key))
  ) {
    fail('/consoleOrganizationTokenRequest/form', 'organization-token-form');
  }

  assertEqual(
    request.trigger,
    expectedOrganizationTokenTrigger,
    '/consoleOrganizationTokenRequest/trigger',
    'organization-token-route'
  );
  assertEqual(
    request.method,
    'POST',
    '/consoleOrganizationTokenRequest/method',
    'organization-token-route'
  );
  assertEqual(
    request.url,
    `${profile.consoleAuthentication.issuer}/token`,
    '/consoleOrganizationTokenRequest/url',
    'organization-token-route'
  );
  assertEqual(
    request.contentType,
    'application/x-www-form-urlencoded',
    '/consoleOrganizationTokenRequest/contentType',
    'organization-token-route'
  );
  assertEqual(
    request.form.client_id,
    profile.fixtures.adminTenant.application.id,
    '/consoleOrganizationTokenRequest/form/client_id',
    'organization-token-fixture'
  );
  assertEqual(
    request.form.grant_type,
    'refresh_token',
    '/consoleOrganizationTokenRequest/form/grant_type',
    'organization-token-route'
  );
  assertEqual(
    request.form.refresh_token,
    expectedRefreshCredentialPlaceholder,
    '/consoleOrganizationTokenRequest/form/refresh_token',
    'organization-token-credential-placeholder'
  );
  assertEqual(
    request.form.organization_id,
    profile.fixtures.adminTenant.tenantOrganization.id,
    '/consoleOrganizationTokenRequest/form/organization_id',
    'organization-token-fixture'
  );
  assertEqual(
    request.form.resource,
    null,
    '/consoleOrganizationTokenRequest/form/resource',
    'organization-token-route'
  );
  assertEqual(
    request.form.scope,
    null,
    '/consoleOrganizationTokenRequest/form/scope',
    'organization-token-route'
  );
  assertEqual(
    request.expectedStatus,
    200,
    '/consoleOrganizationTokenRequest/expectedStatus',
    'operation-status'
  );
  assertEqual(
    request.requiredTokenResponseProjection.token_type,
    'Bearer',
    '/consoleOrganizationTokenRequest/requiredTokenResponseProjection/token_type',
    'operation-projection'
  );
  assertEqual(
    request.requiredTokenResponseProjection.scope,
    '',
    '/consoleOrganizationTokenRequest/requiredTokenResponseProjection/scope',
    'operation-projection'
  );
  assertEqual(
    request.requiredAccessTokenProjection.format,
    'JWT',
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/format',
    'operation-projection'
  );
  assertEqual(
    request.requiredAccessTokenProjection.iss,
    profile.consoleAuthentication.issuer,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/iss',
    'operation-projection'
  );
  assertEqual(
    request.requiredAccessTokenProjection.sub,
    profile.fixtures.adminTenant.operator.id,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/sub',
    'operation-projection'
  );
  assertEqual(
    request.requiredAccessTokenProjection.aud,
    `urn:logto:organization:${profile.fixtures.adminTenant.tenantOrganization.id}`,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/aud',
    'operation-projection'
  );
  assertEqual(
    request.requiredAccessTokenProjection.client_id,
    profile.consoleAuthentication.applicationId,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/client_id',
    'operation-projection'
  );
  assertEqual(
    request.requiredAccessTokenProjection.scope,
    '',
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/scope',
    'operation-projection'
  );
  assertExactOrder(
    request.requiredAccessTokenOmissions,
    ['organization_id'],
    '/consoleOrganizationTokenRequest/requiredAccessTokenOmissions',
    'operation-projection'
  );
  assertEqual(
    request.requiredPersistedOutcome,
    expectedOrganizationTokenPersistedOutcome,
    '/consoleOrganizationTokenRequest/requiredPersistedOutcome',
    'operation-projection'
  );
};

const isInvalidScopeToken = (token: unknown): boolean =>
  typeof token !== 'string' || token.length === 0 || /\s/u.test(token);

const deriveScopes = (configuredScopes: readonly string[], pointer: string): readonly string[] => {
  configuredScopes.forEach((scope, index) => {
    if (isInvalidScopeToken(scope)) {
      fail(`${pointer}/${index}`, 'sdk-scope-token');
    }
  });

  return withReservedScopes([...configuredScopes]).split(' ');
};

const assertSdkDerivations = (profile: Phase1Profile): void => {
  const browserConfiguration = profile.fixtures.dataTenant.browserClientConfiguration;
  const browserRawScope = browserConfiguration.localStorageValue.scope;

  if (typeof browserRawScope !== 'string') {
    fail(
      '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/scope',
      'sdk-scope-token'
    );
  }
  const browserScopes = browserRawScope.split(' ');

  if (browserScopes.some((scope) => isInvalidScopeToken(scope))) {
    fail(
      '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/scope',
      'sdk-scope-token'
    );
  }
  const derivedBrowserScopes = withReservedScopes(browserScopes).split(' ');
  assertExactOrder(
    browserConfiguration.effectiveScopes,
    derivedBrowserScopes,
    '/fixtures/dataTenant/browserClientConfiguration/effectiveScopes',
    'sdk-derived-order'
  );

  const derivedConsoleScopes = deriveScopes(
    profile.consoleAuthentication.configuredScopes,
    '/consoleAuthentication/configuredScopes'
  );
  assertExactOrder(
    profile.consoleAuthentication.effectiveScopes,
    derivedConsoleScopes,
    '/consoleAuthentication/effectiveScopes',
    'sdk-derived-order'
  );

  const derivedConsoleResources = [
    ...new Set([
      ...profile.consoleAuthentication.configuredResources,
      ...(profile.consoleAuthentication.configuredScopes.includes(UserScope.Organizations)
        ? [ReservedResource.Organization]
        : []),
    ]),
  ];
  assertExactOrder(
    profile.consoleAuthentication.effectiveResources,
    derivedConsoleResources,
    '/consoleAuthentication/effectiveResources',
    'sdk-derived-order'
  );

  const resourceScopeNames = profile.fixtures.dataTenant.resource.scopes.map(({ name }) => name);
  profile.interactionOperations.forEach((operation, index) => {
    const pointer = `/interactionOperations/${index}`;

    if (operation.method === 'GET') {
      assertOrderedSubset(
        operation.requiredProjection.missingOIDCScope,
        derivedBrowserScopes,
        `${pointer}/requiredProjection/missingOIDCScope`
      );
      const missingResourceScopeNames = operation.requiredProjection.missingResourceScopes.flatMap(
        ({ scopes }) => scopes.map(({ name }) => name)
      );
      assertOrderedSubset(
        missingResourceScopeNames,
        resourceScopeNames,
        `${pointer}/requiredProjection/missingResourceScopes/0/scopes`
      );
    } else {
      assertOrderedSubset(
        operation.requiredPersistedOutcome.oidcScopes,
        derivedBrowserScopes,
        `${pointer}/requiredPersistedOutcome/oidcScopes`
      );
      assertOrderedSubset(
        operation.requiredPersistedOutcome.resourceScopes,
        resourceScopeNames,
        `${pointer}/requiredPersistedOutcome/resourceScopes`
      );
    }
  });
};

export const assertOperationSemantics = (profile: Phase1Profile): void => {
  assertUiRoutes(profile);
  assertOperationRegistries(profile);
  assertConsoleReads(profile);
  assertBootstrapAndAccountOperations(profile);
  assertCors(profile);
  assertConsentPair(profile);
  assertOrganizationTokenRequest(profile);
  assertSdkDerivations(profile);
};

/* eslint-enable max-lines, no-restricted-syntax, unicorn/no-array-for-each, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-confusing-void-expression */
