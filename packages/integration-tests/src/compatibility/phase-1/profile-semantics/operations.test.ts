/* eslint-disable max-lines, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression -- The route and SDK matrix applies one observable mutation per case. */
import type { Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

import { assertOperationSemantics } from './operations.js';

const required = <Value>(value: Value | undefined): Value => {
  if (value === undefined) {
    throw new Error('Synthetic operation profile is incomplete');
  }

  return value;
};

const expectSemanticFailure = (profile: Phase1Profile, pointer: string, rule: string) => {
  try {
    assertOperationSemantics(profile);
    throw new Error('Expected semantic validation to fail');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    expect(error).toMatchObject({
      message: 'Invalid Phase 1 semantics',
      stage: 'semantic',
      pointers: [pointer],
      rules: [rule],
    });
  }
};

const operationProfile = () =>
  ({
    routing: { userEndpoint: 'https://data.example', adminEndpoint: 'https://admin.example' },
    uiAssetContracts: [
      {
        application: 'experience-user',
        tenant: 'data',
        baseUrl: 'https://data.example',
        htmlFallbackRoutes: ['/sign-in'],
        assetPrefix: '/assets/',
      },
      {
        application: 'experience-admin',
        tenant: 'admin',
        baseUrl: 'https://admin.example',
        htmlFallbackRoutes: ['/sign-in'],
        assetPrefix: '/assets/',
      },
      {
        application: 'demo-app',
        baseUrl: 'https://data.example',
        htmlFallbackRoutes: ['/demo-app'],
        assetPrefix: '/demo-app/assets/',
      },
      {
        application: 'console',
        baseUrl: 'https://admin.example',
        htmlFallbackRoutes: ['/console/callback'],
        assetPrefix: '/console/assets/',
      },
    ],
    fixtures: {
      adminTenant: {
        id: 'admin',
        operator: {
          id: 'operator',
          username: 'operator-name',
          primaryEmail: 'operator@example.test',
        },
        application: { id: 'console-client' },
        resources: [
          { indicator: 'https://data.example/api', scopes: ['all'] },
          { indicator: 'https://admin.example/me', scopes: ['all'] },
          {
            indicator: 'urn:logto:resource:organizations',
            scopes: ['urn:logto:scope:organizations', 'urn:logto:scope:organization_roles'],
          },
        ],
        tenantOrganization: { id: 'organization' },
      },
      dataTenant: {
        id: 'data',
        subject: {
          id: 'subject',
          username: 'subject-name',
          name: 'Subject',
          primaryEmail: 'subject@example.test',
          primaryPhone: '+15555550100',
        },
        applications: [
          {
            id: 'first-party',
            name: 'First Party',
            type: 'SPA',
            isThirdParty: false,
            oidcClientMetadata: { redirectUris: ['https://data.example/callback'] },
          },
          {
            id: 'browser-client',
            name: 'Browser Client',
            type: 'SPA',
            isThirdParty: true,
            oidcClientMetadata: { redirectUris: ['https://data.example/callback'] },
            userConsentScopes: ['profile', 'email'],
            resourceConsentScopes: ['scope-id'],
          },
        ],
        resource: {
          id: 'resource-id',
          name: 'Resource',
          indicator: 'https://resource.example',
          scopes: [{ id: 'scope-id', name: 'read:data', description: 'Read data' }],
        },
        browserClientConfiguration: {
          localStorageValue: {
            appId: 'browser-client',
            scope: 'profile email read:data',
            resource: 'https://resource.example',
          },
          effectiveScopes: ['openid', 'offline_access', 'profile', 'email', 'read:data'],
        },
      },
    },
    consoleAuthentication: {
      endpoint: 'https://admin.example',
      issuer: 'https://admin.example/oidc',
      applicationId: 'console-client',
      configuredResources: ['https://data.example/api', 'https://admin.example/me'],
      effectiveResources: [
        'https://data.example/api',
        'https://admin.example/me',
        'urn:logto:resource:organizations',
      ],
      configuredScopes: ['profile', 'email', 'urn:logto:scope:organizations', 'all'],
      effectiveScopes: [
        'openid',
        'offline_access',
        'profile',
        'email',
        'urn:logto:scope:organizations',
        'all',
      ],
    },
    consoleOrganizationTokenRequest: {
      trigger: 'useTenantScopeListener after the authenticated default-tenant Console mounts',
      method: 'POST',
      url: 'https://admin.example/oidc/token',
      contentType: 'application/x-www-form-urlencoded',
      form: {
        client_id: 'console-client',
        grant_type: 'refresh_token',
        refresh_token: 'in-memory credential omitted from evidence',
        organization_id: 'organization',
        resource: null,
        scope: null,
      },
      expectedStatus: 200,
      requiredTokenResponseProjection: { token_type: 'Bearer', scope: '' },
      requiredAccessTokenProjection: {
        format: 'JWT',
        iss: 'https://admin.example/oidc',
        sub: 'operator',
        aud: 'urn:logto:organization:organization',
        client_id: 'console-client',
        scope: '',
      },
      requiredAccessTokenOmissions: ['organization_id'],
      requiredPersistedOutcome:
        'reference-compatible refresh rotation with no tenant, membership, role, or consent mutation',
    },
    oidc: { issuerPath: '/oidc' },
    managementOperations: [
      'http.management-api.get./api/applications',
      'http.management-api.get./api/users',
    ],
    accountOperations: ['http.user-api.get./api/my-account'],
    experienceBootstrapOperations: [
      'http.management-api.get./api/.well-known/phrases',
      'http.management-api.get./api/.well-known/sign-in-exp',
    ],
    consoleBootstrapOperations: ['GET https://admin.example/api/.well-known/endpoints/default'],
    experienceOperations: [
      'http.experience-api.get./api/experience/interaction',
      'http.experience-api.post./api/experience/identification',
      'http.experience-api.post./api/experience/submit',
      'http.experience-api.post./api/experience/verification/password',
      'http.experience-api.put./api/experience',
      'http.experience-api.put./api/experience/interaction-event',
    ],
    consoleReadRequests: [
      {
        method: 'GET',
        baseUrl: 'https://admin.example',
        path: '/api/.well-known/endpoints/default',
        query: {},
        authorization: null,
        expectedStatus: 200,
        requiredProjection: { user: 'https://data.example' },
      },
      {
        method: 'GET',
        baseUrl: 'https://data.example',
        baseUrlField: 'routing.userEndpoint',
        origin: 'https://admin.example',
        path: '/api/applications',
        query: { page: '1', page_size: '20', isThirdParty: 'false' },
        headers: { 'Accept-Language': 'en' },
        authorization: {
          issuer: 'https://admin.example/oidc',
          resource: 'https://data.example/api',
          scope: 'all',
        },
        expectedStatus: 200,
        requiredResponseHeaders: ['Total-Number'],
        requiredHeaderValues: { 'Total-Number': '1' },
        requiredBodyLength: 1,
        requiredProjection: [{ id: 'first-party' }],
      },
      {
        method: 'GET',
        baseUrl: 'https://data.example',
        baseUrlField: 'routing.userEndpoint',
        origin: 'https://admin.example',
        path: '/api/applications',
        query: { page: '1', page_size: '20', isThirdParty: 'true' },
        headers: { 'Accept-Language': 'en' },
        authorization: {
          issuer: 'https://admin.example/oidc',
          resource: 'https://data.example/api',
          scope: 'all',
        },
        expectedStatus: 200,
        requiredResponseHeaders: ['Total-Number'],
        requiredHeaderValues: { 'Total-Number': '1' },
        requiredBodyLength: 1,
        requiredProjection: [{ id: 'browser-client' }],
      },
      {
        method: 'GET',
        baseUrl: 'https://data.example',
        baseUrlField: 'routing.userEndpoint',
        origin: 'https://admin.example',
        path: '/api/applications',
        query: { page: '1', page_size: '1', isThirdParty: 'false', types: 'SAML' },
        headers: { 'Accept-Language': 'en' },
        authorization: {
          issuer: 'https://admin.example/oidc',
          resource: 'https://data.example/api',
          scope: 'all',
        },
        expectedStatus: 200,
        requiredResponseHeaders: ['Total-Number'],
        requiredHeaderValues: { 'Total-Number': '0' },
        requiredBodyLength: 0,
        requiredProjection: [],
      },
      {
        method: 'GET',
        baseUrl: 'https://data.example',
        baseUrlField: 'routing.userEndpoint',
        origin: 'https://admin.example',
        path: '/api/users',
        query: { page: '1', page_size: '20' },
        headers: { 'Accept-Language': 'en' },
        authorization: {
          issuer: 'https://admin.example/oidc',
          resource: 'https://data.example/api',
          scope: 'all',
        },
        expectedStatus: 200,
        requiredResponseHeaders: ['Total-Number'],
        requiredHeaderValues: { 'Total-Number': '1' },
        requiredBodyLength: 1,
        requiredProjection: [{ id: 'subject' }],
      },
    ],
    experienceBootstrapRequests: [
      {
        method: 'GET',
        baseUrl: 'https://data.example',
        path: '/api/.well-known/sign-in-exp',
        query: { appId: 'browser-client', uiLocales: 'en' },
        expectedStatus: 200,
        requiredProjection: 'username/password sign-in settings for browser-client',
      },
      {
        method: 'GET',
        baseUrl: 'https://data.example',
        path: '/api/.well-known/phrases',
        query: { lng: 'en' },
        headers: { 'Accept-Language': 'en' },
        expectedStatus: 200,
        requiredProjection: 'English phrase payload used by the pinned Experience tree',
      },
      {
        method: 'GET',
        baseUrl: 'https://admin.example',
        path: '/api/.well-known/sign-in-exp',
        query: { appId: 'console-client', uiLocales: 'en' },
        expectedStatus: 200,
        requiredProjection: 'username/password sign-in settings for console-client',
      },
      {
        method: 'GET',
        baseUrl: 'https://admin.example',
        path: '/api/.well-known/phrases',
        query: { lng: 'en' },
        headers: { 'Accept-Language': 'en' },
        expectedStatus: 200,
        requiredProjection:
          'English admin-tenant phrase payload used by the pinned Experience tree',
      },
    ],
    consoleAccountRequests: [
      {
        method: 'GET',
        url: 'https://admin.example/api/my-account/',
        authorization: {
          issuer: 'https://admin.example/oidc',
          resource: null,
          tokenFormat: 'opaque',
        },
        expectedStatus: 200,
        requiredProjection: { id: 'operator' },
      },
    ],
    cors: {
      origin: 'https://admin.example',
      target: 'https://data.example',
      methods: ['OPTIONS', 'GET'],
      allowedRequestHeaders: ['Authorization', 'Accept-Language', 'Content-Type'],
      allowOriginResponse: 'https://admin.example',
      exposeHeadersResponse: '*',
      browserReadableHeader: 'Total-Number',
      preflightPaths: ['/api/applications', '/api/users'],
      preflightStatus: 204,
    },
    interactionOperations: [
      {
        id: 'phase1.http.interaction.get./api/interaction/consent',
        method: 'GET',
        baseUrl: 'https://data.example',
        path: '/api/interaction/consent',
        authorization: 'active interaction cookies for phase1-browser and phase1-user',
        cookieJarContinuity:
          'same in-memory jar from authorization and password interaction; raw values never enter evidence',
        expectedStatus: 200,
        errorStatuses: [400],
        requiredProjection: {
          application: { id: 'browser-client', name: 'Browser Client' },
          user: {
            id: 'subject',
            username: 'subject-name',
            name: 'Subject',
            primaryEmail: 'subject@example.test',
            primaryPhone: '+15555550100',
          },
          organizations: [],
          missingOIDCScope: ['profile', 'email'],
          missingResourceScopes: [
            {
              resource: {
                id: 'resource-id',
                name: 'Resource',
                indicator: 'https://resource.example',
              },
              scopes: [{ id: 'scope-id', name: 'read:data', description: 'Read data' }],
            },
          ],
          redirectUri: 'https://data.example/callback',
        },
      },
      {
        id: 'phase1.http.interaction.post./api/interaction/consent',
        method: 'POST',
        baseUrl: 'https://data.example',
        path: '/api/interaction/consent',
        authorization: 'the same active interaction cookies returned by the GET operation',
        cookieJarContinuity:
          'reuse the exact GET jar and then the exact resulting jar for the resume request',
        body: {},
        expectedStatus: 200,
        errorStatuses: [400],
        requiredProjection: {
          redirectTo: {
            scheme: 'https',
            origin: 'https://data.example',
            pathTemplate: '/oidc/auth/{one-time-resume-credential}',
            queryKeys: [],
            fragment: '',
          },
        },
        requiredPersistedOutcome: {
          applicationId: 'browser-client',
          userId: 'subject',
          oidcScopes: ['profile', 'email'],
          resource: 'https://resource.example',
          resourceScopes: ['read:data'],
          userFirstConsentedApplicationId: 'browser-client',
          sessionExtension: {
            accountId: 'subject',
            clientId: 'browser-client',
            lastSubmission:
              'exact normalized login submission from the same authorization transaction',
          },
        },
      },
    ],
    consentSessionBoundaryContract: { scenarioId: 'consent-boundary' },
    differentialScenarios: ['consent-boundary'],
  }) as unknown as Phase1Profile;

type OperationMutation = Readonly<{
  name: string;
  pointer: string;
  rule: string;
  mutate: (profile: Phase1Profile) => void;
}>;

const operationMutations: readonly OperationMutation[] = [
  {
    name: 'Management method',
    pointer: '/consoleReadRequests/1/method',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.consoleReadRequests.at(1)) as { method: string }).method = 'POST';
    },
  },
  {
    name: 'Management base',
    pointer: '/consoleReadRequests/1/baseUrl',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.consoleReadRequests.at(1)) as { baseUrl: string }).baseUrl =
        'https://wrong.example';
    },
  },
  {
    name: 'Management issuer',
    pointer: '/consoleReadRequests/1/authorization/issuer',
    rule: 'operation-authorization',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request.authorization as { issuer: string }).issuer = 'https://wrong.example/oidc';
      }
    },
  },
  {
    name: 'cross-origin origin',
    pointer: '/consoleReadRequests/1/origin',
    rule: 'operation-cors',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request as { origin: string }).origin = 'https://wrong.example';
      }
    },
  },
  {
    name: 'CORS preflight path set',
    pointer: '/cors/preflightPaths/1',
    rule: 'cors-preflight-exact-set',
    mutate: (profile) => {
      (profile.cors.preflightPaths as string[])[1] = '/api/missing';
    },
  },
  {
    name: 'Consent POST path',
    pointer: '/interactionOperations/1/path',
    rule: 'consent-operation-pair',
    mutate: (profile) => {
      (required(profile.interactionOperations.at(1)) as { path: string }).path =
        '/api/interaction/missing';
    },
  },
  {
    name: 'Consent cookie continuity',
    pointer: '/interactionOperations/1/cookieJarContinuity',
    rule: 'consent-cookie-continuity',
    mutate: (profile) => {
      (
        required(profile.interactionOperations.at(1)) as { cookieJarContinuity: string }
      ).cookieJarContinuity = 'new unrelated jar';
    },
  },
  {
    name: 'negated Consent cookie continuity prose',
    pointer: '/interactionOperations/1/cookieJarContinuity',
    rule: 'consent-cookie-continuity',
    mutate: (profile) => {
      (
        required(profile.interactionOperations.at(1)) as { cookieJarContinuity: string }
      ).cookieJarContinuity =
        'do not reuse the exact GET jar and then the exact resulting jar for the resume request';
    },
  },
  {
    name: 'Consent boundary scenario',
    pointer: '/consentSessionBoundaryContract/scenarioId',
    rule: 'differential-scenario-reference',
    mutate: (profile) => {
      (profile.consentSessionBoundaryContract as { scenarioId: string }).scenarioId = 'missing';
    },
  },
  {
    name: 'browser SDK scope order',
    pointer: '/fixtures/dataTenant/browserClientConfiguration/effectiveScopes/0',
    rule: 'sdk-derived-order',
    mutate: (profile) => {
      const scopes = profile.fixtures.dataTenant.browserClientConfiguration
        .effectiveScopes as string[];
      const first = required(scopes.at(0));
      const second = required(scopes.at(1));
      [scopes[0], scopes[1]] = [second, first];
    },
  },
  ...[
    { name: 'empty browser SDK raw scope', value: '' },
    { name: 'browser SDK raw scope with double spaces', value: 'profile  email' },
    { name: 'browser SDK raw scope with leading whitespace', value: ' profile email' },
    { name: 'browser SDK raw scope with trailing whitespace', value: 'profile email ' },
    { name: 'browser SDK raw scope with embedded tab', value: 'profile\temail' },
  ].map<OperationMutation>(({ name, value }) => ({
    name,
    pointer: '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/scope',
    rule: 'sdk-scope-token',
    mutate: (profile) => {
      (
        profile.fixtures.dataTenant.browserClientConfiguration.localStorageValue as {
          scope: string;
        }
      ).scope = value;
    },
  })),
  ...[
    { name: 'empty Console SDK scope token', value: '' },
    { name: 'Console SDK scope token with a space', value: 'profile email' },
    { name: 'Console SDK scope token with leading whitespace', value: ' profile' },
    { name: 'Console SDK scope token with trailing whitespace', value: 'profile ' },
    { name: 'Console SDK scope token with a tab', value: 'profile\temail' },
  ].map<OperationMutation>(({ name, value }) => ({
    name,
    pointer: '/consoleAuthentication/configuredScopes/0',
    rule: 'sdk-scope-token',
    mutate: (profile) => {
      (profile.consoleAuthentication.configuredScopes as string[])[0] = value;
    },
  })),
  {
    name: 'Console SDK scope duplicate',
    pointer: '/consoleAuthentication/effectiveScopes/6',
    rule: 'sdk-derived-order',
    mutate: (profile) => {
      (profile.consoleAuthentication.effectiveScopes as string[]).push('profile');
    },
  },
  {
    name: 'Console SDK resource order',
    pointer: '/consoleAuthentication/effectiveResources/0',
    rule: 'sdk-derived-order',
    mutate: (profile) => {
      const resources = profile.consoleAuthentication.effectiveResources as string[];
      const first = required(resources.at(0));
      const second = required(resources.at(1));
      [resources[0], resources[1]] = [second, first];
    },
  },
  {
    name: 'Consent OIDC scope order',
    pointer: '/interactionOperations/0/requiredProjection/missingOIDCScope/1',
    rule: 'consent-scope-ordered-subset',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(0));

      if (operation.method === 'GET') {
        const scopes = operation.requiredProjection.missingOIDCScope as string[];
        const first = required(scopes.at(0));
        const second = required(scopes.at(1));
        [scopes[0], scopes[1]] = [second, first];
      }
    },
  },
  {
    name: 'Consent resource scope',
    pointer: '/interactionOperations/1/requiredPersistedOutcome/resourceScopes/0',
    rule: 'consent-scope-ordered-subset',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation.requiredPersistedOutcome.resourceScopes as string[])[0] = 'missing';
      }
    },
  },
  {
    name: 'Console asset base',
    pointer: '/uiAssetContracts/3/baseUrl',
    rule: 'asset-route',
    mutate: (profile) => {
      (profile.uiAssetContracts[3] as { baseUrl: string }).baseUrl = 'https://wrong.example';
    },
  },
  {
    name: 'Management operation order',
    pointer: '/managementOperations/0',
    rule: 'operation-registry',
    mutate: (profile) => {
      const operations = profile.managementOperations as string[];
      const first = required(operations.at(0));
      const second = required(operations.at(1));
      [operations[0], operations[1]] = [second, first];
    },
  },
  {
    name: 'Account operation closure',
    pointer: '/accountOperations/1',
    rule: 'operation-registry',
    mutate: (profile) => {
      (profile.accountOperations as string[]).push('http.user-api.get./api/missing');
    },
  },
  {
    name: 'Experience operation closure',
    pointer: '/experienceOperations/5',
    rule: 'operation-registry',
    mutate: (profile) => {
      (profile.experienceOperations as string[])[5] =
        'http.experience-api.put./api/experience/missing';
    },
  },
  {
    name: 'Consent operation ID derivation',
    pointer: '/interactionOperations/0/id',
    rule: 'consent-operation-id',
    mutate: (profile) => {
      (required(profile.interactionOperations.at(0)) as { id: string }).id = 'wrong';
    },
  },
  {
    name: 'organization token route',
    pointer: '/consoleOrganizationTokenRequest/url',
    rule: 'organization-token-route',
    mutate: (profile) => {
      (profile.consoleOrganizationTokenRequest as { url: string }).url =
        'https://admin.example/missing';
    },
  },
  {
    name: 'Consent redirect origin',
    pointer: '/interactionOperations/1/requiredProjection/redirectTo/origin',
    rule: 'consent-redirect-route',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation.requiredProjection.redirectTo as { origin: string }).origin =
          'https://wrong.example';
      }
    },
  },
  {
    name: 'missing bootstrap phrases request',
    pointer: '/experienceBootstrapRequests',
    rule: 'bootstrap-request-matrix',
    mutate: (profile) => {
      (profile.experienceBootstrapRequests as unknown as unknown[]).pop();
    },
  },
  {
    name: 'bootstrap request order',
    pointer: '/experienceBootstrapRequests/0/path',
    rule: 'bootstrap-request-matrix',
    mutate: (profile) => {
      const requests = profile.experienceBootstrapRequests as unknown as unknown[];
      const first = required(requests.at(0));
      const second = required(requests.at(1));
      [requests[0], requests[1]] = [second, first];
    },
  },
  {
    name: 'bootstrap app query',
    pointer: '/experienceBootstrapRequests/0/query/appId',
    rule: 'bootstrap-request-matrix',
    mutate: (profile) => {
      const request = required(profile.experienceBootstrapRequests.at(0));
      (request.query as { appId: string }).appId = 'missing';
    },
  },
  {
    name: 'bootstrap locale query',
    pointer: '/experienceBootstrapRequests/0/query/uiLocales',
    rule: 'bootstrap-request-matrix',
    mutate: (profile) => {
      const request = required(profile.experienceBootstrapRequests.at(0));
      (request.query as { uiLocales: string }).uiLocales = 'ja';
    },
  },
  {
    name: 'bootstrap phrase language query',
    pointer: '/experienceBootstrapRequests/1/query/lng',
    rule: 'bootstrap-request-matrix',
    mutate: (profile) => {
      const request = required(profile.experienceBootstrapRequests.at(1));
      (request.query as { lng: string }).lng = 'ja';
    },
  },
  {
    name: 'bootstrap phrase header',
    pointer: '/experienceBootstrapRequests/1/headers/Accept-Language',
    rule: 'bootstrap-request-matrix',
    mutate: (profile) => {
      const request = required(profile.experienceBootstrapRequests.at(1));

      if (request.path === '/api/.well-known/phrases') {
        (request.headers as { 'Accept-Language': string })['Accept-Language'] = 'ja';
      }
    },
  },
  {
    name: 'bootstrap projection',
    pointer: '/experienceBootstrapRequests/2/requiredProjection',
    rule: 'operation-projection',
    mutate: (profile) => {
      (
        required(profile.experienceBootstrapRequests.at(2)) as { requiredProjection: string }
      ).requiredProjection = 'wrong';
    },
  },
  {
    name: 'bootstrap status',
    pointer: '/experienceBootstrapRequests/3/expectedStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (
        required(profile.experienceBootstrapRequests.at(3)) as { expectedStatus: number }
      ).expectedStatus = 201;
    },
  },
  {
    name: 'CORS method order',
    pointer: '/cors/methods/0',
    rule: 'operation-cors',
    mutate: (profile) => {
      const methods = profile.cors.methods as string[];
      [methods[0], methods[1]] = ['GET', 'OPTIONS'];
    },
  },
  {
    name: 'CORS allowed header order',
    pointer: '/cors/allowedRequestHeaders/0',
    rule: 'operation-cors',
    mutate: (profile) => {
      const headers = profile.cors.allowedRequestHeaders as string[];
      [headers[0], headers[1]] = ['Accept-Language', 'Authorization'];
    },
  },
  {
    name: 'CORS allow-origin response',
    pointer: '/cors/allowOriginResponse',
    rule: 'operation-cors',
    mutate: (profile) => {
      (profile.cors as { allowOriginResponse: string }).allowOriginResponse = '*';
    },
  },
  {
    name: 'CORS exposed headers',
    pointer: '/cors/exposeHeadersResponse',
    rule: 'operation-cors',
    mutate: (profile) => {
      (profile.cors as { exposeHeadersResponse: string }).exposeHeadersResponse = 'Total-Number';
    },
  },
  {
    name: 'CORS browser-readable header',
    pointer: '/cors/browserReadableHeader',
    rule: 'operation-cors',
    mutate: (profile) => {
      (profile.cors as { browserReadableHeader: string }).browserReadableHeader = 'Missing';
    },
  },
  {
    name: 'CORS preflight status',
    pointer: '/cors/preflightStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (profile.cors as { preflightStatus: number }).preflightStatus = 200;
    },
  },
  {
    name: 'Console endpoint status',
    pointer: '/consoleReadRequests/0/expectedStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (required(profile.consoleReadRequests.at(0)) as { expectedStatus: number }).expectedStatus =
        201;
    },
  },
  {
    name: 'Management status',
    pointer: '/consoleReadRequests/1/expectedStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (required(profile.consoleReadRequests.at(1)) as { expectedStatus: number }).expectedStatus =
        201;
    },
  },
  {
    name: 'Account status',
    pointer: '/consoleAccountRequests/0/expectedStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (
        required(profile.consoleAccountRequests.at(0)) as { expectedStatus: number }
      ).expectedStatus = 201;
    },
  },
  {
    name: 'Consent GET error status',
    pointer: '/interactionOperations/0/errorStatuses/0',
    rule: 'operation-status',
    mutate: (profile) => {
      (required(profile.interactionOperations.at(0)).errorStatuses as number[])[0] = 401;
    },
  },
  {
    name: 'Consent POST status',
    pointer: '/interactionOperations/1/expectedStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (required(profile.interactionOperations.at(1)) as { expectedStatus: number }).expectedStatus =
        201;
    },
  },
  ...(
    [
      ['trigger', 'organization-token-route', 'wrong'],
      ['method', 'organization-token-route', 'GET'],
      ['contentType', 'organization-token-route', 'application/json'],
      ['requiredPersistedOutcome', 'operation-projection', 'wrong'],
    ] as const
  ).map(([field, rule, value]) => ({
    name: `organization token ${field}`,
    pointer: `/consoleOrganizationTokenRequest/${field}`,
    rule,
    mutate: (profile: Phase1Profile) => {
      (profile.consoleOrganizationTokenRequest as unknown as Record<string, unknown>)[field] =
        value;
    },
  })),
  ...(
    [
      ['client_id', 'organization-token-fixture', 'missing'],
      ['grant_type', 'organization-token-route', 'client_credentials'],
      ['refresh_token', 'organization-token-credential-placeholder', 'raw-secret-shaped-value'],
      ['organization_id', 'organization-token-fixture', 'missing'],
      ['resource', 'organization-token-route', 'https://resource.example'],
      ['scope', 'organization-token-route', 'all'],
    ] as const
  ).map(([field, rule, value]) => ({
    name: `organization token form ${field}`,
    pointer: `/consoleOrganizationTokenRequest/form/${field}`,
    rule,
    mutate: (profile: Phase1Profile) => {
      (profile.consoleOrganizationTokenRequest.form as unknown as Record<string, unknown>)[field] =
        value;
    },
  })),
  ...(
    [
      ['token_type', 'NotBearer'],
      ['scope', 'all'],
    ] as const
  ).map(([field, value]) => ({
    name: `organization token response ${field}`,
    pointer: `/consoleOrganizationTokenRequest/requiredTokenResponseProjection/${field}`,
    rule: 'operation-projection',
    mutate: (profile: Phase1Profile) => {
      (
        profile.consoleOrganizationTokenRequest
          .requiredTokenResponseProjection as unknown as Record<string, unknown>
      )[field] = value;
    },
  })),
  ...(
    [
      ['format', 'opaque'],
      ['iss', 'https://wrong.example/oidc'],
      ['sub', 'missing'],
      ['aud', 'urn:logto:organization:missing'],
      ['client_id', 'missing'],
      ['scope', 'all'],
    ] as const
  ).map(([field, value]) => ({
    name: `organization access projection ${field}`,
    pointer: `/consoleOrganizationTokenRequest/requiredAccessTokenProjection/${field}`,
    rule: 'operation-projection',
    mutate: (profile: Phase1Profile) => {
      (
        profile.consoleOrganizationTokenRequest.requiredAccessTokenProjection as unknown as Record<
          string,
          unknown
        >
      )[field] = value;
    },
  })),
  {
    name: 'organization token omission set',
    pointer: '/consoleOrganizationTokenRequest/requiredAccessTokenOmissions/0',
    rule: 'operation-projection',
    mutate: (profile) => {
      (profile.consoleOrganizationTokenRequest.requiredAccessTokenOmissions as string[])[0] =
        'missing';
    },
  },
  {
    name: 'organization token status',
    pointer: '/consoleOrganizationTokenRequest/expectedStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (profile.consoleOrganizationTokenRequest as { expectedStatus: number }).expectedStatus = 201;
    },
  },
  {
    name: 'Consent POST nonempty body',
    pointer: '/interactionOperations/1/body',
    rule: 'consent-body',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation as unknown as { body: Record<string, unknown> }).body = { unexpected: true };
      }
    },
  },
  {
    name: 'bootstrap method',
    pointer: '/experienceBootstrapRequests/0/method',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.experienceBootstrapRequests.at(0)) as { method: string }).method = 'POST';
    },
  },
  {
    name: 'bootstrap admin base',
    pointer: '/experienceBootstrapRequests/2/baseUrl',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.experienceBootstrapRequests.at(2)) as { baseUrl: string }).baseUrl =
        'https://data.example';
    },
  },
  {
    name: 'CORS origin',
    pointer: '/cors/origin',
    rule: 'operation-cors',
    mutate: (profile) => {
      (profile.cors as { origin: string }).origin = 'https://wrong.example';
    },
  },
  {
    name: 'CORS target',
    pointer: '/cors/target',
    rule: 'operation-cors',
    mutate: (profile) => {
      (profile.cors as { target: string }).target = 'https://wrong.example';
    },
  },
  {
    name: 'missing Console request',
    pointer: '/consoleReadRequests',
    rule: 'console-request-matrix',
    mutate: (profile) => {
      (profile.consoleReadRequests as unknown as unknown[]).pop();
    },
  },
  ...(
    [
      ['page', '2'],
      ['page_size', '10'],
      ['isThirdParty', 'true'],
    ] as const
  ).map(([field, value]) => ({
    name: `Management query ${field}`,
    pointer: `/consoleReadRequests/1/query/${field}`,
    rule: 'console-request-matrix',
    mutate: (profile: Phase1Profile) => {
      const request = required(profile.consoleReadRequests.at(1));
      (request.query as unknown as Record<string, unknown>)[field] = value;
    },
  })),
  {
    name: 'SAML query type',
    pointer: '/consoleReadRequests/3/query/types',
    rule: 'console-request-matrix',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(3));
      (request.query as { types: string }).types = 'OIDC';
    },
  },
  {
    name: 'user query page size',
    pointer: '/consoleReadRequests/4/query/page_size',
    rule: 'console-request-matrix',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(4));
      (request.query as { page_size: string }).page_size = '1';
    },
  },
  {
    name: 'Management language header',
    pointer: '/consoleReadRequests/1/headers/Accept-Language',
    rule: 'operation-header',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request.headers as { 'Accept-Language': string })['Accept-Language'] = 'ja';
      }
    },
  },
  {
    name: 'Management authorization resource',
    pointer: '/consoleReadRequests/1/authorization/resource',
    rule: 'operation-authorization',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request.authorization as { resource: string }).resource = 'https://wrong.example/api';
      }
    },
  },
  {
    name: 'Management authorization scope',
    pointer: '/consoleReadRequests/1/authorization/scope',
    rule: 'operation-authorization',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request.authorization as { scope: string }).scope = 'missing';
      }
    },
  },
  {
    name: 'Management response header set',
    pointer: '/consoleReadRequests/1/requiredResponseHeaders/0',
    rule: 'operation-header',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request.requiredResponseHeaders as string[])[0] = 'Missing';
      }
    },
  },
  {
    name: 'Management Total-Number value',
    pointer: '/consoleReadRequests/1/requiredHeaderValues/Total-Number',
    rule: 'operation-header',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request.requiredHeaderValues as { 'Total-Number': string })['Total-Number'] = '2';
      }
    },
  },
  {
    name: 'Management body length',
    pointer: '/consoleReadRequests/1/requiredBodyLength',
    rule: 'operation-projection',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request as { requiredBodyLength: number }).requiredBodyLength = 2;
      }
    },
  },
  {
    name: 'Account method',
    pointer: '/consoleAccountRequests/0/method',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.consoleAccountRequests.at(0)) as { method: string }).method = 'POST';
    },
  },
  {
    name: 'Account URL',
    pointer: '/consoleAccountRequests/0/url',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.consoleAccountRequests.at(0)) as { url: string }).url =
        'https://admin.example/missing';
    },
  },
  {
    name: 'Account token format',
    pointer: '/consoleAccountRequests/0/authorization/tokenFormat',
    rule: 'operation-authorization',
    mutate: (profile) => {
      const request = required(profile.consoleAccountRequests.at(0));
      (request.authorization as { tokenFormat: string }).tokenFormat = 'JWT';
    },
  },
  {
    name: 'Consent GET status',
    pointer: '/interactionOperations/0/expectedStatus',
    rule: 'operation-status',
    mutate: (profile) => {
      (required(profile.interactionOperations.at(0)) as { expectedStatus: number }).expectedStatus =
        201;
    },
  },
  {
    name: 'Consent POST error status',
    pointer: '/interactionOperations/1/errorStatuses/0',
    rule: 'operation-status',
    mutate: (profile) => {
      (required(profile.interactionOperations.at(1)).errorStatuses as number[])[0] = 401;
    },
  },
  {
    name: 'Console endpoint authorization',
    pointer: '/consoleReadRequests/0/authorization',
    rule: 'operation-authorization',
    mutate: (profile) => {
      (
        required(profile.consoleReadRequests.at(0)) as unknown as { authorization: unknown }
      ).authorization = { token: 'unexpected' };
    },
  },
  {
    name: 'Console endpoint projection',
    pointer: '/consoleReadRequests/0/requiredProjection/user',
    rule: 'operation-projection',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(0));

      if (request.path === '/api/.well-known/endpoints/default') {
        (request.requiredProjection as { user: string }).user = 'https://wrong.example';
      }
    },
  },
  {
    name: 'Management path',
    pointer: '/consoleReadRequests/1/path',
    rule: 'console-request-matrix',
    mutate: (profile) => {
      (required(profile.consoleReadRequests.at(1)) as { path: string }).path = '/api/missing';
    },
  },
  {
    name: 'Management base field',
    pointer: '/consoleReadRequests/1/baseUrlField',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.consoleReadRequests.at(1)) as { baseUrlField: string }).baseUrlField =
        'routing.adminEndpoint';
    },
  },
  {
    name: 'Consent GET base',
    pointer: '/interactionOperations/0/baseUrl',
    rule: 'operation-route',
    mutate: (profile) => {
      (required(profile.interactionOperations.at(0)) as { baseUrl: string }).baseUrl =
        'https://wrong.example';
    },
  },
  ...(
    [
      ['scheme', 'http'],
      ['pathTemplate', '/oidc/wrong/{one-time-resume-credential}'],
      ['fragment', 'fragment'],
    ] as const
  ).map(([field, value]) => ({
    name: `Consent redirect ${field}`,
    pointer: `/interactionOperations/1/requiredProjection/redirectTo/${field}`,
    rule: 'consent-redirect-route',
    mutate: (profile: Phase1Profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation.requiredProjection.redirectTo as unknown as Record<string, unknown>)[field] =
          value;
      }
    },
  })),
  {
    name: 'Consent redirect query keys',
    pointer: '/interactionOperations/1/requiredProjection/redirectTo/queryKeys/0',
    rule: 'consent-redirect-route',
    mutate: (profile) => {
      const operation = required(profile.interactionOperations.at(1));

      if (operation.method === 'POST') {
        (operation.requiredProjection.redirectTo.queryKeys as string[]).push('unexpected');
      }
    },
  },
  {
    name: 'empty first-party projection',
    pointer: '/consoleReadRequests/1/requiredProjection/0/id',
    rule: 'console-projection-matrix',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(1));

      if (request.path === '/api/applications') {
        (request.requiredProjection as unknown as unknown[]).pop();
      }
    },
  },
  {
    name: 'wrong third-party projection',
    pointer: '/consoleReadRequests/2/requiredProjection/0/id',
    rule: 'console-projection-matrix',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(2));

      if (request.path === '/api/applications') {
        (required(request.requiredProjection.at(0)) as { id: string }).id = 'first-party';
      }
    },
  },
  {
    name: 'extra SAML projection',
    pointer: '/consoleReadRequests/3/requiredProjection/0/id',
    rule: 'console-projection-matrix',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(3));

      if (request.path === '/api/applications') {
        (request.requiredProjection as unknown as Array<{ id: string }>).push({
          id: 'first-party',
        });
      }
    },
  },
  {
    name: 'wrong user projection',
    pointer: '/consoleReadRequests/4/requiredProjection/0/id',
    rule: 'console-projection-matrix',
    mutate: (profile) => {
      const request = required(profile.consoleReadRequests.at(4));

      if (request.path === '/api/users') {
        (required(request.requiredProjection.at(0)) as { id: string }).id = 'missing';
      }
    },
  },
  {
    name: 'Consent route changed consistently with derived IDs',
    pointer: '/interactionOperations/0/path',
    rule: 'operation-route',
    mutate: (profile) => {
      for (const operation of profile.interactionOperations) {
        (operation as { path: string; id: string }).path = '/api/interaction/other';
        (operation as { path: string; id: string }).id =
          `phase1.http.interaction.${operation.method.toLowerCase()}./api/interaction/other`;
      }
    },
  },
  {
    name: 'organization token extra raw client secret field',
    pointer: '/consoleOrganizationTokenRequest/form',
    rule: 'organization-token-form',
    mutate: (profile) => {
      const form = profile.consoleOrganizationTokenRequest.form as unknown as Record<
        string,
        unknown
      >;
      form.client_secret = 'raw-secret-shaped-value';
    },
  },
];

describe('Phase 1 route operation CORS and SDK semantics', () => {
  it('accepts a compact internally resolved operation inventory', () => {
    expect(() => assertOperationSemantics(operationProfile())).not.toThrow();
  });

  it.each(operationMutations)('rejects a mutated $name at the exact pointer', (mutation) => {
    const profile = operationProfile();
    mutation.mutate(profile);
    expectSemanticFailure(profile, mutation.pointer, mutation.rule);
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression */
