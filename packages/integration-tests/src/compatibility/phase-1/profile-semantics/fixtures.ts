/* eslint-disable max-lines, no-restricted-syntax, unicorn/no-array-for-each, prefer-destructuring -- Fixture referential integrity is one closed graph walk with static diagnostics. */
import type { Phase1Application, Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

const fail = (pointer: string): never => {
  throw new Phase1ProfileValidationError('semantic', [pointer], ['fixture-reference']);
};

const requireValue = <Value>(value: Value, pointer: string): NonNullable<Value> =>
  value === undefined || value === null ? fail(pointer) : (value as NonNullable<Value>);

const assertEqual = (actual: unknown, expected: unknown, pointer: string): void => {
  if (actual !== expected) {
    fail(pointer);
  }
};

const assertMembers = (
  values: readonly string[],
  allowed: ReadonlySet<string>,
  pointer: string
): void => {
  values.forEach((value, index) => {
    if (!allowed.has(value)) {
      fail(`${pointer}/${index}`);
    }
  });
};

const assertExactStrings = (
  actual: readonly string[],
  expected: readonly string[],
  pointer: string
): void => {
  const firstDifference = Array.from(
    { length: Math.max(actual.length, expected.length) },
    (_, index) => index
  ).find((index) => actual[index] !== expected[index]);

  if (firstDifference !== undefined) {
    fail(`${pointer}/${firstDifference}`);
  }
};

const expectedUiTreeFields = {
  'experience-user': 'experienceTree',
  'experience-admin': 'experienceTree',
  'demo-app': 'demoAppTree',
  console: 'consoleTree',
} as const;

const assertUiAssetReferences = (profile: Phase1Profile): void => {
  profile.uiAssetContracts.forEach((asset, index) => {
    const pointer = `/uiAssetContracts/${index}`;
    const expectedTree = expectedUiTreeFields[asset.application];

    if (asset.sourceTreeField !== expectedTree || profile.uiSource[expectedTree].length === 0) {
      fail(`${pointer}/sourceTreeField`);
    }

    if ('tenant' in asset) {
      const expectedTenant =
        asset.application === 'experience-user'
          ? profile.fixtures.dataTenant.id
          : profile.fixtures.adminTenant.id;
      assertEqual(asset.tenant, expectedTenant, `${pointer}/tenant`);
    }
  });
};

const assertFixtureGraph = (profile: Phase1Profile): void => {
  const { adminTenant, dataTenant } = profile.fixtures;
  const memberIds = new Set([adminTenant.operator.id]);
  const organizationScopeNames = new Set(adminTenant.tenantOrganization.scopes);
  const dataUserIds = new Set([dataTenant.subject.id]);
  const resourceScopeIds = new Set(dataTenant.resource.scopes.map(({ id }) => id));

  assertMembers(
    adminTenant.tenantOrganization.memberUserIds,
    memberIds,
    '/fixtures/adminTenant/tenantOrganization/memberUserIds'
  );

  adminTenant.tenantOrganization.organizationRoles.forEach((role, index) => {
    assertMembers(
      role.scopeNames,
      organizationScopeNames,
      `/fixtures/adminTenant/tenantOrganization/organizationRoles/${index}/scopeNames`
    );
    assertMembers(
      role.userIds,
      memberIds,
      `/fixtures/adminTenant/tenantOrganization/organizationRoles/${index}/userIds`
    );
  });

  assertMembers(
    dataTenant.resourceScopeRole.scopeIds,
    resourceScopeIds,
    '/fixtures/dataTenant/resourceScopeRole/scopeIds'
  );
  assertMembers(
    dataTenant.resourceScopeRole.userIds,
    dataUserIds,
    '/fixtures/dataTenant/resourceScopeRole/userIds'
  );

  dataTenant.applications.forEach((application, index) => {
    if (application.isThirdParty) {
      assertMembers(
        application.resourceConsentScopes,
        resourceScopeIds,
        `/fixtures/dataTenant/applications/${index}/resourceConsentScopes`
      );
    }
  });
};

const assertBrowserConfiguration = (profile: Phase1Profile): void => {
  const { dataTenant } = profile.fixtures;
  const { localStorageValue } = dataTenant.browserClientConfiguration;
  const client = requireValue(
    dataTenant.applications.find(
      (application): application is Extract<Phase1Application, Readonly<{ isThirdParty: true }>> =>
        application.id === localStorageValue.appId && application.isThirdParty
    ),
    '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/appId'
  );

  assertEqual(
    localStorageValue.resource,
    dataTenant.resource.indicator,
    '/fixtures/dataTenant/browserClientConfiguration/localStorageValue/resource'
  );
  const allowedScopes = new Set([
    ...client.userConsentScopes,
    ...dataTenant.resource.scopes.map(({ name }) => name),
  ]);
  const configuredScopes = localStorageValue.scope.split(' ').filter(Boolean);

  if (configuredScopes.some((scope) => !allowedScopes.has(scope))) {
    fail('/fixtures/dataTenant/browserClientConfiguration/localStorageValue/scope');
  }
};

const assertConsoleReferences = (profile: Phase1Profile): void => {
  const { adminTenant, dataTenant } = profile.fixtures;
  const authentication = profile.consoleAuthentication;
  assertEqual(
    authentication.endpoint,
    profile.routing.adminEndpoint,
    '/consoleAuthentication/endpoint'
  );
  assertEqual(
    authentication.issuer,
    `${profile.routing.adminEndpoint}/oidc`,
    '/consoleAuthentication/issuer'
  );
  assertEqual(
    authentication.managementDataTenant,
    dataTenant.id,
    '/consoleAuthentication/managementDataTenant'
  );
  assertEqual(
    authentication.applicationId,
    adminTenant.application.id,
    '/consoleAuthentication/applicationId'
  );

  if (
    !adminTenant.application.oidcClientMetadata.redirectUris.includes(authentication.redirectUri)
  ) {
    fail('/consoleAuthentication/redirectUri');
  }

  const resourceIndicators = new Set(adminTenant.resources.map(({ indicator }) => indicator));
  assertMembers(
    authentication.configuredResources,
    resourceIndicators,
    '/consoleAuthentication/configuredResources'
  );

  const request = profile.consoleOrganizationTokenRequest;
  assertEqual(
    request.form.client_id,
    adminTenant.application.id,
    '/consoleOrganizationTokenRequest/form/client_id'
  );
  assertEqual(
    request.form.organization_id,
    adminTenant.tenantOrganization.id,
    '/consoleOrganizationTokenRequest/form/organization_id'
  );
  assertEqual(
    request.requiredAccessTokenProjection.iss,
    authentication.issuer,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/iss'
  );
  assertEqual(
    request.requiredAccessTokenProjection.sub,
    adminTenant.operator.id,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/sub'
  );
  assertEqual(
    request.requiredAccessTokenProjection.aud,
    `urn:logto:organization:${adminTenant.tenantOrganization.id}`,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/aud'
  );
  assertEqual(
    request.requiredAccessTokenProjection.client_id,
    adminTenant.application.id,
    '/consoleOrganizationTokenRequest/requiredAccessTokenProjection/client_id'
  );
};

const assertConsoleResponseProjections = (profile: Phase1Profile): void => {
  const { adminTenant, dataTenant } = profile.fixtures;

  profile.consoleReadRequests.forEach((request, requestIndex) => {
    if (request.path === '/api/applications') {
      request.requiredProjection.forEach((projection, projectionIndex) => {
        const pointer = `/consoleReadRequests/${requestIndex}/requiredProjection/${projectionIndex}`;
        const fixture = requireValue(
          dataTenant.applications.find(({ id }) => id === projection.id),
          `${pointer}/id`
        );

        assertEqual(projection.name, fixture.name, `${pointer}/name`);
        assertEqual(projection.type, fixture.type, `${pointer}/type`);
        assertEqual(projection.isThirdParty, fixture.isThirdParty, `${pointer}/isThirdParty`);

        if (
          Object.keys(projection.customClientMetadata).length > 0 ||
          Object.keys(fixture.customClientMetadata).length > 0
        ) {
          fail(`${pointer}/customClientMetadata`);
        }
      });
    }

    if (request.path === '/api/users') {
      request.requiredProjection.forEach((projection, projectionIndex) => {
        const pointer = `/consoleReadRequests/${requestIndex}/requiredProjection/${projectionIndex}`;
        const subject = dataTenant.subject;
        assertEqual(projection.id, subject.id, `${pointer}/id`);
        assertEqual(projection.username, subject.username, `${pointer}/username`);
        assertEqual(projection.name, subject.name, `${pointer}/name`);
        assertEqual(projection.primaryEmail, subject.primaryEmail, `${pointer}/primaryEmail`);
        assertEqual(projection.primaryPhone, subject.primaryPhone, `${pointer}/primaryPhone`);
        assertEqual(projection.applicationId, subject.applicationId, `${pointer}/applicationId`);
        assertEqual(projection.avatar, null, `${pointer}/avatar`);
        assertEqual(projection.lastSignInAt, null, `${pointer}/lastSignInAt`);
        assertEqual(projection.isSuspended, false, `${pointer}/isSuspended`);
        assertEqual(projection.hasPassword, true, `${pointer}/hasPassword`);
      });
    }
  });

  profile.consoleAccountRequests.forEach((request, index) => {
    const pointer = `/consoleAccountRequests/${index}/requiredProjection`;
    assertEqual(request.requiredProjection.id, adminTenant.operator.id, `${pointer}/id`);
    assertEqual(
      request.requiredProjection.username,
      adminTenant.operator.username,
      `${pointer}/username`
    );
    assertEqual(
      request.requiredProjection.primaryEmail,
      adminTenant.operator.primaryEmail,
      `${pointer}/primaryEmail`
    );
  });
};

const assertConsentReferences = (profile: Phase1Profile): void => {
  const { dataTenant } = profile.fixtures;
  const client = requireValue(
    dataTenant.applications.find(
      (application): application is Extract<Phase1Application, Readonly<{ isThirdParty: true }>> =>
        application.isThirdParty &&
        application.id === dataTenant.browserClientConfiguration.localStorageValue.appId
    ),
    '/fixtures/dataTenant/applications'
  );

  const scopeById = new Map(dataTenant.resource.scopes.map((scope) => [scope.id, scope]));

  profile.interactionOperations.forEach((operation, operationIndex) => {
    const pointer = `/interactionOperations/${operationIndex}`;

    if (operation.method === 'GET') {
      const { requiredProjection } = operation;
      assertEqual(
        requiredProjection.application.id,
        client.id,
        `${pointer}/requiredProjection/application/id`
      );
      assertEqual(
        requiredProjection.application.name,
        client.name,
        `${pointer}/requiredProjection/application/name`
      );
      const subjectFields = ['id', 'username', 'name', 'primaryEmail', 'primaryPhone'] as const;
      subjectFields.forEach((field) => {
        assertEqual(
          requiredProjection.user[field],
          dataTenant.subject[field],
          `${pointer}/requiredProjection/user/${field}`
        );
      });
      assertExactStrings(
        requiredProjection.organizations,
        [],
        `${pointer}/requiredProjection/organizations`
      );
      assertExactStrings(
        requiredProjection.missingOIDCScope,
        client.userConsentScopes,
        `${pointer}/requiredProjection/missingOIDCScope`
      );
      if (requiredProjection.missingResourceScopes.length !== 1) {
        fail(`${pointer}/requiredProjection/missingResourceScopes`);
      }

      const expectedResourceScopeIds = client.resourceConsentScopes;
      requiredProjection.missingResourceScopes.forEach((missing, missingIndex) => {
        const missingPointer = `${pointer}/requiredProjection/missingResourceScopes/${missingIndex}`;
        assertEqual(missing.resource.id, dataTenant.resource.id, `${missingPointer}/resource/id`);
        assertEqual(
          missing.resource.name,
          dataTenant.resource.name,
          `${missingPointer}/resource/name`
        );
        assertEqual(
          missing.resource.indicator,
          dataTenant.resource.indicator,
          `${missingPointer}/resource/indicator`
        );
        if (missing.scopes.length !== expectedResourceScopeIds.length) {
          fail(`${missingPointer}/scopes`);
        }

        missing.scopes.forEach((scope, scopeIndex) => {
          if (scope.id !== expectedResourceScopeIds[scopeIndex]) {
            fail(`${missingPointer}/scopes/${scopeIndex}/id`);
          }
        });
        missing.scopes.forEach((scope, scopeIndex) => {
          const scopePointer = `${missingPointer}/scopes/${scopeIndex}`;
          const fixtureScope = requireValue(scopeById.get(scope.id), `${scopePointer}/id`);

          assertEqual(scope.name, fixtureScope.name, `${scopePointer}/name`);
          assertEqual(scope.description, fixtureScope.description, `${scopePointer}/description`);
        });
      });

      if (!client.oidcClientMetadata.redirectUris.includes(requiredProjection.redirectUri)) {
        fail(`${pointer}/requiredProjection/redirectUri`);
      }
    } else {
      const outcome = operation.requiredPersistedOutcome;
      assertEqual(
        outcome.applicationId,
        client.id,
        `${pointer}/requiredPersistedOutcome/applicationId`
      );
      assertEqual(
        outcome.userId,
        dataTenant.subject.id,
        `${pointer}/requiredPersistedOutcome/userId`
      );
      assertExactStrings(
        outcome.oidcScopes,
        client.userConsentScopes,
        `${pointer}/requiredPersistedOutcome/oidcScopes`
      );
      assertEqual(
        outcome.resource,
        dataTenant.resource.indicator,
        `${pointer}/requiredPersistedOutcome/resource`
      );
      const expectedResourceScopeNames = client.resourceConsentScopes
        .map((scopeId) =>
          requireValue(scopeById.get(scopeId), `${pointer}/requiredPersistedOutcome/resourceScopes`)
        )
        .map(({ name }) => name);
      assertExactStrings(
        outcome.resourceScopes,
        expectedResourceScopeNames,
        `${pointer}/requiredPersistedOutcome/resourceScopes`
      );
      assertEqual(
        outcome.userFirstConsentedApplicationId,
        client.id,
        `${pointer}/requiredPersistedOutcome/userFirstConsentedApplicationId`
      );
      assertEqual(
        outcome.sessionExtension.accountId,
        dataTenant.subject.id,
        `${pointer}/requiredPersistedOutcome/sessionExtension/accountId`
      );
      assertEqual(
        outcome.sessionExtension.clientId,
        client.id,
        `${pointer}/requiredPersistedOutcome/sessionExtension/clientId`
      );
      assertEqual(
        outcome.sessionExtension.lastSubmission,
        'exact normalized login submission from the same authorization transaction',
        `${pointer}/requiredPersistedOutcome/sessionExtension/lastSubmission`
      );
    }
  });
};

export const assertFixtureSemantics = (profile: Phase1Profile): void => {
  assertUiAssetReferences(profile);
  assertFixtureGraph(profile);
  assertBrowserConfiguration(profile);
  assertConsoleReferences(profile);
  assertConsoleResponseProjections(profile);
  assertConsentReferences(profile);
};

/* eslint-enable max-lines, no-restricted-syntax, unicorn/no-array-for-each, prefer-destructuring */
