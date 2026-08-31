/* eslint-disable no-restricted-syntax, unicorn/no-array-for-each, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition -- The validator preserves profile order while deriving one closed conformance projection. */
import type { Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

export type Phase1ConformanceExecution = Readonly<{
  checkedOutSuiteCommit: string;
}>;

const fail = (pointer: string, rule: string): never => {
  throw new Phase1ProfileValidationError('semantic', [pointer], [rule]);
};

const requireValue = <Value>(value: Value, pointer: string, rule: string): NonNullable<Value> =>
  value === undefined || value === null ? fail(pointer, rule) : (value as NonNullable<Value>);

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

const assertDerivedUrls = (profile: Phase1Profile): void => {
  const { target } = profile.conformance;
  const expectedDiscovery = `${target.issuer}/.well-known/openid-configuration`;

  if (target.discoveryUrl !== expectedDiscovery) {
    fail('/conformance/target/discoveryUrl', 'conformance-derived-url');
  }

  const expectedCallback = `${target.suiteBaseUrl}/test/a/${target.alias}/callback`;

  if (target.callbackUri !== expectedCallback) {
    fail('/conformance/target/callbackUri', 'conformance-derived-url');
  }
};

const assertClientAndPlanMethods = (profile: Phase1Profile): void => {
  const supportedMethods = new Set(profile.oidc.tokenEndpointAuthMethods);
  const staticMethodOrder: string[] = [];

  profile.conformance.staticClients.forEach((client, index) => {
    if (!supportedMethods.has(client.tokenEndpointAuthMethod)) {
      fail(
        `/conformance/staticClients/${index}/tokenEndpointAuthMethod`,
        'conformance-client-method'
      );
    }

    if (!staticMethodOrder.includes(client.tokenEndpointAuthMethod)) {
      staticMethodOrder.push(client.tokenEndpointAuthMethod);
    }

    client.redirectUris.forEach((redirectUri, redirectIndex) => {
      if (redirectUri !== profile.conformance.target.callbackUri) {
        fail(
          `/conformance/staticClients/${index}/redirectUris/${redirectIndex}`,
          'conformance-client-redirect'
        );
      }
    });
  });

  const basicPlanIndex = profile.conformance.plans.findIndex(
    ({ testPlanName }) => testPlanName === 'oidcc-basic-certification-test-plan'
  );

  if (basicPlanIndex === -1) {
    fail('/conformance/plans', 'conformance-basic-plan');
  }

  const basicPlan = requireValue(
    profile.conformance.plans.at(basicPlanIndex),
    '/conformance/plans',
    'conformance-basic-plan'
  );

  if (basicPlan.testPlanName !== 'oidcc-basic-certification-test-plan') {
    fail('/conformance/plans', 'conformance-basic-plan');
  }
  const { variants } = basicPlan;

  const clientAuthTypes =
    'clientAuthTypes' in variants
      ? variants.clientAuthTypes
      : fail('/conformance/plans', 'conformance-basic-plan');

  assertExactOrder(
    clientAuthTypes,
    staticMethodOrder,
    `/conformance/plans/${basicPlanIndex}/variants/clientAuthTypes`,
    'conformance-plan-client-methods'
  );
  assertExactOrder(
    profile.oidc.tokenEndpointAuthMethods,
    [...staticMethodOrder, 'none'],
    '/oidc/tokenEndpointAuthMethods',
    'conformance-client-method'
  );
};

const assertProtocolSelections = (profile: Phase1Profile): void => {
  profile.consoleAuthentication.grants.forEach((grant, index) => {
    if (!profile.oidc.grants.includes(grant)) {
      fail(`/consoleAuthentication/grants/${index}`, 'conformance-grant');
    }
  });
  assertExactOrder(
    profile.oidc.grants,
    profile.consoleAuthentication.grants,
    '/oidc/grants',
    'conformance-grant'
  );

  if (!profile.oidc.tokenEndpointAuthMethods.includes('none')) {
    fail('/oidc/tokenEndpointAuthMethods', 'conformance-client-method');
  }

  const selectedResponseTypes: string[] = [];
  const selectedResponseModes: string[] = [];

  profile.conformance.plans.forEach((plan, index) => {
    const pointer = `/conformance/plans/${index}/variants`;

    if (plan.variants.clientRegistration !== 'static_client') {
      fail(`${pointer}/clientRegistration`, 'conformance-client-registration');
    }

    if (plan.variants.serverMetadata !== 'discovery') {
      fail(`${pointer}/serverMetadata`, 'conformance-server-metadata');
    }

    if (plan.testPlanName === 'oidcc-basic-certification-test-plan') {
      if (!profile.oidc.responseTypes.includes(plan.variants.responseType)) {
        fail(`${pointer}/responseType`, 'conformance-response-type');
      }

      if (!selectedResponseTypes.includes(plan.variants.responseType)) {
        selectedResponseTypes.push(plan.variants.responseType);
      }

      const resolvedResponseMode =
        plan.variants.responseMode === 'default' ? 'query' : plan.variants.responseMode;

      if (!profile.oidc.responseModes.includes(resolvedResponseMode)) {
        fail(`${pointer}/responseMode`, 'conformance-response-mode');
      }

      if (!selectedResponseModes.includes(resolvedResponseMode)) {
        selectedResponseModes.push(resolvedResponseMode);
      }
    }
  });
  assertExactOrder(
    profile.oidc.responseTypes,
    selectedResponseTypes,
    '/oidc/responseTypes',
    'conformance-response-type'
  );
  assertExactOrder(
    profile.oidc.responseModes,
    selectedResponseModes,
    '/oidc/responseModes',
    'conformance-response-mode'
  );
};

const assertSigningMetadata = (profile: Phase1Profile): void => {
  const { jwksKeyMetadata, idTokenSigningAlgorithmsSupported } = profile.oidc;

  if (!idTokenSigningAlgorithmsSupported.includes(jwksKeyMetadata.alg)) {
    fail('/oidc/jwksKeyMetadata/alg', 'conformance-signing-metadata');
  }
  assertExactOrder(
    idTokenSigningAlgorithmsSupported,
    [jwksKeyMetadata.alg],
    '/oidc/idTokenSigningAlgorithmsSupported',
    'conformance-signing-metadata'
  );

  const expectedKeyMetadata = {
    ES384: { kty: 'EC', crv: 'P-384' },
  } as const;
  const expected = expectedKeyMetadata[jwksKeyMetadata.alg as keyof typeof expectedKeyMetadata];

  if (!expected || jwksKeyMetadata.kty !== expected.kty) {
    fail('/oidc/jwksKeyMetadata/kty', 'conformance-signing-metadata');
  }

  if (jwksKeyMetadata.crv !== expected.crv) {
    fail('/oidc/jwksKeyMetadata/crv', 'conformance-signing-metadata');
  }

  if (jwksKeyMetadata.use !== 'sig') {
    fail('/oidc/jwksKeyMetadata/use', 'conformance-signing-metadata');
  }
};

const assertFixtureClients = (profile: Phase1Profile): void => {
  const clients = [
    profile.fixtures.adminTenant.application,
    ...profile.fixtures.dataTenant.applications,
  ];

  clients.forEach((client, clientIndex) => {
    client.oidcClientMetadata.redirectUris.forEach((redirectUri, redirectIndex) => {
      try {
        const parsed = new URL(redirectUri);

        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
          fail(
            `/fixtures/${clientIndex === 0 ? 'adminTenant/application' : `dataTenant/applications/${clientIndex - 1}`}/oidcClientMetadata/redirectUris/${redirectIndex}`,
            'conformance-client-redirect'
          );
        }
      } catch {
        fail(
          `/fixtures/${clientIndex === 0 ? 'adminTenant/application' : `dataTenant/applications/${clientIndex - 1}`}/oidcClientMetadata/redirectUris/${redirectIndex}`,
          'conformance-client-redirect'
        );
      }
    });
  });
};

export const assertConformanceSemantics = (profile: Phase1Profile): void => {
  assertDerivedUrls(profile);
  assertClientAndPlanMethods(profile);
  assertProtocolSelections(profile);
  assertSigningMetadata(profile);
  assertFixtureClients(profile);
};

export const assertConformanceExecution = (
  profile: Phase1Profile,
  execution: Phase1ConformanceExecution
): void => {
  if (execution.checkedOutSuiteCommit !== profile.conformance.suiteCommit) {
    fail('/conformance/suiteCommit', 'conformance-suite-checkout');
  }
};

/* eslint-enable no-restricted-syntax, unicorn/no-array-for-each, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unnecessary-condition */
