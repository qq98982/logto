/* eslint-disable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression -- Each case mutates one conformance contract field and asserts its stable diagnostic. */
import type { Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

import { assertConformanceExecution, assertConformanceSemantics } from './conformance.js';

const required = <Value>(value: Value | undefined): Value => {
  if (value === undefined) {
    throw new Error('Synthetic conformance fixture is incomplete');
  }

  return value;
};

const conformanceProfile = () =>
  ({
    fixtures: {
      adminTenant: {
        application: { oidcClientMetadata: { redirectUris: ['https://admin.example/callback'] } },
      },
      dataTenant: {
        applications: [{ oidcClientMetadata: { redirectUris: ['https://data.example/callback'] } }],
      },
    },
    consoleAuthentication: { grants: ['authorization_code', 'refresh_token'] },
    oidc: {
      grants: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      responseModes: ['query'],
      tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
      idTokenSigningAlgorithmsSupported: ['ES384'],
      jwksKeyMetadata: { kty: 'EC', use: 'sig', alg: 'ES384', crv: 'P-384' },
    },
    conformance: {
      suiteCommit: '1111111111111111111111111111111111111111',
      target: {
        issuer: 'https://server.example/oidc',
        discoveryUrl: 'https://server.example/oidc/.well-known/openid-configuration',
        suiteBaseUrl: 'https://suite.example',
        alias: 'phase-one',
        callbackUri: 'https://suite.example/test/a/phase-one/callback',
      },
      staticClients: [
        {
          id: 'basic-a',
          tokenEndpointAuthMethod: 'client_secret_basic',
          redirectUris: ['https://suite.example/test/a/phase-one/callback'],
        },
        {
          id: 'basic-b',
          tokenEndpointAuthMethod: 'client_secret_basic',
          redirectUris: ['https://suite.example/test/a/phase-one/callback'],
        },
        {
          id: 'post',
          tokenEndpointAuthMethod: 'client_secret_post',
          redirectUris: ['https://suite.example/test/a/phase-one/callback'],
        },
      ],
      plans: [
        {
          testPlanName: 'oidcc-basic-certification-test-plan',
          variants: {
            serverMetadata: 'discovery',
            clientRegistration: 'static_client',
            responseType: 'code',
            responseMode: 'default',
            clientAuthTypes: ['client_secret_basic', 'client_secret_post'],
          },
        },
        {
          testPlanName: 'oidcc-config-certification-test-plan',
          variants: { serverMetadata: 'discovery', clientRegistration: 'static_client' },
        },
      ],
    },
  }) as unknown as Phase1Profile;

const expectConformanceFailure = (operation: () => void, pointer: string, rule: string) => {
  try {
    operation();
    throw new Error('Expected conformance validation to fail');
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

describe('Phase 1 conformance relationships', () => {
  it('accepts derived target URLs and supported plans and clients', () => {
    expect(() => assertConformanceSemantics(conformanceProfile())).not.toThrow();
  });

  it('requires the exact pinned checkout before accepting an execution', () => {
    expect(() =>
      assertConformanceExecution(conformanceProfile(), {
        checkedOutSuiteCommit: '1111111111111111111111111111111111111111',
      })
    ).not.toThrow();

    expectConformanceFailure(
      () =>
        assertConformanceExecution(conformanceProfile(), {
          checkedOutSuiteCommit: '2222222222222222222222222222222222222222',
        }),
      '/conformance/suiteCommit',
      'conformance-suite-checkout'
    );
  });

  it.each([
    {
      name: 'discovery URL',
      pointer: '/conformance/target/discoveryUrl',
      rule: 'conformance-derived-url',
      mutate: (profile: Phase1Profile) => {
        (profile.conformance.target as { discoveryUrl: string }).discoveryUrl =
          'https://server.example/missing';
      },
    },
    {
      name: 'callback URI',
      pointer: '/conformance/target/callbackUri',
      rule: 'conformance-derived-url',
      mutate: (profile: Phase1Profile) => {
        (profile.conformance.target as { callbackUri: string }).callbackUri =
          'https://suite.example/missing';
      },
    },
    {
      name: 'static client auth method',
      pointer: '/conformance/staticClients/0/tokenEndpointAuthMethod',
      rule: 'conformance-client-method',
      mutate: (profile: Phase1Profile) => {
        (
          required(profile.conformance.staticClients.at(0)) as { tokenEndpointAuthMethod: string }
        ).tokenEndpointAuthMethod = 'private_key_jwt';
      },
    },
    {
      name: 'static client redirect',
      pointer: '/conformance/staticClients/0/redirectUris/0',
      rule: 'conformance-client-redirect',
      mutate: (profile: Phase1Profile) => {
        (required(profile.conformance.staticClients.at(0)).redirectUris as string[])[0] =
          'https://suite.example/missing';
      },
    },
    {
      name: 'Basic plan auth order',
      pointer: '/conformance/plans/0/variants/clientAuthTypes/0',
      rule: 'conformance-plan-client-methods',
      mutate: (profile: Phase1Profile) => {
        const plan = required(profile.conformance.plans.at(0));

        if (plan.testPlanName === 'oidcc-basic-certification-test-plan') {
          const methods = plan.variants.clientAuthTypes as string[];
          const first = required(methods.at(0));
          const second = required(methods.at(1));
          [methods[0], methods[1]] = [second, first];
        }
      },
    },
    {
      name: 'Console grant',
      pointer: '/consoleAuthentication/grants/1',
      rule: 'conformance-grant',
      mutate: (profile: Phase1Profile) => {
        (profile.consoleAuthentication.grants as string[])[1] = 'missing';
      },
    },
    {
      name: 'Basic response type',
      pointer: '/conformance/plans/0/variants/responseType',
      rule: 'conformance-response-type',
      mutate: (profile: Phase1Profile) => {
        const plan = required(profile.conformance.plans.at(0));

        if (plan.testPlanName === 'oidcc-basic-certification-test-plan') {
          (plan.variants as { responseType: string }).responseType = 'token';
        }
      },
    },
    {
      name: 'Basic response mode',
      pointer: '/conformance/plans/0/variants/responseMode',
      rule: 'conformance-response-mode',
      mutate: (profile: Phase1Profile) => {
        const plan = required(profile.conformance.plans.at(0));

        if (plan.testPlanName === 'oidcc-basic-certification-test-plan') {
          (plan.variants as { responseMode: string }).responseMode = 'fragment';
        }
      },
    },
    {
      name: 'JWK signing algorithm',
      pointer: '/oidc/jwksKeyMetadata/alg',
      rule: 'conformance-signing-metadata',
      mutate: (profile: Phase1Profile) => {
        (profile.oidc.jwksKeyMetadata as { alg: string }).alg = 'ES256';
      },
    },
    {
      name: 'extra declared grant',
      pointer: '/oidc/grants/2',
      rule: 'conformance-grant',
      mutate: (profile: Phase1Profile) => {
        (profile.oidc.grants as string[]).push('client_credentials');
      },
    },
    {
      name: 'declared client method order',
      pointer: '/oidc/tokenEndpointAuthMethods/0',
      rule: 'conformance-client-method',
      mutate: (profile: Phase1Profile) => {
        const methods = profile.oidc.tokenEndpointAuthMethods as string[];
        const first = required(methods.at(0));
        const second = required(methods.at(1));
        [methods[0], methods[1]] = [second, first];
      },
    },
    {
      name: 'extra declared response type',
      pointer: '/oidc/responseTypes/1',
      rule: 'conformance-response-type',
      mutate: (profile: Phase1Profile) => {
        (profile.oidc.responseTypes as string[]).push('id_token');
      },
    },
    {
      name: 'extra declared response mode',
      pointer: '/oidc/responseModes/1',
      rule: 'conformance-response-mode',
      mutate: (profile: Phase1Profile) => {
        (profile.oidc.responseModes as string[]).push('fragment');
      },
    },
    {
      name: 'extra declared signing algorithm',
      pointer: '/oidc/idTokenSigningAlgorithmsSupported/1',
      rule: 'conformance-signing-metadata',
      mutate: (profile: Phase1Profile) => {
        (profile.oidc.idTokenSigningAlgorithmsSupported as string[]).push('ES256');
      },
    },
  ])('rejects a mutated $name at the exact pointer', ({ mutate, pointer, rule }) => {
    const profile = conformanceProfile();
    mutate(profile);
    expectConformanceFailure(() => assertConformanceSemantics(profile), pointer, rule);
  });
});

/* eslint-enable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression */
