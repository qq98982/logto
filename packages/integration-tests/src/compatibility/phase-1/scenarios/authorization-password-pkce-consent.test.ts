/* eslint-disable max-lines, max-params, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods -- The protocol fake records the exact credential-preserving redirect chain, deliberately structural clients, and cookie-jar continuity. */
import { createHash } from 'node:crypto';

import { SymbolTable } from '../../symbol-table.js';
import {
  MemoryProtocolSecretStore,
  protocolHeaderPairs,
  type ProtocolRequestOptions,
} from '../clients/oidc.js';
import {
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
} from '../fixture-map.js';
import type { Phase1FixtureSecretLease } from '../fixtures.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import { runAuthorizationPasswordPkceConsent } from './authorization-password-pkce-consent.js';
import {
  assertPositiveOidcAuthorizationGrantActive,
  withPositiveOidcFlow,
  type PositiveOidcAuthorizationGrant,
  type PositiveOidcFlowRandomSource,
} from './positive-oidc-flow.js';

const target = {
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
};
const runtimeApplicationId = 'runtime-consent-client';
const runtimeUserId = 'runtime-subject';
const runtimeResourceId = 'runtime-resource';
const runtimeScopeId = 'runtime-scope';
const configuredResourceIndicator = 'https://api.example.com';
const configuredScopeName = 'read:profile';
const dataAllocationId = 'data-allocation';
const runtimeUsername = getPhase1FixtureRuntimeUsername('phase1-user', dataAllocationId);
const runtimeApplicationName = getPhase1FixtureRuntimeText('Consent client', dataAllocationId);
const runtimeResourceName = getPhase1FixtureRuntimeText('Phase 1 API', dataAllocationId);
const runtimeResourceIndicator = getPhase1FixtureRuntimeResourceIndicator(
  configuredResourceIndicator,
  dataAllocationId
);
const runtimeScopeName = getPhase1FixtureRuntimeText(configuredScopeName, dataAllocationId);
const logicalApplicationId = 'phase1-browser';
const logicalUserId = 'phase1-user';
const leasedPassword = 'fixture-password-private';
const verifier = 'v'.repeat(64);
const originalState = 'state-private-value';
const authorizationCode = 'code-private-value';
const verificationId = 'verification-private-value';
const firstResume = 'login-resume-private';
const consentResume = 'consent-resume-private';
const encodedConsentResume = 'consent-%72esume-private';
const unrelatedEncodedCookiePath = '/cookie%2Fprefix%25literal%3Bmarker';
const interactionCookie = 'interaction-private-value';

const profile = {
  fixtures: {
    dataTenant: {
      id: 'default',
      subject: {
        id: logicalUserId,
        username: 'phase1-user',
        name: 'phase1-user',
        primaryEmail: 'phase1-user@example.com',
        primaryPhone: '+15555550101',
        profile: { address: { formatted: '1 Aster Way', country: 'US' } },
      },
      applications: [
        {
          id: 'phase1-app',
          name: 'First party',
          type: 'SPA',
          isThirdParty: false,
          oidcClientMetadata: {
            redirectUris: ['https://client.example/first-party'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
        },
        {
          id: logicalApplicationId,
          name: 'Consent client',
          type: 'SPA',
          isThirdParty: true,
          oidcClientMetadata: {
            redirectUris: ['https://client.example/callback'],
            postLogoutRedirectUris: [],
          },
          customClientMetadata: {},
          userConsentScopes: ['profile', 'email', 'address', 'phone'],
          resourceConsentScopes: ['phase1-read-profile'],
        },
      ],
      resource: {
        id: 'phase1-api',
        name: 'Phase 1 API',
        indicator: configuredResourceIndicator,
        scopes: [
          {
            id: 'phase1-read-profile',
            name: 'read:profile',
            description: "Read the signed-in user's profile",
          },
        ],
      },
      browserClientConfiguration: {
        localStorageKey: 'logto:demo-app:dev:config',
        localStorageValue: {
          appId: logicalApplicationId,
          prompt: 'login consent',
          scope: 'profile email address phone read:profile',
          resource: 'https://api.example.com',
        },
      },
    },
  },
  oidc: {
    issuerPath: '/oidc',
    authorizationPath: '/oidc/auth',
  },
};

type RecordedRequest = Readonly<{
  client: 'oidc' | 'experience' | 'consent';
  operation: string;
  path: string;
  method: string;
  contentType: string | undefined;
  body: string | undefined;
  cookie: string | undefined;
  store: MemoryProtocolSecretStore;
}>;

const headerValue = (
  headers: ProtocolRequestOptions['headers'],
  name: string
): string | undefined => {
  if (!headers) {
    return;
  }
  return protocolHeaderPairs(headers).find(([candidate]) => candidate.toLowerCase() === name)?.[1];
};

const response = (
  status: number,
  body: unknown = '',
  headers: ReadonlyArray<readonly [string, string]> = []
) => ({
  status,
  headers,
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

const fixtureMap = {
  schemaVersion: 1 as const,
  recipe: 'dataProtocol' as const,
  allocations: [
    {
      allocationId: dataAllocationId,
      role: 'data' as const,
      target: 'primary' as const,
      isolation: {
        persistenceId: 'data-persistence',
        cookieKeyId: 'data-cookie-key',
        signingKeyId: 'data-signing-key',
      },
      entities: [
        { kind: 'tenant' as const, logicalId: 'default', runtimeId: 'default' },
        { kind: 'user' as const, logicalId: logicalUserId, runtimeId: runtimeUserId },
        {
          kind: 'application' as const,
          logicalId: logicalApplicationId,
          runtimeId: runtimeApplicationId,
        },
        {
          kind: 'resource' as const,
          logicalId: 'phase1-api',
          runtimeId: runtimeResourceId,
        },
        {
          kind: 'scope' as const,
          logicalId: 'phase1-read-profile',
          runtimeId: runtimeScopeId,
        },
      ],
    },
  ],
};

const createHarness = (
  harnessOptions: Readonly<{
    includeResource?: boolean;
    consentResumeCredential?: string;
    secondaryCookieCredential?: string;
    secondaryCookiePath?: string;
    overlapCookieCredential?: string;
    missingOidcScopes?: readonly string[];
    omitMissingOidcScopes?: boolean;
  }> = {}
) => {
  const store = new MemoryProtocolSecretStore();
  const records: RecordedRequest[] = [];
  const semanticReads: string[] = [];
  const activeConsentResume = harnessOptions.consentResumeCredential ?? encodedConsentResume;
  const secondaryCookieCredential =
    harnessOptions.secondaryCookieCredential ?? 'secondary-private-value';
  const secondaryCookiePath = harnessOptions.secondaryCookiePath ?? `/${secondaryCookieCredential}`;
  const applyResponseCookies = (
    raw: ReturnType<typeof response>,
    requestUrl: URL
  ): ReturnType<typeof response> => {
    for (const [name, value] of raw.headers) {
      if (name.toLowerCase() === 'set-cookie') {
        store.setCookie(value, requestUrl);
      }
    }

    return raw;
  };
  const record = (
    client: RecordedRequest['client'],
    operation: string,
    path: string,
    options: ProtocolRequestOptions | undefined,
    requestUrl: URL
  ) => {
    records.push({
      client,
      operation,
      path,
      method: options?.method ?? (options?.body === undefined ? 'GET' : 'POST'),
      contentType: headerValue(options?.headers, 'content-type'),
      body: options?.body,
      cookie: store.getCookieHeader(requestUrl),
      store,
    });
  };
  const oidc = {
    store,
    request: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        const requestUrl = new URL(path, target.coreUrl);
        record('oidc', operation, path, options, requestUrl);

        if (operation === 'authorization-start') {
          return applyResponseCookies(
            response(303, 'Redirecting to /sign-in.', [
              ['location', '/sign-in'],
              ['set-cookie', `_interaction=${interactionCookie}; Path=/; HttpOnly; SameSite=Lax`],
              [
                'set-cookie',
                `_interaction.sig=interaction-signature-private; Path=/; HttpOnly; SameSite=Lax`,
              ],
              [
                'set-cookie',
                `_secondary=${secondaryCookieCredential}; Path=${secondaryCookiePath}; HttpOnly; SameSite=Lax`,
              ],
              ...(harnessOptions.overlapCookieCredential
                ? [
                    [
                      'set-cookie',
                      `_overlap=${harnessOptions.overlapCookieCredential}; Path=/; HttpOnly; SameSite=Lax`,
                    ] as const,
                  ]
                : []),
            ]),
            requestUrl
          );
        }
        if (operation === 'authorization-consent-bridge') {
          const location = `/consent?app_id=${runtimeApplicationId}`;

          return applyResponseCookies(
            response(303, `Redirecting to ${location}.`, [
              ['location', location],
              ['set-cookie', `_session=session-private; Path=/; HttpOnly; SameSite=Lax`],
              [
                'set-cookie',
                `_interaction_resume=; Path=/oidc/auth/${firstResume}; Max-Age=0; HttpOnly; SameSite=Lax`,
              ],
            ]),
            requestUrl
          );
        }
        if (operation === 'authorization-resume') {
          const location = `https://client.example/callback?code=${authorizationCode}&state=${originalState}&iss=https%3A%2F%2Foracle.example%2Foidc`;

          return applyResponseCookies(
            response(303, `Redirecting to ${location.replaceAll('&', '&amp;')}.`, [
              ['location', location],
              [
                'set-cookie',
                `_interaction=; Path=${unrelatedEncodedCookiePath}/oidc/auth/${activeConsentResume}; Max-Age=0; HttpOnly; SameSite=Lax`,
              ],
            ]),
            requestUrl
          );
        }

        throw new Error(`unexpected OIDC operation: ${operation}`);
      }
    ),
  };
  const experience = {
    store,
    requestExperience: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        const requestUrl = new URL(path, new URL('/api/', target.coreUrl));
        record('experience', operation, path, options, requestUrl);

        if (operation === 'experience-bootstrap') {
          return response(204);
        }
        if (operation === 'experience-password') {
          expect(options?.body).toContain(leasedPassword);
          return response(200, { verificationId }, [['content-type', 'application/json']]);
        }
        if (operation === 'experience-identify') {
          return response(204);
        }
        if (operation === 'experience-submit') {
          return applyResponseCookies(
            response(200, { redirectTo: `${target.coreUrl}oidc/auth/${firstResume}` }, [
              ['content-type', 'application/json'],
              [
                'set-cookie',
                `_interaction_resume=${firstResume}; Path=/oidc/auth/${firstResume}; HttpOnly; SameSite=Lax`,
              ],
            ]),
            requestUrl
          );
        }

        throw new Error(`unexpected experience operation: ${operation}`);
      }
    ),
  };
  const consent = {
    store,
    requestConsent: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        const requestUrl = new URL(path, new URL('/api/interaction/', target.coreUrl));
        record('consent', operation, path, options, requestUrl);

        if (operation === 'consent-get') {
          return response(
            200,
            {
              application: { id: runtimeApplicationId, name: runtimeApplicationName },
              user: { id: runtimeUserId, username: runtimeUsername },
              organizations: [],
              ...(harnessOptions.omitMissingOidcScopes
                ? {}
                : {
                    missingOIDCScope: harnessOptions.missingOidcScopes ?? [
                      'profile',
                      'email',
                      'address',
                      'phone',
                    ],
                  }),
              missingResourceScopes:
                harnessOptions.includeResource === false
                  ? []
                  : [
                      {
                        resource: {
                          id: runtimeResourceId,
                          name: runtimeResourceName,
                          indicator: runtimeResourceIndicator,
                        },
                        scopes: [
                          {
                            id: runtimeScopeId,
                            name: runtimeScopeName,
                            description: "Read the signed-in user's profile",
                          },
                        ],
                      },
                    ],
              redirectUri: 'https://client.example/callback',
            },
            [['content-type', 'application/json']]
          );
        }
        if (operation === 'consent-post') {
          return response(
            200,
            { redirectTo: `${target.coreUrl}oidc/auth/${activeConsentResume}` },
            [['content-type', 'application/json']]
          );
        }

        throw new Error(`unexpected consent operation: ${operation}`);
      }
    ),
  };
  const scenarioState = {
    body: { observed: true },
    semanticState: {
      session: {
        updatedAt: 1_700_000_000_000,
        accountId: runtimeUserId,
        clientId: runtimeApplicationId,
      },
    },
    persistedState: {
      grant: {
        applicationId: runtimeApplicationId,
        userId: runtimeUserId,
        oidcScopes: ['profile', 'email', 'address', 'phone'],
        resource: runtimeResourceIndicator,
        resourceScopes: [runtimeScopeName],
      },
      userFirstConsentedApplicationId: runtimeApplicationId,
      sessionExtension: {
        accountId: runtimeUserId,
        clientId: runtimeApplicationId,
        lastSubmission: { login: { accountId: runtimeUserId } },
      },
    },
    generatedIds: {},
    sideEffects: { consentPersisted: true },
  };
  const management = {
    store,
    requestManagement: import.meta.jest.fn(async () => {
      throw new Error('unexpected management request');
    }),
  };
  const allocationSymbols = new SymbolTable();

  for (const entity of fixtureMap.allocations[0]!.entities) {
    allocationSymbols.bind(`${entity.kind}.${entity.logicalId}`, entity.runtimeId);
  }
  const context: Phase1ScenarioRunContext = {
    profile: profile as never,
    target,
    fixture: {
      public: fixtureMap,
      withSecretLease: async <Result>(use: (lease: Phase1FixtureSecretLease) => Promise<Result>) =>
        use({ getPassword: () => leasedPassword } as never),
    } as never,
    signal: new AbortController().signal,
    protocol: {
      publicOidc: oidc as never,
      publicSymbols: new SymbolTable(),
      forAllocation: () => ({
        oidc,
        experience,
        consent,
        management,
        account: {} as never,
        state: {} as never,
      }),
      symbolsFor: () => allocationSymbols,
    },
    projectFixtureState: async () => ({
      schemaVersion: 1,
      recipe: 'dataProtocol',
      allocations: [],
    }),
    projectScenarioState: async ({ stepId }) => {
      semanticReads.push(stepId);
      const generatedIds: Record<string, string> =
        stepId === 'authorize' ? { interaction: '<interaction.1>' } : {};

      return {
        ...scenarioState,
        generatedIds,
      };
    },
  };
  const random: PositiveOidcFlowRandomSource = {
    codeVerifier: () => verifier,
    state: () => originalState,
  };

  return { context, records, semanticReads, random, scenarioState, store, management };
};

describe('authorization.password-pkce-consent', () => {
  it('preserves state cookie continuity consent and one callback code', async () => {
    const harness = createHarness();
    const consume = import.meta.jest.fn(async (grant: PositiveOidcAuthorizationGrant) => {
      expect(() => {
        assertPositiveOidcAuthorizationGrantActive(grant);
      }).not.toThrow();
      expect(() => JSON.stringify(grant)).toThrow(
        'Phase 1 authorization grant is not serializable'
      );

      return null;
    });
    const output = await withPositiveOidcFlow(harness.context, { random: harness.random }, consume);
    const { steps } = output;
    expect(output.result).toBeNull();
    expect(consume).toHaveBeenCalledTimes(1);
    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'authorize',
      'experience-bootstrap',
      'password',
      'identify',
      'submit',
      'consent-get',
      'consent-post',
      'resume',
      'callback',
      'state',
    ]);
    expect(harness.records.map(({ client, operation }) => `${client}:${operation}`)).toEqual([
      'oidc:authorization-start',
      'experience:experience-bootstrap',
      'experience:experience-password',
      'experience:experience-identify',
      'experience:experience-submit',
      'oidc:authorization-consent-bridge',
      'consent:consent-get',
      'consent:consent-post',
      'oidc:authorization-resume',
    ]);
    expect(harness.management.requestManagement).not.toHaveBeenCalled();
    expect(harness.records[5]?.path).toBe(`oidc/auth/${firstResume}`);
    expect(harness.records[8]?.path).toBe(`oidc/auth/${encodedConsentResume}`);
    expect(new Set(harness.records.map(({ store }) => store))).toEqual(new Set([harness.store]));
    expect(harness.records.slice(1).every(({ cookie }) => Boolean(cookie))).toBe(true);
    expect(harness.records.map(({ contentType }) => contentType)).toEqual([
      undefined,
      'application/json',
      'application/json',
      'application/json',
      undefined,
      undefined,
      undefined,
      'application/json',
      undefined,
    ]);
    expect(harness.records.map(({ body }) => body)).toEqual([
      undefined,
      JSON.stringify({ interactionEvent: 'SignIn' }),
      JSON.stringify({
        identifier: { type: 'username', value: runtimeUsername },
        password: leasedPassword,
      }),
      JSON.stringify({ verificationId }),
      undefined,
      undefined,
      undefined,
      JSON.stringify({}),
      undefined,
    ]);
    const authorizationUrl = new URL(harness.records[0]!.path, target.coreUrl);
    expect(authorizationUrl.pathname).toBe('/oidc/auth');
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorizationUrl.searchParams.get('code_challenge')).toBe(
      createHash('sha256').update(verifier).digest('base64url')
    );
    expect(authorizationUrl.searchParams.getAll('state')).toEqual([originalState]);
    expect(authorizationUrl.searchParams.get('client_id')).toBe(runtimeApplicationId);
    expect(authorizationUrl.searchParams.get('redirect_uri')).toBe(
      'https://client.example/callback'
    );
    expect(authorizationUrl.searchParams.getAll('resource')).toEqual([runtimeResourceIndicator]);
    expect(authorizationUrl.searchParams.get('scope')?.split(' ')).toContain(runtimeScopeName);
    expect(steps[4]?.value).toMatchObject({
      outcomes: [{ kind: 'unobserved-consent-bridge', response: { status: 303 } }],
    });
    const bridgeEvidence = JSON.stringify(steps[4]?.value.outcomes);
    expect(bridgeEvidence).toContain('"name":"_interaction_resume"');
    expect(bridgeEvidence).toContain('"path":"/oidc/auth/aster-cookie-attribute-value"');
    expect(steps[0]?.value).toMatchObject({
      body: 'Redirecting to <response-location>.',
      generatedIds: { interaction: '<interaction.1>' },
    });
    expect(steps[0]?.value.cookies).toContainEqual(
      expect.objectContaining({ name: '_secondary', path: '/aster-cookie-attribute-value' })
    );
    expect(steps[7]?.value).toMatchObject({
      body: 'Redirecting to <response-location>.',
      cookies: [
        expect.objectContaining({
          path: `${unrelatedEncodedCookiePath}/oidc/auth/aster-cookie-attribute-value`,
        }),
      ],
    });
    expect(steps[8]?.value.cookies).toContainEqual(
      expect.objectContaining({
        path: `${unrelatedEncodedCookiePath}/oidc/auth/aster-cookie-attribute-value`,
      })
    );
    expect(JSON.stringify(steps)).not.toContain(encodedConsentResume);
    expect(JSON.stringify(steps)).not.toContain(firstResume);
    expect(steps[9]?.value).toMatchObject({
      body: harness.scenarioState.body,
      semanticState: {
        session: {
          accountId: '<user.phase1-user>',
          clientId: '<application.phase1-browser>',
          updatedAt: { $timestamp: 1_700_000_000, $toleranceSeconds: 30 },
        },
      },
      persistedState: {
        grant: {
          applicationId: '<application.phase1-browser>',
          oidcScopes: ['profile', 'email', 'address', 'phone'],
          resource: '<fixture.data.resource-indicator>',
          resourceScopes: ['<fixture.data.scope-name>'],
          userId: '<user.phase1-user>',
        },
        sessionExtension: {
          accountId: '<user.phase1-user>',
          clientId: '<application.phase1-browser>',
          lastSubmission: { login: { accountId: '<user.phase1-user>' } },
        },
        userFirstConsentedApplicationId: '<application.phase1-browser>',
      },
      sideEffects: harness.scenarioState.sideEffects,
    });
    expect(harness.semanticReads).toEqual([
      'authorize',
      'experience-bootstrap',
      'password',
      'identify',
      'submit',
      'consent-get',
      'consent-post',
      'resume',
      'callback',
      'state',
    ]);
    const serialized = JSON.stringify(steps);
    expect(serialized).not.toMatch(
      /runtime-consent-client|runtime-subject|runtime-resource|runtime-scope/u
    );
    expect(serialized).not.toMatch(
      /fixture-password-private|state-private-value|code-private-value|verification-private-value|interaction-private-value|resume-private|session-private|signature-private/u
    );
  });

  it.each([
    ['an omitted field', { omitMissingOidcScopes: true }],
    ['an exact empty array', { missingOidcScopes: [] }],
  ] as const)('accepts %s after prior OIDC consent', async (_name, consentShape) => {
    const harness = createHarness({ includeResource: false, ...consentShape });
    const consume = import.meta.jest.fn(async () => null);
    const output = await withPositiveOidcFlow(
      harness.context,
      {
        random: harness.random,
        captureSteps: false,
        includeResource: false,
        expectOidcConsentAlreadyGranted: true,
      },
      consume
    );

    expect(output).toEqual({ steps: [], result: null });
    expect(consume).toHaveBeenCalledTimes(1);
    expect(harness.semanticReads).toEqual([]);
    expect(harness.records.map(({ operation }) => operation)).toContain('consent-get');
  });

  it('rejects non-empty missing scopes after prior OIDC consent', async () => {
    const harness = createHarness({ includeResource: false, missingOidcScopes: ['profile'] });

    await expect(
      withPositiveOidcFlow(
        harness.context,
        {
          random: harness.random,
          captureSteps: false,
          includeResource: false,
          expectOidcConsentAlreadyGranted: true,
        },
        async () => null
      )
    ).rejects.toThrow('Phase 1 consent response is invalid');
  });

  it('keeps an omitted missing-scope field invalid for a fresh consent flow', async () => {
    const harness = createHarness({ includeResource: false, omitMissingOidcScopes: true });

    await expect(
      withPositiveOidcFlow(
        harness.context,
        { random: harness.random, captureSteps: false, includeResource: false },
        async () => null
      )
    ).rejects.toThrow('Phase 1 consent response is invalid');
  });

  it('publishes the authorization scenario without the credential handle', async () => {
    const harness = createHarness();
    const steps = await runAuthorizationPasswordPkceConsent(harness.context, {
      random: harness.random,
    });

    expect(steps).toHaveLength(10);
    expect(Object.values(steps).some((value) => typeof value === 'function')).toBe(false);
    expect(JSON.stringify(steps)).not.toContain(authorizationCode);
  });

  it.each([
    [
      'a 1536-byte resume credential',
      { consentResumeCredential: 'r'.repeat(1536) },
      'r'.repeat(1536),
    ],
    ['a 4096-byte cookie value', { secondaryCookieCredential: 'c'.repeat(4096) }, 'c'.repeat(4096)],
  ] as const)('sanitizes %s without regex-size failure', async (_name, options, credential) => {
    const harness = createHarness(options);
    const steps = await runAuthorizationPasswordPkceConsent(harness.context, {
      random: harness.random,
    });

    expect(steps).toHaveLength(10);
    expect(JSON.stringify(steps)).not.toContain(credential);
  });

  it.each([
    [
      'start',
      (encoded: string) => ({
        path: `%FF${encoded}`,
        expected: '%FFaster-cookie-attribute-value',
      }),
    ],
    [
      'middle',
      (encoded: string) => ({
        path: `%41%FF${encoded}`,
        expected: '%41%FFaster-cookie-attribute-value',
      }),
    ],
    [
      'end',
      (encoded: string) => ({
        path: `${encoded}%FF`,
        expected: 'aster-cookie-attribute-value%FF',
      }),
    ],
  ] as const)(
    'preserves an invalid UTF-8 percent run with the invalid byte at the %s',
    async (_position, invalidRun) => {
      const credential = 'abcdefgh';
      const encodedCredential = [...credential]
        .map((character) => `%${character.codePointAt(0)?.toString(16)}`)
        .join('');
      const rawRun = invalidRun(encodedCredential);
      const harness = createHarness({
        secondaryCookieCredential: credential,
        secondaryCookiePath: `/${rawRun.path}`,
      });
      const steps = await runAuthorizationPasswordPkceConsent(harness.context, {
        random: harness.random,
      });

      expect(steps[0]?.value.cookies).toContainEqual(
        expect.objectContaining({ name: '_secondary', path: `/${rawRun.expected}` })
      );
    }
  );

  it('keeps adjacent credential spans distinct in the cookie projection', async () => {
    const credential = 'abcdefgh';
    const harness = createHarness({
      secondaryCookieCredential: credential,
      secondaryCookiePath: `/${credential}${credential}`,
    });
    const steps = await runAuthorizationPasswordPkceConsent(harness.context, {
      random: harness.random,
    });

    expect(JSON.stringify(steps)).toContain(
      '/aster-cookie-attribute-valueaster-cookie-attribute-value'
    );
  });

  it('merges truly overlapping credentials without changing surrounding bytes', async () => {
    const harness = createHarness({
      secondaryCookieCredential: 'abcdefgh',
      secondaryCookiePath: '/prefix-abcdefghij-suffix',
      overlapCookieCredential: 'cdefghij',
    });
    const steps = await runAuthorizationPasswordPkceConsent(harness.context, {
      random: harness.random,
    });

    expect(JSON.stringify(steps)).toContain('/prefix-aster-cookie-attribute-value-suffix');
  });

  it('maps a percent-encoded Unicode credential to its exact raw span', async () => {
    const credential = 'token-🔐-value';
    const encoded = encodeURIComponent(credential);
    const harness = createHarness({
      secondaryCookieCredential: encoded,
      secondaryCookiePath: `/prefix/${encoded}/suffix`,
    });
    const steps = await runAuthorizationPasswordPkceConsent(harness.context, {
      random: harness.random,
    });
    const serialized = JSON.stringify(steps);

    expect(serialized).toContain('/prefix/aster-cookie-attribute-value/suffix');
    expect(serialized).not.toContain(encoded);
    expect(serialized).not.toContain(credential);
  });

  it('executes hidden preparation without cross-scenario state reads', async () => {
    const harness = createHarness({ includeResource: false });
    const output = await withPositiveOidcFlow(
      harness.context,
      { random: harness.random, captureSteps: false, includeResource: false },
      async (grant) => {
        expect(() => {
          assertPositiveOidcAuthorizationGrantActive(grant);
        }).not.toThrow();
        return { exchanged: true };
      }
    );

    expect(output).toEqual({ steps: [], result: { exchanged: true } });
    expect(harness.semanticReads).toEqual([]);
    const authorize = new URL(harness.records[0]!.path, target.coreUrl);
    expect(authorize.searchParams.has('resource')).toBe(false);
    expect(authorize.searchParams.get('scope')?.split(' ')).not.toContain(configuredScopeName);
    expect(JSON.stringify(output)).not.toMatch(
      /code-private-value|state-private-value|fixture-password-private/u
    );
  });

  it('rejects a sign-in redirect outside the configured core origin', async () => {
    const harness = createHarness();
    const request = import.meta.jest.spyOn(
      harness.context.protocol.forAllocation('data').oidc,
      'request'
    );
    request.mockResolvedValueOnce(
      response(303, 'Redirecting to https://attacker.example/sign-in.', [
        ['location', 'https://attacker.example/sign-in'],
      ])
    );

    await expect(
      runAuthorizationPasswordPkceConsent(harness.context, { random: harness.random })
    ).rejects.toThrow('Phase 1 authorization start redirect is invalid');
  });

  it('rejects incomplete persisted consent and session effects', async () => {
    const harness = createHarness();
    const context: Phase1ScenarioRunContext = {
      ...harness.context,
      projectScenarioState: async (input) =>
        input.stepId === 'state'
          ? { ...harness.scenarioState, persistedState: {} }
          : harness.context.projectScenarioState(input),
    };

    await expect(
      runAuthorizationPasswordPkceConsent(context, { random: harness.random })
    ).rejects.toThrow('Phase 1 authorization persisted state is invalid');
  });

  it('rejects callback results and errors that contain registered ephemeral credentials', async () => {
    const retainedCapability = createHarness();
    const { promise: retainedPromise, resolve: retain } =
      // eslint-disable-next-line no-use-extend-native/no-use-extend-native -- Promise.withResolvers is the standard ES2024 deferred primitive, not a prototype extension.
      Promise.withResolvers<PositiveOidcAuthorizationGrant>();
    await withPositiveOidcFlow(
      retainedCapability.context,
      { random: retainedCapability.random, captureSteps: false },
      async (grant) => {
        retain(grant);
        return null;
      }
    );
    const retained = await retainedPromise;
    expect(() => {
      assertPositiveOidcAuthorizationGrantActive(retained);
    }).toThrow('Invalid Phase 1 authorization grant');
    const forged = Object.freeze({
      toJSON: () => {
        throw new TypeError('forged');
      },
    }) as PositiveOidcAuthorizationGrant;
    expect(() => {
      assertPositiveOidcAuthorizationGrantActive(forged);
    }).toThrow('Invalid Phase 1 authorization grant');

    const escapedCapability = createHarness();
    await expect(
      withPositiveOidcFlow(
        escapedCapability.context,
        { random: escapedCapability.random, captureSteps: false },
        async (grant) => grant
      )
    ).rejects.toThrow('Phase 1 authorization consumer failed');

    const leakedResult = createHarness();
    await expect(
      withPositiveOidcFlow(
        leakedResult.context,
        { random: leakedResult.random, captureSteps: false },
        async () => ({ note: authorizationCode })
      )
    ).rejects.toThrow('Phase 1 authorization consumer failed');

    const leakedError = createHarness();
    const failure = await withPositiveOidcFlow(
      leakedError.context,
      { random: leakedError.random, captureSteps: false },
      async () => {
        throw new Error(authorizationCode);
      }
    ).catch((error: unknown) => error);
    expect(String(failure)).toBe('Error: Phase 1 authorization consumer failed');
    expect(String(failure)).not.toContain(authorizationCode);
  });
});

/* eslint-enable max-lines, max-params, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-mutating-methods */
