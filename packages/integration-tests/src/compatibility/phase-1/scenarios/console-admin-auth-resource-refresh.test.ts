/* eslint-disable max-lines, @silverhand/fp/no-mutation -- The focused admin authorization and refresh security matrix stays in one harness. */
import { createHash } from 'node:crypto';
import { inspect } from 'node:util';

import { normalizeHeaders } from '../normalizers.js';

import { runConsoleAdminAuthResourceRefresh } from './console-admin-auth-resource-refresh.js';
import {
  assertPositiveAdminRefreshTokenIsFresh,
  createPositiveAdminNormalizationContext,
  readPositiveAdminSession,
  withPositiveAdminSession,
} from './positive-admin-flow.js';
import {
  adminInitialResponseScope,
  adminRequestedScope,
  adminRuntime,
  adminSecrets,
  adminTestTarget,
  createAdminScenarioHarness,
  createAdminTestSigner,
  requestContentType,
  requestForm,
  tokenBody,
} from './positive-admin-flow.test-helpers.js';
import {
  refreshPositiveAdminAccountResourceToken,
  refreshPositiveAdminManagementToken,
  refreshPositiveAdminManagementTokenWithoutAllScope,
  refreshPositiveAdminUserInfoTokenWithoutOpenId,
} from './positive-admin-token.js';

const adminCallbackLocation = (mutate?: (callback: URL) => string): string => {
  const callback = new URL(`${adminTestTarget.adminUrl}console/callback`);

  callback.searchParams.set('code', adminSecrets.code);
  callback.searchParams.set('state', adminSecrets.state);
  callback.searchParams.set('iss', `${adminTestTarget.adminUrl}oidc`);
  return mutate?.(callback) ?? callback.href;
};

const adminConsentBridgeLocation = (mutate?: (bridge: URL) => string): string => {
  const bridge = new URL(`${adminTestTarget.adminUrl}consent`);

  bridge.searchParams.set('app_id', 'admin-console');
  return mutate?.(bridge) ?? `${bridge.pathname}${bridge.search}`;
};

const adminConsentResumeLocation = (mutate?: (resume: URL) => string): string => {
  const resume = new URL(`${adminTestTarget.adminUrl}oidc/auth/${adminSecrets.consentResume}`);

  return mutate?.(resume) ?? resume.href;
};

const initialResponseScopeMutants = [
  [
    'missing the organizations user scope',
    adminInitialResponseScope
      .split(' ')
      .filter((scope) => scope !== 'urn:logto:scope:organizations')
      .join(' '),
  ],
  [
    'missing the organization roles user scope',
    adminInitialResponseScope
      .split(' ')
      .filter((scope) => scope !== 'urn:logto:scope:organization_roles')
      .join(' '),
  ],
  ['including the resource-only all scope', `${adminInitialResponseScope} all`],
] as const;

const cookiePairs = (value: string | undefined): readonly string[] =>
  value
    ?.split(';')
    .map((pair) => pair.trim())
    .filter(Boolean)
    .toSorted() ?? [];

type AdminHarnessOptions = Omit<Parameters<typeof createAdminScenarioHarness>[0], 'jwk' | 'tokens'>;

type AdminIntermediateExpectation = Readonly<{
  expectedMessage: string;
  forbiddenValues: readonly string[];
  absentOperations: readonly string[];
  unregisteredValues?: readonly string[];
}>;

type CallbackHarnessOptions = Pick<
  Parameters<typeof createAdminScenarioHarness>[0],
  'resumeStatus' | 'callbackLocations' | 'resumeBody'
>;

const expectAdminCallbackRejection = async (
  options: CallbackHarnessOptions,
  forbiddenValues: readonly string[],
  expectedMessage = 'Phase 1 admin authorization callback is invalid',
  unregisteredValues: readonly string[] = [adminSecrets.code]
): Promise<void> => {
  const signer = await createAdminTestSigner();
  const harness = createAdminScenarioHarness({
    jwk: signer.jwk,
    tokens: { initial: {} },
    ...options,
  });
  const caught: unknown = await runConsoleAdminAuthResourceRefresh(harness.context, {
    random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
  }).then(
    () => new Error('Expected the admin callback to be rejected'),
    (error: unknown) => error
  );

  expect(caught).toBeInstanceOf(Error);
  expect((caught as Error).message).toBe(expectedMessage);
  expect(String(caught)).toBe(`Error: ${expectedMessage}`);
  for (const value of forbiddenValues) {
    expect(inspect(caught, { depth: null })).not.toContain(value);
    expect(String(caught)).not.toContain(value);
  }
  for (const value of unregisteredValues) {
    expect(() => {
      harness.store.assertNoCredentialMaterial(value);
    }).not.toThrow();
  }
  expect(
    harness.records.some(({ operation }) => operation === 'admin-token-authorization-code')
  ).toBe(false);
};

const expectAdminResumeRedirectRejection = async (
  resumeRedirectTo: string,
  forbiddenValues: readonly string[],
  unregisteredValues: readonly string[]
): Promise<void> => {
  const signer = await createAdminTestSigner();
  const harness = createAdminScenarioHarness({
    jwk: signer.jwk,
    tokens: { initial: {} },
    resumeRedirectTo,
  });
  const expectedMessage = 'Phase 1 admin interaction resume redirect is invalid';
  const caught: unknown = await runConsoleAdminAuthResourceRefresh(harness.context, {
    random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
  }).then(
    () => new Error('Expected the interaction resume redirect to be rejected'),
    (error: unknown) => error
  );

  expect(caught).toBeInstanceOf(Error);
  expect((caught as Error).message).toBe(expectedMessage);
  expect(String(caught)).toBe(`Error: ${expectedMessage}`);
  for (const value of forbiddenValues) {
    expect(inspect(caught, { depth: null })).not.toContain(value);
    expect(String(caught)).not.toContain(value);
  }
  for (const value of unregisteredValues) {
    expect(() => {
      harness.store.assertNoCredentialMaterial(value);
    }).not.toThrow();
  }
  expect(harness.records.some(({ operation }) => operation === 'admin-authorization-resume')).toBe(
    false
  );
  expect(
    harness.records.some(({ operation }) => operation === 'admin-authorization-consent-bridge')
  ).toBe(false);
  expect(harness.records.some(({ operation }) => operation === 'admin-consent-auto')).toBe(false);
  expect(
    harness.records.some(({ operation }) => operation === 'admin-token-authorization-code')
  ).toBe(false);
};

const expectAdminIntermediateRejection = async (
  options: AdminHarnessOptions,
  expectation: AdminIntermediateExpectation
): Promise<void> => {
  const {
    expectedMessage,
    forbiddenValues,
    absentOperations,
    unregisteredValues = [],
  } = expectation;
  const signer = await createAdminTestSigner();
  const harness = createAdminScenarioHarness({
    jwk: signer.jwk,
    tokens: { initial: {} },
    ...options,
  });
  const caught: unknown = await runConsoleAdminAuthResourceRefresh(harness.context, {
    random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
  }).then(
    () => new Error('Expected the intermediate admin authorization step to be rejected'),
    (error: unknown) => error
  );

  expect(caught).toBeInstanceOf(Error);
  expect((caught as Error).message).toBe(expectedMessage);
  expect(String(caught)).toBe(`Error: ${expectedMessage}`);
  for (const value of forbiddenValues) {
    expect(inspect(caught, { depth: null })).not.toContain(value);
    expect(String(caught)).not.toContain(value);
  }
  for (const value of unregisteredValues) {
    expect(() => {
      harness.store.assertNoCredentialMaterial(value);
    }).not.toThrow();
  }
  for (const operation of absentOperations) {
    expect(harness.records.some((record) => record.operation === operation)).toBe(false);
  }
};

describe('console.admin-auth-resource-refresh', () => {
  it('derives candidate marker enforcement from the scenario profile', async () => {
    const signer = await createAdminTestSigner();
    const harness = createAdminScenarioHarness({ jwk: signer.jwk, tokens: { initial: {} } });
    const candidateContext = {
      ...harness.context,
      profile: {
        fixtures: {
          adminTenant: { operator: harness.context.profile.fixtures.adminTenant.operator },
          dataTenant: {
            browserClientConfiguration: { localStorageKey: 'aster:demo-app:dev:config' },
          },
        },
      },
    } as unknown as typeof harness.context;
    const normalizationContext = createPositiveAdminNormalizationContext(candidateContext);

    expect(normalizationContext.nativeSurfaceImplementation).toBe('candidate');
    expect(
      normalizeHeaders([['aster-core-request-id', 'abcdefghijklmnop']], normalizationContext)
    ).toEqual({ 'aster-core-request-id': ['<per-request-id>'] });
    expect(() =>
      normalizeHeaders([['logto-core-request-id', 'abcdefghijklmnop']], normalizationContext)
    ).toThrow('Invalid phase 1 headers');
  });

  it('sanitizes noncompliant state and resume cookie values before projecting authorization', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const rawStateCookie = '_logto={"appId":"admin-console"}; Path=/; SameSite=Lax';
    const rawInteractionCookie = `_interaction=private-admin-interaction-cookie; Path=/oidc/auth/${adminSecrets.resume}; HttpOnly; SameSite=Lax`;
    const rawInteractionSignatureCookie = `_interaction.sig=private-admin-interaction-signature; Path=/oidc/auth/${adminSecrets.resume}; HttpOnly; SameSite=Lax`;
    const rawResumeCookie = `_interaction_resume=${adminSecrets.resume}; Path=/oidc/auth/${adminSecrets.resume}; HttpOnly; SameSite=Lax`;
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
      },
      authorizeSetCookieHeaders: [
        rawStateCookie,
        rawInteractionCookie,
        rawInteractionSignatureCookie,
        rawResumeCookie,
      ],
    });
    const output = await withPositiveAdminSession(
      harness.context,
      {
        random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
        captureAuthorize: true,
        captureCodeToken: false,
      },
      async () => null
    );
    const authorize = output.steps[0]?.value;
    const authorizeCookies = harness.authorizeCookieSnapshots[0];

    expect(cookiePairs(authorizeCookies?.root)).toEqual(['_logto={"appId":"admin-console"}']);
    expect(cookiePairs(authorizeCookies?.resume)).toEqual([
      '_interaction.sig=private-admin-interaction-signature',
      '_interaction=private-admin-interaction-cookie',
      '_interaction_resume=private-admin-resume',
      '_logto={"appId":"admin-console"}',
    ]);
    expect(
      cookiePairs(harness.store.getCookieHeader(new URL('/', adminTestTarget.adminUrl)))
    ).toContain('_logto={"appId":"admin-console"}');
    expect(
      cookiePairs(
        harness.records.find(({ operation }) => operation === 'admin-experience-bootstrap')?.cookie
      )
    ).toContain('_logto={"appId":"admin-console"}');

    expect(authorize?.cookies).toEqual([
      {
        name: '_aster',
        path: '/',
        httpOnly: false,
        secure: false,
        sameSite: 'Lax',
        extensions: [],
      },
      {
        name: '_interaction',
        path: '/oidc/auth/aster-cookie-attribute-value',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
        extensions: [],
      },
      {
        name: '_interaction.sig',
        path: '/oidc/auth/aster-cookie-attribute-value',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
        extensions: [],
      },
      {
        name: '_interaction_resume',
        path: '/oidc/auth/aster-cookie-attribute-value',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
        extensions: [],
      },
    ]);
    expect(authorize?.headers['set-cookie']).toEqual(authorize?.cookies);
    const serialized = JSON.stringify(output.steps);

    expect(serialized).toContain('"name":"_aster"');
    expect(serialized).toContain('"name":"_interaction"');
    expect(serialized).toContain('"name":"_interaction.sig"');
    expect(serialized).toContain('"name":"_interaction_resume"');
    expect(serialized).not.toContain('{"appId":"admin-console"}');
    expect(serialized).not.toContain('private-admin-interaction-cookie');
    expect(serialized).not.toContain('private-admin-interaction-signature');
    expect(serialized).not.toContain(adminSecrets.resume);
  });

  it('rejects a malformed cookie name before projecting authorization', async () => {
    const signer = await createAdminTestSigner();
    const rawCookieValue = 'private-admin-state-cookie';
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: { initial: {} },
      authorizeSetCookieHeaders: [`_logto =${rawCookieValue}; Path=/; SameSite=Lax`],
    });
    const caught: unknown = await withPositiveAdminSession(
      harness.context,
      {
        random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
        captureAuthorize: true,
        captureCodeToken: false,
      },
      async () => null
    ).then(
      () => new Error('Expected the malformed admin authorization cookie to be rejected'),
      (error: unknown) => error
    );

    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe('Invalid phase 1 HTTP projection');
    expect(inspect(caught, { depth: null })).not.toContain(rawCookieValue);
    expect(String(caught)).not.toContain(rawCookieValue);
    expect(
      harness.records.some(({ operation }) => operation === 'admin-experience-bootstrap')
    ).toBe(false);
  });

  it.each(initialResponseScopeMutants)(
    'rejects an initial token response %s',
    async (_name, responseScope) => {
      const signer = await createAdminTestSigner();
      const now = Math.floor(Date.now() / 1000);
      const idToken = await signer.sign({
        iss: `${adminTestTarget.adminUrl}oidc`,
        sub: adminRuntime.userId,
        aud: 'admin-console',
        iat: now,
        exp: now + 3600,
      });
      const harness = createAdminScenarioHarness({
        jwk: signer.jwk,
        tokens: {
          initial: tokenBody(
            adminSecrets.initialAccess,
            idToken,
            adminSecrets.initialRefresh,
            responseScope
          ),
        },
      });

      await expect(
        withPositiveAdminSession(
          harness.context,
          {
            random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
          },
          async () => null
        )
      ).rejects.toThrow('Phase 1 admin authorization code exchange failed');
    }
  );

  it('issues, rotates, and privately installs a signature-valid Account-resource token', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const accountAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'https://admin.logto.app/me',
      client_id: 'admin-console',
      scope: 'all',
      iat: now + 1,
      exp: now + 3601,
    });
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        accountAuthority: tokenBody(
          accountAccess,
          idToken,
          adminSecrets.accountAuthorityRefresh,
          'all'
        ),
      },
    });

    await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async (session) => {
        await refreshPositiveAdminAccountResourceToken(harness.context, session);
        expect(readPositiveAdminSession(session).refreshToken).toBe(
          adminSecrets.accountAuthorityRefresh
        );

        return null;
      }
    );

    const refresh = harness.records.find(
      ({ operation }) => operation === 'admin-token-account-authority-refresh'
    );
    expect(requestForm(refresh)).toEqual({
      client_id: 'admin-console',
      refresh_token: adminSecrets.initialRefresh,
      grant_type: 'refresh_token',
      resource: 'https://admin.logto.app/me',
    });
    expect(requestContentType(refresh)).toBe('application/x-www-form-urlencoded');
    expect(harness.store.getToken('authority-wrong-audience')).toBe(accountAccess);
    expect(harness.dataStore.getToken('authority-wrong-audience')).toBeUndefined();
  });

  it.each(['signature', 'issuer', 'audience', 'scope'] as const)(
    'rejects an Account-resource authority token with invalid %s',
    async (invalidField) => {
      const signer = await createAdminTestSigner();
      const foreignSigner = await createAdminTestSigner();
      const now = Math.floor(Date.now() / 1000);
      const idToken = await signer.sign({
        iss: `${adminTestTarget.adminUrl}oidc`,
        sub: adminRuntime.userId,
        aud: 'admin-console',
        iat: now,
        exp: now + 3600,
      });
      const accountAccess = await (invalidField === 'signature' ? foreignSigner : signer).sign({
        iss:
          invalidField === 'issuer'
            ? `${adminTestTarget.coreUrl}oidc`
            : `${adminTestTarget.adminUrl}oidc`,
        sub: adminRuntime.userId,
        aud:
          invalidField === 'audience'
            ? 'https://default.logto.app/api'
            : 'https://admin.logto.app/me',
        client_id: 'admin-console',
        scope: invalidField === 'scope' ? '' : 'all',
        iat: now + 1,
        exp: now + 3601,
      });
      const harness = createAdminScenarioHarness({
        jwk: signer.jwk,
        tokens: {
          initial: tokenBody(
            adminSecrets.initialAccess,
            idToken,
            adminSecrets.initialRefresh,
            adminInitialResponseScope
          ),
          accountAuthority: tokenBody(
            accountAccess,
            idToken,
            adminSecrets.accountAuthorityRefresh,
            'all'
          ),
        },
      });

      await withPositiveAdminSession(
        harness.context,
        { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
        async (session) => {
          const before = readPositiveAdminSession(session);

          await expect(
            refreshPositiveAdminAccountResourceToken(harness.context, session)
          ).rejects.toThrow();
          expect(readPositiveAdminSession(session)).toEqual(before);
          expect(harness.store.getToken('authority-wrong-audience')).toBeUndefined();

          return null;
        }
      );
    }
  );

  it('issues, rotates, and installs a signature-valid empty-scope Management token', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const managementAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'https://default.logto.app/api',
      client_id: 'admin-console',
      scope: '',
      iat: now + 1,
      exp: now + 3601,
    });
    const replacementRefresh = 'private-admin-management-missing-scope-refresh';
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      includeDataAllocation: true,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        managementMissingScope: tokenBody(managementAccess, idToken, replacementRefresh, ''),
      },
    });

    await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async (session) => {
        await refreshPositiveAdminManagementTokenWithoutAllScope(harness.context, session);
        expect(readPositiveAdminSession(session).refreshToken).toBe(replacementRefresh);

        return null;
      }
    );

    const refresh = harness.records.find(
      ({ operation }) => operation === 'admin-token-management-missing-scope-refresh'
    );
    expect(requestForm(refresh)).toEqual({
      client_id: 'admin-console',
      refresh_token: adminSecrets.initialRefresh,
      grant_type: 'refresh_token',
      resource: 'https://default.logto.app/api',
      scope: 'openid',
    });
    expect(requestContentType(refresh)).toBe('application/x-www-form-urlencoded');
    expect(harness.store.getToken('management-missing-scope')).toBeUndefined();
    expect(harness.dataStore.getToken('management-missing-scope')).toBe(managementAccess);
  });

  it.each(['signature', 'issuer', 'audience', 'claim-scope', 'response-scope'] as const)(
    'rejects a missing-scope Management token with invalid %s authority',
    async (invalidField) => {
      const signer = await createAdminTestSigner();
      const foreignSigner = await createAdminTestSigner();
      const now = Math.floor(Date.now() / 1000);
      const idToken = await signer.sign({
        iss: `${adminTestTarget.adminUrl}oidc`,
        sub: adminRuntime.userId,
        aud: 'admin-console',
        iat: now,
        exp: now + 3600,
      });
      const managementAccess = await (invalidField === 'signature' ? foreignSigner : signer).sign({
        iss:
          invalidField === 'issuer'
            ? `${adminTestTarget.coreUrl}oidc`
            : `${adminTestTarget.adminUrl}oidc`,
        sub: adminRuntime.userId,
        aud:
          invalidField === 'audience'
            ? 'https://admin.logto.app/me'
            : 'https://default.logto.app/api',
        client_id: 'admin-console',
        scope: invalidField === 'claim-scope' ? 'all' : '',
        iat: now + 1,
        exp: now + 3601,
      });
      const harness = createAdminScenarioHarness({
        jwk: signer.jwk,
        includeDataAllocation: true,
        tokens: {
          initial: tokenBody(
            adminSecrets.initialAccess,
            idToken,
            adminSecrets.initialRefresh,
            adminInitialResponseScope
          ),
          managementMissingScope: tokenBody(
            managementAccess,
            idToken,
            'private-admin-invalid-management-refresh',
            invalidField === 'response-scope' ? 'all' : ''
          ),
        },
      });

      await expect(
        withPositiveAdminSession(
          harness.context,
          {
            random: {
              codeVerifier: () => adminSecrets.verifier,
              state: () => adminSecrets.state,
            },
          },
          async (session) => {
            await refreshPositiveAdminManagementTokenWithoutAllScope(harness.context, session);

            return null;
          }
        )
      ).rejects.toThrow('Phase 1 admin session consumer failed');
      expect(harness.dataStore.getToken('management-missing-scope')).toBeUndefined();
    }
  );

  it('rotates an access-only downscoped UserInfo token and rejects stale reuse', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const opaqueAccess = 'opaque-profile-only-access';
    const replacementRefresh = 'profile-only-refresh';
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        userinfoMissingOpenId: {
          access_token: opaqueAccess,
          refresh_token: replacementRefresh,
          token_type: 'Bearer',
          expires_in: 3600,
          scope: 'profile',
        },
      },
    });

    await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async (session) => {
        await refreshPositiveAdminUserInfoTokenWithoutOpenId(harness.context, session);
        expect(readPositiveAdminSession(session).refreshToken).toBe(replacementRefresh);
        expect(harness.store.getToken('userinfo-missing-openid')).toBe(opaqueAccess);
        expect(() => {
          assertPositiveAdminRefreshTokenIsFresh(session, replacementRefresh, [opaqueAccess]);
        }).toThrow('Phase 1 admin refresh token was not rotated');

        return null;
      }
    );
  });

  it.each([
    ['missing', undefined],
    ['zero', 0],
    ['noninteger', 1.5],
    ['wrong type', '3600'],
  ] as const)('rejects a UserInfo token response with %s expires_in', async (_name, expiresIn) => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const invalidTokenBody = {
      access_token: 'opaque-profile-only-access',
      refresh_token: 'profile-only-refresh',
      token_type: 'Bearer',
      scope: 'profile',
      ...(expiresIn === undefined ? {} : { expires_in: expiresIn }),
    };
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        userinfoMissingOpenId: invalidTokenBody,
      },
    });

    await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async (session) => {
        const before = readPositiveAdminSession(session);

        await expect(
          refreshPositiveAdminUserInfoTokenWithoutOpenId(harness.context, session)
        ).rejects.toThrow('Phase 1 admin UserInfo missing-openid refresh failed');
        expect(readPositiveAdminSession(session)).toEqual(before);
        expect(harness.store.getToken('userinfo-missing-openid')).toBeUndefined();

        return null;
      }
    );
  });

  it('refreshes the exact default Management resource token', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const managementAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'https://default.logto.app/api',
      client_id: 'admin-console',
      scope: 'all',
      iat: now + 1,
      exp: now + 3601,
    });
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        management: tokenBody(managementAccess, idToken, adminSecrets.managementRefresh, 'all'),
      },
    });
    const steps = await runConsoleAdminAuthResourceRefresh(harness.context, {
      random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'authorize',
      'code-token',
      'management-refresh',
      'state',
    ]);
    expect(harness.records.map(({ client, operation }) => `${client}:${operation}`)).toEqual([
      'oidc:admin-authorization-start',
      'experience:admin-experience-bootstrap',
      'experience:admin-experience-password',
      'experience:admin-experience-identify',
      'experience:admin-experience-submit',
      'oidc:admin-authorization-consent-bridge',
      'oidc:admin-consent-auto',
      'oidc:admin-authorization-resume',
      'oidc:admin-token-authorization-code',
      'oidc:admin-token-jwks',
      'oidc:admin-token-management-refresh',
      'oidc:admin-token-jwks',
    ]);
    const authorize = new URL(harness.records[0]!.path, adminTestTarget.adminUrl);
    expect(authorize.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authorize.searchParams.get('code_challenge')).toBe(
      createHash('sha256').update(adminSecrets.verifier).digest('base64url')
    );
    expect(authorize.searchParams.get('scope')).toBe(adminRequestedScope);
    expect(adminRequestedScope.split(' ')).toContain('all');
    expect(adminInitialResponseScope.split(' ')).not.toContain('all');
    expect(adminInitialResponseScope).not.toBe(adminRequestedScope);
    expect(authorize.searchParams.get('scope')?.split(' ')).toEqual([
      'openid',
      'offline_access',
      'profile',
      'email',
      'phone',
      'identities',
      'custom_data',
      'urn:logto:scope:organizations',
      'urn:logto:scope:organization_roles',
      'all',
    ]);
    expect(authorize.searchParams.getAll('resource')).toEqual([
      'https://default.logto.app/api',
      'https://admin.logto.app/me',
      'urn:logto:resource:organizations',
    ]);
    expect(
      requestForm(
        harness.records.find(({ operation }) => operation === 'admin-token-authorization-code')
      )
    ).toEqual({
      client_id: 'admin-console',
      code: adminSecrets.code,
      code_verifier: adminSecrets.verifier,
      redirect_uri: `${adminTestTarget.adminUrl}console/callback`,
      grant_type: 'authorization_code',
    });
    const managementRefresh = harness.records.find(
      ({ operation }) => operation === 'admin-token-management-refresh'
    );
    expect(requestForm(managementRefresh)).toEqual({
      client_id: 'admin-console',
      refresh_token: adminSecrets.initialRefresh,
      grant_type: 'refresh_token',
      resource: 'https://default.logto.app/api',
    });
    expect(requestContentType(managementRefresh)).toBe('application/x-www-form-urlencoded');
    const consentAuto = harness.records.find(({ operation }) => operation === 'admin-consent-auto');
    const consentBridge = harness.records.find(
      ({ operation }) => operation === 'admin-authorization-consent-bridge'
    );
    const consentResume = harness.records.find(
      ({ operation }) => operation === 'admin-authorization-resume'
    );

    expect(consentAuto?.path).toBe('consent?app_id=admin-console');
    expect(consentAuto?.options?.method).toBe('GET');
    expect(consentAuto?.options?.includeCookies).toBe(true);
    expect(cookiePairs(consentAuto?.cookie)).toEqual([
      '_interaction.sig=private-admin-consent-cookie-signature',
      '_interaction=private-admin-consent-cookie',
    ]);
    expect(cookiePairs(consentAuto?.cookie)).not.toContain('_interaction=private-admin-cookie');
    expect(cookiePairs(consentAuto?.cookie)).not.toContain(
      '_interaction.sig=private-admin-cookie-signature'
    );
    expect(consentBridge?.options?.method).toBe('GET');
    expect(consentBridge?.options?.includeCookies).toBe(true);
    expect(cookiePairs(consentBridge?.cookie)).toEqual([
      '_interaction.sig=private-admin-cookie-signature',
      '_interaction=private-admin-cookie',
      `_interaction_resume=${adminSecrets.resume}`,
    ]);
    expect(cookiePairs(consentResume?.cookie)).toEqual([
      '_interaction.sig=private-admin-consent-cookie-signature',
      '_interaction=private-admin-consent-cookie',
      `_interaction_resume=${adminSecrets.consentResume}`,
    ]);
    expect(cookiePairs(consentResume?.cookie)).not.toContain('_interaction=private-admin-cookie');
    expect(cookiePairs(consentResume?.cookie)).not.toContain(
      '_interaction.sig=private-admin-cookie-signature'
    );
    expect(consentResume?.options?.method).toBe('GET');
    expect(consentResume?.options?.includeCookies).toBe(true);
    expect(harness.store.getToken('management')).toBeUndefined();
    expect(harness.dataStore.getToken('management')).toBeUndefined();
    expect(steps[1]?.value).toMatchObject({
      body: {
        tokenType: 'Bearer',
        access: { format: 'opaque' },
        id: { format: 'jwt' },
        refresh: { format: 'opaque', present: true },
      },
      tokens: [],
    });
    expect(steps[2]?.value.tokens[0]).toMatchObject({
      kind: 'access',
      format: 'jwt',
      signatureVerified: true,
      claims: {
        sub: '<user.phase1-admin>',
        aud: 'urn:aster:resource:management',
        client_id: '<application.admin-console>',
        scope: 'all',
      },
    });
    expect(steps[3]?.value).toMatchObject({
      generatedIds: { tokenFamily: '<token-family.1>' },
      persistedState: {
        grantConsumed: true,
        familyCount: 1,
        rotation: { replaced: true, sameFamily: true },
        unrelatedMutation: false,
      },
    });
    expect(JSON.stringify(steps)).not.toMatch(/private-admin|vvvvvvvv/u);
  });

  it('installs the Management token only for fullPhase1 data consumers', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const managementAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'https://default.logto.app/api',
      client_id: 'admin-console',
      scope: 'all',
      iat: now,
      exp: now + 3600,
    });
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      includeDataAllocation: true,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        management: tokenBody(managementAccess, idToken, adminSecrets.managementRefresh, 'all'),
      },
    });

    await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async (session) => refreshPositiveAdminManagementToken(harness.context, session)
    );

    expect(harness.store.getToken('management')).toBeUndefined();
    expect(harness.dataStore.getToken('management')).toBe(managementAccess);
  });

  it.each([200, 302, 307, 308])('rejects an admin consent bridge with HTTP %i', async (status) => {
    await expectAdminIntermediateRejection(
      { consentBridgeStatus: status },
      {
        expectedMessage: 'Phase 1 admin authorization consent bridge failed',
        forbiddenValues: [adminSecrets.code, adminSecrets.state],
        absentOperations: [
          'admin-consent-auto',
          'admin-authorization-resume',
          'admin-token-authorization-code',
        ],
      }
    );
  });

  it.each([
    ['missing Location', []],
    ['duplicate Location', [adminConsentBridgeLocation(), adminConsentBridgeLocation()]],
  ] as const)('rejects an admin consent bridge with %s', async (_name, locations) => {
    await expectAdminIntermediateRejection(
      { consentBridgeLocations: locations },
      {
        expectedMessage: 'Phase 1 admin consent bridge redirect is invalid',
        forbiddenValues: [adminSecrets.code, adminSecrets.state],
        absentOperations: [
          'admin-consent-auto',
          'admin-authorization-resume',
          'admin-token-authorization-code',
        ],
      }
    );
  });

  it.each([
    [
      'missing app_id',
      (bridge: URL) => {
        bridge.searchParams.delete('app_id');
        return bridge.href;
      },
    ],
    [
      'empty app_id',
      (bridge: URL) => {
        bridge.searchParams.set('app_id', '');
        return bridge.href;
      },
    ],
    [
      'wrong app_id',
      (bridge: URL) => {
        bridge.searchParams.set('app_id', 'wrong-admin-client');
        return bridge.href;
      },
    ],
    [
      'duplicate app_id',
      (bridge: URL) => {
        bridge.searchParams.append('app_id', 'second-admin-client');
        return bridge.href;
      },
    ],
    [
      'wrong origin',
      (bridge: URL) => {
        bridge.hostname = 'attacker.example';
        return bridge.href;
      },
    ],
    [
      'scheme downgrade',
      (bridge: URL) => {
        bridge.protocol = 'http:';
        return bridge.href;
      },
    ],
    [
      'wrong port',
      (bridge: URL) => {
        bridge.port = '444';
        return bridge.href;
      },
    ],
    [
      'wrong path',
      (bridge: URL) => {
        bridge.pathname = '/wrong-consent';
        return bridge.href;
      },
    ],
    [
      'fragment',
      (bridge: URL) => {
        bridge.hash = 'unexpected';
        return bridge.href;
      },
    ],
    [
      'username',
      (bridge: URL) => {
        bridge.username = 'unexpected-user';
        return bridge.href;
      },
    ],
    [
      'password',
      (bridge: URL) => {
        bridge.password = 'unexpected-password';
        return bridge.href;
      },
    ],
    [
      'extra parameter',
      (bridge: URL) => {
        bridge.searchParams.set('unexpected', 'value');
        return bridge.href;
      },
    ],
    ['query-only relative Location', (bridge: URL) => bridge.search],
    ['path-relative Location', (bridge: URL) => `consent${bridge.search}`],
  ] as const)('rejects an admin consent bridge with %s', async (_name, mutate) => {
    const location = adminConsentBridgeLocation(mutate);

    await expectAdminIntermediateRejection(
      { consentBridgeLocations: [location] },
      {
        expectedMessage: 'Phase 1 admin consent bridge redirect is invalid',
        forbiddenValues: [location, adminSecrets.code, adminSecrets.state],
        absentOperations: [
          'admin-consent-auto',
          'admin-authorization-resume',
          'admin-token-authorization-code',
        ],
      }
    );
  });

  it.each([200, 303, 307, 308])('rejects admin auto-consent with HTTP %i', async (status) => {
    await expectAdminIntermediateRejection(
      { consentAutoStatus: status },
      {
        expectedMessage: 'Phase 1 admin auto-consent failed',
        forbiddenValues: [adminSecrets.code, adminSecrets.state],
        absentOperations: ['admin-authorization-resume', 'admin-token-authorization-code'],
      }
    );
  });

  it.each([
    ['missing Location', []],
    ['duplicate Location', [adminConsentResumeLocation(), adminConsentResumeLocation()]],
  ] as const)('rejects admin auto-consent with %s', async (_name, locations) => {
    await expectAdminIntermediateRejection(
      { consentResumeLocations: locations },
      {
        expectedMessage: 'Phase 1 admin consent resume redirect is invalid',
        forbiddenValues: [adminSecrets.code, adminSecrets.state],
        absentOperations: ['admin-authorization-resume', 'admin-token-authorization-code'],
      }
    );
  });

  it('rejects a consent resume credential reused from the login bridge', async () => {
    const signer = await createAdminTestSigner();
    const loginResumeLocation = `${adminTestTarget.adminUrl}oidc/auth/${adminSecrets.resume}`;
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: { initial: {} },
      consentResumeLocations: [loginResumeLocation],
    });
    const registerSecret = import.meta.jest.spyOn(harness.store, 'registerSecret');
    const expectedMessage = 'Phase 1 admin consent resume redirect is invalid';
    const caught: unknown = await runConsoleAdminAuthResourceRefresh(harness.context, {
      random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
    }).then(
      () => new Error('Expected the reused consent resume credential to be rejected'),
      (error: unknown) => error
    );

    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toBe(expectedMessage);
    expect(String(caught)).toBe(`Error: ${expectedMessage}`);
    expect(inspect(caught, { depth: null })).not.toContain(loginResumeLocation);
    expect(inspect(caught, { depth: null })).not.toContain(adminSecrets.resume);
    expect(
      harness.records.some(({ operation }) => operation === 'admin-authorization-resume')
    ).toBe(false);
    expect(
      harness.records.some(({ operation }) => operation === 'admin-token-authorization-code')
    ).toBe(false);
    expect(
      registerSecret.mock.calls.filter(([value]) => value === adminSecrets.resume)
    ).toHaveLength(2);
  });

  it.each([
    [
      'wrong origin',
      (resume: URL) => {
        resume.hostname = 'attacker.example';
        return resume.href;
      },
    ],
    [
      'scheme downgrade',
      (resume: URL) => {
        resume.protocol = 'http:';
        return resume.href;
      },
    ],
    [
      'wrong port',
      (resume: URL) => {
        resume.port = '444';
        return resume.href;
      },
    ],
    [
      'wrong path',
      (resume: URL) => {
        resume.pathname = '/wrong-resume';
        return resume.href;
      },
    ],
    [
      'query',
      (resume: URL) => {
        resume.searchParams.set('unexpected', 'value');
        return resume.href;
      },
    ],
    [
      'fragment',
      (resume: URL) => {
        resume.hash = 'unexpected';
        return resume.href;
      },
    ],
    [
      'username',
      (resume: URL) => {
        resume.username = 'unexpected-user';
        return resume.href;
      },
    ],
    [
      'password',
      (resume: URL) => {
        resume.password = 'unexpected-password';
        return resume.href;
      },
    ],
  ] as const)('rejects an admin consent resume URL containing a %s', async (_name, mutate) => {
    const location = adminConsentResumeLocation(mutate);

    await expectAdminIntermediateRejection(
      { consentResumeLocations: [location] },
      {
        expectedMessage: 'Phase 1 admin consent resume redirect is invalid',
        forbiddenValues: [location, adminSecrets.code, adminSecrets.state],
        absentOperations: ['admin-authorization-resume', 'admin-token-authorization-code'],
      }
    );
  });

  it.each([
    ['a malformed percent escape', 'private%GGconsent-resume', 'private%GGconsent-resume'],
    ['a decoded control character', 'private%00consent-resume', 'private\u0000consent-resume'],
    ['an encoded slash', 'private%2Fconsent-resume', 'private/consent-resume'],
    ['an encoded backslash', 'private%5Cconsent-resume', 'private\\consent-resume'],
  ] as const)(
    'rejects an admin consent resume URL containing %s',
    async (_name, encodedCredential, decodedCredential) => {
      const location = `${adminTestTarget.adminUrl}oidc/auth/${encodedCredential}`;

      await expectAdminIntermediateRejection(
        { consentResumeLocations: [location] },
        {
          expectedMessage: 'Phase 1 admin consent resume redirect is invalid',
          forbiddenValues: [location, encodedCredential, adminSecrets.code, adminSecrets.state],
          absentOperations: ['admin-authorization-resume', 'admin-token-authorization-code'],
          unregisteredValues: [encodedCredential, decodedCredential],
        }
      );
    }
  );

  it.each([
    [
      'missing code',
      (callback: URL) => {
        callback.searchParams.delete('code');
        return callback.href;
      },
    ],
    [
      'empty code',
      (callback: URL) => {
        callback.searchParams.set('code', '');
        return callback.href;
      },
    ],
    [
      'duplicate code',
      (callback: URL) => {
        callback.searchParams.append('code', 'second-code');
        return callback.href;
      },
    ],
    [
      'missing state',
      (callback: URL) => {
        callback.searchParams.delete('state');
        return callback.href;
      },
    ],
    [
      'empty state',
      (callback: URL) => {
        callback.searchParams.set('state', '');
        return callback.href;
      },
    ],
    [
      'wrong state',
      (callback: URL) => {
        callback.searchParams.set('state', 'wrong-state');
        return callback.href;
      },
    ],
    [
      'duplicate state',
      (callback: URL) => {
        callback.searchParams.append('state', 'second-state');
        return callback.href;
      },
    ],
    [
      'missing issuer',
      (callback: URL) => {
        callback.searchParams.delete('iss');
        return callback.href;
      },
    ],
    [
      'empty issuer',
      (callback: URL) => {
        callback.searchParams.set('iss', '');
        return callback.href;
      },
    ],
    [
      'wrong issuer',
      (callback: URL) => {
        callback.searchParams.set('iss', 'https://wrong.example/oidc');
        return callback.href;
      },
    ],
    [
      'duplicate issuer',
      (callback: URL) => {
        callback.searchParams.append('iss', 'second-issuer');
        return callback.href;
      },
    ],
    [
      'wrong origin',
      (callback: URL) => {
        callback.hostname = 'attacker.example';
        return callback.href;
      },
    ],
    [
      'scheme downgrade',
      (callback: URL) => {
        callback.protocol = 'http:';
        return callback.href;
      },
    ],
    [
      'wrong port',
      (callback: URL) => {
        callback.port = '444';
        return callback.href;
      },
    ],
    [
      'wrong path',
      (callback: URL) => {
        callback.pathname = '/wrong-callback';
        return callback.href;
      },
    ],
    [
      'fragment',
      (callback: URL) => {
        callback.hash = 'unexpected';
        return callback.href;
      },
    ],
    [
      'username',
      (callback: URL) => {
        callback.username = 'unexpected-user';
        return callback.href;
      },
    ],
    [
      'password',
      (callback: URL) => {
        callback.password = 'unexpected-password';
        return callback.href;
      },
    ],
    [
      'extra parameter',
      (callback: URL) => {
        callback.searchParams.set('unexpected', 'value');
        return callback.href;
      },
    ],
    ['query-only relative Location', (callback: URL) => `${callback.search}${callback.hash}`],
    [
      'path-relative Location',
      (callback: URL) => `console/callback${callback.search}${callback.hash}`,
    ],
  ] as const)('rejects callback locations with %s', async (_name, mutate) => {
    const location = adminCallbackLocation(mutate);

    await expectAdminCallbackRejection({ callbackLocations: [location] }, [
      location,
      adminSecrets.code,
      adminSecrets.state,
    ]);
  });

  it('rejects a callback code containing a decoded control character', async () => {
    const controlCode = 'private\u0000admin-code';
    const location = adminCallbackLocation((callback) => {
      callback.searchParams.set('code', controlCode);
      return callback.href;
    });

    await expectAdminCallbackRejection(
      { callbackLocations: [location] },
      [location, controlCode, adminSecrets.state],
      'Phase 1 admin authorization callback is invalid',
      [controlCode]
    );
  });

  it.each([
    ['HTTP 302 redirect', { resumeStatus: 302 }, 'Phase 1 admin authorization resume failed'],
    ['HTTP 307 redirect', { resumeStatus: 307 }, 'Phase 1 admin authorization resume failed'],
    ['HTTP 308 redirect', { resumeStatus: 308 }, 'Phase 1 admin authorization resume failed'],
    [
      'HTTP 200 form_post downgrade',
      {
        resumeStatus: 200,
        callbackLocations: [],
        resumeBody: `<form action="${adminTestTarget.adminUrl}console/callback"><input name="code" value="${adminSecrets.code}"><input name="state" value="${adminSecrets.state}"></form>`,
      },
      'Phase 1 admin authorization resume failed',
    ],
    [
      'missing Location',
      { callbackLocations: [] },
      'Phase 1 admin authorization callback is invalid',
    ],
    [
      'duplicate Location',
      { callbackLocations: [adminCallbackLocation(), adminCallbackLocation()] },
      'Phase 1 admin authorization callback is invalid',
    ],
  ] as const)('rejects a resume response with %s', async (_name, options, expectedMessage) => {
    const callbackOptions: CallbackHarnessOptions = options;
    const forbiddenValues = callbackOptions.resumeBody
      ? [adminSecrets.code, adminSecrets.state, callbackOptions.resumeBody]
      : [adminSecrets.code, adminSecrets.state];

    await expectAdminCallbackRejection(callbackOptions, forbiddenValues, expectedMessage);
  });

  it('accepts a root-relative callback Location resolved against the resume origin', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const rootRelativeCallback = adminCallbackLocation(
      (callback) => `${callback.pathname}${callback.search}`
    );
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
      },
      callbackLocations: [rootRelativeCallback],
      consentResumeLocations: [`/oidc/auth/${adminSecrets.consentResume}`],
    });

    await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async () => null
    );

    expect(
      harness.records.some(({ operation }) => operation === 'admin-token-authorization-code')
    ).toBe(true);
  });

  it('preserves non-slug opaque callback and resume credentials', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const callbackCode = "opaque+code/=~:@!$&'()*";
    const loginResumeCredential = "opaque!$&'()*+,;=:@~login-resume";
    const consentResumeCredential = "opaque!$&'()*+,;=:@~consent-resume";
    const encodedLoginResumeCredential = encodeURIComponent(loginResumeCredential);
    const encodedConsentResumeCredential = encodeURIComponent(consentResumeCredential);
    const callbackLocation = adminCallbackLocation((callback) => {
      callback.searchParams.set('code', callbackCode);
      return callback.href;
    });
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
      },
      callbackLocations: [callbackLocation],
      resumeRedirectTo: `${adminTestTarget.adminUrl}oidc/auth/${encodedLoginResumeCredential}`,
      consentResumeLocations: [
        `${adminTestTarget.adminUrl}oidc/auth/${encodedConsentResumeCredential}`,
      ],
    });

    await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async () => null
    );

    expect(
      harness.records.find(({ operation }) => operation === 'admin-authorization-consent-bridge')
        ?.path
    ).toBe(`oidc/auth/${encodedLoginResumeCredential}`);
    expect(
      harness.records.find(({ operation }) => operation === 'admin-authorization-resume')?.path
    ).toBe(`oidc/auth/${encodedConsentResumeCredential}`);
    expect(
      requestForm(
        harness.records.find(({ operation }) => operation === 'admin-token-authorization-code')
      ).code
    ).toBe(callbackCode);
  });

  it.each(['username', 'password'] as const)(
    'rejects an interaction resume URL containing a %s',
    async (component) => {
      const resumeUrl = new URL(`${adminTestTarget.adminUrl}oidc/auth/${adminSecrets.resume}`);
      const embeddedCredential = `embedded-${component}`;

      resumeUrl[component] = embeddedCredential;

      await expectAdminResumeRedirectRejection(
        resumeUrl.href,
        [resumeUrl.href, embeddedCredential],
        [embeddedCredential]
      );
    }
  );

  it.each([
    ['a malformed percent escape', 'private%GGresume', 'private%GGresume'],
    ['a decoded control character', 'private%00resume', 'private\u0000resume'],
    ['an encoded slash', 'private%2Fresume', 'private/resume'],
    ['an encoded backslash', 'private%5Cresume', 'private\\resume'],
  ] as const)(
    'rejects an interaction resume credential containing %s',
    async (_name, encodedCredential, decodedCredential) => {
      const resumeRedirectTo = `${adminTestTarget.adminUrl}oidc/auth/${encodedCredential}`;

      await expectAdminResumeRedirectRejection(
        resumeRedirectTo,
        [resumeRedirectTo, encodedCredential, decodedCredential],
        [encodedCredential, decodedCredential]
      );
    }
  );

  it('rejects an initial ID token that is not valid yet', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      nbf: now + 3600,
      exp: now + 7200,
    });
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
      },
    });

    await expect(
      runConsoleAdminAuthResourceRefresh(harness.context, {
        random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
      })
    ).rejects.toThrow('Phase 1 admin code token claims are invalid');
    expect(harness.store.getToken('management')).toBeUndefined();
  });

  it('rejects private JWK material on a hidden Management refresh', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const managementAccess = await signer.sign(
      {
        iss: `${adminTestTarget.adminUrl}oidc`,
        sub: adminRuntime.userId,
        aud: 'https://default.logto.app/api',
        client_id: 'admin-console',
        scope: 'all',
        iat: now,
        exp: now + 3600,
      },
      { jwk: { kty: 'EC', d: 'private-key-material' } }
    );
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      includeDataAllocation: true,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        management: tokenBody(managementAccess, idToken, adminSecrets.managementRefresh, 'all'),
      },
    });

    const output = await withPositiveAdminSession(
      harness.context,
      { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
      async (session) => {
        await expect(refreshPositiveAdminManagementToken(harness.context, session)).rejects.toThrow(
          'Phase 1 admin Management token claims are invalid'
        );
        expect(readPositiveAdminSession(session).refreshToken).toBe(adminSecrets.initialRefresh);

        return true;
      }
    );
    expect(output.result).toBe(true);
    expect(harness.dataStore.getToken('management')).toBeUndefined();
  });

  it('rejects organization coupling on a default Management resource token', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const managementAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'https://default.logto.app/api',
      client_id: 'admin-console',
      scope: 'all',
      organization_id: 't-default',
      iat: now,
      exp: now + 3600,
    });
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      includeDataAllocation: true,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        management: tokenBody(managementAccess, idToken, adminSecrets.managementRefresh, 'all'),
      },
    });

    await expect(
      withPositiveAdminSession(
        harness.context,
        { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
        async (session) => refreshPositiveAdminManagementToken(harness.context, session)
      )
    ).rejects.toThrow('Phase 1 admin session consumer failed');
    expect(harness.dataStore.getToken('management')).toBeUndefined();
  });

  it('rejects a refresh token that aliases an earlier session credential', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const managementAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'https://default.logto.app/api',
      client_id: 'admin-console',
      scope: 'all',
      iat: now,
      exp: now + 3600,
    });
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      includeDataAllocation: true,
      tokens: {
        initial: tokenBody(
          adminSecrets.initialAccess,
          idToken,
          adminSecrets.initialRefresh,
          adminInitialResponseScope
        ),
        management: tokenBody(managementAccess, idToken, adminSecrets.initialAccess, 'all'),
      },
    });

    await expect(
      withPositiveAdminSession(
        harness.context,
        { random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state } },
        async (session) => refreshPositiveAdminManagementToken(harness.context, session)
      )
    ).rejects.toThrow('Phase 1 admin session consumer failed');
    expect(harness.dataStore.getToken('management')).toBeUndefined();
  });
});

/* eslint-enable @silverhand/fp/no-mutation */

/* eslint-enable max-lines */
