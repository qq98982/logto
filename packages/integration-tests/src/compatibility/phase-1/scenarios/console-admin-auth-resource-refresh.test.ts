/* eslint-disable max-lines -- The focused admin authorization and refresh security matrix stays in one harness. */
import { createHash } from 'node:crypto';

import { runConsoleAdminAuthResourceRefresh } from './console-admin-auth-resource-refresh.js';
import {
  assertPositiveAdminRefreshTokenIsFresh,
  readPositiveAdminSession,
  withPositiveAdminSession,
} from './positive-admin-flow.js';
import {
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

const effectiveScope =
  'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all';

describe('console.admin-auth-resource-refresh', () => {
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
          effectiveScope
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
            effectiveScope
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
          effectiveScope
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
            effectiveScope
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
          effectiveScope
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
          effectiveScope
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
          effectiveScope
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
    expect(requestForm(harness.records[6])).toEqual({
      client_id: 'admin-console',
      code: adminSecrets.code,
      code_verifier: adminSecrets.verifier,
      redirect_uri: `${adminTestTarget.adminUrl}console/callback`,
      grant_type: 'authorization_code',
    });
    expect(requestForm(harness.records[8])).toEqual({
      client_id: 'admin-console',
      refresh_token: adminSecrets.initialRefresh,
      grant_type: 'refresh_token',
      resource: 'https://default.logto.app/api',
    });
    expect(requestContentType(harness.records[8])).toBe('application/x-www-form-urlencoded');
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
        aud: '<resource.admin.resource.1>',
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
          effectiveScope
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

  it('rejects callback inputs reassociated away from the submitted form', async () => {
    const signer = await createAdminTestSigner();
    const harness = createAdminScenarioHarness({
      jwk: signer.jwk,
      tokens: { initial: {} },
      callbackBody: `<!doctype html><form method="post" action="${adminTestTarget.adminUrl}console/callback"><input type="hidden" name="code" value="${adminSecrets.code}" form="other"><input type="hidden" name="state" value="${adminSecrets.state}"><input type="hidden" name="iss" value="${adminTestTarget.adminUrl}oidc"></form>`,
    });

    await expect(
      runConsoleAdminAuthResourceRefresh(harness.context, {
        random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
      })
    ).rejects.toThrow('Phase 1 admin authorization callback is invalid');
    expect(
      harness.records.some(({ operation }) => operation === 'admin-token-authorization-code')
    ).toBe(false);
  });

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
          effectiveScope
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
          effectiveScope
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
          effectiveScope
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
          effectiveScope
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

/* eslint-enable max-lines */
