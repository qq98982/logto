import { createHash } from 'node:crypto';

import { runConsoleAdminAuthResourceRefresh } from './console-admin-auth-resource-refresh.js';
import { readPositiveAdminSession, withPositiveAdminSession } from './positive-admin-flow.js';
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
import { refreshPositiveAdminManagementToken } from './positive-admin-token.js';

const effectiveScope =
  'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all';

describe('console.admin-auth-resource-refresh', () => {
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
