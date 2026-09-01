import { runConsoleAdminOrganizationTokenRefresh } from './console-admin-organization-token-refresh.js';
import {
  adminRuntime,
  adminSecrets,
  adminTestTarget,
  createAdminScenarioHarness,
  createAdminTestSigner,
  requestForm,
  tokenBody,
} from './positive-admin-flow.test-helpers.js';

describe('console.admin-organization-token-refresh', () => {
  it('issues the fixed t-default empty-scope organization JWT', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const organizationAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'urn:logto:organization:t-default',
      client_id: 'admin-console',
      scope: '',
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
          'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all'
        ),
        organization: tokenBody(organizationAccess, idToken, adminSecrets.organizationRefresh, ''),
      },
    });
    const steps = await runConsoleAdminOrganizationTokenRefresh(harness.context, {
      random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
    });

    expect(steps.map(({ stepId }) => stepId)).toEqual(['organization-refresh', 'state']);
    expect(harness.stateReads).toEqual([
      'console.admin-organization-token-refresh:organization-refresh',
      'console.admin-organization-token-refresh:state',
    ]);
    const organizationRequest = harness.records.find(
      ({ operation }) => operation === 'admin-token-organization-refresh'
    );
    expect(requestForm(organizationRequest)).toEqual({
      client_id: 'admin-console',
      refresh_token: adminSecrets.initialRefresh,
      grant_type: 'refresh_token',
      organization_id: 't-default',
    });
    expect(organizationRequest?.options?.body).not.toMatch(/(?:^|&)resource=|(?:^|&)scope=/u);
    expect(steps[0]?.value).toMatchObject({
      body: { tokenType: 'Bearer', scope: '' },
      tokens: [
        {
          kind: 'access',
          format: 'jwt',
          signatureVerified: true,
          claims: {
            sub: '<user.phase1-admin>',
            aud: 'urn:logto:organization:t-default',
            client_id: '<application.admin-console>',
            scope: '',
          },
        },
        { kind: 'id', format: 'jwt', signatureVerified: true },
        { kind: 'refresh', format: 'opaque', present: true },
      ],
    });
    expect(steps[0]?.value.tokens[0]).not.toHaveProperty('claims.organization_id');
    expect(steps[1]?.value.persistedState).toEqual({
      grantConsumed: true,
      familyCount: 1,
      rotation: { replaced: true, sameFamily: true },
      tenantMutation: false,
      membershipMutation: false,
      roleMutation: false,
      consentMutation: false,
    });
    expect(JSON.stringify(steps)).not.toMatch(/private-admin|vvvvvvvv/u);
  });

  it('rejects a resource-coupled organization token or an organization_id claim', async () => {
    const signer = await createAdminTestSigner();
    const now = Math.floor(Date.now() / 1000);
    const idToken = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'admin-console',
      iat: now,
      exp: now + 3600,
    });
    const invalidAccess = await signer.sign({
      iss: `${adminTestTarget.adminUrl}oidc`,
      sub: adminRuntime.userId,
      aud: 'urn:logto:organization:t-default',
      client_id: 'admin-console',
      scope: '',
      organization_id: 't-default',
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
          'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all'
        ),
        organization: tokenBody(invalidAccess, idToken, adminSecrets.organizationRefresh, ''),
      },
    });

    await expect(
      runConsoleAdminOrganizationTokenRefresh(harness.context, {
        random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
      })
    ).rejects.toThrow('Phase 1 admin session consumer failed');
    expect(harness.store.getToken('organization')).toBeUndefined();
  });
});
