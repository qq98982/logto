import { runAccountAdminOperatorRead } from './account-admin-operator-read.js';
import { PositiveAdminSession } from './positive-admin-flow.js';
import {
  adminRuntime,
  adminSecrets,
  adminTestTarget,
  createAdminScenarioHarness,
  createAdminTestSigner,
  tokenBody,
} from './positive-admin-flow.test-helpers.js';

const effectiveScope =
  'openid offline_access profile email phone identities custom_data urn:logto:scope:organizations urn:logto:scope:organization_roles all';

describe('account.admin-operator-read', () => {
  it('authorizes the account read with the opaque admin token', async () => {
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
          effectiveScope
        ),
      },
      accountBody: {
        id: adminRuntime.userId,
        username: adminRuntime.username,
        primaryEmail: adminRuntime.email,
        createdAt: 1_700_000_000_000,
        updatedAt: 1_700_000_001_000,
      },
    });
    const steps = await runAccountAdminOperatorRead(harness.context, {
      sessionOptions: {
        random: { codeVerifier: () => adminSecrets.verifier, state: () => adminSecrets.state },
      },
    });

    expect(harness.account.requestAccount).toHaveBeenCalledWith(
      'account-admin-operator-read',
      'my-account/',
      { method: 'GET', includeCookies: false }
    );
    expect(harness.store.getToken('account')).toBe(adminSecrets.initialAccess);
    expect(steps.map(({ stepId }) => stepId)).toEqual(['account', 'state']);
    expect(steps[0]?.value).toMatchObject({
      status: 200,
      body: {
        id: '<user.phase1-admin>',
        username: '<fixture.admin.username>',
        primaryEmail: '<fixture.admin.email>',
        createdAt: { $timestamp: 1_700_000_000, $toleranceSeconds: 30 },
        updatedAt: { $timestamp: 1_700_000_001, $toleranceSeconds: 30 },
      },
    });
    expect(steps[1]?.value).toMatchObject({
      persistedState: { unrelatedMutation: false },
      sideEffects: { unrelatedMutation: false },
    });
    harness.store.assertNoCredentialMaterial(steps);
  });

  it('rejects forged admin session capabilities', () => {
    expect(
      () =>
        new PositiveAdminSession(undefined, {
          clientId: 'admin-console',
          accessToken: 'forged-access',
          idToken: 'forged-id',
          refreshToken: 'forged-refresh',
        })
    ).toThrow('Invalid Phase 1 admin session');
  });
});
