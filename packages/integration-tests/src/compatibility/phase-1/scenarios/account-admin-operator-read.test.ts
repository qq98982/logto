import { runAccountAdminOperatorRead } from './account-admin-operator-read.js';
import { PositiveAdminSession } from './positive-admin-flow.js';
import {
  adminInitialResponseScope,
  adminRequestedScope,
  adminRuntime,
  adminSecrets,
  adminTestTarget,
  createAdminScenarioHarness,
  createAdminTestSigner,
  tokenBody,
} from './positive-admin-flow.test-helpers.js';

const createdAt = 1_700_000_000_000;
const updatedAt = 1_700_000_002_001;
const signInStartedAt = 1_700_000_000_500;
const lastSignInAt = 1_700_000_002_000;

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
          adminInitialResponseScope
        ),
      },
      accountBody: {
        id: adminRuntime.userId,
        username: adminRuntime.username,
        primaryEmail: adminRuntime.email,
        createdAt,
        updatedAt,
        lastSignInAt,
      },
    });
    const steps = await runAccountAdminOperatorRead(harness.context, {
      now: () => signInStartedAt,
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
    expect(adminRequestedScope.split(' ')).toContain('all');
    expect(adminInitialResponseScope.split(' ')).not.toContain('all');
    expect(steps.map(({ stepId }) => stepId)).toEqual(['account', 'state']);
    expect(steps[0]?.value).toMatchObject({
      status: 200,
      body: {
        id: '<user.phase1-admin>',
        username: '<fixture.admin.username>',
        primaryEmail: '<fixture.admin.email>',
        createdAt: { $timestamp: Math.floor(createdAt / 1000), $toleranceSeconds: 30 },
        updatedAt: { $timestamp: Math.floor(updatedAt / 1000), $toleranceSeconds: 30 },
        lastSignInAt: { $timestamp: Math.floor(lastSignInAt / 1000), $toleranceSeconds: 30 },
      },
    });
    expect(steps[1]?.value).toMatchObject({
      persistedState: { unrelatedMutation: false },
      sideEffects: { unrelatedMutation: false },
    });
    harness.store.assertNoCredentialMaterial(steps);
  });

  it.each([
    ['missing', undefined],
    ['null', null],
    ['string', '1700000002000'],
    ['before the sign-in lower bound', signInStartedAt - 1],
  ] as const)('rejects a %s lastSignInAt value before normalization', async (_name, value) => {
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
          adminInitialResponseScope
        ),
      },
      accountBody: {
        id: adminRuntime.userId,
        username: adminRuntime.username,
        primaryEmail: adminRuntime.email,
        createdAt,
        updatedAt,
        ...(value === undefined ? {} : { lastSignInAt: value }),
      },
    });

    await expect(
      runAccountAdminOperatorRead(harness.context, {
        withPositiveAdminSession: async (_context, _options, consume) => ({
          steps: [],
          result: await consume({} as never),
        }),
        installPositiveAdminAccountToken: () => {
          harness.store.setToken('account', adminSecrets.initialAccess);
        },
        now: () => signInStartedAt,
      })
    ).rejects.toThrow('Phase 1 Account operator is invalid');
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
