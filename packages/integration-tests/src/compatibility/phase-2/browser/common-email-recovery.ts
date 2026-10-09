/* eslint-disable no-await-in-loop -- Six passcode fields are filled in visible order. */
export type CommonEmailRecoveryBrowserSession = Readonly<{
  navigate(step: string, path: string): Promise<void>;
  waitForRoute(step: string, paths: readonly string[]): Promise<void>;
  fill(step: string, selector: string, value: string): Promise<void>;
  click(step: string, selector: string): Promise<void>;
  assertCallback(): Promise<void>;
  captureAuthority(): Promise<
    Readonly<{
      assertAccessUsable(): Promise<void>;
      assertRefreshUsable(): Promise<void>;
    }>
  >;
  assertPasswordRejected(identifier: string, password: string): Promise<void>;
}>;

export type CommonEmailRecoveryProjection = Readonly<{
  identifier: 'email';
  recovery: 'completed';
  previousBeforeReset: 'accepted';
  updateApplied: true;
  replacementAccepted: 'accepted';
  previousRejected: 'rejected';
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  profileVerified: true;
  refreshRotated: true;
  priorAccessUsable: true;
  priorSessionUsable: true;
}>;

type Stage =
  | 'admission'
  | 'initial-password'
  | 'forgot-password'
  | 'passcode-retrieval'
  | 'passcode-format'
  | 'passcode-fill'
  | 'new-password-reset'
  | 'prior-access'
  | 'prior-refresh'
  | 'new-password-sign-in'
  | 'old-password-rejection';
const fail = (stage: Stage): never => {
  throw new TypeError(`Common email recovery failed: ${stage}`);
};
const atStage = async <Result>(stage: Stage, run: () => Promise<Result>): Promise<Result> => {
  try {
    return await run();
  } catch {
    return fail(stage);
  }
};

const signIn = async (
  session: CommonEmailRecoveryBrowserSession,
  email: string,
  password: string
) => {
  await session.navigate('open-demo', '/demo-app');
  await session.waitForRoute('wait-sign-in', ['/sign-in', '/sign-in/password']);
  await session.fill('fill-email', 'input[name="identifier"]', email);
  await session.fill('fill-password', 'input[name="password"]', password);
  await session.click('submit-sign-in', 'button[name="submit"]');
  await session.waitForRoute('wait-consent', ['/consent']);
  await session.click('authorize-consent', 'role=button[name="Authorize"]');
  await session.assertCallback();
  return session.captureAuthority();
};

export const commonEmailRecoveryExpectedFlowProjection = Object.freeze({
  identifier: 'email',
  recovery: 'completed',
  previousBeforeReset: 'accepted',
  updateApplied: true,
  replacementAccepted: 'accepted',
  previousRejected: 'rejected',
  callback: 'state-issuer-code-bound',
  pkce: 'S256',
  profileVerified: true,
  refreshRotated: true,
  priorAccessUsable: true,
  priorSessionUsable: true,
}) satisfies CommonEmailRecoveryProjection;

export const runCommonEmailRecovery = async (
  input: Readonly<{
    mixedCaseEmail: string;
    canonicalEmail: string;
    oldPassword(): string;
    newPassword(): string;
    takeVerificationCode(recipient: string): Promise<string>;
    withInitialSession<Result>(
      use: (session: CommonEmailRecoveryBrowserSession) => Promise<Result>
    ): Promise<Result>;
    withFreshSession<Result>(
      name: 'recovery' | 'new-password' | 'old-password',
      use: (session: CommonEmailRecoveryBrowserSession) => Promise<Result>
    ): Promise<Result>;
  }>
): Promise<CommonEmailRecoveryProjection> => {
  const oldPassword = input.oldPassword();
  const newPassword = input.newPassword();
  if (
    input.mixedCaseEmail.toLowerCase() !== input.canonicalEmail ||
    input.mixedCaseEmail === input.canonicalEmail ||
    oldPassword === newPassword
  ) {
    return fail('admission');
  }

  return input.withInitialSession(async (initialSession) => {
    const priorAuthority = await atStage('initial-password', async () =>
      signIn(initialSession, input.mixedCaseEmail, oldPassword)
    );
    await input.withFreshSession('recovery', async (session) => {
      await atStage('forgot-password', async () => {
        await session.navigate('recovery-open-demo', '/demo-app');
        await session.waitForRoute('recovery-sign-in', ['/sign-in', '/sign-in/password']);
        await session.click('forgot-password-link', 'a:has-text("Forgot your password?")');
        await session.waitForRoute('forgot-password-route', ['/forgot-password']);
        await session.fill(
          'forgot-password-email',
          'input[name="identifier"]',
          input.mixedCaseEmail
        );
        await session.click('forgot-password-submit', 'role=button[name="Continue"]');
        await session.waitForRoute('forgot-password-code', ['/forgot-password/verification-code']);
      });
      const code = await atStage('passcode-retrieval', async () =>
        input.takeVerificationCode(input.canonicalEmail)
      );
      if (!/^\d{6}$/u.test(code)) {
        return fail('passcode-format');
      }
      await atStage('passcode-fill', async () => {
        for (const [index, value] of [...code].entries()) {
          await session.fill(
            `recovery-passcode-${index}`,
            `input[name="passcode_${index}"]`,
            value
          );
        }
        await session.waitForRoute('recovery-reset-route', ['/forgot-password/reset']);
      });
      await atStage('new-password-reset', async () => {
        await session.fill('new-password', 'input[name="newPassword"]', newPassword);
        await session.click('save-new-password', 'button[name="submit"]');
        await session.waitForRoute('reset-complete-sign-in', ['/sign-in', '/sign-in/password']);
      });
    });
    await atStage('prior-access', priorAuthority.assertAccessUsable);
    await atStage('prior-refresh', priorAuthority.assertRefreshUsable);
    await atStage('new-password-sign-in', async () =>
      input.withFreshSession('new-password', async (session) => {
        const replacementAuthority = await signIn(session, input.canonicalEmail, newPassword);
        await replacementAuthority.assertAccessUsable();
        await replacementAuthority.assertRefreshUsable();
      })
    );
    await atStage('old-password-rejection', async () =>
      input.withFreshSession('old-password', async (session) => {
        await session.navigate('old-password-open', '/demo-app');
        await session.waitForRoute('old-password-sign-in', ['/sign-in', '/sign-in/password']);
        await session.assertPasswordRejected(input.canonicalEmail, oldPassword);
      })
    );
    return commonEmailRecoveryExpectedFlowProjection;
  });
};
/* eslint-enable no-await-in-loop */
