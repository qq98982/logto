/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/member-ordering, @typescript-eslint/no-throw-literal -- One closed flow validates callback, profile, refresh, and controls together. */
export const commonEmailPasswordScenarioId = 'common.email.password-sign-in';

export type CommonEmailPasswordBrowserSession = Readonly<{
  navigate(step: string, path: string): Promise<void>;
  waitForRoute(step: string, paths: readonly string[]): Promise<void>;
  fill(step: string, selector: string, value: string): Promise<void>;
  click(step: string, selector: string): Promise<void>;
  assertInitialCallback(): Promise<void>;
  readProfile(): Promise<Readonly<{ sub?: unknown; email?: unknown; emailVerified?: unknown }>>;
  refresh(): Promise<Readonly<{ subject?: unknown; rotated: boolean }>>;
}>;

export type CommonEmailPasswordControls = Readonly<{
  assertInvalidPassword(identifier: string, password: string): Promise<void>;
  assertSuspended(identifier: string, password: string): Promise<void>;
  authenticateUsername(identifier: string, password: string): Promise<string>;
  setSuspended(userId: string, suspended: boolean): Promise<void>;
}>;

export type CommonEmailPasswordProjection = Readonly<{
  identifier: 'email';
  casing: 'canonical-owner';
  passwordOutcome: 'accepted';
  consent: true;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  profileSubject: true;
  emailVerified: true;
  refreshRotated: true;
  invalidPassword: 'rejected';
  suspended: 'rejected';
  usernamePreserved: true;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Common email password sign-in');
};
const contractFail = (name: string): never => {
  throw new TypeError(`Common email password stage failed: ${name}`);
};
const atFlowStage = async <Result>(name: string, run: () => Promise<Result>): Promise<Result> => {
  try {
    return await run();
  } catch (error: unknown) {
    const callbackField =
      name === 'callback' && error instanceof Error
        ? /^Common email password callback failed: ([a-z0-9-]+)$/u.exec(error.message)?.[1]
        : undefined;
    const refreshField =
      name === 'refresh' && error instanceof Error
        ? /^Common email password refresh failed: ([a-z-]+)$/u.exec(error.message)?.[1]
        : undefined;
    if (callbackField) {
      throw new TypeError(`Common email password stage failed: callback-${callbackField}`);
    }
    if (refreshField) {
      throw new TypeError(`Common email password stage failed: refresh-${refreshField}`);
    }
    throw new TypeError(`Common email password stage failed: ${name}`);
  }
};

export const runCommonEmailPasswordSignIn = async (
  input: Readonly<{
    session: CommonEmailPasswordBrowserSession;
    email: string;
    canonicalEmail: string;
    password(): string;
    invalidPassword(): string;
    expectedSubject: string;
    controls: CommonEmailPasswordControls;
    usernameControl: Readonly<{ identifier: string; password(): string; expectedSubject: string }>;
  }>
): Promise<CommonEmailPasswordProjection> => {
  if (
    input.email.toLowerCase() !== input.canonicalEmail ||
    input.email === input.canonicalEmail ||
    !input.expectedSubject
  ) {
    return fail();
  }
  await atFlowStage('initialization', async () => {
    await input.session.navigate('open-demo', '/demo-app');
    await input.session.waitForRoute('wait-sign-in', ['/sign-in', '/sign-in/password']);
  });
  await atFlowStage('credentials', async () => {
    await input.session.fill('fill-email', 'input[name="identifier"]', input.email);
    await input.session.fill('fill-password', 'input[name="password"]', input.password());
    await input.session.click('submit-sign-in', 'button[name="submit"]');
  });
  await atFlowStage('consent', async () => {
    await input.session.waitForRoute('wait-consent', ['/consent']);
    await input.session.click('authorize-consent', 'role=button[name="Authorize"]');
  });
  await atFlowStage('callback', async () => input.session.assertInitialCallback());
  const profile = await atFlowStage('profile', async () => input.session.readProfile());
  if (profile.sub !== input.expectedSubject) {
    contractFail('profile-sub');
  }
  if (profile.email !== input.canonicalEmail) {
    contractFail('profile-email');
  }
  if (profile.emailVerified !== true) {
    contractFail('profile-email-verified');
  }
  const refresh = await atFlowStage('refresh', async () => input.session.refresh());
  if (refresh.subject !== input.expectedSubject) {
    contractFail('refresh-sub');
  }
  if (!refresh.rotated) {
    contractFail('refresh-rotation');
  }
  await atFlowStage('controls-invalid', async () =>
    input.controls.assertInvalidPassword(input.canonicalEmail, input.invalidPassword())
  );
  let setError: unknown;
  try {
    await atFlowStage('controls-suspended-set', async () =>
      input.controls.setSuspended(input.expectedSubject, true)
    );
  } catch (error: unknown) {
    setError = error;
  }
  if (setError) {
    try {
      await atFlowStage('controls-suspended-restore', async () =>
        input.controls.setSuspended(input.expectedSubject, false)
      );
    } catch {
      contractFail('controls-suspended-set-restore');
    }
    throw setError;
  }
  let attemptError: unknown;
  let restoreError: unknown;
  try {
    await atFlowStage('controls-suspended-attempt', async () =>
      input.controls.assertSuspended(input.canonicalEmail, input.password())
    );
  } catch (error: unknown) {
    attemptError = error;
  }
  try {
    await atFlowStage('controls-suspended-restore', async () =>
      input.controls.setSuspended(input.expectedSubject, false)
    );
  } catch (error: unknown) {
    restoreError = error;
  }
  if (attemptError && restoreError) {
    contractFail('controls-suspended-attempt-restore');
  }
  if (attemptError) {
    throw attemptError;
  }
  if (restoreError) {
    throw restoreError;
  }
  const usernameSubject = await atFlowStage('controls-username', async () =>
    input.controls.authenticateUsername(
      input.usernameControl.identifier,
      input.usernameControl.password()
    )
  );
  if (usernameSubject !== input.usernameControl.expectedSubject) {
    contractFail('username-sub');
  }
  return Object.freeze({
    identifier: 'email',
    casing: 'canonical-owner',
    passwordOutcome: 'accepted',
    consent: true,
    callback: 'state-issuer-code-bound',
    pkce: 'S256',
    profileSubject: true,
    emailVerified: true,
    refreshRotated: true,
    invalidPassword: 'rejected',
    suspended: 'rejected',
    usernamePreserved: true,
  });
};

/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/member-ordering, @typescript-eslint/no-throw-literal */
