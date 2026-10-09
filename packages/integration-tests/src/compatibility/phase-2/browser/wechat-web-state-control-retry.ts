import { isDeepStrictEqual } from 'node:util';

const fail = (): never => {
  throw new TypeError('Invalid WeChat Web state control retry');
};

export const completeWechatWebStateControlRetry = async (
  input: Readonly<{
    retryPath: string;
    expectedOwnerId: string;
    ownerBefore: unknown;
    session: Readonly<{
      navigate(step: string, path: string): Promise<void>;
      waitForRoute(step: string, paths: readonly string[]): Promise<void>;
      click(step: string, selector: string): Promise<void>;
      assertInitialCallback(): Promise<void>;
      readProfile(): Promise<Readonly<{ sub?: unknown }>>;
      refresh(): Promise<Readonly<{ subject?: unknown; rotated: boolean }>>;
    }>;
    ownerSnapshot(): Promise<unknown>;
  }>
): Promise<void> => {
  if (!input.retryPath.startsWith('/callback/') || !input.expectedOwnerId) {
    return fail();
  }
  await input.session.navigate('wechat-web-correct-callback-retry', input.retryPath);
  await input.session.waitForRoute('wechat-web-correct-retry-consent', ['/consent']);
  await input.session.click('wechat-web-correct-retry-authorize', 'role=button[name="Authorize"]');
  await input.session.assertInitialCallback();
  const profile = await input.session.readProfile();
  const refreshed = await input.session.refresh();
  const ownerAfter = await input.ownerSnapshot();
  if (
    profile.sub !== input.expectedOwnerId ||
    refreshed.subject !== input.expectedOwnerId ||
    !refreshed.rotated ||
    !isDeepStrictEqual(input.ownerBefore, ownerAfter)
  ) {
    return fail();
  }
};
