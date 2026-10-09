/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Ordered stage capture and no-op successful browser actions isolate provider observation failure. */
import { runCommonWechatWebExistingOwner } from './common-wechat-web.js';

test('classifies asynchronous provider receipt rejection at the provider stage', async () => {
  const stages: string[] = [];
  await expect(
    runCommonWechatWebExistingOwner({
      session: {
        navigate: async () => {},
        waitForRoute: async () => {},
        click: async () => {},
        assertInitialCallback: async () => {},
        refresh: async () => ({ subject: 'owner', rotated: true }),
        expectCount: async () => {},
        consentFailureRoute: async () => 'other-none-0-not-applicable-none',
        readProfile: async () => ({ sub: 'owner' }),
      },
      selector: 'wechat',
      expectedSubject: 'owner',
      providerObservation: async () => {
        throw new TypeError('private receipt detail');
      },
      reportStage: (stage) => {
        stages.push(stage);
      },
    })
  ).rejects.toThrow('Common WeChat Web failed: provider');
  expect(stages.at(-1)).toBe('provider');
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
