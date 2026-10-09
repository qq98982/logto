/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- Ordered fake observations and no-op browser operations prove bounded terminal waiting and action order. */
import { runWechatWebProviderDenialControl } from './wechat-web-provider-denial-control.js';

test('captures the exact delayed no-UnionID response without waiting for consent', async () => {
  const actions: string[] = [];
  let reads = 0;
  const result = await runWechatWebProviderDenialControl({
    selector: 'wechat',
    expectedStatus: 400,
    expectedError: 'connector.wechat_unionid_required',
    ownerBefore: { id: 'owner', stable: true },
    ownerSnapshot: async () => ({ id: 'owner', stable: true }),
    session: {
      navigate: async (step) => {
        actions.push(step);
      },
      waitForRoute: async (step) => {
        actions.push(step);
      },
      expectCount: async (step) => {
        actions.push(step);
      },
      click: async (step) => {
        actions.push(step);
      },
      beginExperienceObservation: async () => {
        actions.push('wechat-web-control-observation-reset');
      },
      readExperienceFailure: async () => {
        reads += 1;
        return reads === 1
          ? { operation: 'resume', status: 302, binding: 'complete', code: 'none' }
          : {
              operation: 'social-verify',
              status: 400,
              binding: 'not-applicable',
              code: 'connector.wechat_unionid_required',
            };
      },
    },
    timing: { wait: async () => {} },
  });
  expect(result).toEqual({
    accepted: false,
    status: 400,
    error: 'connector.wechat_unionid_required',
    ownerPreserved: true,
  });
  expect(actions).toEqual([
    'wechat-web-control-open',
    'wechat-web-control-sign-in',
    'wechat-web-control-provider-count',
    'wechat-web-control-observation-reset',
    'wechat-web-control-provider',
  ]);
  expect(reads).toBe(2);
});

test('rejects an unknown response or changed owner', async () => {
  await expect(
    runWechatWebProviderDenialControl({
      selector: 'wechat',
      expectedStatus: 401,
      expectedError: 'connector.social_auth_code_invalid',
      ownerBefore: { id: 'owner', stable: true },
      ownerSnapshot: async () => ({ id: 'owner', stable: false }),
      session: {
        navigate: async () => {},
        waitForRoute: async () => {},
        expectCount: async () => {},
        click: async () => {},
        beginExperienceObservation: async () => {},
        readExperienceFailure: async () => ({
          operation: 'social-verify',
          status: 401,
          binding: 'not-applicable',
          code: 'unknown',
        }),
      },
    })
  ).rejects.toThrow('Invalid WeChat Web provider denial control');
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
