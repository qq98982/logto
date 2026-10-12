/* eslint-disable @silverhand/fp/no-mutating-methods -- Ordered calls prove the browser and provider contract. */
import { runCommonAccountPhoneLogin } from './common-account-phone-change-target-driver.js';
import type { CommonPhoneCodeBrowserSession } from './common-phone-code.js';

test('exercises a same-owner phone-code S256 session through profile and rotating refresh', async () => {
  const calls: string[] = [];
  const session: CommonPhoneCodeBrowserSession = {
    navigate: async (step) => {
      calls.push(step);
    },
    waitForRoute: async (step) => {
      calls.push(step);
    },
    selectChinaCountryCode: async (step) => {
      calls.push(step);
    },
    fill: async (step) => {
      calls.push(step);
    },
    click: async (step) => {
      calls.push(step);
    },
    assertInitialCallback: async () => {
      calls.push('callback');
    },
    readProfile: async () => ({
      sub: 'owner',
      phoneNumber: '8613000000000',
      phoneNumberVerified: true,
      emailAbsent: false,
    }),
    refresh: async () => ({
      subject: 'owner',
      rotated: true,
      phoneNumber: '8613000000000',
    }),
  };
  await expect(
    runCommonAccountPhoneLogin({
      session,
      phone: '8613000000000',
      ownerId: 'owner',
      provider: {
        configuration: {
          accessKeyId: 'private-id',
          accessKeySecret: 'private-secret',
          signName: 'Aster',
          templates: [],
        },
        arm: async (_recipient, purpose) => {
          calls.push(`arm-${purpose}`);
        },
        takeCode: async (_recipient, purpose) => {
          calls.push(`take-${purpose}`);
          return '123456';
        },
      },
    })
  ).resolves.toEqual({ refreshRotated: true });
  expect(calls).toEqual(
    expect.arrayContaining(['arm-SignIn', 'take-SignIn', 'callback', 'authorize-account-phone'])
  );
  expect(calls.filter((value) => value.startsWith('account-phone-code-'))).toHaveLength(6);

  await expect(
    runCommonAccountPhoneLogin({
      session: {
        ...session,
        readProfile: async () => ({ ...(await session.readProfile()), emailAbsent: true }),
      },
      phone: '8613000000000',
      ownerId: 'owner',
      provider: {
        configuration: {
          accessKeyId: 'id',
          accessKeySecret: 'secret',
          signName: 'Aster',
          templates: [],
        },
        arm: async () => {
          await Promise.resolve();
        },
        takeCode: async () => '123456',
      },
    })
  ).rejects.toThrow('Invalid Common Account phone change target (flow)');
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
