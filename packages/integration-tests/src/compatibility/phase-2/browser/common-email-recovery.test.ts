/* eslint-disable @silverhand/fp/no-mutating-methods -- Ordered calls and latches are the observable browser contract. */
import {
  commonEmailRecoveryExpectedFlowProjection,
  runCommonEmailRecovery,
  type CommonEmailRecoveryBrowserSession,
} from './common-email-recovery.js';

const createSession = (
  events: string[],
  authorityLabel = 'prior'
): CommonEmailRecoveryBrowserSession => ({
  navigate: async (step) => {
    events.push(step);
  },
  waitForRoute: async (step) => {
    events.push(step);
  },
  fill: async (step) => {
    events.push(step);
  },
  click: async (step) => {
    events.push(step);
  },
  assertCallback: async () => {
    events.push(`${authorityLabel}-callback`);
  },
  captureAuthority: async () => {
    events.push(`${authorityLabel}-authority-captured`);
    return {
      assertAccessUsable: async () => {
        events.push(`${authorityLabel}-access-usable`);
      },
      assertRefreshUsable: async () => {
        events.push(`${authorityLabel}-refresh-usable`);
      },
    };
  },
  assertPasswordRejected: async () => {
    events.push('old-password-rejected');
  },
});

const input = (
  events: string[],
  overrides: Partial<Parameters<typeof runCommonEmailRecovery>[0]> = {}
): Parameters<typeof runCommonEmailRecovery>[0] => ({
  mixedCaseEmail: 'Owner@Example.Invalid',
  canonicalEmail: 'owner@example.invalid',
  oldPassword: () => 'private-old',
  newPassword: () => 'private-new',
  takeVerificationCode: async () => '123456',
  withInitialSession: async (use) => use(createSession(events)),
  withFreshSession: async (name, use) =>
    use(createSession(events, name === 'new-password' ? 'replacement' : name)),
  ...overrides,
});

test('retains prior access and refresh after reset, accepts the replacement, and rejects the old password', async () => {
  const events: string[] = [];
  await expect(runCommonEmailRecovery(input(events))).resolves.toEqual(
    commonEmailRecoveryExpectedFlowProjection
  );
  expect(events.indexOf('save-new-password')).toBeLessThan(events.indexOf('prior-access-usable'));
  expect(events.indexOf('prior-access-usable')).toBeLessThan(
    events.indexOf('prior-refresh-usable')
  );
  expect(events).toContain('replacement-access-usable');
  expect(events).toContain('replacement-refresh-usable');
  expect(events).toContain('old-password-rejected');
  expect(JSON.stringify(commonEmailRecoveryExpectedFlowProjection)).not.toContain('private');
});

test.each([
  ['prior access', 'prior-access', 'access'],
  ['prior refresh', 'prior-refresh', 'refresh'],
] as const)('fails closed at %s after the password update', async (_name, stage, failure) => {
  const events: string[] = [];
  await expect(
    runCommonEmailRecovery(
      input(events, {
        withInitialSession: async (use) => {
          const session = createSession(events);
          return use({
            ...session,
            captureAuthority: async () => ({
              assertAccessUsable: async () => {
                if (failure === 'access') {
                  throw new Error('private access detail');
                }
              },
              assertRefreshUsable: async () => {
                if (failure === 'refresh') {
                  throw new Error('private refresh detail');
                }
              },
            }),
          });
        },
      })
    )
  ).rejects.toThrow(`Common email recovery failed: ${stage}`);
});

test('fails closed before replacement sign-in when the recovery code is malformed', async () => {
  const events: string[] = [];
  const sessions: string[] = [];
  await expect(
    runCommonEmailRecovery(
      input(events, {
        takeVerificationCode: async () => '12345',
        withInitialSession: async (use) => {
          sessions.push('initial-password');
          return use(createSession(events));
        },
        withFreshSession: async (name, use) => {
          sessions.push(name);
          return use(createSession(events, name));
        },
      })
    )
  ).rejects.toThrow('Common email recovery failed: passcode-format');
  expect(sessions).toEqual(['initial-password', 'recovery']);
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
