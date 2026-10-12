/* eslint-disable @silverhand/fp/no-mutating-methods -- Ordered cleanup attempts prove independent restoration. */
import {
  accountPasswordPolicyMatches,
  isolateAccountPasswordPolicy,
  runIndependentAccountSettingsCleanup,
  selectAccountSettingsFields,
} from './selected-account-settings-fixture.js';

describe('selected Account settings fixture', () => {
  it('disables only the pwned-password check for the default empty policy', () => {
    expect(isolateAccountPasswordPolicy({})).toEqual({
      previous: {},
      isolated: {
        length: { min: 8, max: 256 },
        characterTypes: { min: 1 },
        rejects: {
          pwned: false,
          repetitionAndSequence: true,
          userInfo: true,
          words: [],
        },
      },
    });
  });

  it('preserves local password rules and the exact restoration snapshot', () => {
    const input = {
      length: { min: 12 },
      rejects: { repetitionAndSequence: true, pwned: true },
    };

    const result = isolateAccountPasswordPolicy(input);

    expect(result).toEqual({
      previous: input,
      isolated: {
        length: { min: 12, max: 256 },
        characterTypes: { min: 1 },
        rejects: {
          repetitionAndSequence: true,
          pwned: false,
          userInfo: true,
          words: [],
        },
      },
    });
    expect(result.previous).toEqual(input);
    expect(input.rejects.pwned).toBe(true);
  });

  it('leaves an omitted policy untouched and rejects malformed policy shapes', () => {
    expect(isolateAccountPasswordPolicy()).toEqual({});
    expect(() => isolateAccountPasswordPolicy(null)).toThrow(
      'Invalid selected Account settings fixture'
    );
    expect(() => isolateAccountPasswordPolicy({ rejects: null })).toThrow(
      'Invalid selected Account settings fixture'
    );
  });

  it('validates persisted password policy from an independent readback', () => {
    const expected = { rejects: { pwned: false } };

    expect(accountPasswordPolicyMatches({ passwordPolicy: expected }, expected)).toBe(true);
    expect(accountPasswordPolicyMatches({ updatedAt: 1 }, expected)).toBe(false);
    expect(accountPasswordPolicyMatches({ passwordPolicy: {} }, expected)).toBe(false);
    expect(accountPasswordPolicyMatches({ passwordPolicy: {} }, {})).toBe(true);
  });

  it('selects only the fields required by each Account main flow', () => {
    const previous = { name: 'ReadOnly' };

    expect(selectAccountSettingsFields(previous, 'password', 'Edit')).toEqual({
      name: 'ReadOnly',
      password: 'Edit',
      email: 'ReadOnly',
    });
    expect(selectAccountSettingsFields(previous, 'password', 'ReadOnly')).toEqual({
      name: 'ReadOnly',
      password: 'ReadOnly',
      email: 'ReadOnly',
    });
    expect(selectAccountSettingsFields(previous, 'email', 'Edit')).toEqual({
      name: 'ReadOnly',
      email: 'Edit',
    });
    expect(selectAccountSettingsFields(previous, 'email', 'Edit', ['phone'])).toEqual({
      name: 'ReadOnly',
      email: 'Edit',
      phone: 'ReadOnly',
    });
    expect(selectAccountSettingsFields(previous, 'phone', 'Edit')).toEqual({
      name: 'ReadOnly',
      email: 'ReadOnly',
      phone: 'Edit',
    });
    expect(selectAccountSettingsFields(previous, 'phone', 'ReadOnly')).toEqual({
      name: 'ReadOnly',
      email: 'ReadOnly',
      phone: 'ReadOnly',
    });
    expect(previous).toEqual({ name: 'ReadOnly' });
  });

  it('selects social edit permission while preserving the other Account fields', () => {
    const previous = { email: 'ReadOnly', phone: 'ReadOnly', password: 'Edit' };
    expect(selectAccountSettingsFields(previous, 'social', 'Edit')).toEqual({
      ...previous,
      social: 'Edit',
    });
    expect(selectAccountSettingsFields(previous, 'social', 'ReadOnly')).toEqual({
      ...previous,
      social: 'ReadOnly',
    });
    expect(previous).toEqual({ email: 'ReadOnly', phone: 'ReadOnly', password: 'Edit' });
  });

  it('attempts policy and Account restoration when connector cleanup fails', async () => {
    const attempted: string[] = [];
    await expect(
      runIndependentAccountSettingsCleanup({
        connector: async () => {
          attempted.push('connector');
          throw new Error('private connector failure');
        },
        policy: async () => {
          attempted.push('policy');
        },
        accountCenter: async () => {
          attempted.push('account-center');
        },
      })
    ).rejects.toThrow('Selected Account fixture cleanup failed');
    expect(attempted).toEqual(['connector', 'policy', 'account-center']);
  });
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
