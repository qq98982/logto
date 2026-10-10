import { isolateAccountPasswordPolicy } from './selected-account-settings-fixture.js';

describe('selected Account settings fixture', () => {
  it('disables only the pwned-password check for the default empty policy', () => {
    expect(isolateAccountPasswordPolicy({})).toEqual({
      previous: {},
      isolated: { rejects: { pwned: false } },
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
        length: { min: 12 },
        rejects: { repetitionAndSequence: true, pwned: false },
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
});
