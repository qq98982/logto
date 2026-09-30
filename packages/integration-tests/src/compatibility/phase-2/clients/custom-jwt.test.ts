/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The local call journal proves invocation ordering; the no-op fence is an explicit negative-test capability. */
import { createCustomJwtHttpPort } from './custom-jwt.js';

describe('custom JWT HTTP port', () => {
  it('preserves fencing and confines the M2M secret to its lease', async () => {
    const calls: string[] = [];
    const port = createCustomJwtHttpPort({
      assertInvocationFence: async () => {
        calls.push('fence');
      },
      managementRequest: async ({ signal }) => ({
        status: signal.aborted ? 500 : 200,
        headers: {},
        body: { ok: true },
      }),
      withM2MSecret: async (use) => use('private-secret'),
      issueClientCredentials: async ({ clientSecret, signal }) => {
        calls.push(clientSecret === 'private-secret' && !signal.aborted ? 'issue' : 'bad');
        return { status: 200, body: { access_token: 'opaque' } };
      },
      verifyAccessToken: async () => ({ verified: true }),
      issueUserTokens: async () => ({ access: 'user-access', refresh: 'user-refresh' }),
      exchangeUserRefresh: async ({ refreshToken, signal }) => ({
        status: refreshToken === 'user-refresh' && !signal.aborted ? 200 : 500,
        body: { access_token: 'rotated-access' },
      }),
    });
    await expect(
      port.request({ method: 'GET', path: 'configs/jwt-customizer' })
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      port.issueClientCredentials({ caseId: 'custom-jwt.m2m-success' })
    ).resolves.toMatchObject({ status: 200 });
    expect(calls).toEqual(['fence', 'fence', 'fence', 'issue', 'fence']);
    const user = await port.issueUserTokens();
    const exchanged = await port.exchangeUserRefresh({ refreshToken: user.refresh });
    expect(exchanged).toMatchObject({
      status: 200,
    });
    expect(() => JSON.stringify(exchanged)).toThrow('Invalid Phase 2 custom JWT HTTP observation');
    expect(() => JSON.stringify(user)).toThrow('Invalid Phase 2 custom JWT HTTP observation');
    expect(JSON.stringify(port)).not.toContain('private-secret');
  });

  it('rejects oversized or credential-bearing observations', async () => {
    const base = {
      assertInvocationFence: async () => {},
      withM2MSecret: async <Result>(use: (secret: string) => Promise<Result>) => use('secret'),
      issueClientCredentials: async () => ({ status: 200, body: {} }),
      verifyAccessToken: async () => ({}),
      issueUserTokens: async () => ({ access: 'access', refresh: 'refresh' }),
      exchangeUserRefresh: async () => ({ status: 200, body: {} }),
    };
    const oversized = createCustomJwtHttpPort({
      ...base,
      managementRequest: async () => ({
        status: 200,
        headers: {},
        body: { value: 'x'.repeat(70 * 1024) },
      }),
    });
    await expect(oversized.request({ method: 'GET', path: 'x' })).rejects.toThrow(
      'Invalid Phase 2 custom JWT HTTP observation'
    );
    const header = createCustomJwtHttpPort({
      ...base,
      managementRequest: async () => ({
        status: 200,
        headers: { authorization: 'secret' },
        body: {},
      }),
    });
    await expect(header.request({ method: 'GET', path: 'x' })).rejects.toThrow(
      'Invalid Phase 2 custom JWT HTTP observation'
    );

    const invalidSignature = createCustomJwtHttpPort({
      ...base,
      managementRequest: async () => ({ status: 200, headers: {}, body: {} }),
      verifyAccessToken: async () => {
        throw new TypeError('invalid signature');
      },
    });
    await expect(invalidSignature.verifyAccessToken('forged.jwt.signature')).rejects.toThrow(
      'invalid signature'
    );
  });
});

/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function */
