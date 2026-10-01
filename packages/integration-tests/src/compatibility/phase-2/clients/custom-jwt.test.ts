/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/no-empty-function -- The local call journal proves invocation ordering; the no-op fence is an explicit negative-test capability. */
import { createCustomJwtHttpPort } from './custom-jwt.js';

describe('custom JWT HTTP port', () => {
  it('validates and freezes bounded fetch observer receipts from the injected capability', async () => {
    const calls: string[] = [];
    const port = createCustomJwtHttpPort({
      assertInvocationFence: async () => {
        calls.push('fence');
      },
      managementRequest: async () => ({ status: 200, headers: {}, body: {} }),
      withM2MSecret: async <Result>(use: (secret: string) => Promise<Result>) => use('secret'),
      issueClientCredentials: async () => ({ status: 200, body: {} }),
      verifyAccessToken: async () => ({}),
      issueUserTokens: async () => ({ access: 'access', refresh: 'refresh' }),
      exchangeUserRefresh: async () => ({ status: 200, body: {} }),
      observeDeviceResourceRefresh: async () => ({
        status: 200,
        initialAccessOpaque: true,
        invoked: true,
        userContextPresent: true,
        applicationContextPresent: true,
        userMatchesToken: true,
        applicationMatchesToken: true,
        protectedClaimsMatch: true,
        tokenKind: 'access_token',
        grantType: 'device_code refresh_token',
      }),
      readAndResetFetchReceipts: async ({ signal, accept }) => {
        calls.push(signal.aborted ? 'aborted' : 'take');
        accept([
          { method: 'GET', path: '/redirect', headerMatches: true, bodyMatches: true },
          { method: 'GET', path: '/final', headerMatches: true, bodyMatches: true },
        ]);
      },
    });

    const receipts = await port.readAndResetFetchReceipts();

    expect(receipts).toEqual([
      { method: 'GET', path: '/redirect', headerMatches: true, bodyMatches: true },
      { method: 'GET', path: '/final', headerMatches: true, bodyMatches: true },
    ]);
    expect(Object.isFrozen(receipts)).toBe(true);
    expect(receipts.every((receipt) => Object.isFrozen(receipt))).toBe(true);
    expect(calls).toEqual(['fence', 'take', 'fence']);
  });

  it.each([
    ['missing capability', undefined],
    [
      'too many receipts',
      Array.from({ length: 65 }, () => ({
        method: 'GET',
        path: '/text',
        headerMatches: true,
        bodyMatches: true,
      })),
    ],
    [
      'oversized serialized receipts',
      [
        {
          method: 'GET',
          path: `/${'x'.repeat(17 * 1024)}`,
          headerMatches: true,
          bodyMatches: true,
        },
      ],
    ],
    ['unknown path', [{ method: 'GET', path: '/private', headerMatches: true, bodyMatches: true }]],
    [
      'unexpected keys',
      [{ method: 'GET', path: '/text', headerMatches: true, bodyMatches: true, secret: 'private' }],
    ],
  ])('rejects %s from the fetch receipt capability', async (_name, receiptValue) => {
    const port = createCustomJwtHttpPort({
      assertInvocationFence: async () => {},
      managementRequest: async () => ({ status: 200, headers: {}, body: {} }),
      withM2MSecret: async <Result>(use: (secret: string) => Promise<Result>) => use('secret'),
      issueClientCredentials: async () => ({ status: 200, body: {} }),
      verifyAccessToken: async () => ({}),
      issueUserTokens: async () => ({ access: 'access', refresh: 'refresh' }),
      exchangeUserRefresh: async () => ({ status: 200, body: {} }),
      ...(receiptValue === undefined
        ? {}
        : {
            readAndResetFetchReceipts: async ({ accept }: { accept(value: unknown): void }) => {
              accept(receiptValue);
            },
          }),
    });

    await expect(port.readAndResetFetchReceipts()).rejects.toThrow(
      'Invalid Phase 2 custom JWT HTTP observation'
    );
  });

  it.each([
    [
      'an own array mapper',
      Object.assign([{ method: 'GET', path: '/text', headerMatches: true, bodyMatches: true }], {
        map: () => [{ method: 'GET', path: '/private' }],
      }),
    ],
    [
      'an array proxy',
      new Proxy([{ method: 'GET', path: '/text', headerMatches: true, bodyMatches: true }], {}),
    ],
    [
      'an accessor record',
      [
        Object.create(Object.prototype, {
          method: { enumerable: true, get: () => 'GET' },
          path: { enumerable: true, value: '/text' },
          headerMatches: { enumerable: true, value: true },
          bodyMatches: { enumerable: true, value: true },
        }),
      ],
    ],
    [
      'a symbol-bearing record',
      [
        {
          method: 'GET',
          path: '/text',
          headerMatches: true,
          bodyMatches: true,
          [Symbol('private')]: 'hidden',
        },
      ],
    ],
  ])('fails closed on %s without invoking caller-controlled properties', async (_name, value) => {
    const port = createCustomJwtHttpPort({
      assertInvocationFence: async () => {},
      managementRequest: async () => ({ status: 200, headers: {}, body: {} }),
      withM2MSecret: async <Result>(use: (secret: string) => Promise<Result>) => use('secret'),
      issueClientCredentials: async () => ({ status: 200, body: {} }),
      verifyAccessToken: async () => ({}),
      issueUserTokens: async () => ({ access: 'access', refresh: 'refresh' }),
      exchangeUserRefresh: async () => ({ status: 200, body: {} }),
      readAndResetFetchReceipts: async ({ accept }) => {
        accept(value);
      },
    });

    await expect(port.readAndResetFetchReceipts()).rejects.toThrow(
      'Invalid Phase 2 custom JWT HTTP observation'
    );
  });

  it('rejects a receipt proxy before invoking its traps', async () => {
    const trapCalls: string[] = [];
    const port = createCustomJwtHttpPort({
      assertInvocationFence: async () => {},
      managementRequest: async () => ({ status: 200, headers: {}, body: {} }),
      withM2MSecret: async <Result>(use: (secret: string) => Promise<Result>) => use('secret'),
      issueClientCredentials: async () => ({ status: 200, body: {} }),
      verifyAccessToken: async () => ({}),
      issueUserTokens: async () => ({ access: 'access', refresh: 'refresh' }),
      exchangeUserRefresh: async () => ({ status: 200, body: {} }),
      readAndResetFetchReceipts: async ({ accept }) => {
        accept([
          new Proxy(
            {},
            {
              ownKeys: () => {
                trapCalls.push('ownKeys');
                throw new Error('private trap message');
              },
            }
          ),
        ]);
      },
    });

    await expect(port.readAndResetFetchReceipts()).rejects.toThrow(
      'Invalid Phase 2 custom JWT HTTP observation'
    );
    expect(trapCalls).toEqual([]);
  });

  it('validates raw receipts inside the callback before promise thenable adoption', async () => {
    const trapCalls: string[] = [];
    const raw = new Proxy([], {
      get: (_target, key) => {
        trapCalls.push(String(key));
        throw new Error('private then trap message');
      },
    });
    const port = createCustomJwtHttpPort({
      assertInvocationFence: async () => {},
      managementRequest: async () => ({ status: 200, headers: {}, body: {} }),
      withM2MSecret: async <Result>(use: (secret: string) => Promise<Result>) => use('secret'),
      issueClientCredentials: async () => ({ status: 200, body: {} }),
      verifyAccessToken: async () => ({}),
      issueUserTokens: async () => ({ access: 'access', refresh: 'refresh' }),
      exchangeUserRefresh: async () => ({ status: 200, body: {} }),
      readAndResetFetchReceipts: async ({ accept }) => {
        accept(raw);
      },
    });

    await expect(port.readAndResetFetchReceipts()).rejects.toThrow(
      'Invalid Phase 2 custom JWT HTTP observation'
    );
    expect(trapCalls).toEqual([]);
  });

  it('rejects an own then property without reading it', async () => {
    const trapCalls: string[] = [];
    // eslint-disable-next-line unicorn/no-thenable -- This hostile thenable proves validation happens before Promise adoption.
    const raw = Object.defineProperty([], 'then', {
      enumerable: true,
      get: () => {
        trapCalls.push('then');
        throw new Error('private then message');
      },
    });
    const port = createCustomJwtHttpPort({
      assertInvocationFence: async () => {},
      managementRequest: async () => ({ status: 200, headers: {}, body: {} }),
      withM2MSecret: async <Result>(use: (secret: string) => Promise<Result>) => use('secret'),
      issueClientCredentials: async () => ({ status: 200, body: {} }),
      verifyAccessToken: async () => ({}),
      issueUserTokens: async () => ({ access: 'access', refresh: 'refresh' }),
      exchangeUserRefresh: async () => ({ status: 200, body: {} }),
      readAndResetFetchReceipts: async ({ accept }) => {
        accept(raw);
      },
    });

    await expect(port.readAndResetFetchReceipts()).rejects.toThrow(
      'Invalid Phase 2 custom JWT HTTP observation'
    );
    expect(trapCalls).toEqual([]);
  });

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
      observeDeviceResourceRefresh: async () => ({
        status: 200,
        initialAccessOpaque: true,
        invoked: true,
        userContextPresent: true,
        applicationContextPresent: true,
        userMatchesToken: true,
        applicationMatchesToken: true,
        protectedClaimsMatch: true,
        tokenKind: 'access_token',
        grantType: 'device_code refresh_token',
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
    await expect(port.observeDeviceResourceRefresh()).resolves.toEqual({
      status: 200,
      initialAccessOpaque: true,
      invoked: true,
      userContextPresent: true,
      applicationContextPresent: true,
      userMatchesToken: true,
      applicationMatchesToken: true,
      protectedClaimsMatch: true,
      tokenKind: 'access_token',
      grantType: 'device_code refresh_token',
    });
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
