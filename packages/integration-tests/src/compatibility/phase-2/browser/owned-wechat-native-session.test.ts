/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- Cleanup receipts are recorded by a bounded fixture double. */
import { withOwnedWechatNativeSession } from './owned-wechat-native-session.js';

test('independently stops the provider and deletes the connector after association rejection', async () => {
  const cleanup: string[] = [];
  await expect(
    withOwnedWechatNativeSession(
      {
        target: {
          label: 'candidate',
          coreUrl: 'https://core.example/',
          adminUrl: 'https://admin.example/',
        },
        fixture: { public: { allocationId: 'owned' } } as never,
        providerClientId: 'provider-client',
        providerClientSecret: 'provider-secret',
        universalLink: 'https://app.example/wechat/',
        wechatSubject: 'expected-subject',
        expectedIssuer: 'https://core.example/oidc',
        managementRequest: async (request) => {
          if (request.method === 'POST' && request.path === 'connectors') {
            return { id: 'connector', connectorId: 'wechat-native' };
          }
          if (request.method === 'POST' && request.path.endsWith('/identities')) {
            return { wechat: { userId: 'wrong-subject' } };
          }
          if (request.method === 'DELETE') {
            cleanup.push('connector');
            return 204;
          }
          throw new TypeError('unexpected request');
        },
        withNativeFixture: async (_fixture, _options, use) =>
          use({
            public: {
              selectedNative: {
                identity: { id: 'owner', primaryEmail: 'owner@example.test' },
                clientId: 'native-client',
                redirectUri: 'https://app.example/callback',
                resource: { indicator: 'https://app.example/api' },
              },
            },
          } as never),
        prepareProvider: async () => ({
          associationData: { code: 'association' },
          takeCode: async () => 'provider-code',
          stop: async () => {
            cleanup.push('provider');
          },
        }),
      },
      async () => {
        throw new TypeError('must not run');
      }
    )
  ).rejects.toThrow('Invalid owned WeChat Native session');
  expect(cleanup).toEqual(['provider', 'connector']);
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
