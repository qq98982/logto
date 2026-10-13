/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Records independent cleanup attempts and provider ordering. */
import {
  runCommonWechatNativeScenarioRow,
  runWechatNativeControlsAndAudit,
} from './common-wechat-native.js';

test('audits native provider receipts only after every control completes', async () => {
  const order: string[] = [];
  let controlsComplete = false;
  const provider = {
    associationData: { code: 'association' },
    takeCode: async () => 'code',
    takeControlCode: async () => 'control-code',
    observation: async () => {
      if (!controlsComplete) {
        throw new TypeError('provider audited before controls');
      }
      order.push('observation');
      return {
        authorizationExact: true as const,
        tokenExact: true as const,
        userinfoExact: true as const,
        unionIdStable: true as const,
      };
    },
    stop: async () => {},
  };

  const result = await runWechatNativeControlsAndAudit(provider, async () => {
    order.push('controls');
    controlsComplete = true;
    return { replay: 'denied' as const };
  });

  expect(order).toEqual(['controls', 'observation']);
  expect(result).toEqual({
    controls: { replay: 'denied' },
    observed: {
      authorizationExact: true,
      tokenExact: true,
      userinfoExact: true,
      unionIdStable: true,
    },
  });
});

test('fails closed when the completed native provider receipt is not exact', async () => {
  const provider = {
    associationData: { code: 'association' },
    takeCode: async () => 'code',
    takeControlCode: async () => 'control-code',
    observation: async () => ({
      authorizationExact: true as const,
      tokenExact: true as const,
      userinfoExact: false as const,
      unionIdStable: true as const,
    }),
    stop: async () => {},
  };

  await expect(
    runWechatNativeControlsAndAudit(provider as never, async () => ({ replay: 'denied' as const }))
  ).rejects.toThrow('Invalid Common WeChat Native scenario');
});

test('stops the provider and deletes the connector after downstream failure', async () => {
  const cleanup: string[] = [];
  const fixturePublic = { allocationId: 'owned' };
  const fixture = { public: fixturePublic } as never;
  await expect(
    runCommonWechatNativeScenarioRow({
      target: {
        label: 'candidate',
        coreUrl: 'https://core.example/',
        adminUrl: 'https://admin.example/',
      },
      fixture,
      jwks: { keys: [] },
      clientId: 'provider-client',
      clientSecret: 'provider-secret',
      universalLink: 'https://app.example/wechat/',
      wechatSubject: 'wechat-subject',
      managementRequest: async (request) => {
        if (request.path === 'connectors' && request.method === 'POST') {
          return { id: 'connector', connectorId: 'wechat-native' };
        }
        if (request.path.includes('/identities')) {
          return { wechat: { userId: 'wechat-subject' } };
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
              redirectUri: 'https://app.example.test/callback',
              resource: {
                indicator: 'https://app.example.test/api',
                scope: { name: 'session:exchange' },
              },
            },
          },
        } as never),
      prepareProvider: async () => ({
        associationData: { code: 'association' },
        takeCode: async () => 'code',
        takeControlCode: async () => 'control-code',
        observation: async () => ({
          authorizationExact: true,
          tokenExact: true,
          userinfoExact: true,
          unionIdStable: true,
        }),
        stop: async () => {
          cleanup.push('provider');
        },
      }),
      fetch: async () =>
        new Response('{}', { status: 500, headers: { 'content-type': 'application/json' } }),
    })
  ).rejects.toThrow();
  expect(cleanup).toEqual(['provider', 'connector']);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
