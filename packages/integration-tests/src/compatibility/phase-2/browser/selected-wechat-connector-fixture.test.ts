/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- The stateful request fake exercises the ordered connector transaction and its compensating restores. */
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedWechatConnectorFixture } from './selected-wechat-connector-fixture.js';

test('creates the H5 verification transport with the Aliyun SMS factory', async () => {
  const originalMetadata = { redirectUris: ['https://original.invalid/'] };
  const originalSie = {
    socialSignInConnectorTargets: [],
    branding: { logoUrl: 'https://brand.invalid/logo' },
    signInMode: 'SignInAndRegister',
    signUp: { identifiers: ['email'], password: true, verify: true },
  };
  let currentMetadata: unknown = originalMetadata;
  let currentSie: typeof originalSie | Record<string, unknown> = originalSie;
  let smsFactory: unknown;
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.method === 'GET' && input.path === 'sign-in-exp') {
      return currentSie;
    }
    if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
      currentSie = { ...currentSie, ...(input.body as Record<string, unknown>) };
      return currentSie;
    }
    if (input.path === 'applications/client') {
      if (input.method === 'PATCH') {
        currentMetadata = Reflect.get(input.body ?? {}, 'oidcClientMetadata');
      }
      return { id: 'client', type: 'SPA', oidcClientMetadata: currentMetadata };
    }
    if (input.method === 'GET' && input.path === 'resources') {
      return [{ id: 'resource', scopes: [{ id: 'scope', name: 'session:exchange' }] }];
    }
    if (input.method === 'POST' && input.path === 'roles') {
      return { id: 'role', type: 'User', isDefault: true };
    }
    if (input.method === 'POST' && input.path === 'connectors') {
      const connectorId = Reflect.get(input.body ?? {}, 'connectorId');
      if (connectorId !== 'wechat-h5') {
        smsFactory = connectorId;
      }
      return { id: connectorId === 'wechat-h5' ? 'wechat' : 'sms', connectorId };
    }
    if (input.method === 'GET' && input.path === 'users') {
      return [];
    }
    if (input.method === 'DELETE') {
      return 204;
    }
    throw new TypeError('Unexpected test request');
  };
  await expect(
    withSelectedWechatConnectorFixture({
      fixture: {
        public: { allocationId: 'fixture' },
        status: {
          resource: {
            id: 'resource',
            indicator: 'https://resource.invalid/',
            scopeName: 'session:exchange',
          },
        },
      } as ProvisionedPhase2Fixture,
      request,
      targetOrigin: 'https://target.invalid/',
      browser: { clientId: 'client', redirectUri: 'https://target.invalid/demo-app' },
      clientId: 'wx0123456789abcdef',
      clientSecret: '0123456789abcdef',
      channel: 'h5',
      wechatSubject: 'subject',
      registrationPhone: '15555550101',
      smsAccessSecret: 'controlled-secret',
      ownerMode: 'registration',
      prepareConnector: async () => {
        throw new TypeError('Controlled stop after connector creation');
      },
      use: async () => {},
    })
  ).rejects.toThrow('Selected Wechat connector fixture failed: prepare-connector');
  expect(smsFactory).toBe('aliyun-short-message-service');
  expect(currentMetadata).toEqual(originalMetadata);
  expect(currentSie).toMatchObject({
    socialSignInConnectorTargets: originalSie.socialSignInConnectorTargets,
    branding: originalSie.branding,
  });
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
