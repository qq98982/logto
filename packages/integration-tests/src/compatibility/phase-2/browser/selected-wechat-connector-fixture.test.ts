/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- The stateful request fake exercises the ordered connector transaction and its compensating restores. */
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
  let smsBody: unknown;
  let cleanupFails = false;
  const cleanupAttempts: string[] = [];
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
        smsBody = input.body;
      }
      return { id: connectorId === 'wechat-h5' ? 'wechat' : 'sms', connectorId };
    }
    if (input.method === 'GET' && input.path === 'users') {
      return [];
    }
    if (input.method === 'DELETE') {
      cleanupAttempts.push(input.path);
      if (cleanupFails) {
        throw new TypeError('Controlled cleanup failure');
      }
      return 204;
    }
    throw new TypeError('Unexpected test request');
  };
  const primary = new TypeError('Controlled stop after connector creation');
  const fixtureInput = {
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
    smsConfiguration: {
      accessKeyId: 'controlled-id',
      accessKeySecret: 'controlled-secret',
      signName: 'Controlled Sign',
      templates: {
        Register: 'controlled-register',
        SignIn: 'controlled-sign-in',
        ForgotPassword: 'controlled-forgot',
        Generic: 'controlled-generic',
      },
    },
    ownerMode: 'registration',
    prepareConnector: async () => {
      throw primary;
    },
    use: async () => {},
  } as const;
  try {
    await withSelectedWechatConnectorFixture(fixtureInput);
    throw new TypeError('Expected fixture failure');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(TypeError);
    expect((error as Error).message).toBe(
      'Selected Wechat connector fixture failed: prepare-connector'
    );
    expect((error as Error).cause).toBe(primary);
  }
  expect(smsBody).toEqual({
    connectorId: 'aliyun-short-message-service',
    config: {
      accessKeyId: 'controlled-id',
      accessKeySecret: 'controlled-secret',
      signName: 'Controlled Sign',
      templates: [
        { usageType: 'Register', templateCode: 'controlled-register' },
        { usageType: 'SignIn', templateCode: 'controlled-sign-in' },
        { usageType: 'ForgotPassword', templateCode: 'controlled-forgot' },
        { usageType: 'Generic', templateCode: 'controlled-generic' },
      ],
    },
  });
  expect(currentMetadata).toEqual(originalMetadata);
  expect(currentSie).toMatchObject({
    socialSignInConnectorTargets: originalSie.socialSignInConnectorTargets,
    branding: originalSie.branding,
    signUp: originalSie.signUp,
  });

  cleanupFails = true;
  cleanupAttempts.length = 0;
  try {
    await withSelectedWechatConnectorFixture(fixtureInput);
    throw new TypeError('Expected fixture cleanup failure');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(AggregateError);
    const { errors } = error as AggregateError;
    const fixedPrimary = errors.find(
      (value) =>
        value instanceof TypeError &&
        value.message === 'Selected Wechat connector fixture failed: prepare-connector'
    );
    expect(fixedPrimary).toBeInstanceOf(TypeError);
    expect((fixedPrimary as Error).cause).toBe(primary);
  }
  expect(cleanupAttempts).toEqual(['roles/role', 'connectors/wechat', 'connectors/sms']);
});

test('restores the exact registration sign-up configuration after a successful row', async () => {
  const originalMetadata = { redirectUris: ['https://original.invalid/'] };
  const originalSie = {
    socialSignInConnectorTargets: [],
    branding: { logoUrl: 'https://brand.invalid/logo' },
    signInMode: 'SignInAndRegister',
    signUp: { identifiers: ['email'], password: true, verify: true },
  };
  let currentMetadata: unknown = originalMetadata;
  let currentSie: typeof originalSie | Record<string, unknown> = originalSie;
  let ownerExists = false;
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
      return { id: connectorId === 'wechat-h5' ? 'wechat' : 'sms', connectorId };
    }
    if (input.method === 'GET' && input.path === 'users') {
      return ownerExists
        ? [
            {
              id: 'owner',
              primaryPhone: '15555550101',
              hasPassword: false,
              identities: { wechat: { userId: 'subject' } },
            },
          ]
        : [];
    }
    if (input.method === 'DELETE') {
      if (input.path === 'users/owner') {
        ownerExists = false;
      }
      return 204;
    }
    throw new TypeError('Unexpected test request');
  };
  const result = Object.freeze({ completed: true });
  const fixtureInput = {
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
    smsConfiguration: {
      accessKeyId: 'controlled-id',
      accessKeySecret: 'controlled-secret',
      signName: 'Controlled Sign',
      templates: {
        Register: 'controlled-register',
        SignIn: 'controlled-sign-in',
        ForgotPassword: 'controlled-forgot',
        Generic: 'controlled-generic',
      },
    },
    ownerMode: 'registration',
    prepareConnector: async () => ({
      associationData: { code: 'setup' },
      observation: () =>
        ({
          setupRequests: 0,
          browserRequests: 1,
          authorizationExact: true,
          tokenExact: true,
          userinfoExact: true,
          unionIdStable: true,
        }) as const,
      stop: async () => {},
    }),
    use: async () => {
      ownerExists = true;
      return result;
    },
  } as const;
  const actual = await withSelectedWechatConnectorFixture(fixtureInput);
  expect(actual).toBe(result);
  expect(ownerExists).toBe(false);
  expect(currentMetadata).toEqual(originalMetadata);
  expect(currentSie).toEqual(originalSie);

  const primary = new TypeError('Controlled failure after registration setup');
  try {
    await withSelectedWechatConnectorFixture({
      ...fixtureInput,
      use: async () => {
        ownerExists = true;
        throw primary;
      },
    });
    throw new TypeError('Expected controlled registration failure');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(TypeError);
    expect((error as Error).message).toBe(
      'Selected Wechat connector fixture failed: registration-owner-use'
    );
    expect((error as Error).cause).toBe(primary);
  }
  expect(ownerExists).toBe(false);
  expect(currentMetadata).toEqual(originalMetadata);
  expect(currentSie).toEqual(originalSie);
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
