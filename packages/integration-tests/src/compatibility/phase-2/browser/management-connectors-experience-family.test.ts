/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake records compensation after a forced projection failure. */
import type { Phase2AdminRequest, Phase2AdminRequestFunction } from '../fixtures.js';

import { runManagementConnectorsExperienceFamily } from './management-connectors-experience-family.js';

test('attempts Experience restoration and exact owned connector cleanup independently', async () => {
  const calls: Phase2AdminRequest[] = [];
  let patchCount = 0;
  const previous = {
    signIn: { methods: [] },
    socialSignIn: { automaticAccountLinking: false },
    socialSignInConnectorTargets: [],
  };
  let experience: Readonly<Record<string, unknown>> = previous;
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(input);
    if (input.path === 'sign-in-exp' && input.method === 'GET') {
      return experience;
    }
    if (input.path === 'sign-in-exp' && input.method === 'PATCH') {
      patchCount += 1;
      if (patchCount === 3) {
        throw new TypeError('forced restoration failure');
      }
      experience = { ...experience, ...(input.body as Readonly<Record<string, unknown>>) };
      return experience;
    }
    if (input.path === 'connectors' && input.method === 'POST') {
      return { id: 'owned-connector', connectorId: 'google-universal', target: 'google' };
    }
    if (input.path === 'connectors/owned-connector' && input.method === 'PATCH') {
      return { id: 'owned-connector', connectorId: 'google-universal', target: 'google' };
    }
    if (input.path === 'connectors' && input.method === 'GET') {
      return [{ id: 'owned-connector', connectorId: 'google-universal', target: 'google' }];
    }
    return null;
  };

  await expect(
    runManagementConnectorsExperienceFamily({
      target: {
        label: 'candidate',
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      },
      request,
      createManagementHeaders: () => new Headers({ authorization: 'Bearer fixture' }),
      observeForeignConnectorPreserved: async (use) => {
        await use('foreign-connector');
        return true;
      },
      observeMutation: async ({ path, method, validAuthorization }) =>
        validAuthorization === false
          ? { status: 401, code: 'auth.authorization_header_missing' }
          : path === 'connectors' && method === 'POST'
            ? { status: 422, code: 'connector.multiple_instances_not_supported' }
            : path === 'sign-in-exp'
              ? { status: 400, code: 'guard.invalid_input' }
              : { status: 404, code: 'entity.not_found' },
      fetch: async (url) =>
        new Response(
          JSON.stringify(
            String(url).includes('connector-factories')
              ? [{ id: 'google-universal' }, { id: 'wechat-web' }, { id: 'wechat-native' }]
              : { socialSignInConnectorTargets: ['google'] }
          ),
          { status: 200 }
        ),
    })
  ).rejects.toThrow('restore-experience');

  const operations = calls.map(({ method, path }) => `${method} ${path}`);
  expect(operations).toContain('GET connectors');
  expect(operations.slice(-2)).toEqual(
    expect.arrayContaining(['PATCH sign-in-exp', 'DELETE connectors/owned-connector'])
  );
});

test('compares public Experience with the state after the omission patch', async () => {
  const previous = {
    signIn: { methods: [] },
    socialSignIn: { automaticAccountLinking: false },
    socialSignInConnectorTargets: [],
  };
  let experience: Readonly<Record<string, unknown>> = previous;
  const request: Phase2AdminRequestFunction = async (input) => {
    if (input.path === 'sign-in-exp' && input.method === 'GET') {
      return experience;
    }
    if (input.path === 'sign-in-exp' && input.method === 'PATCH') {
      experience = { ...experience, ...(input.body as Readonly<Record<string, unknown>>) };
      return experience;
    }
    if (input.path === 'connectors' && input.method === 'POST') {
      return { id: 'owned-connector', connectorId: 'google-universal', target: 'google' };
    }
    if (input.path === 'connectors/owned-connector' && input.method === 'PATCH') {
      return { id: 'owned-connector', connectorId: 'google-universal', target: 'google' };
    }
    if (input.path === 'connectors' && input.method === 'GET') {
      return [{ id: 'owned-connector', connectorId: 'google-universal', target: 'google' }];
    }
    return null;
  };

  await expect(
    runManagementConnectorsExperienceFamily({
      target: {
        label: 'candidate',
        coreUrl: 'https://candidate.example/',
        adminUrl: 'https://candidate-admin.example/',
      },
      request,
      createManagementHeaders: () => new Headers({ authorization: 'Bearer fixture' }),
      observeForeignConnectorPreserved: async (use) => {
        await use('foreign-connector');
        return true;
      },
      observeMutation: async ({ path, method, validAuthorization }) =>
        validAuthorization === false
          ? { status: 401, code: 'auth.authorization_header_missing' }
          : path === 'connectors' && method === 'POST'
            ? { status: 422, code: 'connector.multiple_instances_not_supported' }
            : path === 'sign-in-exp'
              ? { status: 400, code: 'guard.invalid_input' }
              : { status: 404, code: 'entity.not_found' },
      fetch: async (url) =>
        new Response(
          JSON.stringify(
            String(url).includes('connector-factories')
              ? [{ id: 'google-universal' }, { id: 'wechat-web' }, { id: 'wechat-native' }]
              : Object.fromEntries(
                  Object.entries(experience).filter(([key]) => key !== 'forgotPasswordMethods')
                )
          ),
          { status: 200 }
        ),
    })
  ).resolves.toMatchObject({ publicBootstrapMatches: true, experienceRoundTrip: true });
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
