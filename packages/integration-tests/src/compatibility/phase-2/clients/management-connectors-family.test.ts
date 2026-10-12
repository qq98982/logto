/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake records request order and captured ownership. */
import type { Phase2AdminRequest, Phase2AdminRequestFunction } from '../fixtures.js';

import {
  createManagementConnector,
  deleteManagementConnector,
  readManagementConnectorFactoryIds,
  readManagementPublicExperience,
} from './management-connectors-family.js';

test('captures and compensates an owned connector through public Management', async () => {
  const calls: Phase2AdminRequest[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(input);
    return input.method === 'POST'
      ? { id: 'connector', connectorId: 'google-universal', target: 'google' }
      : 204;
  };
  let owned: string | undefined;
  const connector = await createManagementConnector(
    request,
    { factoryId: 'google-universal', config: { clientId: 'id', clientSecret: 'private' } },
    (id) => {
      owned = id;
    }
  );
  await deleteManagementConnector(request, connector.id);
  expect(owned).toBe('connector');
  expect(calls.map(({ method, path }) => `${method} ${path}`)).toEqual([
    'POST connectors',
    'DELETE connectors/connector',
  ]);
});

test('captures an owned connector before rejecting credential material in its projection', async () => {
  let owned: string | undefined;
  await expect(
    createManagementConnector(
      async () => ({
        id: 'connector',
        connectorId: 'google-universal',
        target: 'google',
        clientSecret: 'must-not-enter-the-projection',
      }),
      { factoryId: 'google-universal', config: {} },
      (id) => {
        owned = id;
      }
    )
  ).rejects.toThrow('Invalid Common Management connectors family transport');
  expect(owned).toBe('connector');
});

test('reads the bounded public Experience document from the Data origin', async () => {
  await expect(
    readManagementPublicExperience(
      {
        label: 'candidate',
        coreUrl: 'https://core.example/',
        adminUrl: 'https://admin.example/',
      },
      async (url) => {
        expect(String(url)).toBe('https://core.example/api/.well-known/sign-in-exp');
        return new Response(JSON.stringify({ signIn: { methods: [] } }), { status: 200 });
      }
    )
  ).resolves.toEqual({ signIn: { methods: [] } });
});

test('reads only bounded advertised connector factory identifiers', async () => {
  await expect(
    readManagementConnectorFactoryIds(
      {
        label: 'oracle',
        coreUrl: 'https://oracle.example/',
        adminUrl: 'https://oracle-admin.example/',
      },
      () => new Headers({ authorization: 'Bearer fixture' }),
      async () =>
        new Response(
          JSON.stringify([{ id: 'google-universal' }, { connectorId: 'wechat-native' }]),
          { status: 200 }
        )
    )
  ).resolves.toEqual(['google-universal', 'wechat-native']);
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
