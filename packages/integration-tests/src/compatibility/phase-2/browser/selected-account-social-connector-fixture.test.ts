/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- The failure-path fake records ordered calls and supplies only fields unreachable before provider failure. */
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedAccountSocialConnector } from './selected-account-social-connector-fixture.js';

test('removes the owned connector and restores social targets when provider preparation fails', async () => {
  const calls: string[] = [];
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(`${input.method} ${input.path}`);
    if (input.method === 'GET') {
      return { socialSignInConnectorTargets: ['github'] };
    }
    if (input.method === 'POST') {
      return { id: 'connector', connectorId: 'google-universal' };
    }
    return input.responseKind === 'status' ? 204 : { socialSignInConnectorTargets: ['github'] };
  };
  await expect(
    withSelectedAccountSocialConnector({
      fixture: { public: { allocationId: 'fixture' } } as ProvisionedPhase2Fixture,
      request,
      browser: { clientId: 'client', redirectUri: 'https://app.example/callback' },
      provider: 'google',
      connectorConfig: { clientId: 'owned', clientSecret: 'private' },
      getPassword: () => 'private',
      prepareProvider: async () => {
        throw new TypeError('provider unavailable');
      },
      use: async () => true,
    })
  ).rejects.toThrow('Selected Account social connector fixture failed');
  expect(calls).toEqual([
    'GET sign-in-exp',
    'POST connectors',
    'PATCH sign-in-exp',
    'DELETE connectors/connector',
  ]);
});
/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
