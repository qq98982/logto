/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The metadata model records persisted before/after state. */
import { withOwnedBackchannelApplication } from './common-session-logout-target-driver.js';

test('sets backchannel metadata before the identity entry and restores all original metadata after failure', async () => {
  const previous = {
    redirectUris: ['https://owned.example/callback'],
    postLogoutRedirectUris: [],
    unknownRetainedProperty: true,
  };
  const state = { metadata: previous as unknown };
  let uses = 0;
  await expect(
    withOwnedBackchannelApplication(
      async (input) => {
        expect(input.path).toBe('applications/owned-client');
        if (input.method === 'PATCH') {
          state.metadata = Reflect.get(input.body ?? {}, 'oidcClientMetadata');
        }
        return { id: 'owned-client', oidcClientMetadata: state.metadata };
      },
      'owned-client',
      async () => {
        uses += 1;
        expect(state.metadata).toEqual({
          ...previous,
          backchannelLogoutUri: 'https://backchannel.aster.test:8443/backchannel-logout',
          backchannelLogoutSessionRequired: true,
        });
        throw new Error('identity failed');
      }
    )
  ).rejects.toThrow('identity failed');
  expect(uses).toBe(1);
  expect(state.metadata).toEqual(previous);
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
