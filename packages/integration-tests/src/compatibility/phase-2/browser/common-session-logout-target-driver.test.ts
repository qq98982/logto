/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- The metadata model records persisted before/after state. */
import {
  getCommonSessionLogoutFailurePhase,
  observeEmailSessionPreparation,
  runCommonSessionLogoutForTarget,
  withOwnedBackchannelApplication,
} from './common-session-logout-target-driver.js';

test('observes existing email preparation calls once without replacing responses or errors', async () => {
  const response = new Response('{}', { status: 429 });
  const deliveryError = new Error('Phase 2 verification delivery failed: not-found');
  let fetchCalls = 0;
  let takeCalls = 0;
  const observed = observeEmailSessionPreparation(
    async () => {
      fetchCalls += 1;
      return response;
    },
    async () => {
      takeCalls += 1;
      throw deliveryError;
    }
  );

  const returned = await observed.fetch(
    'https://core.example/api/experience/verification/verification-code'
  );
  const thrown = await observed.takeCode('owned@example.invalid').catch((error: unknown) => error);
  expect(returned).toBe(response);
  expect(thrown).toBe(deliveryError);
  expect(fetchCalls).toBe(1);
  expect(takeCalls).toBe(1);
  expect(observed.facts).toEqual({
    route: 'verification-code-send',
    status: 429,
    smtp: 'failure-not-found',
  });
});

test('does not invoke arbitrary delivery error getters', async () => {
  let getterCalls = 0;
  // eslint-disable-next-line @silverhand/fp/no-mutating-methods
  const error = Object.defineProperty(new Error('private delivery'), 'message', {
    get: () => {
      getterCalls += 1;
      throw new Error('private');
    },
  });
  const observed = observeEmailSessionPreparation(fetch, async () => {
    throw error;
  });
  const thrown = await observed
    .takeCode('owned@example.invalid')
    .catch((error_: unknown) => error_);
  expect(thrown).toBe(error);
  expect(getterCalls).toBe(0);
  expect(observed.facts.smtp).toBe('failure-unknown');
});

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

test('records transformed discovery and direct authority failures without reading private fields', async () => {
  const discoveryFailure = new Error('private discovery');
  let messageGetterCalls = 0;
  // eslint-disable-next-line @silverhand/fp/no-mutating-methods
  Object.defineProperty(discoveryFailure, 'message', {
    configurable: true,
    get: () => {
      messageGetterCalls += 1;
      throw new Error('message getter must not run');
    },
  });
  const base = {
    target: {
      label: 'oracle' as const,
      coreUrl: 'https://core.example/',
      adminUrl: 'https://admin.example/',
    },
    fixture: {
      status: { client: { id: 'owned-client', redirectUri: 'https://app.example/callback' } },
    },
    runtime: {},
    jwks: { keys: [] },
    signal: new AbortController().signal,
  };
  const discovery = runCommonSessionLogoutForTarget({
    ...base,
    fetch: async () => {
      throw discoveryFailure;
    },
  } as never);
  const observedDiscovery = await discovery.catch((error: unknown) => error);
  expect(observedDiscovery === discoveryFailure).toBe(false);
  expect(messageGetterCalls).toBe(0);
  expect(getCommonSessionLogoutFailurePhase(discoveryFailure)).toBeUndefined();
  expect(getCommonSessionLogoutFailurePhase(observedDiscovery)).toBe('discovery');

  const authorityFailure = new Error('private authority');
  const authority = runCommonSessionLogoutForTarget({
    ...base,
    fixture: {
      ...base.fixture,
      withSecretLease: async () => {
        throw authorityFailure;
      },
    },
    fetch: async () =>
      new Response(JSON.stringify({ issuer: 'https://core.example/oidc' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
  } as never);
  const observedAuthority = await authority.catch((error: unknown) => error);
  expect(observedAuthority === authorityFailure).toBe(true);
  expect(getCommonSessionLogoutFailurePhase(authorityFailure)).toBe('authority');
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
