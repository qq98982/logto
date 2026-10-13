/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment -- Stateful wire doubles exercise compensation after each observable failure. */
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import { withSelectedPasswordCoreApplication } from './selected-password-core-application-fixture.js';

const fixture = Object.freeze({
  public: {},
  status: Object.freeze({
    client: Object.freeze({ id: 'status-client', redirectUri: 'http://localhost:3311/demo-app' }),
  }),
}) as unknown as ProvisionedPhase2Fixture;
const original = {
  redirectUris: ['http://localhost:3311/demo-app'],
  postLogoutRedirectUris: [],
  custom: { retained: true },
};

test('registers the password callback for the scoped fixture and restores all metadata', async () => {
  let metadata: Record<string, unknown> = JSON.parse(JSON.stringify(original)) as Record<
    string,
    unknown
  >;
  const request: Phase2AdminRequestFunction = async ({ method, body }) => {
    if (method === 'PATCH') {
      metadata = JSON.parse(
        JSON.stringify((body as { oidcClientMetadata: unknown }).oidcClientMetadata)
      ) as Record<string, unknown>;
    }
    return {
      id: 'status-client',
      type: 'SPA',
      oidcClientMetadata: JSON.parse(JSON.stringify(metadata)),
    };
  };
  await expect(
    withSelectedPasswordCoreApplication({
      fixture,
      request,
      redirectUri: 'https://localhost:3361/demo-app',
      use: async (scoped) => {
        expect(scoped.status?.client.redirectUri).toBe('https://localhost:3361/demo-app');
        expect(metadata.redirectUris).toEqual([
          'https://localhost:3361/demo-app',
          'http://localhost:3311/demo-app',
        ]);
        return 'used';
      },
    })
  ).resolves.toBe('used');
  expect(metadata).toEqual(original);
});

test('restores metadata after the selected readback rejects before the body runs', async () => {
  let metadata: Record<string, unknown> = JSON.parse(JSON.stringify(original)) as Record<
    string,
    unknown
  >;
  let selected = false;
  let reads = 0;
  const request: Phase2AdminRequestFunction = async ({ method, body }) => {
    if (method === 'PATCH') {
      metadata = JSON.parse(
        JSON.stringify((body as { oidcClientMetadata: unknown }).oidcClientMetadata)
      ) as Record<string, unknown>;
      selected =
        Array.isArray(metadata.redirectUris) &&
        metadata.redirectUris[0] === 'https://localhost:3361/demo-app';
    } else {
      reads += 1;
    }
    const visible = selected && reads === 2 ? original : metadata;
    return {
      id: 'status-client',
      type: 'SPA',
      oidcClientMetadata: JSON.parse(JSON.stringify(visible)),
    };
  };
  let used = false;
  await expect(
    withSelectedPasswordCoreApplication({
      fixture,
      request,
      redirectUri: 'https://localhost:3361/demo-app',
      use: async () => {
        used = true;
      },
    })
  ).rejects.toThrow('selection-readback');
  expect(used).toBe(false);
  expect(metadata).toEqual(original);
});

test('attempts restoration and reports both body and restoration failures', async () => {
  let patchCount = 0;
  const request: Phase2AdminRequestFunction = async ({ method, body }) => {
    if (method === 'PATCH') {
      patchCount += 1;
      if (patchCount === 2) {
        throw new TypeError('restore failed');
      }
      return {
        id: 'status-client',
        type: 'SPA',
        oidcClientMetadata: (body as { oidcClientMetadata: unknown }).oidcClientMetadata,
      };
    }
    return {
      id: 'status-client',
      type: 'SPA',
      oidcClientMetadata:
        patchCount === 0
          ? original
          : {
              ...original,
              redirectUris: ['https://localhost:3361/demo-app', ...original.redirectUris],
            },
    };
  };
  const failure = await withSelectedPasswordCoreApplication({
    fixture,
    request,
    redirectUri: 'https://localhost:3361/demo-app',
    use: async () => {
      throw new TypeError('body failed');
    },
  }).catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(AggregateError);
  const { errors } = failure as AggregateError;
  expect(errors).toHaveLength(2);
  const [bodyError, cleanupError] = errors;
  expect(bodyError).toBeInstanceOf(TypeError);
  expect((bodyError as Error).message).toBe('body failed');
  expect(cleanupError).toBeInstanceOf(TypeError);
  expect((cleanupError as Error).message).toBe('restore failed');
  expect(patchCount).toBe(2);
});
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/no-unsafe-assignment */
