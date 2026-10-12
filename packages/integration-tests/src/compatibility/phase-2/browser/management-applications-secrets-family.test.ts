/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake transport records repeated provisioning and secret catalog state. */
import type { Phase2AdminRequest, Phase2AdminRequestFunction } from '../fixtures.js';

import {
  managementApplicationsSecretsExpectedProjection,
  runManagementApplicationsSecretsFamily,
} from './management-applications-secrets-family.js';

test('repeats application metadata provisioning and publishes no secret value', async () => {
  const calls: Phase2AdminRequest[] = [];
  const owned: string[] = [];
  let name = '';
  let description = '';
  let redirectUri = '';
  let postLogoutRedirectUri = '';
  let backchannelLogoutUri = '';
  let added = false;
  const authenticationPairs: string[] = [];
  const application = () => ({
    id: 'owned-app',
    name,
    description,
    type: 'Traditional',
    isThirdParty: false,
    oidcClientMetadata: {
      redirectUris: [redirectUri],
      postLogoutRedirectUris: [postLogoutRedirectUri],
      backchannelLogoutUri,
      backchannelLogoutSessionRequired: true,
    },
  });
  const request: Phase2AdminRequestFunction = async (input) => {
    calls.push(input);
    if (input.path === 'applications' && input.method === 'POST') {
      const body = input.body as {
        name: string;
        description: string;
        oidcClientMetadata: {
          redirectUris: string[];
          postLogoutRedirectUris: string[];
          backchannelLogoutUri: string;
        };
      };
      name = body.name;
      description = body.description;
      redirectUri = body.oidcClientMetadata.redirectUris[0] ?? '';
      postLogoutRedirectUri = body.oidcClientMetadata.postLogoutRedirectUris[0] ?? '';
      backchannelLogoutUri = body.oidcClientMetadata.backchannelLogoutUri;
      return application();
    }
    if (input.path === 'applications/owned-app' && input.method !== 'GET') {
      const body = input.body as {
        description: string;
        oidcClientMetadata: {
          postLogoutRedirectUris: string[];
          backchannelLogoutUri: string;
        };
      };
      description = body.description;
      postLogoutRedirectUri = body.oidcClientMetadata.postLogoutRedirectUris[0] ?? '';
      backchannelLogoutUri = body.oidcClientMetadata.backchannelLogoutUri;
      return application();
    }
    if (input.path === 'applications/owned-app') {
      return application();
    }
    if (input.path.endsWith('/secrets') && input.method === 'POST') {
      added = true;
      return { name: `${name}-secondary`, value: 'added-private', createdAt: 2, expiresAt: null };
    }
    return [
      { name: 'Default secret', value: 'initial-private', createdAt: 1, expiresAt: null },
      ...(added
        ? [{ name: `${name}-secondary`, value: 'added-private', createdAt: 2, expiresAt: null }]
        : []),
    ];
  };
  const projection = await runManagementApplicationsSecretsFamily({
    target: {
      label: 'candidate',
      coreUrl: 'https://candidate.example/',
      adminUrl: 'https://candidate-admin.example/',
    },
    request,
    captureOwnedApplication: (id) => owned.push(id),
    observeForeignApplicationPreserved: async (use) => {
      await use('foreign-app');
      return true;
    },
    observeMutation: async ({ path, validAuthorization }) =>
      validAuthorization === false
        ? { status: 401, code: 'unauthorized' }
        : path === 'applications'
          ? { status: 400, code: 'guard.invalid_input' }
          : { status: 404, code: 'entity.not_found' },
    fetch: async (_url, init) => {
      const authorization = new Headers(init?.headers).get('authorization') ?? '';
      const credential = Buffer.from(authorization.slice('Basic '.length), 'base64').toString();
      const secret = credential.slice(credential.indexOf(':') + 1);
      authenticationPairs.push(secret);
      return ['initial-private', 'added-private'].includes(secret)
        ? new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })
        : new Response(JSON.stringify({ error: 'invalid_client' }), { status: 401 });
    },
  });
  expect(projection).toEqual(managementApplicationsSecretsExpectedProjection);
  expect(JSON.stringify(projection)).not.toContain('private');
  expect(owned).toEqual(['owned-app']);
  expect(calls.filter(({ method }) => method === 'PATCH')).toHaveLength(2);
  expect(authenticationPairs).toEqual([
    'initial-private',
    'aster-invalid-secret',
    'added-private',
    'aster-invalid-secret',
  ]);
});
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
