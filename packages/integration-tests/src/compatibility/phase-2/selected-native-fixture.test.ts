/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The fake Management transport records lease state plus ordered setup and compensation. */
import type {
  Phase2AdminRequest,
  Phase2AdminRequestFunction,
  Phase2FixtureSecretLease,
  ProvisionedPhase2Fixture,
} from './fixtures.js';
import { withSelectedNativeFixture } from './selected-native-fixture.js';

const candidate = {
  label: 'candidate' as const,
  coreUrl: 'https://candidate.example/',
  adminUrl: 'https://candidate-admin.example/',
};
const oracle = {
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
};

const fixture = (): ProvisionedPhase2Fixture => {
  let active = false;
  const value: ProvisionedPhase2Fixture = {
    public: {
      allocationId: 'selected-native-allocation',
      clients: {
        basic: { id: 'basic', method: 'client_secret_basic' },
        post: { id: 'post', method: 'client_secret_post' },
      },
      deviceClients: {
        firstParty: {
          id: 'device-first',
          applicationType: 'Native',
          authenticationMethod: 'none',
          isThirdParty: false,
          deviceGrantEnabled: true,
        },
        thirdParty: {
          id: 'device-third',
          applicationType: 'Native',
          authenticationMethod: 'none',
          isThirdParty: true,
          deviceGrantEnabled: true,
        },
        missingGrant: {
          id: 'device-none',
          applicationType: 'Native',
          authenticationMethod: 'none',
          isThirdParty: false,
          deviceGrantEnabled: false,
        },
        ineligibleWeb: {
          id: 'device-web',
          applicationType: 'SPA',
          authenticationMethod: 'none',
          isThirdParty: false,
          deviceGrantEnabled: false,
        },
      },
      resources: {
        primary: { id: 'resource', indicator: 'https://resource.example/api' },
        default: { id: 'default', indicator: 'https://default.example/api' },
      },
      organization: { id: 'organization', scopeName: 'organization:read' },
      scopes: {
        read: { id: 'read', name: 'read' },
        write: { id: 'write', name: 'write' },
        unassigned: { id: 'none', name: 'unassigned' },
      },
      boundary: { primary: 'provisioned', foreign: 'unchanged' },
    },
    withSecretLease: async <Result>(use: (lease: Phase2FixtureSecretLease) => Promise<Result>) => {
      if (active) {
        throw new Error('lease');
      }
      active = true;
      const lease: Phase2FixtureSecretLease = {
        getClientSecret: () => 'unused',
        getStatusClientSecret: () => 'unused',
        getSelectedNativePassword: () => {
          if (!active) {
            throw new Error('lease');
          }
          return 'private-native-password-A1!';
        },
        toJSON: (): never => {
          throw new Error('lease');
        },
      };
      try {
        return await use(lease);
      } finally {
        active = false;
      }
    },
  };
  return Object.freeze(value);
};

const resource = {
  id: 'native-resource',
  indicator: 'https://app.example.test/api',
  accessTokenTtl: 300,
};
const scope = {
  id: 'native-scope',
  resourceId: 'native-resource',
  name: 'session:exchange',
};
const role = { id: 'native-role', isDefault: true };
const identity = {
  id: 'native-user',
  primaryEmail: 'phase2-native-0345a11679f07965@example.invalid',
  hasPassword: true,
};
const application = {
  id: 'native-client',
  type: 'Native',
  isThirdParty: false,
  oidcClientMetadata: {
    redirectUris: ['https://app.example.test/wechat/logto-callback'],
    postLogoutRedirectUris: [],
  },
};

const management = (
  requests: Phase2AdminRequest[],
  options: Readonly<{
    malformedCreate?: boolean;
    malformedReadback?: boolean;
    malformedPolicyResponse?: boolean;
    throwAfterPolicyMutation?: boolean;
    observeMethods?(methods: ReadonlyArray<Readonly<Record<string, unknown>>>): void;
  }> = {}
): Phase2AdminRequestFunction => {
  let methods = [
    {
      identifier: 'username',
      password: true,
      verificationCode: false,
      isPasswordPrimary: true,
    },
  ];
  return async (request) => {
    requests.push(request);
    const { method, path, query, body } = request;
    if (method === 'GET' && path === 'sign-in-exp') {
      return { signIn: { methods } };
    }
    if (method === 'PATCH' && path === 'sign-in-exp') {
      const patch = body as { signIn?: { methods?: typeof methods } };
      methods = patch.signIn?.methods ?? methods;
      options.observeMethods?.(methods);
      const enablingEmail = methods[0]?.identifier === 'email';
      if (enablingEmail && options.throwAfterPolicyMutation === true) {
        throw new Error('accepted policy mutation transport failure');
      }
      if (enablingEmail && options.malformedPolicyResponse === true) {
        return { signIn: { methods: [] } };
      }
      return { signIn: { methods } };
    }
    if (method === 'POST' && path === 'resources') {
      expect(body).toMatchObject({
        indicator: resource.indicator,
        accessTokenTtl: 300,
      });
      return options.malformedCreate ? { ...resource, accessTokenTtl: 301 } : resource;
    }
    if (method === 'POST' && path === 'resources/native-resource/scopes') {
      expect(body).toEqual({
        name: 'session:exchange',
        description: 'Exchange a Native session',
      });
      return scope;
    }
    if (method === 'POST' && path === 'roles') {
      expect(body).toMatchObject({ type: 'User', isDefault: true, scopeIds: ['native-scope'] });
      return role;
    }
    if (method === 'POST' && path === 'users') {
      expect(body).toEqual({
        primaryEmail: identity.primaryEmail,
        password: 'private-native-password-A1!',
      });
      return identity;
    }
    if (method === 'POST' && path === 'applications') {
      expect(body).toMatchObject({
        type: 'Native',
        isThirdParty: false,
        oidcClientMetadata: application.oidcClientMetadata,
      });
      return application;
    }
    if (method === 'GET' && path === 'applications/native-client') {
      return options.malformedReadback ? { ...application, type: 'SPA' } : application;
    }
    if (method === 'GET' && path === 'resources') {
      expect(query).toEqual({ includeScopes: 'true' });
      return [{ ...resource, scopes: [scope] }];
    }
    if (method === 'GET' && path === 'roles') {
      expect(query).toEqual({ page: '1', page_size: '20' });
      return [role];
    }
    if (method === 'GET' && path === 'roles/native-role/scopes') {
      return [scope];
    }
    if (method === 'GET' && path === 'users') {
      expect(query).toEqual({ page: '1', page_size: '100' });
      return [identity];
    }
    if (method === 'DELETE') {
      return 204;
    }
    throw new Error(`unexpected ${method} ${path}`);
  };
};

describe('selected Native public Management fixture', () => {
  it('creates candidate metadata without unsupported DELETEs or changing coordinator public', async () => {
    const base = fixture();
    const requests: Phase2AdminRequest[] = [];
    await withSelectedNativeFixture(
      base,
      { request: management(requests), target: candidate },
      async (selected) => {
        expect(base.public.selectedNative).toBeUndefined();
        expect(selected.public.selectedNative).toEqual({
          clientId: 'native-client',
          applicationType: 'Native',
          redirectUri: 'https://app.example.test/wechat/logto-callback',
          resource: {
            id: 'native-resource',
            indicator: 'https://app.example.test/api',
            accessTokenTtl: 300,
            scope: { id: 'native-scope', name: 'session:exchange' },
          },
          defaultUserRoleId: 'native-role',
          identity: {
            id: 'native-user',
            primaryEmail: identity.primaryEmail,
          },
        });
        await selected.withSecretLease(async (lease) => {
          expect(lease.getSelectedNativePassword?.()).toBe('private-native-password-A1!');
        });
      }
    );
    expect(requests.map(({ method, path }) => `${method} ${path}`)).toEqual([
      'GET sign-in-exp',
      'PATCH sign-in-exp',
      'POST resources',
      'POST resources/native-resource/scopes',
      'POST roles',
      'POST users',
      'POST applications',
      'GET applications/native-client',
      'GET resources',
      'GET roles',
      'GET roles/native-role/scopes',
      'GET users',
      'PATCH sign-in-exp',
    ]);
    expect(requests[1]?.body).toEqual({
      signIn: {
        methods: [
          {
            identifier: 'email',
            password: true,
            verificationCode: false,
            isPasswordPrimary: true,
          },
          {
            identifier: 'username',
            password: true,
            verificationCode: false,
            isPasswordPrimary: true,
          },
        ],
      },
    });
    expect(requests.some(({ method }) => method === 'DELETE')).toBe(false);
  });

  it('compensates reference objects in reverse order after use', async () => {
    const requests: Phase2AdminRequest[] = [];
    await withSelectedNativeFixture(
      fixture(),
      { request: management(requests), target: oracle },
      async () => 'used'
    );
    expect(requests.some(({ path }) => path.includes('user-consent-scopes'))).toBe(false);
    expect(requests.filter(({ method }) => method === 'DELETE').map(({ path }) => path)).toEqual([
      'applications/native-client',
      'users/native-user',
      'roles/native-role',
      'resources/native-resource',
    ]);
  });

  it('rejects malformed readback and compensates every created object', async () => {
    const requests: Phase2AdminRequest[] = [];
    await expect(
      withSelectedNativeFixture(
        fixture(),
        {
          request: management(requests, { malformedReadback: true }),
          target: oracle,
        },
        async () => 'unused'
      )
    ).rejects.toThrow('Invalid Phase 2 selected Native fixture');
    expect(requests.filter(({ method }) => method === 'DELETE')).toHaveLength(4);
  });

  it('registers a valid created ID for compensation before validating other fields', async () => {
    const requests: Phase2AdminRequest[] = [];
    await expect(
      withSelectedNativeFixture(
        fixture(),
        { request: management(requests, { malformedCreate: true }), target: oracle },
        async () => 'unused'
      )
    ).rejects.toThrow('Invalid Phase 2 selected Native fixture');
    expect(requests.filter(({ method }) => method === 'DELETE').map(({ path }) => path)).toEqual([
      'resources/native-resource',
    ]);
  });

  it('restores the prior policy after an accepted PATCH returns a malformed success body', async () => {
    const requests: Phase2AdminRequest[] = [];
    const observed: Array<ReadonlyArray<Readonly<Record<string, unknown>>>> = [];
    await expect(
      withSelectedNativeFixture(
        fixture(),
        {
          request: management(requests, {
            malformedPolicyResponse: true,
            observeMethods: (methods) => observed.push(methods),
          }),
          target: candidate,
        },
        async () => 'unused'
      )
    ).rejects.toThrow('Invalid Phase 2 selected Native fixture');
    expect(observed.at(-1)).toEqual([
      {
        identifier: 'username',
        password: true,
        verificationCode: false,
        isPasswordPrimary: true,
      },
    ]);
    expect(requests.map(({ method, path }) => `${method} ${path}`)).toEqual([
      'GET sign-in-exp',
      'PATCH sign-in-exp',
      'PATCH sign-in-exp',
    ]);
  });

  it('restores the prior policy after the accepted PATCH transport throws', async () => {
    const requests: Phase2AdminRequest[] = [];
    const observed: Array<ReadonlyArray<Readonly<Record<string, unknown>>>> = [];
    await expect(
      withSelectedNativeFixture(
        fixture(),
        {
          request: management(requests, {
            throwAfterPolicyMutation: true,
            observeMethods: (methods) => observed.push(methods),
          }),
          target: candidate,
        },
        async () => 'unused'
      )
    ).rejects.toThrow('accepted policy mutation transport failure');
    expect(observed.at(-1)).toEqual([
      {
        identifier: 'username',
        password: true,
        verificationCode: false,
        isPasswordPrimary: true,
      },
    ]);
    expect(requests.map(({ method, path }) => `${method} ${path}`)).toEqual([
      'GET sign-in-exp',
      'PATCH sign-in-exp',
      'PATCH sign-in-exp',
    ]);
  });
});

/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
