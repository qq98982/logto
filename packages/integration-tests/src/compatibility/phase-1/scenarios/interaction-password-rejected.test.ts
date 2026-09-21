/* eslint-disable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions -- The structural harness records requests and uses narrow fixture/context test doubles. */
import { SymbolTable } from '../../symbol-table.js';
import {
  MemoryProtocolSecretStore,
  protocolHeaderPairs,
  type ProtocolRequestOptions,
} from '../clients/oidc.js';
import { getPhase1FixtureRuntimeUsername } from '../fixture-map.js';
import type { Phase1ScenarioRunContext } from '../model.js';

import {
  runInteractionPasswordRejected,
  type PasswordRejectedRandomSource,
} from './interaction-password-rejected.js';

const allocationId = 'password-rejected-allocation';
const runtimeUsername = getPhase1FixtureRuntimeUsername('phase1-user', allocationId);
const fixtureMap = {
  schemaVersion: 1 as const,
  recipe: 'dataProtocol' as const,
  allocations: [
    {
      allocationId,
      role: 'data' as const,
      target: 'primary' as const,
      isolation: {
        persistenceId: 'data-persistence',
        cookieKeyId: 'data-cookie-key',
        signingKeyId: 'data-signing-key',
      },
      entities: [
        { kind: 'tenant' as const, logicalId: 'default', runtimeId: 'default' },
        { kind: 'user' as const, logicalId: 'phase1-user', runtimeId: 'runtime-user' },
        {
          kind: 'application' as const,
          logicalId: 'phase1-browser',
          runtimeId: 'runtime-client',
        },
      ],
    },
  ],
};
const profile = {
  fixtures: {
    dataTenant: {
      subject: { id: 'phase1-user', username: 'phase1-user' },
      applications: [
        {
          id: 'phase1-browser',
          isThirdParty: true,
          oidcClientMetadata: { redirectUris: ['https://client.example/callback'] },
        },
      ],
      browserClientConfiguration: {
        localStorageKey: 'logto:demo-app:dev:config',
      },
    },
  },
  oidc: { authorizationPath: '/oidc/auth' },
};
const target = {
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://admin.example/',
};
const closedState = {
  body: { observed: true },
  semanticState: { interactionStatus: 'present' },
  persistedState: {
    verificationRecords: 0,
    identifiedUsers: 0,
    grants: 0,
    issuances: 0,
    sessionExtensions: 0,
  },
  generatedIds: { interaction: '<interaction.1>' },
  sideEffects: { authenticationState: 'unchanged' },
};

type RecordedRequest = Readonly<{
  operation: string;
  path: string;
  method: string;
  contentType: string | undefined;
  body: string | undefined;
  cookiePresent: boolean;
}>;

type HarnessOptions = Readonly<{
  state?: typeof closedState;
  setCookieOperation?: 'bootstrap' | 'password';
  encodedLeak?: 'password' | 'verifier' | 'state' | 'cookie';
}>;

const encodeAll = (value: string) =>
  Buffer.from(value, 'utf8')
    .toString('hex')
    .match(/.{2}/gu)
    ?.map((byte) => `%${byte}`)
    .join('') ?? '';

const createHarness = ({
  state = closedState,
  setCookieOperation,
  encodedLeak,
}: HarnessOptions = {}) => {
  const store = new MemoryProtocolSecretStore();
  const records: RecordedRequest[] = [];
  const record = (operation: string, path: string, options?: ProtocolRequestOptions) => {
    records.push({
      operation,
      path,
      method: options?.method ?? (options?.body === undefined ? 'GET' : 'POST'),
      contentType: protocolHeaderPairs(options?.headers).find(
        ([name]) => name.toLowerCase() === 'content-type'
      )?.[1],
      body: options?.body,
      cookiePresent: Boolean(
        store.getCookieHeader(new URL(path, new URL('/api/', target.coreUrl)))
      ),
    });
  };
  const oidc = {
    store,
    request: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        record(operation, path, options);
        store.setCookie(
          '_interaction=private-interaction; Path=/; HttpOnly',
          new URL(target.coreUrl)
        );
        store.setCookie(
          '_interaction.sig=private-signature; Path=/; HttpOnly',
          new URL(target.coreUrl)
        );

        return { status: 303, headers: [['location', '/sign-in']] as const, body: '' };
      }
    ),
  };
  const experience = {
    store,
    requestExperience: import.meta.jest.fn(
      // eslint-disable-next-line complexity -- Each branch injects one bounded transformed credential into an otherwise exact response.
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        record(operation, path, options);
        const leaked =
          encodedLeak === 'password' && operation === 'password-rejected-verification'
            ? encodeAll('fixture-password-private.rejected')
            : encodedLeak === 'verifier' && operation === 'password-rejected-bootstrap'
              ? encodeAll('v'.repeat(64))
              : encodedLeak === 'state' && operation === 'password-rejected-bootstrap'
                ? encodeAll('authorization-state-private')
                : encodedLeak === 'cookie' && operation === 'password-rejected-bootstrap'
                  ? encodeAll('private-interaction')
                  : undefined;

        return operation === 'password-rejected-bootstrap'
          ? {
              status: 204,
              headers: [
                ...(setCookieOperation === 'bootstrap'
                  ? ([['set-cookie', 'unexpected=private; Path=/; HttpOnly']] as const)
                  : []),
                ...(leaked ? ([['x-credential-leak', leaked]] as const) : []),
              ] as const,
              body: '',
            }
          : {
              status: 422,
              headers: [
                ['content-type', 'application/json; charset=utf-8'],
                ...(setCookieOperation === 'password'
                  ? ([['set-cookie', 'unexpected=private; Path=/; HttpOnly']] as const)
                  : []),
                ...(leaked ? ([['x-credential-leak', leaked]] as const) : []),
              ] as const,
              body: JSON.stringify({
                code: 'session.invalid_credentials',
                message: 'Incorrect account or password. Please check your input.',
              }),
            };
      }
    ),
  };
  const symbols = new SymbolTable();

  for (const entity of fixtureMap.allocations[0]!.entities) {
    symbols.bind(`${entity.kind}.${entity.logicalId}`, entity.runtimeId);
  }
  const context = {
    profile: profile as never,
    target,
    fixture: {
      public: fixtureMap,
      withSecretLease: async <Result>(
        use: (lease: { getPassword(id: string): string }) => Promise<Result>
      ) => use({ getPassword: () => 'fixture-password-private' }),
    } as never,
    signal: new AbortController().signal,
    protocol: {
      publicOidc: oidc,
      publicSymbols: new SymbolTable(),
      forAllocation: () => ({
        oidc,
        experience,
        consent: { store },
        management: { store },
        account: { store },
        state: { store },
      }),
      symbolsFor: () => symbols,
    } as never,
    projectFixtureState: async () =>
      ({ schemaVersion: 1, recipe: 'dataProtocol', allocations: [] }) as never,
    projectScenarioState: import.meta.jest.fn(async () => state),
  } as unknown as Phase1ScenarioRunContext;
  const random: PasswordRejectedRandomSource = {
    codeVerifier: () => 'v'.repeat(64),
    state: () => 'authorization-state-private',
  };

  return { context, records, random, store };
};

describe('interaction.password-rejected', () => {
  it('keeps one cookie jar across bootstrap and the exact rejected password response', async () => {
    const { context, records, random, store } = createHarness();
    const steps = await runInteractionPasswordRejected(context, random);

    expect(steps.map(({ stepId }) => stepId)).toEqual([
      'experience-bootstrap',
      'password',
      'state',
    ]);
    expect(
      records.map(({ operation, method, contentType, cookiePresent }) => ({
        operation,
        method,
        contentType,
        cookiePresent,
      }))
    ).toEqual([
      {
        operation: 'password-rejected-authorization-start',
        method: 'GET',
        contentType: undefined,
        cookiePresent: false,
      },
      {
        operation: 'password-rejected-bootstrap',
        method: 'PUT',
        contentType: 'application/json',
        cookiePresent: true,
      },
      {
        operation: 'password-rejected-verification',
        method: 'POST',
        contentType: 'application/json',
        cookiePresent: true,
      },
    ]);
    const authorization = new URL(records[0]!.path, target.coreUrl);
    expect(authorization.pathname).toBe('/oidc/auth');
    const authorizationParameters = Object.fromEntries(authorization.searchParams);
    expect(typeof authorizationParameters.code_challenge).toBe('string');
    expect(authorizationParameters.code_challenge).toHaveLength(43);
    expect(authorizationParameters).toEqual({
      client_id: 'runtime-client',
      redirect_uri: 'https://client.example/callback',
      code_challenge: authorizationParameters.code_challenge,
      code_challenge_method: 'S256',
      state: 'authorization-state-private',
      response_type: 'code',
      prompt: 'login',
      scope: 'openid',
    });
    expect(records.map(({ path }) => path.split('?', 1)[0])).toEqual([
      'oidc/auth',
      'experience',
      'experience/verification/password',
    ]);
    expect(records[0]?.body).toBeUndefined();
    expect(records[1]?.body).toBe(JSON.stringify({ interactionEvent: 'SignIn' }));
    expect(records[2]?.body).toBe(
      JSON.stringify({
        identifier: { type: 'username', value: runtimeUsername },
        password: 'fixture-password-private.rejected',
      })
    );
    expect(store.getCookieHeader(new URL(target.coreUrl))).toBeTruthy();
    expect(steps[1]?.value).toMatchObject({
      status: 422,
      error: {
        errorCode: 'session.invalid_credentials',
        message: 'Incorrect account or password. Please check your input.',
      },
      cookies: [],
      redirect: null,
    });
    expect(context.projectScenarioState).toHaveBeenCalledTimes(3);
  });

  it.each([
    'verificationRecords',
    'identifiedUsers',
    'grants',
    'issuances',
    'sessionExtensions',
  ] as const)('rejects a state port that mutates %s', async (field) => {
    const { context, random } = createHarness({
      state: {
        ...closedState,
        persistedState: { ...closedState.persistedState, [field]: 1 },
      },
    });

    await expect(runInteractionPasswordRejected(context, random)).rejects.toThrow(
      'Phase 1 rejected password state is invalid'
    );
  });

  it.each(['bootstrap', 'password'] as const)(
    'rejects an unexpected Set-Cookie on the %s response',
    async (setCookieOperation) => {
      const { context, random } = createHarness({ setCookieOperation });

      await expect(runInteractionPasswordRejected(context, random)).rejects.toThrow(
        setCookieOperation === 'bootstrap'
          ? 'Phase 1 rejected password bootstrap mutated cookies'
          : 'Phase 1 rejected password mutated cookies'
      );
    }
  );

  it.each(['password', 'verifier', 'state', 'cookie'] as const)(
    'rejects a fully percent-encoded %s leak in an otherwise valid response header',
    async (encodedLeak) => {
      const { context, random } = createHarness({ encodedLeak });

      await expect(runInteractionPasswordRejected(context, random)).rejects.toThrow(
        'Invalid phase 1 HTTP projection'
      );
    }
  );
});

/* eslint-enable @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions */
