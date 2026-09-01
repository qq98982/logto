/* eslint-disable @silverhand/fp/no-mutating-methods, no-restricted-syntax, @typescript-eslint/consistent-type-assertions -- The focused protocol harness records ordered requests and consumes queued responses while structurally replacing live clients. */
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';

import type { JsonObject } from '../../normalize.js';
import { SymbolTable } from '../../symbol-table.js';
import {
  MemoryProtocolSecretStore,
  type ProtocolRequestOptions,
  type RawProtocolResponse,
} from '../clients/oidc.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimePhone,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
} from '../fixture-map.js';
import type { Phase1ScenarioRunContext } from '../model.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

import {
  type PositiveOidcAuthorizationGrant,
  type PositiveOidcFlowOptions,
  type PositiveOidcFlowOutput,
  withSyntheticPositiveOidcAuthorizationGrant,
} from './positive-oidc-flow.js';

export const tokenTestTarget = Object.freeze({
  label: 'oracle' as const,
  coreUrl: 'https://oracle.example/',
  adminUrl: 'https://oracle-admin.example/',
});

export const tokenTestCredentials = Object.freeze({
  clientId: 'runtime-consent-client',
  code: 'private-authorization-code',
  codeVerifier: 'v'.repeat(64),
  redirectUri: 'https://client.example/callback',
});
const dataAllocationId = 'data-allocation';
export const tokenTestRuntimeValues = Object.freeze({
  username: getPhase1FixtureRuntimeUsername('phase1-user', dataAllocationId),
  email: getPhase1FixtureRuntimeEmail('phase1-user@example.com', dataAllocationId),
  phone: getPhase1FixtureRuntimePhone(dataAllocationId),
  resourceIndicator: getPhase1FixtureRuntimeResourceIndicator(
    'https://api.example.com',
    dataAllocationId
  ),
  scopeName: getPhase1FixtureRuntimeText('read:profile', dataAllocationId),
});

export type TokenTestRequest = Readonly<{
  operation: string;
  path: string;
  options: ProtocolRequestOptions | undefined;
}>;

export type TokenTestSigner = Readonly<{
  jwk: JWK;
  sign(claims: Readonly<Record<string, unknown>>): Promise<string>;
}>;

export const createTokenTestSigner = async (
  algorithm: 'ES384' | 'RS256' = 'ES384'
): Promise<TokenTestSigner> => {
  const { privateKey, publicKey } = await generateKeyPair(algorithm);
  const jwk = { ...(await exportJWK(publicKey)), kid: 'runtime-signing-key', alg: algorithm };

  return Object.freeze({
    jwk,
    sign: async (claims) =>
      new SignJWT({ ...claims })
        .setProtectedHeader({ alg: algorithm, kid: 'runtime-signing-key' })
        .sign(privateKey),
  });
};

const profile = Object.freeze({
  fixtures: {
    dataTenant: {
      subject: {
        id: 'phase1-user',
        username: 'phase1-user',
        name: 'Phase 1 User',
        primaryEmail: 'phase1-user@example.com',
        primaryPhone: '+15555550101',
        profile: { address: { formatted: '1 Aster Way', country: 'US' } },
      },
      resource: {
        indicator: 'https://api.example.com',
        scopes: [{ name: 'read:profile' }],
      },
    },
  },
  oidc: {
    issuerPath: '/oidc',
    tokenPath: '/oidc/token',
    userinfoPath: '/oidc/me',
    jwksPath: '/oidc/jwks',
    idTokenSigningAlgorithmsSupported: ['ES384'],
  },
});

const fixtureMap = Object.freeze({
  schemaVersion: 1 as const,
  recipe: 'dataProtocol' as const,
  allocations: Object.freeze([
    Object.freeze({
      allocationId: dataAllocationId,
      role: 'data' as const,
      target: 'primary' as const,
      isolation: Object.freeze({
        persistenceId: 'data-persistence',
        cookieKeyId: 'data-cookie',
        signingKeyId: 'data-signing',
      }),
      entities: Object.freeze([
        Object.freeze({
          kind: 'user' as const,
          logicalId: 'phase1-user',
          runtimeId: 'runtime-subject',
        }),
        Object.freeze({
          kind: 'application' as const,
          logicalId: 'phase1-browser',
          runtimeId: tokenTestCredentials.clientId,
        }),
      ]),
    }),
  ]),
});

const response = (body: unknown) =>
  Object.freeze({
    status: 200,
    headers: Object.freeze([Object.freeze(['content-type', 'application/json'] as const)]),
    body: JSON.stringify(body),
  });

export const tokenGrantBody = (
  input: Readonly<{
    accessToken: string;
    idToken: string;
    refreshToken: string;
  }>
) => ({
  access_token: input.accessToken,
  id_token: input.idToken,
  refresh_token: input.refreshToken,
  token_type: 'Bearer',
  expires_in: 3600,
  scope: 'openid offline_access profile email address phone',
});

export const createTokenScenarioHarness = (
  input: Readonly<{
    jwk: JWK;
    tokenBodies: readonly unknown[];
    tokenResponses?: readonly RawProtocolResponse[];
    userInfoBody?: unknown;
    projectScenarioState?: (input: {
      scenarioId: string;
      stepId: string;
    }) => Promise<Phase1ScenarioStateProjectionInput>;
  }>
) => {
  const requests: TokenTestRequest[] = [];
  const stateReads: string[] = [];
  const tokenBodies = [...input.tokenBodies];
  const tokenResponses = [...(input.tokenResponses ?? [])];
  const store = new MemoryProtocolSecretStore();
  const dataSymbols = new SymbolTable();
  dataSymbols.bind('user.phase1-user', 'runtime-subject');
  dataSymbols.bind('application.phase1-browser', tokenTestCredentials.clientId);
  dataSymbols.bind('fixture.data.username', tokenTestRuntimeValues.username);
  dataSymbols.bind('fixture.data.email', tokenTestRuntimeValues.email);
  dataSymbols.bind('fixture.data.phone', tokenTestRuntimeValues.phone);
  dataSymbols.bind('fixture.data.resource-indicator', tokenTestRuntimeValues.resourceIndicator);
  dataSymbols.bind('fixture.data.scope-name', tokenTestRuntimeValues.scopeName);
  const dataOidc = {
    store,
    request: import.meta.jest.fn(
      async (operation: string, path: string, options?: ProtocolRequestOptions) => {
        requests.push({ operation, path, options });
        if (operation === 'userinfo-openid') {
          return response(input.userInfoBody);
        }
        const tokenResponse = tokenResponses.shift();

        if (tokenResponse) {
          return tokenResponse;
        }
        const body = tokenBodies.shift();

        if (body === undefined) {
          throw new Error('unexpected token request');
        }

        return response(body);
      }
    ),
  };
  const publicOidc = {
    store: new MemoryProtocolSecretStore(),
    request: import.meta.jest.fn(async (operation: string) => {
      if (operation !== 'token-jwks') {
        throw new Error('unexpected public request');
      }

      return response({ keys: [input.jwk] });
    }),
  };
  const context: Phase1ScenarioRunContext = {
    profile: profile as never,
    target: tokenTestTarget,
    fixture: { public: fixtureMap } as never,
    signal: new AbortController().signal,
    protocol: {
      publicOidc: publicOidc as never,
      publicSymbols: new SymbolTable(),
      forAllocation: () => ({
        oidc: dataOidc as never,
        experience: {} as never,
        consent: {} as never,
        management: {} as never,
        account: {} as never,
        state: {} as never,
      }),
      symbolsFor: () => dataSymbols,
    },
    projectFixtureState: async () => ({
      schemaVersion: 1,
      recipe: 'dataProtocol',
      allocations: [],
    }),
    // eslint-disable-next-line complexity -- The focused harness supplies exact state contracts for the existing positive token scenarios.
    projectScenarioState: async ({
      scenarioId,
      stepId,
    }): Promise<Phase1ScenarioStateProjectionInput> => {
      stateReads.push(stepId);
      if (input.projectScenarioState) {
        return input.projectScenarioState({ scenarioId, stepId });
      }
      const generatedIds: Readonly<Record<string, string>> =
        (scenarioId === 'token.authorization-code' && stepId === 'state') ||
        (scenarioId === 'token.refresh-rotation' && stepId === 'family-state')
          ? { tokenFamily: '<token-family.1>' }
          : {};

      const persistedState: JsonObject =
        scenarioId === 'token.authorization-code' && stepId === 'state'
          ? { grantConsumed: true, familyCount: 1, unrelatedMutation: false }
          : scenarioId === 'token.refresh-rotation' && stepId === 'family-state'
            ? {
                rotation: { replaced: true, sameFamily: true },
                unrelatedMutation: false,
              }
            : scenarioId === 'userinfo.openid' && stepId === 'state'
              ? { unrelatedMutation: false }
              : { stepId, unrelatedMutation: false };

      return {
        body: { stepId },
        semanticState: { stepId, unrelatedMutation: false },
        persistedState,
        generatedIds,
        sideEffects: { unrelatedMutation: false },
      };
    },
  };
  const flow = async <Result>(
    _context: Phase1ScenarioRunContext,
    options: PositiveOidcFlowOptions,
    consume: (grant: PositiveOidcAuthorizationGrant) => Promise<Result>
  ): Promise<PositiveOidcFlowOutput<Result>> => {
    expect(options.captureSteps).toBe(false);
    const result = await withSyntheticPositiveOidcAuthorizationGrant(tokenTestCredentials, consume);

    return Object.freeze({ steps: Object.freeze([]), result });
  };

  return Object.freeze({ context, flow, requests, stateReads, dataSymbols });
};

/* eslint-enable @silverhand/fp/no-mutating-methods, no-restricted-syntax, @typescript-eslint/consistent-type-assertions */
