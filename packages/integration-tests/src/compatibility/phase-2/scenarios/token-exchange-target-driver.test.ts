/* eslint-disable max-lines, complexity, no-await-in-loop, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The test models a secret lease and counts sequential exchanges. */
import { setImmediate as nextTurn } from 'node:timers/promises';

import { generateKeyPair, exportJWK, SignJWT } from 'jose';

import type { ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  expectTokenExchangeGrammarError,
  observeTokenExchangeUserJwtMatrix,
  resolveTokenExchangeClientRoles,
  withApplicationExchangeEnabled,
  withRequiredCleanup,
  withTokenExchangeClientsEnabled,
} from './token-exchange-target-driver.js';

const target = Object.freeze({
  label: 'candidate' as const,
  coreUrl: 'https://core.test/',
  adminUrl: 'https://admin.test/',
});
const fixture = Object.freeze({
  public: {
    clients: { basic: { id: 'first-party-confidential', method: 'client_secret_basic' } },
    deviceClients: {
      firstParty: {
        id: 'first-party-public',
        applicationType: 'Native',
        authenticationMethod: 'none',
        isThirdParty: false,
        deviceGrantEnabled: true,
      },
    },
    organization: { id: 'org', scopeName: 'organization:read' },
    resources: {
      primary: { id: 'resource-primary', indicator: 'https://primary-api.test/' },
      default: { id: 'resource-default', indicator: 'https://default-api.test/' },
    },
  } as ProvisionedPhase2Fixture['public'],
  status: Object.freeze({
    user: Object.freeze({ id: 'user-1', username: 'user' }),
    client: Object.freeze({ id: 'third-party-status-public', redirectUri: 'https://app.test/cb' }),
    confidentialClient: Object.freeze({
      id: 'third-party-status-confidential',
      redirectUri: 'https://app.test/cb',
    }),
    resource: Object.freeze({
      id: 'resource-1',
      indicator: 'https://api.test/',
      scopeName: 'read:fixture',
    }),
  }),
  withSecretLease: async <Result>(use: (lease: never) => Promise<Result>) =>
    use(
      Object.freeze({
        getSubjectPassword: () => 'secret-password',
        getClientSecret: (logicalClient: 'basic' | 'post') => {
          if (logicalClient !== 'basic') {
            throw new Error('unexpected confidential client secret selection');
          }
          return 'confidential-secret';
        },
        getStatusClientSecret: () => 'confidential-secret',
        toJSON: () => {
          throw new Error('private');
        },
      }) as never
    ),
}) satisfies ProvisionedPhase2Fixture;

it('exchanges one source twice and projects only verified stable semantics', async () => {
  const { privateKey, publicKey } = await generateKeyPair('ES384');
  const jwk = await exportJWK(publicKey);
  let requests = 0;
  const managedDispatches: Array<
    Readonly<{ source: string; kind: 'managed' | 'pat'; target: string; actor?: string }>
  > = [];
  const managementDispatches: string[] = [];
  const managementRequests: Array<Readonly<{ method: string; path: string; body: unknown }>> = [];
  const enabledTransitions: boolean[] = [];
  const grammarDispatches: Array<
    Readonly<{
      entries: ReadonlyArray<readonly [string, string]>;
      authentication: 'none' | 'correct' | 'wrong';
    }>
  > = [];
  const tokenUses: Array<Readonly<{ token: string; kind: string }>> = [];
  const resourceRequestScopes: string[] = [];
  let leaseActive = false;
  let leaseCount = 0;
  let subjects = 0;
  let revoked = false;
  let customizerMode: 'absent' | 'context' | 'throwing' | 'deny' = 'absent';
  let installedCustomizerScript = '';
  let invalidCustomizerReadback: 'script' | 'block' | undefined;
  let customizerActorClaims: Readonly<Record<string, unknown>> = Object.freeze({
    sub: 'phase2-customizer-actor',
  });
  let throwingCustomizerFailsOpen = true;
  let throwingReplayAccepted = false;
  const throwingConsumedSubjects = new Set<string>();
  let rejectedPatCreateName: string | undefined;
  let rejectedPatDeleteName: string | undefined;
  let defaultResourceEnabled = true;
  let repeatedResourceError: Error | undefined;
  let restoreDefaultError: Error | undefined;
  let restoreGate: Promise<void> | undefined;
  let repeatedResourceStarted: (() => void) | undefined;
  let restoreStarted: (() => void) | undefined;
  const signed = async (
    clientId: string,
    actor?: string,
    options: Readonly<{
      audience?: string;
      lifetime?: number;
      scope?: string;
      organizationId?: string;
      claims?: Readonly<Record<string, unknown>>;
    }> = {}
  ) =>
    new SignJWT({
      sub: 'user-1',
      client_id: clientId,
      scope: options.scope ?? 'read:fixture',
      ...(actor ? { act: { sub: actor } } : {}),
      ...(options.organizationId === undefined ? {} : { organization_id: options.organizationId }),
      ...options.claims,
    })
      .setProtectedHeader({ alg: 'ES384', typ: 'at+jwt', kid: 'key-1' })
      .setIssuer('https://core.test/oidc')
      .setAudience(options.audience ?? 'https://api.test/')
      .setIssuedAt(1000)
      .setExpirationTime(1000 + (options.lifetime ?? 3600))
      .sign(privateKey);
  const adapters: Parameters<typeof observeTokenExchangeUserJwtMatrix>[1] = {
    withExchangeEnabled: async (_input, use) =>
      use(
        async (request) => {
          managementDispatches.push(`${request.method} ${request.path}`);
          managementRequests.push({
            method: String(request.method),
            path: request.path,
            body: request.body,
          });
          if (request.path === 'configs/jwt-customizer/access-token') {
            if (request.method === 'GET') {
              return customizerMode === 'absent'
                ? { code: 'entity.not_exists_with_id' }
                : {
                    script: invalidCustomizerReadback === 'script' ? '' : installedCustomizerScript,
                    blockIssuanceOnError: invalidCustomizerReadback !== 'block',
                  };
            }
            if (String(request.method) === 'PUT') {
              const body = request.body as Readonly<Record<string, unknown>>;
              const script = String(body.script);
              installedCustomizerScript = script;
              customizerMode = script.includes('denyAccess')
                ? 'deny'
                : script.includes('throw new Error')
                  ? 'throwing'
                  : 'context';
              return { script: customizerMode, blockIssuanceOnError: true };
            }
            if (request.method === 'DELETE') {
              customizerMode = 'absent';
              return 204;
            }
          }
          if (request.path === 'subject-tokens') {
            subjects += 1;
            return { expiresIn: 600, subjectToken: `managed-${subjects}` };
          }
          if (request.path === 'resources/resource-default/is-default') {
            const body = request.body as Readonly<{ isDefault: boolean }>;
            if (body.isDefault) {
              restoreStarted?.();
              await restoreGate;
              if (restoreDefaultError) {
                throw restoreDefaultError;
              }
            }
            defaultResourceEnabled = body.isDefault;
            return { id: 'resource-default', isDefault: body.isDefault };
          }
          if (request.method === 'POST' && request.path.endsWith('personal-access-tokens')) {
            const body = request.body as Readonly<{ name: string }>;
            if (body.name === rejectedPatCreateName) {
              throw new Error(`create response rejected for ${body.name}`);
            }
            return {
              createdAt: 1,
              expiresAt: null,
              name: 'phase2-token-exchange-pat',
              tenantId: 'tenant',
              userId: 'user-1',
              value: 'pat-secret',
            };
          }
          if (request.method === 'GET') {
            return [
              {
                createdAt: 1,
                expiresAt: null,
                name: 'phase2-token-exchange-pat',
                tenantId: 'tenant',
                userId: 'user-1',
                value: 'pat-secret',
              },
            ];
          }
          if (request.path.endsWith('/delete')) {
            const body = request.body as Readonly<{ name: string }>;
            if (body.name === rejectedPatDeleteName) {
              throw new Error(`delete failed for ${body.name}`);
            }
            return 204;
          }
          throw new Error('unexpected management request');
        },
        async (enabled) => {
          enabledTransitions.push(enabled);
        }
      ),
    issueSource: async (_input, password) => {
      expect(leaseActive).toBe(false);
      expect(password).toBe('secret-password');
      return Object.freeze({
        access: 'source.secret.value',
        toJSON: () => {
          throw new Error('private');
        },
      });
    },
    request: async (_input, source, options) => {
      if (options?.resource === false) {
        return new Response(
          JSON.stringify({
            access_token:
              source === 'opaque-openid'
                ? 'opaque-child'
                : options.scope === 'profile'
                  ? 'opaque-profile'
                  : 'opaque-openid',
            expires_in: 3600,
            scope: options.scope,
            token_type: 'Bearer',
          }),
          { status: 200 }
        );
      }
      if (options?.scope !== 'read:fixture') {
        throw new Error('resource scope was not serialized from the fixture');
      }
      if (source === 'opaque-openid' && revoked) {
        return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
      }
      if (source === 'opaque-openid' || source === 'opaque-profile') {
        return new Response(
          JSON.stringify({
            access_token: await signed('first-party-public'),
            expires_in: 3600,
            scope: 'read:fixture',
            token_type: 'Bearer',
          }),
          { status: 200 }
        );
      }
      expect(source).toBe('source.secret.value');
      resourceRequestScopes.push(options.scope);
      requests += 1;
      const access = await signed('first-party-public');
      return new Response(
        JSON.stringify({
          access_token: access,
          expires_in: 3600,
          scope: 'read:fixture',
          token_type: 'Bearer',
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      );
    },
    managedRequest: async (_input, source, secret, options) => {
      expect(secret).toBe('confidential-secret');
      managedDispatches.push({ source, ...options });
      const index = managedDispatches.length;
      if (customizerMode === 'deny') {
        return new Response(JSON.stringify({ error: 'access_denied' }), { status: 400 });
      }
      if (customizerMode === 'throwing' && !throwingCustomizerFailsOpen) {
        return new Response(JSON.stringify({ error: 'server_error' }), { status: 500 });
      }
      if (throwingConsumedSubjects.has(source) && !throwingReplayAccepted) {
        return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
      }
      if (index === 1) {
        return new Response(JSON.stringify({ error: 'invalid_target' }), { status: 400 });
      }
      if (
        index === 3 ||
        index === 4 ||
        index === 8 ||
        options.actor === 'opaque-profile' ||
        (options.actor === 'opaque-openid' && revoked)
      ) {
        return new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 });
      }
      if (customizerMode === 'throwing') {
        throwingConsumedSubjects.add(source);
      }
      return new Response(
        JSON.stringify({
          access_token: await signed(
            'first-party-confidential',
            options.actor === 'opaque-openid' || options.actor === 'opaque-child'
              ? 'user-1'
              : undefined,
            customizerMode === 'context'
              ? {
                  claims:
                    options.kind === 'managed'
                      ? {
                          phase2_token_shape: true,
                          phase2_user_context: true,
                          phase2_application_context: true,
                          phase2_organization_context: true,
                          phase2_subject_context: true,
                          act: customizerActorClaims,
                        }
                      : { phase2_subject_context_absent: true },
                }
              : {}
          ),
          expires_in: 3600,
          scope: 'read:fixture',
          token_type: 'Bearer',
        }),
        { status: 200 }
      );
    },
    tokenUse: async (_input, token, kind) => {
      tokenUses.push({ token, kind });
      if (kind === 'revocation') {
        expect(token).toBe('opaque-openid');
        revoked = true;
        return new Response('', { status: 200 });
      }
      if (kind === 'userinfo') {
        return new Response(JSON.stringify({ sub: 'user-1' }), { status: 200 });
      }
      return new Response(
        JSON.stringify(
          token === 'opaque-openid'
            ? {
                active: true,
                sub: 'user-1',
                client_id: 'first-party-public',
                scope: 'openid profile',
              }
            : { active: true, sub: 'user-1' }
        ),
        { status: 200 }
      );
    },
    grammarRequest: async (_input, entries, authentication, confidentialSecret) => {
      if (authentication === 'correct') {
        expect(leaseActive).toBe(false);
        expect(confidentialSecret).toBe('confidential-secret');
      }
      grammarDispatches.push({ entries, authentication });
      const index = grammarDispatches.length - 1;
      const descriptions = [
        'requested grant type is not allowed for this client',
        'invalid client unknown-client',
        "missing required parameter 'subject_token'",
        "missing required parameter 'subject_token_type'",
        'no client authentication mechanism provided',
        'client authentication failed',
        "missing required parameters 'subject_token' and 'subject_token_type'",
        "'subject_token' parameter must not be provided twice",
        "'subject_token_type' parameter must not be provided twice",
        "'actor_token' parameter must not be provided twice",
        "'actor_token_type' parameter must not be provided twice",
      ] as const;
      if (index === 1 || index === 5) {
        return new Response(
          JSON.stringify({ error: 'invalid_client', error_description: descriptions[index] }),
          {
            status: index === 5 ? 401 : 400,
          }
        );
      }
      if (index < 11) {
        return new Response(
          JSON.stringify({ error: 'invalid_request', error_description: descriptions[index] }),
          { status: 400 }
        );
      }
      if (index === 11) {
        expect(defaultResourceEnabled).toBe(true);
        return new Response(
          JSON.stringify({
            error: 'invalid_target',
            error_description: 'resource indicator is missing, or unknown',
          }),
          { status: 400 }
        );
      }
      if (index === 12) {
        expect(defaultResourceEnabled).toBe(false);
        repeatedResourceStarted?.();
        if (repeatedResourceError) {
          throw repeatedResourceError;
        }
        return new Response(
          JSON.stringify({
            access_token: 'grammar-opaque',
            expires_in: 3600,
            scope: '',
            token_type: 'Bearer',
          }),
          { status: 200 }
        );
      }
      if (index === 14) {
        return new Response(
          JSON.stringify({
            access_token: await signed('first-party-public', undefined, {
              audience: 'urn:aster:organization:org',
              lifetime: 3600,
              scope: '',
            }),
            expires_in: 3600,
            scope: '',
            token_type: 'Bearer',
          }),
          { status: 200 }
        );
      }
      if (index === 16) {
        return new Response(
          JSON.stringify({
            access_token: 'scope-canonical-opaque',
            expires_in: 3600,
            scope: 'openid profile',
            token_type: 'Bearer',
          }),
          { status: 200 }
        );
      }
      if (index === 18) {
        return new Response(
          JSON.stringify({
            access_token: await signed('first-party-public', undefined, {
              audience: 'urn:aster:organization:org',
              lifetime: 3600,
              scope: '',
            }),
            expires_in: 3600,
            scope: '',
            token_type: 'Bearer',
          }),
          { status: 200 }
        );
      }
      if (index === 19) {
        return new Response(
          JSON.stringify({
            access_token: await signed('first-party-confidential', undefined, {
              claims: { phase2_subject_context_absent: true },
            }),
            expires_in: 3600,
            scope: 'read:fixture',
            token_type: 'Bearer',
          }),
          { status: 200 }
        );
      }
      return new Response(
        JSON.stringify({
          access_token: await signed(
            'first-party-public',
            undefined,
            index === 15 ? { organizationId: 'org' } : {}
          ),
          expires_in: 3600,
          scope: 'read:fixture',
          token_type: 'Bearer',
        }),
        { status: 200 }
      );
    },
    settleCustomizer: async () => {
      expect(customizerMode).toBeDefined();
    },
    readJwks: async () => ({ keys: [{ ...jwk, kid: 'key-1', alg: 'ES384', use: 'sig' }] }),
    now: () => 1001,
  };
  const exclusiveFixture = {
    ...fixture,
    withSecretLease: async <Result>(use: (lease: never) => Promise<Result>) => {
      if (leaseActive) {
        throw new Error('secret lease re-entry');
      }
      leaseActive = true;
      leaseCount += 1;
      try {
        return await fixture.withSecretLease(use);
      } finally {
        leaseActive = false;
      }
    },
  } satisfies ProvisionedPhase2Fixture;
  const runMatrix = async () =>
    observeTokenExchangeUserJwtMatrix(
      { target, fixture: exclusiveFixture, signal: new AbortController().signal },
      adapters
    );
  const projection = await runMatrix();
  expect(requests).toBe(2);
  expect(resourceRequestScopes).toEqual(['read:fixture', 'read:fixture']);
  expect(leaseCount).toBe(1);
  expect(enabledTransitions).toEqual([false, true]);
  expect(grammarDispatches).toHaveLength(20);
  expect(grammarDispatches[7]?.entries.filter(([key]) => key === 'subject_token')).toHaveLength(2);
  expect(
    grammarDispatches[8]?.entries.filter(([key]) => key === 'subject_token_type')
  ).toHaveLength(2);
  expect(grammarDispatches[9]?.entries.filter(([key]) => key === 'actor_token')).toHaveLength(2);
  expect(grammarDispatches[10]?.entries.filter(([key]) => key === 'actor_token_type')).toHaveLength(
    2
  );
  expect(grammarDispatches[11]?.entries.filter(([key]) => key === 'resource')).toEqual([
    ['resource', 'https://api.test/'],
    ['resource', 'https://primary-api.test/'],
  ]);
  expect(grammarDispatches[12]?.entries).toEqual(grammarDispatches[11]?.entries);
  expect(grammarDispatches[13]?.entries.at(-1)).toEqual([
    'requested_token_type',
    'urn:example:ignored',
  ]);
  expect(grammarDispatches[14]?.entries.at(-1)).toEqual(['organization_id', 'org']);
  expect(grammarDispatches[15]?.entries.slice(-3)).toEqual([
    ['resource', 'https://api.test/'],
    ['scope', 'read:fixture'],
    ['organization_id', 'org'],
  ]);
  expect(grammarDispatches.slice(16, 19).map(({ entries }) => entries.at(-1))).toEqual([
    ['scope', 'openid openid profile profile unknown unknown'],
    ['scope', 'read:fixture read:fixture unknown unknown'],
    ['scope', 'organization:read organization:read unknown unknown'],
  ]);
  expect(grammarDispatches[19]?.authentication).toBe('correct');
  expect(tokenUses.slice(-3)).toEqual([
    { token: 'opaque-openid', kind: 'revocation' },
    { token: 'opaque-child', kind: 'introspection' },
    { token: 'opaque-child', kind: 'userinfo' },
  ]);
  expect(subjects).toBe(8);
  expect(managementDispatches).toEqual([
    'POST subject-tokens',
    'POST subject-tokens',
    'POST users/user-1/personal-access-tokens',
    'GET users/user-1/personal-access-tokens',
    'POST users/user-1/personal-access-tokens/delete',
    'POST subject-tokens',
    'POST subject-tokens',
    'POST subject-tokens',
    'PATCH resources/resource-default/is-default',
    'PATCH resources/resource-default/is-default',
    'GET configs/jwt-customizer/access-token',
    'PUT configs/jwt-customizer/access-token',
    'GET configs/jwt-customizer/access-token',
    'POST subject-tokens',
    'POST users/user-1/personal-access-tokens',
    'POST users/user-1/personal-access-tokens/delete',
    'PUT configs/jwt-customizer/access-token',
    'GET configs/jwt-customizer/access-token',
    'POST subject-tokens',
    'DELETE configs/jwt-customizer/access-token',
    'PUT configs/jwt-customizer/access-token',
    'GET configs/jwt-customizer/access-token',
    'POST subject-tokens',
    'DELETE configs/jwt-customizer/access-token',
    'GET configs/jwt-customizer/access-token',
    'GET configs/jwt-customizer/access-token',
  ]);
  expect(managedDispatches).toEqual([
    { source: 'managed-1', kind: 'managed', target: 'https://invalid-target.invalid/' },
    { source: 'managed-1', kind: 'managed', target: 'https://api.test/' },
    { source: 'managed-1', kind: 'managed', target: 'https://api.test/' },
    { source: 'managed-2', kind: 'managed', target: 'https://api.test/', actor: 'invalid-actor' },
    { source: 'managed-2', kind: 'managed', target: 'https://api.test/' },
    { source: 'pat-secret', kind: 'pat', target: 'https://api.test/' },
    { source: 'pat-secret', kind: 'pat', target: 'https://api.test/' },
    { source: 'pat-secret', kind: 'pat', target: 'https://api.test/' },
    { source: 'managed-3', kind: 'managed', target: 'https://api.test/', actor: 'opaque-openid' },
    { source: 'managed-4', kind: 'managed', target: 'https://api.test/', actor: 'opaque-profile' },
    { source: 'managed-4', kind: 'managed', target: 'https://api.test/' },
    { source: 'managed-5', kind: 'managed', target: 'https://api.test/', actor: 'opaque-openid' },
    { source: 'managed-5', kind: 'managed', target: 'https://api.test/' },
    {
      source: 'managed-6',
      kind: 'managed',
      target: 'https://api.test/',
      actor: 'opaque-child',
    },
    { source: 'pat-secret', kind: 'pat', target: 'https://api.test/' },
    { source: 'managed-7', kind: 'managed', target: 'https://api.test/' },
    { source: 'managed-7', kind: 'managed', target: 'https://api.test/' },
    { source: 'managed-8', kind: 'managed', target: 'https://api.test/' },
    { source: 'managed-8', kind: 'managed', target: 'https://api.test/' },
  ]);
  expect(projection).toEqual({
    responseKeys: ['access_token', 'expires_in', 'scope', 'token_type'],
    tokenType: 'Bearer',
    outputKind: 'jwt',
    sourceReusable: true,
    subjectPreserved: true,
    clientPreserved: true,
    audienceIsResource: true,
    scopeMatchesFixtureAuthority: true,
    lifetimeSeconds: 3600,
    managedSubject: {
      creationKeys: ['expiresIn', 'subjectToken'],
      expiresIn: 600,
      badTarget: { status: 400, error: 'invalid_target', sourcePreserved: true },
      successAfterBadTarget: true,
      replay: { status: 400, error: 'invalid_grant' },
      badActor: { status: 400, error: 'invalid_grant', sourcePreserved: true },
      successAfterBadActor: true,
    },
    personalAccessToken: {
      publicKeys: ['createdAt', 'expiresAt', 'name', 'tenantId', 'userId', 'value'],
      expiresAtNull: true,
      listedWithValue: true,
      repeatedResourceExchange: true,
      deleteStatus: 204,
      rejectedAfterDelete: { status: 400, error: 'invalid_grant' },
    },
    opaque: {
      responseKeys: ['access_token', 'expires_in', 'scope', 'token_type'],
      lifetimeSeconds: 3600,
      compact: 'opaque',
      scope: 'openid profile',
      userinfoSubject: true,
      introspectionActive: true,
      subjectToResourceJwt: true,
      openidActorClaim: true,
      profileActorRejected: { status: 400, error: 'invalid_grant', sourcePreserved: true },
      profileSubjectAccepted: true,
      revokedSubjectRejected: { status: 400, error: 'invalid_grant' },
      revokedActorRejected: { status: 400, error: 'invalid_grant', sourcePreserved: true },
      priorOpaqueOutputRemainsActive: true,
    },
    admissionGrammar: {
      disabled: {
        status: 400,
        error: 'invalid_request',
        errorDescription: 'requested grant type is not allowed for this client',
      },
      unknownClientMasksMissingSubject: {
        status: 400,
        error: 'invalid_client',
        errorDescription: 'invalid client unknown-client',
      },
      publicMissingSubject: {
        status: 400,
        error: 'invalid_request',
        errorDescription: "missing required parameter 'subject_token'",
      },
      publicMissingSubjectType: {
        status: 400,
        error: 'invalid_request',
        errorDescription: "missing required parameter 'subject_token_type'",
      },
      confidentialMissingProof: {
        status: 400,
        error: 'invalid_request',
        errorDescription: 'no client authentication mechanism provided',
      },
      confidentialWrongProof: {
        status: 401,
        error: 'invalid_client',
        errorDescription: 'client authentication failed',
      },
      confidentialCorrectProofMasksMissingSubject: {
        status: 400,
        error: 'invalid_request',
        errorDescription: "missing required parameters 'subject_token' and 'subject_token_type'",
      },
      duplicateSubject: {
        status: 400,
        error: 'invalid_request',
        errorDescription: "'subject_token' parameter must not be provided twice",
      },
      duplicateSubjectType: {
        status: 400,
        error: 'invalid_request',
        errorDescription: "'subject_token_type' parameter must not be provided twice",
      },
      duplicateActor: {
        status: 400,
        error: 'invalid_request',
        errorDescription: "'actor_token' parameter must not be provided twice",
      },
      duplicateActorType: {
        status: 400,
        error: 'invalid_request',
        errorDescription: "'actor_token_type' parameter must not be provided twice",
      },
      repeatedResourceSelectsOpaque: true,
      requestedTokenTypeIgnored: true,
      metadataRestored: true,
    },
    organization: {
      organizationOnly: {
        lifetimeSeconds: 3600,
        scope: '',
        audienceMapped: true,
        organizationIdClaimAbsent: true,
      },
      resourceAndOrganization: {
        lifetimeSeconds: 3600,
        scopePreserved: true,
        audienceIsResource: true,
        organizationIdClaim: true,
      },
    },
    customizer: {
      managedTokenShape: true,
      managedUserContext: true,
      managedApplicationContext: true,
      managedOrganizationContext: true,
      managedSubjectTokenContext: true,
      managedActorOverridden: true,
      throwingFailOpenConsumedSource: true,
      ordinaryJwtSubjectTokenContextAbsent: true,
      personalAccessTokenSubjectTokenContextAbsent: true,
      deny: { status: 400, error: 'access_denied', sourcePreserved: true },
      configurationRestored: true,
    },
    scopeCanonicalization: {
      opaque: {
        duplicateNamesCollapsed: true,
        unknownNamesFiltered: true,
        scope: 'openid profile',
      },
      resource: {
        duplicateNamesCollapsed: true,
        unknownNamesFiltered: true,
        scopeMatchesFixtureAuthority: true,
      },
      organization: {
        duplicateNamesCollapsed: true,
        unauthorizedNamesFiltered: true,
        scope: '',
        lifetimeSeconds: 3600,
      },
    },
  });

  const resetMatrixState = () => {
    requests = 0;
    subjects = 0;
    revoked = false;
    customizerMode = 'absent';
    installedCustomizerScript = '';
    invalidCustomizerReadback = undefined;
    customizerActorClaims = Object.freeze({ sub: 'phase2-customizer-actor' });
    throwingCustomizerFailsOpen = true;
    throwingReplayAccepted = false;
    throwingConsumedSubjects.clear();
    rejectedPatCreateName = undefined;
    rejectedPatDeleteName = undefined;
    defaultResourceEnabled = true;
    repeatedResourceError = undefined;
    restoreDefaultError = undefined;
    restoreGate = undefined;
    repeatedResourceStarted = undefined;
    restoreStarted = undefined;
    managedDispatches.length = 0;
    managementDispatches.length = 0;
    managementRequests.length = 0;
    enabledTransitions.length = 0;
    grammarDispatches.length = 0;
    tokenUses.length = 0;
  };
  for (const invalidReadback of ['script', 'block'] as const) {
    resetMatrixState();
    invalidCustomizerReadback = invalidReadback;
    await expect(runMatrix()).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison');
  }
  for (const invalidActorClaims of [
    { sub: 'user-1' },
    { sub: 'wrong-customizer-actor' },
    { sub: 'phase2-customizer-actor', unexpected: true },
  ]) {
    resetMatrixState();
    customizerActorClaims = Object.freeze(invalidActorClaims);
    await expect(runMatrix()).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison');
  }
  resetMatrixState();
  throwingCustomizerFailsOpen = false;
  await expect(runMatrix()).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison');
  resetMatrixState();
  throwingReplayAccepted = true;
  await expect(runMatrix()).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison');
  const expectCommittedCreateCleanup = async (name: string, deleteFails = false) => {
    resetMatrixState();
    rejectedPatCreateName = name;
    rejectedPatDeleteName = deleteFails ? name : undefined;
    const observation = runMatrix();
    await (deleteFails
      ? expect(observation).rejects.toMatchObject({
          errors: [
            expect.objectContaining({ message: `create response rejected for ${name}` }),
            expect.objectContaining({ message: `delete failed for ${name}` }),
          ],
        })
      : expect(observation).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison'));
    expect(
      managementRequests.filter(({ body }) =>
        typeof body === 'object' && body !== null
          ? (body as Readonly<{ name?: unknown }>).name === name
          : false
      )
    ).toEqual([
      { method: 'POST', path: 'users/user-1/personal-access-tokens', body: { name } },
      { method: 'POST', path: 'users/user-1/personal-access-tokens/delete', body: { name } },
    ]);
  };
  await expectCommittedCreateCleanup('phase2-token-exchange-pat');
  await expectCommittedCreateCleanup('phase2-token-exchange-context-pat');
  await expectCommittedCreateCleanup('phase2-token-exchange-pat', true);

  resetMatrixState();
  repeatedResourceError = new Error('repeated resource failed');
  // eslint-disable-next-line no-use-extend-native/no-use-extend-native -- Standard ES2024 deferred primitive.
  const repeatedStarted = Promise.withResolvers<void>();
  // eslint-disable-next-line no-use-extend-native/no-use-extend-native -- Standard ES2024 deferred primitive.
  const restorationStarted = Promise.withResolvers<void>();
  // eslint-disable-next-line no-use-extend-native/no-use-extend-native -- Standard ES2024 deferred primitive.
  const restorationGate = Promise.withResolvers<void>();
  repeatedResourceStarted = repeatedStarted.resolve;
  restoreStarted = restorationStarted.resolve;
  restoreGate = restorationGate.promise;
  const pendingObservation = runMatrix();
  let settled = false;
  void (async () => {
    try {
      await pendingObservation;
    } catch {
      // The assertion below owns the rejection; this observer only records settlement timing.
    } finally {
      settled = true;
    }
  })();
  try {
    await repeatedStarted.promise;
    await restorationStarted.promise;
    await nextTurn();
    expect(settled).toBe(false);
  } finally {
    restorationGate.resolve();
  }
  await expect(pendingObservation).rejects.toThrow(
    'Invalid Phase 2 token-exchange user JWT comparison'
  );
  expect(defaultResourceEnabled).toBe(true);

  resetMatrixState();
  repeatedResourceError = new Error('repeated resource failed');
  restoreDefaultError = new Error('default restoration failed');
  await expect(runMatrix()).rejects.toMatchObject({
    errors: [
      expect.objectContaining({ message: 'repeated resource failed' }),
      expect.objectContaining({ message: 'default restoration failed' }),
    ],
  });
  expect(
    managementRequests.filter(({ path }) => path === 'resources/resource-default/is-default')
  ).toEqual([
    {
      method: 'PATCH',
      path: 'resources/resource-default/is-default',
      body: { isDefault: false },
    },
    {
      method: 'PATCH',
      path: 'resources/resource-default/is-default',
      body: { isDefault: true },
    },
  ]);
});

it('selects first-party requester roles and enables only their applications', async () => {
  expect(resolveTokenExchangeClientRoles(fixture)).toEqual({
    publicClientId: 'first-party-public',
    confidentialClientId: 'first-party-confidential',
  });
  expect(resolveTokenExchangeClientRoles(fixture)).not.toEqual({
    publicClientId: fixture.status.client.id,
    confidentialClientId: fixture.status.confidentialClient.id,
  });
  const metadata = new Map<string, Readonly<Record<string, unknown>>>([
    ['applications/first-party-public', { role: 'public' }],
    ['applications/first-party-confidential', { role: 'confidential' }],
  ]);
  const patchedPaths: string[] = [];
  const request = async (input: Readonly<{ method: string; path: string; body?: unknown }>) => {
    const current = metadata.get(input.path) ?? {};
    if (input.method === 'GET') {
      return { customClientMetadata: current };
    }
    const body = input.body as Readonly<{
      customClientMetadata: Readonly<Record<string, unknown>>;
    }>;
    metadata.set(input.path, body.customClientMetadata);
    patchedPaths.push(input.path);
    return { customClientMetadata: body.customClientMetadata };
  };
  await withTokenExchangeClientsEnabled(request as never, fixture, async (setEnabled) => {
    await setEnabled(true);
  });
  expect(new Set(patchedPaths)).toEqual(
    new Set(['applications/first-party-public', 'applications/first-party-confidential'])
  );
  expect(patchedPaths).not.toContain('applications/third-party-status-public');
  expect(patchedPaths).not.toContain('applications/third-party-status-confidential');
});

it('restores the exact application metadata object after flag mutations', async () => {
  const original = Object.freeze({ sibling: 'kept', nested: Object.freeze({ enabled: false }) });
  let metadata: Readonly<Record<string, unknown>> = structuredClone(original);
  const writes: Array<Readonly<Record<string, unknown>>> = [];
  const request = async (input: Readonly<{ method: string; body?: unknown }>) => {
    if (input.method === 'GET') {
      return { customClientMetadata: structuredClone(metadata) };
    }
    const body = input.body as Readonly<{
      customClientMetadata: Readonly<Record<string, unknown>>;
    }>;
    metadata = structuredClone(body.customClientMetadata);
    writes.push(metadata);
    return { customClientMetadata: metadata };
  };

  await withApplicationExchangeEnabled(request as never, 'client-1', async (setEnabled) => {
    await setEnabled(false);
    await setEnabled(true);
    expect(metadata).toEqual({ ...original, allowTokenExchange: true });
  });

  expect(writes).toEqual([
    { ...original, allowTokenExchange: false },
    { ...original, allowTokenExchange: true },
    original,
  ]);
  expect(metadata).toEqual(original);
  expect(Object.hasOwn(metadata, 'allowTokenExchange')).toBe(false);
});

it('attempts PAT cleanup after an intermediate failure and retains both failures', async () => {
  let cleanupCalls = 0;
  let operationCalls = 0;
  const cleanup = async () => {
    cleanupCalls += 1;
    throw new Error('cleanup failed');
  };
  const operation = async () => {
    operationCalls += 1;
    throw new Error('listing failed');
  };

  await expect(withRequiredCleanup(operation, cleanup)).rejects.toMatchObject({
    errors: [
      expect.objectContaining({ message: 'listing failed' }),
      expect.objectContaining({ message: 'cleanup failed' }),
    ],
  });
  expect(operationCalls).toBe(1);
  expect(cleanupCalls).toBe(1);
});

it('requires the measured disabled-grant admission description', async () => {
  const expected = 'requested grant type is not allowed for this client';
  await expectTokenExchangeGrammarError(
    new Response(JSON.stringify({ error: 'invalid_request', error_description: expected }), {
      status: 400,
    }),
    400,
    'invalid_request',
    expected
  );
  await expect(
    expectTokenExchangeGrammarError(
      new Response(
        JSON.stringify({ error: 'invalid_request', error_description: 'grant request is invalid' }),
        { status: 400 }
      ),
      400,
      'invalid_request',
      expected
    )
  ).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison');
});

it('requires exact ordered token grammar diagnostics', async () => {
  const expected = "missing required parameters 'subject_token' and 'subject_token_type'";
  await expectTokenExchangeGrammarError(
    new Response(JSON.stringify({ error: 'invalid_request', error_description: expected }), {
      status: 400,
    }),
    400,
    'invalid_request',
    expected
  );
  for (const errorDescription of [
    "missing required parameters 'subject_token_type' and 'subject_token'",
    "missing required parameter 'subject_token'",
    'grant request is invalid',
  ]) {
    await expect(
      expectTokenExchangeGrammarError(
        new Response(
          JSON.stringify({ error: 'invalid_request', error_description: errorDescription }),
          { status: 400 }
        ),
        400,
        'invalid_request',
        expected
      )
    ).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison');
  }
});

it('rejects a response with an extra credential-bearing field', async () => {
  await expect(
    observeTokenExchangeUserJwtMatrix(
      { target, fixture, signal: new AbortController().signal },
      {
        withExchangeEnabled: async (_input, use) =>
          use(
            async () => ({}),
            async (enabled) => {
              expect(typeof enabled).toBe('boolean');
            }
          ),
        issueSource: async () => ({
          access: 'source',
          toJSON: () => {
            throw new Error('private');
          },
        }),
        request: async () =>
          new Response(
            JSON.stringify({
              access_token: 'x',
              expires_in: 3600,
              scope: 'read:fixture',
              token_type: 'Bearer',
              refresh_token: 'forbidden',
            })
          ),
        managedRequest: async () => new Response(),
        tokenUse: async () => new Response(),
        grammarRequest: async () =>
          new Response(JSON.stringify({ error: 'invalid_request' }), { status: 400 }),
        settleCustomizer: async () => {
          expect(true).toBe(true);
        },
        readJwks: async () => ({ keys: [] }),
        now: () => 1,
      }
    )
  ).rejects.toThrow('Invalid Phase 2 token-exchange user JWT comparison');
});
/* eslint-enable max-lines, complexity, no-await-in-loop, @typescript-eslint/consistent-type-assertions, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
