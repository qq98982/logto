/* eslint-disable complexity, max-lines, no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- This bounded adapter keeps all bearer material inside one real HTTP flow. */
import { isDeepStrictEqual } from 'node:util';

import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

import type { TargetConfig } from '../../model.js';
import { withCommonManagementMachineBearer } from '../clients/common-management-machine-bearer.js';
import { issuePublicUserResourceTokensWithPassword } from '../clients/user-token-issuance.js';
import {
  createBearerPhase2AdminRequest,
  createReferencePhase2AdminRequest,
  type Phase2AdminRequestFunction,
  type ProvisionedPhase2Fixture,
} from '../fixtures.js';

export const tokenExchangeUserJwtScenarioId = 'token-exchange.user-jwt-reuse';

export type TokenExchangeUserJwtProjection = Readonly<{
  responseKeys: readonly ['access_token', 'expires_in', 'scope', 'token_type'];
  tokenType: 'Bearer';
  outputKind: 'jwt';
  sourceReusable: true;
  subjectPreserved: true;
  clientPreserved: true;
  audienceIsResource: true;
  scopeMatchesFixtureAuthority: true;
  lifetimeSeconds: number;
  managedSubject: Readonly<{
    creationKeys: readonly ['expiresIn', 'subjectToken'];
    expiresIn: 600;
    badTarget: Readonly<{ status: 400; error: 'invalid_target'; sourcePreserved: true }>;
    successAfterBadTarget: true;
    replay: Readonly<{ status: 400; error: 'invalid_grant' }>;
    badActor: Readonly<{ status: 400; error: 'invalid_grant'; sourcePreserved: true }>;
    successAfterBadActor: true;
  }>;
  personalAccessToken: Readonly<{
    publicKeys: readonly ['createdAt', 'expiresAt', 'name', 'tenantId', 'userId', 'value'];
    expiresAtNull: true;
    listedWithValue: true;
    repeatedResourceExchange: true;
    deleteStatus: 204;
    rejectedAfterDelete: Readonly<{ status: 400; error: 'invalid_grant' }>;
  }>;
  opaque: Readonly<{
    responseKeys: readonly ['access_token', 'expires_in', 'scope', 'token_type'];
    lifetimeSeconds: 3600;
    compact: 'opaque';
    scope: 'openid profile';
    userinfoSubject: true;
    introspectionActive: true;
    subjectToResourceJwt: true;
    openidActorClaim: true;
    profileActorRejected: Readonly<{ status: 400; error: 'invalid_grant'; sourcePreserved: true }>;
    profileSubjectAccepted: true;
    revokedSubjectRejected: Readonly<{ status: 400; error: 'invalid_grant' }>;
    revokedActorRejected: Readonly<{ status: 400; error: 'invalid_grant'; sourcePreserved: true }>;
    priorOpaqueOutputRemainsActive: true;
  }>;
  admissionGrammar: Readonly<{
    disabled: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: 'grant request is invalid';
    }>;
    unknownClientMasksMissingSubject: Readonly<{
      status: 400;
      error: 'invalid_client';
      errorDescription: 'invalid client unknown-client';
    }>;
    publicMissingSubject: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: "missing required parameter 'subject_token'";
    }>;
    publicMissingSubjectType: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: "missing required parameter 'subject_token_type'";
    }>;
    confidentialMissingProof: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: 'no client authentication mechanism provided';
    }>;
    confidentialWrongProof: Readonly<{
      status: 401;
      error: 'invalid_client';
      errorDescription: 'client authentication failed';
    }>;
    confidentialCorrectProofMasksMissingSubject: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: "missing required parameters 'subject_token' and 'subject_token_type'";
    }>;
    duplicateSubject: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: "'subject_token' parameter must not be provided twice";
    }>;
    duplicateSubjectType: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: "'subject_token_type' parameter must not be provided twice";
    }>;
    duplicateActor: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: "'actor_token' parameter must not be provided twice";
    }>;
    duplicateActorType: Readonly<{
      status: 400;
      error: 'invalid_request';
      errorDescription: "'actor_token_type' parameter must not be provided twice";
    }>;
    repeatedResourceSelectsOpaque: true;
    requestedTokenTypeIgnored: true;
    metadataRestored: true;
  }>;
  organization: Readonly<{
    organizationOnly: Readonly<{
      lifetimeSeconds: 3600;
      scope: '';
      audienceMapped: true;
      organizationIdClaimAbsent: true;
    }>;
    resourceAndOrganization: Readonly<{
      lifetimeSeconds: number;
      scopePreserved: true;
      audienceIsResource: true;
      organizationIdClaim: true;
    }>;
  }>;
  customizer: Readonly<{
    managedTokenShape: true;
    managedUserContext: true;
    managedApplicationContext: true;
    managedOrganizationContext: true;
    managedSubjectTokenContext: true;
    ordinaryJwtSubjectTokenContextAbsent: true;
    personalAccessTokenSubjectTokenContextAbsent: true;
    deny: Readonly<{ status: 400; error: 'access_denied'; sourcePreserved: true }>;
    configurationRestored: true;
  }>;
  scopeCanonicalization: Readonly<{
    opaque: Readonly<{
      duplicateNamesCollapsed: true;
      unknownNamesFiltered: true;
      scope: 'openid profile';
    }>;
    resource: Readonly<{
      duplicateNamesCollapsed: true;
      unknownNamesFiltered: true;
      scopeMatchesFixtureAuthority: true;
    }>;
    organization: Readonly<{
      duplicateNamesCollapsed: true;
      unauthorizedNamesFiltered: true;
      scope: '';
      lifetimeSeconds: 3600;
    }>;
  }>;
}>;

type DriverInput = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  signal: AbortSignal;
}>;

type SecretTokens = Readonly<{ access: string; toJSON(): never }>;
export const resolveTokenExchangeClientRoles = (fixture: ProvisionedPhase2Fixture) =>
  Object.freeze({
    publicClientId: bounded(fixture.public.deviceClients.firstParty.id, 256),
    confidentialClientId: bounded(fixture.public.clients.basic.id, 256),
  });
type DriverAdapters = Readonly<{
  withExchangeEnabled<Result>(
    input: DriverInput,
    use: (
      request: Phase2AdminRequestFunction,
      setEnabled: (enabled: boolean) => Promise<void>
    ) => Promise<Result>
  ): Promise<Result>;
  issueSource(input: DriverInput, password: string): Promise<SecretTokens>;
  request(
    input: DriverInput,
    source: string,
    options?: Readonly<{ resource?: boolean; scope?: string }>
  ): Promise<Response>;
  managedRequest(
    input: DriverInput,
    source: string,
    secret: string,
    options: Readonly<{ kind: 'managed' | 'pat'; target: string; actor?: string }>
  ): Promise<Response>;
  readJwks(input: DriverInput): Promise<Readonly<JSONWebKeySet>>;
  tokenUse(
    input: DriverInput,
    token: string,
    kind: 'userinfo' | 'introspection' | 'revocation'
  ): Promise<Response>;
  grammarRequest(
    input: DriverInput,
    entries: ReadonlyArray<readonly [string, string]>,
    authentication: 'none' | 'correct' | 'wrong',
    confidentialSecret?: string
  ): Promise<Response>;
  settleCustomizer(): Promise<void>;
  now(): number;
}>;

const diagnostic = 'Invalid Phase 2 token-exchange user JWT comparison';
const fail = (): never => {
  throw new TypeError(diagnostic);
};
const bounded = (value: unknown, maximum = 8192): string =>
  typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum
    ? value
    : fail();
const record = (value: unknown): Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Readonly<Record<string, unknown>>)
    : fail();

export const expectTokenExchangeGrammarError = async (
  response: Response,
  statusCode: 400 | 401,
  error: 'invalid_request' | 'invalid_client',
  errorDescription?: string
): Promise<void> => {
  if (response.status !== statusCode || response.redirected) {
    await response.body?.cancel();
    return fail();
  }
  const body = record(JSON.parse(await response.text()) as unknown);
  if (
    body.error !== error ||
    Object.hasOwn(body, 'access_token') ||
    (errorDescription !== undefined && body.error_description !== errorDescription)
  ) {
    return fail();
  }
};

export const withApplicationExchangeEnabled = async <Result>(
  request: Phase2AdminRequestFunction,
  applicationId: string,
  use: (setEnabled: (enabled: boolean) => Promise<void>) => Promise<Result>
): Promise<Result> => {
  const path = `applications/${encodeURIComponent(applicationId)}`;
  const application = record(
    await request({ method: 'GET', path, expectedStatuses: [200], responseKind: 'object' })
  );
  const originalMetadata = structuredClone(record(application.customClientMetadata));
  const writeMetadata = async (metadata: Readonly<Record<string, unknown>>) => {
    await request({
      method: 'PATCH',
      path,
      body: { customClientMetadata: metadata },
      expectedStatuses: [200],
      responseKind: 'object',
    });
  };
  const writeFlag = async (enabled: boolean) => {
    const latest = record(
      await request({ method: 'GET', path, expectedStatuses: [200], responseKind: 'object' })
    );
    const latestMetadata = record(latest.customClientMetadata);
    await writeMetadata({ ...latestMetadata, allowTokenExchange: enabled });
  };
  try {
    return await use(writeFlag);
  } finally {
    await writeMetadata(originalMetadata);
    const restored = record(
      await request({ method: 'GET', path, expectedStatuses: [200], responseKind: 'object' })
    );
    if (!isDeepStrictEqual(record(restored.customClientMetadata), originalMetadata)) {
      fail();
    }
  }
};

export const withTokenExchangeClientsEnabled = async <Result>(
  request: Phase2AdminRequestFunction,
  fixture: ProvisionedPhase2Fixture,
  use: (setEnabled: (enabled: boolean) => Promise<void>) => Promise<Result>
): Promise<Result> => {
  const roles = resolveTokenExchangeClientRoles(fixture);
  return withApplicationExchangeEnabled(request, roles.publicClientId, async (setPublicEnabled) =>
    withApplicationExchangeEnabled(
      request,
      roles.confidentialClientId,
      async (setConfidentialEnabled) =>
        use(async (enabled) => {
          await setPublicEnabled(enabled);
          await setConfidentialEnabled(enabled);
        })
    )
  );
};

export const withRequiredCleanup = async <Result>(
  use: () => Promise<Result>,
  cleanup: () => Promise<void>
): Promise<Result> => {
  let result: Result;
  try {
    result = await use();
  } catch (primaryError: unknown) {
    try {
      await cleanup();
    } catch (cleanupError: unknown) {
      throw new AggregateError([primaryError, cleanupError], diagnostic);
    }
    throw primaryError;
  }
  await cleanup();
  return result;
};

const readJson = async (response: Response): Promise<Readonly<Record<string, unknown>>> => {
  if (response.status !== 200 || response.redirected) {
    await response.body?.cancel();
    return fail();
  }
  const declared = response.headers.get('content-length');
  if (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > 16_384)) {
    await response.body?.cancel();
    return fail();
  }
  const text = await response.text();
  if (Buffer.byteLength(text) > 16_384) {
    return fail();
  }
  return record(JSON.parse(text) as unknown);
};

const realAdapters: DriverAdapters = Object.freeze({
  withExchangeEnabled: async (input, use) => {
    const operate = async (request: Phase2AdminRequestFunction) =>
      withTokenExchangeClientsEnabled(request, input.fixture, async (setEnabled) =>
        use(request, setEnabled)
      );
    if (input.target.label === 'oracle') {
      return operate(createReferencePhase2AdminRequest(input.target));
    }
    return withCommonManagementMachineBearer(
      { target: input.target, fixture: input.fixture },
      async (bearer) => operate(createBearerPhase2AdminRequest(input.target, bearer))
    );
  },
  issueSource: async (input, password) =>
    issuePublicUserResourceTokensWithPassword(input.target, input.fixture, password, input.signal),
  request: async (input, source, options) => {
    const status = input.fixture.status ?? fail();
    const roles = resolveTokenExchangeClientRoles(input.fixture);
    const requestOptions: Readonly<{ resource?: boolean; scope?: string }> =
      options ?? Object.freeze({ resource: true, scope: status.resource.scopeName });
    return fetch(new URL('/oidc/token', input.target.coreUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        client_id: roles.publicClientId,
        subject_token: source,
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        ...(requestOptions.resource === false ? {} : { resource: status.resource.indicator }),
        ...(requestOptions.scope === undefined ? {} : { scope: requestOptions.scope }),
      }),
      redirect: 'manual',
      signal: input.signal,
    });
  },
  tokenUse: async (input, token, kind) => {
    const roles = resolveTokenExchangeClientRoles(input.fixture);
    if (kind === 'userinfo') {
      return fetch(new URL('/oidc/me', input.target.coreUrl), {
        headers: { authorization: `Bearer ${token}` },
        redirect: 'manual',
        signal: input.signal,
      });
    }
    return fetch(new URL(`/oidc/token/${kind}`, input.target.coreUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token, client_id: roles.publicClientId }),
      redirect: 'manual',
      signal: input.signal,
    });
  },
  grammarRequest: async (input, entries, authentication, confidentialSecret) => {
    const roles = resolveTokenExchangeClientRoles(input.fixture);
    const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
    if (authentication !== 'none') {
      const proof =
        authentication === 'wrong' ? 'invalid-proof' : bounded(confidentialSecret, 1024);
      headers.set(
        'authorization',
        `Basic ${Buffer.from(`${roles.confidentialClientId}:${proof}`).toString('base64')}`
      );
    }
    return fetch(new URL('/oidc/token', input.target.coreUrl), {
      method: 'POST',
      headers,
      body: new URLSearchParams(entries.map(([key, value]) => [key, value])),
      redirect: 'manual',
      signal: input.signal,
    });
  },
  settleCustomizer: async () =>
    new Promise<void>((resolve) => {
      setTimeout(resolve, 2500);
    }),
  managedRequest: async (input, source, secret, options) => {
    const status = input.fixture.status ?? fail();
    const roles = resolveTokenExchangeClientRoles(input.fixture);
    return fetch(new URL('/oidc/token', input.target.coreUrl), {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${roles.confidentialClientId}:${secret}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: source,
        subject_token_type:
          input.target.label === 'oracle'
            ? options.kind === 'managed'
              ? 'urn:logto:token-type:impersonation_token'
              : 'urn:logto:token-type:personal_access_token'
            : options.kind === 'managed'
              ? 'urn:aster:token-type:impersonation_token'
              : 'urn:aster:token-type:personal_access_token',
        resource: options.target,
        ...(options.actor === undefined
          ? {}
          : {
              actor_token: options.actor,
              actor_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            }),
      }),
      redirect: 'manual',
      signal: input.signal,
    });
  },
  readJwks: async (input) => {
    const response = await fetch(new URL('/oidc/jwks', input.target.coreUrl), {
      redirect: 'manual',
      signal: input.signal,
    });
    return readJson(response) as unknown as Readonly<JSONWebKeySet>;
  },
  now: () => Math.floor(Date.now() / 1000),
});

export const observeTokenExchangeUserJwtMatrix = async (
  input: DriverInput,
  adapters: DriverAdapters
): Promise<TokenExchangeUserJwtProjection> => {
  try {
    if (input.signal.aborted) {
      return fail();
    }
    const status = input.fixture.status ?? fail();
    const roles = resolveTokenExchangeClientRoles(input.fixture);
    const secrets = await input.fixture.withSecretLease(async (lease) =>
      Object.freeze({
        password: bounded(lease.getSubjectPassword?.(), 256),
        confidential: bounded(lease.getClientSecret('basic'), 1024),
      })
    );
    return await adapters.withExchangeEnabled(input, async (managementRequest, setEnabled) =>
      (async () => {
        const source = await adapters.issueSource(input, secrets.password);
        const jwks = await adapters.readJwks(input);
        const grant = ['grant_type', 'urn:ietf:params:oauth:grant-type:token-exchange'] as const;
        const subjectType = [
          'subject_token_type',
          'urn:ietf:params:oauth:token-type:access_token',
        ] as const;
        await setEnabled(false);
        await expectTokenExchangeGrammarError(
          await adapters.grammarRequest(
            input,
            [grant, ['client_id', roles.publicClientId]],
            'none'
          ),
          400,
          'invalid_request',
          'grant request is invalid'
        );
        await setEnabled(true);
        const projections = [] as Array<Readonly<{ scope: string; lifetime: number }>>;
        for (let index = 0; index < 2; index += 1) {
          const body = await readJson(
            await adapters.request(input, bounded(source.access), {
              scope: status.resource.scopeName,
            })
          );
          if (
            JSON.stringify(Object.keys(body).sort()) !==
              JSON.stringify(['access_token', 'expires_in', 'scope', 'token_type']) ||
            body.token_type !== 'Bearer' ||
            !Number.isInteger(body.expires_in) ||
            Number(body.expires_in) <= 0 ||
            Number(body.expires_in) > 86_400
          ) {
            return fail();
          }
          const token = bounded(body.access_token);
          if (token.split('.').length !== 3) {
            return fail();
          }
          const scope = bounded(body.scope, 2048);
          const verified = await jwtVerify(token, createLocalJWKSet(jwks), {
            algorithms: ['ES384'],
            issuer: new URL('/oidc', input.target.coreUrl).href,
            audience: status.resource.indicator,
            currentDate: new Date(adapters.now() * 1000),
            clockTolerance: 15,
            requiredClaims: ['sub', 'iat', 'exp'],
          }).catch(fail);
          if (
            verified.protectedHeader.typ !== 'at+jwt' ||
            verified.payload.sub !== status.user.id ||
            verified.payload.client_id !== roles.publicClientId ||
            verified.payload.scope !== scope ||
            !Number.isInteger(verified.payload.iat) ||
            !Number.isInteger(verified.payload.exp) ||
            Number(verified.payload.exp) - Number(verified.payload.iat) !== Number(body.expires_in)
          ) {
            return fail();
          }
          projections.push(Object.freeze({ scope, lifetime: Number(body.expires_in) }));
        }
        const [first, second] = projections;
        if (
          first === undefined ||
          second === undefined ||
          projections.length !== 2 ||
          first.scope !== second.scope ||
          first.scope !== status.resource.scopeName ||
          first.lifetime !== second.lifetime
        ) {
          return fail();
        }
        const secret = secrets.confidential;
        const createManaged = async (
          context: Readonly<Record<string, unknown>> = Object.freeze({})
        ): Promise<string> => {
          const created = record(
            await managementRequest({
              method: 'POST',
              path: 'subject-tokens',
              body: { userId: status.user.id, context },
              expectedStatuses: [201],
              responseKind: 'object',
            })
          );
          if (
            JSON.stringify(Object.keys(created).sort()) !==
              JSON.stringify(['expiresIn', 'subjectToken']) ||
            created.expiresIn !== 600
          ) {
            return fail();
          }
          return bounded(created.subjectToken);
        };
        const expectError = async (
          response: Response,
          expected: 'invalid_target' | 'invalid_grant'
        ) => {
          if (response.status !== 400 || response.redirected) {
            await response.body?.cancel();
            return fail();
          }
          const body = record(JSON.parse(await response.text()) as unknown);
          if (body.error !== expected || Object.hasOwn(body, 'access_token')) {
            return fail();
          }
        };
        const expectSuccess = async (
          response: Response,
          expectedClient = roles.confidentialClientId,
          actorSubject?: string
        ): Promise<string> => {
          const body = await readJson(response);
          if (
            JSON.stringify(Object.keys(body).sort()) !==
              JSON.stringify(['access_token', 'expires_in', 'scope', 'token_type']) ||
            body.token_type !== 'Bearer'
          ) {
            return fail();
          }
          const verified = await jwtVerify(bounded(body.access_token), createLocalJWKSet(jwks), {
            algorithms: ['ES384'],
            issuer: new URL('/oidc', input.target.coreUrl).href,
            audience: status.resource.indicator,
            currentDate: new Date(adapters.now() * 1000),
            clockTolerance: 15,
            requiredClaims: ['sub', 'iat', 'exp'],
          }).catch(fail);
          if (
            verified.protectedHeader.typ !== 'at+jwt' ||
            verified.payload.sub !== status.user.id ||
            verified.payload.client_id !== expectedClient ||
            verified.payload.scope !== body.scope ||
            Number(verified.payload.exp) - Number(verified.payload.iat) !==
              Number(body.expires_in) ||
            (actorSubject !== undefined &&
              (!verified.payload.act ||
                typeof verified.payload.act !== 'object' ||
                Reflect.get(verified.payload.act, 'sub') !== actorSubject))
          ) {
            return fail();
          }
          return bounded(body.access_token);
        };
        const badTargetSource = await createManaged();
        await expectError(
          await adapters.managedRequest(input, badTargetSource, secret, {
            kind: 'managed',
            target: 'https://invalid-target.invalid/',
          }),
          'invalid_target'
        );
        await expectSuccess(
          await adapters.managedRequest(input, badTargetSource, secret, {
            kind: 'managed',
            target: status.resource.indicator,
          })
        );
        await expectError(
          await adapters.managedRequest(input, badTargetSource, secret, {
            kind: 'managed',
            target: status.resource.indicator,
          }),
          'invalid_grant'
        );
        const badActorSource = await createManaged();
        await expectError(
          await adapters.managedRequest(input, badActorSource, secret, {
            kind: 'managed',
            target: status.resource.indicator,
            actor: 'invalid-actor',
          }),
          'invalid_grant'
        );
        await expectSuccess(
          await adapters.managedRequest(input, badActorSource, secret, {
            kind: 'managed',
            target: status.resource.indicator,
          })
        );
        const patName = 'phase2-token-exchange-pat';
        const patPath = `users/${encodeURIComponent(status.user.id)}/personal-access-tokens`;
        const patKeys = ['createdAt', 'expiresAt', 'name', 'tenantId', 'userId', 'value'];
        let pat = '';
        await withRequiredCleanup(
          async () => {
            const createdPat = record(
              await managementRequest({
                method: 'POST',
                path: patPath,
                body: { name: patName },
                expectedStatuses: [201],
                responseKind: 'object',
              })
            );
            if (
              JSON.stringify(Object.keys(createdPat).sort()) !== JSON.stringify(patKeys) ||
              createdPat.name !== patName ||
              createdPat.userId !== status.user.id ||
              createdPat.expiresAt !== null
            ) {
              return fail();
            }
            pat = bounded(createdPat.value);
            const listed = await managementRequest({
              method: 'GET',
              path: patPath,
              expectedStatuses: [200],
              responseKind: 'array',
            });
            if (!Array.isArray(listed)) {
              return fail();
            }
            const selected = listed.filter((value) => record(value).name === patName);
            if (
              selected.length !== 1 ||
              record(selected[0]).value !== pat ||
              JSON.stringify(Object.keys(record(selected[0])).sort()) !== JSON.stringify(patKeys)
            ) {
              return fail();
            }
            await expectSuccess(
              await adapters.managedRequest(input, pat, secret, {
                kind: 'pat',
                target: status.resource.indicator,
              })
            );
            await expectSuccess(
              await adapters.managedRequest(input, pat, secret, {
                kind: 'pat',
                target: status.resource.indicator,
              })
            );
          },
          async () => {
            const deleted = await managementRequest({
              method: 'POST',
              path: `${patPath}/delete`,
              body: { name: patName },
              expectedStatuses: [204],
              responseKind: 'status',
            });
            if (deleted !== 204) {
              fail();
            }
          }
        );
        await expectError(
          await adapters.managedRequest(input, pat, secret, {
            kind: 'pat',
            target: status.resource.indicator,
          }),
          'invalid_grant'
        );
        const exchangeOpaque = async (scope: 'openid profile' | 'profile') => {
          const body = await readJson(
            await adapters.request(input, bounded(source.access), { resource: false, scope })
          );
          if (
            JSON.stringify(Object.keys(body).sort()) !==
              JSON.stringify(['access_token', 'expires_in', 'scope', 'token_type']) ||
            body.token_type !== 'Bearer' ||
            body.expires_in !== 3600 ||
            body.scope !== scope
          ) {
            return fail();
          }
          const token = bounded(body.access_token);
          if (token.split('.').length === 3) {
            return fail();
          }
          return token;
        };
        const openidOpaque = await exchangeOpaque('openid profile');
        const userinfo = await readJson(await adapters.tokenUse(input, openidOpaque, 'userinfo'));
        if (userinfo.sub !== status.user.id) {
          return fail();
        }
        const introspection = await readJson(
          await adapters.tokenUse(input, openidOpaque, 'introspection')
        );
        if (
          introspection.active !== true ||
          introspection.sub !== status.user.id ||
          introspection.client_id !== roles.publicClientId ||
          introspection.scope !== 'openid profile'
        ) {
          return fail();
        }
        await expectSuccess(
          await adapters.request(input, openidOpaque, { scope: status.resource.scopeName }),
          roles.publicClientId
        );
        const actorManaged = await createManaged();
        await expectSuccess(
          await adapters.managedRequest(input, actorManaged, secret, {
            kind: 'managed',
            target: status.resource.indicator,
            actor: openidOpaque,
          }),
          roles.confidentialClientId,
          status.user.id
        );
        const profileOpaque = await exchangeOpaque('profile');
        const profileActorManaged = await createManaged();
        await expectError(
          await adapters.managedRequest(input, profileActorManaged, secret, {
            kind: 'managed',
            target: status.resource.indicator,
            actor: profileOpaque,
          }),
          'invalid_grant'
        );
        await expectSuccess(
          await adapters.managedRequest(input, profileActorManaged, secret, {
            kind: 'managed',
            target: status.resource.indicator,
          })
        );
        await expectSuccess(
          await adapters.request(input, profileOpaque, { scope: status.resource.scopeName }),
          roles.publicClientId
        );
        const childOpaqueBody = await readJson(
          await adapters.request(input, openidOpaque, {
            resource: false,
            scope: 'openid profile',
          })
        );
        if (
          JSON.stringify(Object.keys(childOpaqueBody).sort()) !==
            JSON.stringify(['access_token', 'expires_in', 'scope', 'token_type']) ||
          childOpaqueBody.expires_in !== 3600 ||
          childOpaqueBody.scope !== 'openid profile' ||
          childOpaqueBody.token_type !== 'Bearer'
        ) {
          return fail();
        }
        const childOpaque = bounded(childOpaqueBody.access_token);
        if (childOpaque === openidOpaque || childOpaque.split('.').length === 3) {
          return fail();
        }
        const revoked = await adapters.tokenUse(input, openidOpaque, 'revocation');
        if (revoked.status !== 200 || (await revoked.text()) !== '') {
          return fail();
        }
        await expectError(
          await adapters.request(input, openidOpaque, { scope: status.resource.scopeName }),
          'invalid_grant'
        );
        const revokedActorManaged = await createManaged();
        await expectError(
          await adapters.managedRequest(input, revokedActorManaged, secret, {
            kind: 'managed',
            target: status.resource.indicator,
            actor: openidOpaque,
          }),
          'invalid_grant'
        );
        await expectSuccess(
          await adapters.managedRequest(input, revokedActorManaged, secret, {
            kind: 'managed',
            target: status.resource.indicator,
          })
        );
        const prior = await readJson(await adapters.tokenUse(input, childOpaque, 'introspection'));
        const priorUserinfo = await readJson(
          await adapters.tokenUse(input, childOpaque, 'userinfo')
        );
        if (
          prior.active !== true ||
          prior.sub !== status.user.id ||
          priorUserinfo.sub !== status.user.id
        ) {
          return fail();
        }
        const publicPrefix = [grant, ['client_id', roles.publicClientId] as const] as const;
        const validPublic = [
          ...publicPrefix,
          ['subject_token', bounded(source.access)] as const,
          subjectType,
        ] as const;
        const invalidActor = ['actor_token', 'invalid-actor'] as const;
        const actorType = [
          'actor_token_type',
          'urn:ietf:params:oauth:token-type:access_token',
        ] as const;
        await expectTokenExchangeGrammarError(
          await adapters.grammarRequest(input, [grant, ['client_id', 'unknown-client']], 'none'),
          400,
          'invalid_client',
          'invalid client unknown-client'
        );
        await expectTokenExchangeGrammarError(
          await adapters.grammarRequest(input, [...publicPrefix, subjectType], 'none'),
          400,
          'invalid_request',
          "missing required parameter 'subject_token'"
        );
        await expectTokenExchangeGrammarError(
          await adapters.grammarRequest(
            input,
            [...publicPrefix, ['subject_token', bounded(source.access)]],
            'none'
          ),
          400,
          'invalid_request',
          "missing required parameter 'subject_token_type'"
        );
        const confidentialPayload = [
          grant,
          ['subject_token', bounded(source.access)] as const,
          subjectType,
        ] as const;
        await expectTokenExchangeGrammarError(
          await adapters.grammarRequest(input, confidentialPayload, 'none'),
          400,
          'invalid_request',
          'no client authentication mechanism provided'
        );
        await expectTokenExchangeGrammarError(
          await adapters.grammarRequest(input, confidentialPayload, 'wrong'),
          401,
          'invalid_client',
          'client authentication failed'
        );
        await expectTokenExchangeGrammarError(
          await adapters.grammarRequest(input, [grant], 'correct', secret),
          400,
          'invalid_request',
          "missing required parameters 'subject_token' and 'subject_token_type'"
        );
        for (const [entries, errorDescription] of [
          [
            [...validPublic, ['subject_token', 'duplicate'] as const],
            "'subject_token' parameter must not be provided twice",
          ],
          [
            [...validPublic, ['subject_token_type', 'urn:example:duplicate'] as const],
            "'subject_token_type' parameter must not be provided twice",
          ],
          [
            [...validPublic, invalidActor, invalidActor, actorType],
            "'actor_token' parameter must not be provided twice",
          ],
          [
            [
              ...validPublic,
              invalidActor,
              actorType,
              ['actor_token_type', 'urn:example:duplicate'] as const,
            ],
            "'actor_token_type' parameter must not be provided twice",
          ],
        ] as const) {
          await expectTokenExchangeGrammarError(
            await adapters.grammarRequest(input, entries, 'none'),
            400,
            'invalid_request',
            errorDescription
          );
        }
        const repeatedResource = await readJson(
          await adapters.grammarRequest(
            input,
            [
              ...validPublic,
              ['resource', status.resource.indicator],
              ['resource', 'https://second-resource.invalid/'],
            ],
            'none'
          )
        );
        if (
          JSON.stringify(Object.keys(repeatedResource).sort()) !==
            JSON.stringify(['access_token', 'expires_in', 'scope', 'token_type']) ||
          bounded(repeatedResource.access_token).split('.').length === 3
        ) {
          return fail();
        }
        await expectSuccess(
          await adapters.grammarRequest(
            input,
            [
              ...validPublic,
              ['resource', status.resource.indicator],
              ['requested_token_type', 'urn:example:ignored'],
            ],
            'none'
          ),
          roles.publicClientId
        );
        const verifyOrganizationOutput = async (
          entries: ReadonlyArray<readonly [string, string]>,
          audience: string,
          expectedLifetime: number,
          expectOrganizationClaim: boolean
        ) => {
          const body = await readJson(await adapters.grammarRequest(input, entries, 'none'));
          if (
            JSON.stringify(Object.keys(body).sort()) !==
              JSON.stringify(['access_token', 'expires_in', 'scope', 'token_type']) ||
            body.token_type !== 'Bearer' ||
            body.expires_in !== expectedLifetime
          ) {
            return fail();
          }
          const verified = await jwtVerify(bounded(body.access_token), createLocalJWKSet(jwks), {
            algorithms: ['ES384'],
            issuer: new URL('/oidc', input.target.coreUrl).href,
            audience,
            currentDate: new Date(adapters.now() * 1000),
            clockTolerance: 15,
            requiredClaims: ['sub', 'iat', 'exp'],
          }).catch(fail);
          if (
            verified.protectedHeader.typ !== 'at+jwt' ||
            verified.payload.sub !== status.user.id ||
            verified.payload.client_id !== roles.publicClientId ||
            verified.payload.scope !== body.scope ||
            Number(verified.payload.exp) - Number(verified.payload.iat) !== expectedLifetime ||
            (expectOrganizationClaim
              ? verified.payload.organization_id !== input.fixture.public.organization.id
              : Object.hasOwn(verified.payload, 'organization_id'))
          ) {
            return fail();
          }
          if (typeof body.scope !== 'string' || Buffer.byteLength(body.scope) > 2048) {
            return fail();
          }
          return body.scope;
        };
        const organizationId = input.fixture.public.organization.id;
        const organizationAudience = `${input.target.label === 'oracle' ? 'urn:logto:organization:' : 'urn:aster:organization:'}${organizationId}`;
        const organizationOnlyScope = await verifyOrganizationOutput(
          [...validPublic, ['organization_id', organizationId]],
          organizationAudience,
          3600,
          false
        );
        if (organizationOnlyScope !== '') {
          return fail();
        }
        const resourceOrganizationScope = await verifyOrganizationOutput(
          [
            ...validPublic,
            ['resource', status.resource.indicator],
            ['scope', status.resource.scopeName],
            ['organization_id', organizationId],
          ],
          status.resource.indicator,
          first.lifetime,
          true
        );
        if (resourceOrganizationScope !== first.scope) {
          return fail();
        }
        const duplicateOpaqueBody = await readJson(
          await adapters.grammarRequest(
            input,
            [...validPublic, ['scope', 'openid openid profile profile unknown unknown']],
            'none'
          )
        );
        if (
          JSON.stringify(Object.keys(duplicateOpaqueBody).sort()) !==
            JSON.stringify(['access_token', 'expires_in', 'scope', 'token_type']) ||
          duplicateOpaqueBody.expires_in !== 3600 ||
          duplicateOpaqueBody.scope !== 'openid profile' ||
          bounded(duplicateOpaqueBody.access_token).split('.').length === 3
        ) {
          return fail();
        }
        const duplicateResourceResponse = await adapters.grammarRequest(
          input,
          [
            ...validPublic,
            ['resource', status.resource.indicator],
            ['scope', `${status.resource.scopeName} ${status.resource.scopeName} unknown unknown`],
          ],
          'none'
        );
        const duplicateResourceBody = await readJson(duplicateResourceResponse.clone());
        if (duplicateResourceBody.scope !== status.resource.scopeName) {
          return fail();
        }
        await expectSuccess(duplicateResourceResponse, roles.publicClientId);
        const duplicateOrganizationScope = await verifyOrganizationOutput(
          [
            ...validPublic,
            ['organization_id', organizationId],
            ['scope', 'organization:read organization:read unknown unknown'],
          ],
          organizationAudience,
          3600,
          false
        );
        if (duplicateOrganizationScope !== '') {
          return fail();
        }
        const customizerPath = 'configs/jwt-customizer/access-token';
        type AdminRequestInput = Parameters<Phase2AdminRequestFunction>[0];
        const customizerManagementRequest = managementRequest as (
          request: Omit<AdminRequestInput, 'method'> & {
            method: AdminRequestInput['method'] | 'PUT';
          }
        ) => ReturnType<Phase2AdminRequestFunction>;
        const readCustomizer = async () =>
          record(
            await customizerManagementRequest({
              method: 'GET',
              path: customizerPath,
              expectedStatuses: [200, 404],
              responseKind: 'object',
            })
          );
        const originalCustomizer = await readCustomizer();
        const originalCustomizerPresent = Object.hasOwn(originalCustomizer, 'script');
        const putCustomizer = async (script: string) => {
          await customizerManagementRequest({
            method: 'PUT',
            path: customizerPath,
            body: { script, blockIssuanceOnError: true },
            expectedStatuses: [200, 201],
            responseKind: 'object',
          });
          await adapters.settleCustomizer();
        };
        const deleteCustomizer = async () => {
          await customizerManagementRequest({
            method: 'DELETE',
            path: customizerPath,
            expectedStatuses: [204],
            responseKind: 'status',
          });
          await adapters.settleCustomizer();
        };
        const contextScript = `const getCustomJwtClaims = async ({ token, context }) => ({
          phase2_token_shape: token.kind === 'AccessToken' && typeof token.gty === 'string' &&
            typeof token.accountId === 'string' && typeof token.clientId === 'string' &&
            (typeof token.aud === 'string' || Array.isArray(token.aud)) && typeof token.jti === 'string' &&
            typeof token.grantId === 'string',
          phase2_user_context: context?.user?.id === token.accountId,
          phase2_application_context: context?.application?.id === token.clientId,
          phase2_organization_context: Array.isArray(context?.user?.organizations) &&
            context.user.organizations.some(({ id }) => id === ${JSON.stringify(input.fixture.public.organization.id)}),
          phase2_subject_context: context?.grant?.subjectTokenContext?.kind === 'management-context',
          phase2_subject_context_absent: context?.grant?.subjectTokenContext === undefined
        });`;
        const denyScript = `const getCustomJwtClaims = async ({ api }) => api.denyAccess('blocked');`;
        const readCustomizerClaims = async (token: string) => {
          const verified = await jwtVerify(token, createLocalJWKSet(jwks), {
            algorithms: ['ES384'],
            issuer: new URL('/oidc', input.target.coreUrl).href,
            audience: status.resource.indicator,
            currentDate: new Date(adapters.now() * 1000),
            clockTolerance: 15,
          }).catch(fail);
          return verified.payload;
        };
        try {
          await putCustomizer(contextScript);
          const contextManaged = await createManaged({ kind: 'management-context' });
          const managedCustomized = await expectSuccess(
            await adapters.managedRequest(input, contextManaged, secret, {
              kind: 'managed',
              target: status.resource.indicator,
            })
          );
          const managedClaims = await readCustomizerClaims(managedCustomized);
          if (
            managedClaims.phase2_token_shape !== true ||
            managedClaims.phase2_user_context !== true ||
            managedClaims.phase2_application_context !== true ||
            managedClaims.phase2_organization_context !== true ||
            managedClaims.phase2_subject_context !== true
          ) {
            return fail();
          }
          const ordinaryCustomized = await expectSuccess(
            await adapters.grammarRequest(
              input,
              [
                grant,
                ['subject_token', bounded(source.access)],
                subjectType,
                ['resource', status.resource.indicator],
              ],
              'correct',
              secret
            )
          );
          const ordinaryClaims = await readCustomizerClaims(ordinaryCustomized);
          if (ordinaryClaims.phase2_subject_context_absent !== true) {
            return fail();
          }
          const contextPatName = 'phase2-token-exchange-context-pat';
          await withRequiredCleanup(
            async () => {
              const contextPat = record(
                await managementRequest({
                  method: 'POST',
                  path: patPath,
                  body: { name: contextPatName },
                  expectedStatuses: [201],
                  responseKind: 'object',
                })
              );
              const contextPatValue = bounded(contextPat.value);
              const patCustomized = await expectSuccess(
                await adapters.managedRequest(input, contextPatValue, secret, {
                  kind: 'pat',
                  target: status.resource.indicator,
                })
              );
              const patClaims = await readCustomizerClaims(patCustomized);
              if (patClaims.phase2_subject_context_absent !== true) {
                return fail();
              }
            },
            async () => {
              const deleted = await managementRequest({
                method: 'POST',
                path: `${patPath}/delete`,
                body: { name: contextPatName },
                expectedStatuses: [204],
                responseKind: 'status',
              });
              if (deleted !== 204) {
                fail();
              }
            }
          );
          await putCustomizer(denyScript);
          const deniedManaged = await createManaged({ kind: 'deny-preservation' });
          const deniedResponse = await adapters.managedRequest(input, deniedManaged, secret, {
            kind: 'managed',
            target: status.resource.indicator,
          });
          if (deniedResponse.status !== 400 || deniedResponse.redirected) {
            await deniedResponse.body?.cancel();
            return fail();
          }
          const deniedBody = record(JSON.parse(await deniedResponse.text()) as unknown);
          if (deniedBody.error !== 'access_denied' || Object.hasOwn(deniedBody, 'access_token')) {
            return fail();
          }
          await deleteCustomizer();
          await expectSuccess(
            await adapters.managedRequest(input, deniedManaged, secret, {
              kind: 'managed',
              target: status.resource.indicator,
            })
          );
        } finally {
          const currentCustomizer = await readCustomizer();
          if (originalCustomizerPresent) {
            await customizerManagementRequest({
              method: 'PUT',
              path: customizerPath,
              body: originalCustomizer,
              expectedStatuses: [200, 201],
              responseKind: 'object',
            });
            await adapters.settleCustomizer();
          } else if (Object.hasOwn(currentCustomizer, 'script')) {
            await deleteCustomizer();
          }
          const restoredCustomizer = await readCustomizer();
          if (
            Object.hasOwn(restoredCustomizer, 'script') !== originalCustomizerPresent ||
            (originalCustomizerPresent &&
              !isDeepStrictEqual(restoredCustomizer, originalCustomizer))
          ) {
            fail();
          }
        }
        return Object.freeze({
          responseKeys: Object.freeze([
            'access_token',
            'expires_in',
            'scope',
            'token_type',
          ] as const),
          tokenType: 'Bearer',
          outputKind: 'jwt',
          sourceReusable: true,
          subjectPreserved: true,
          clientPreserved: true,
          audienceIsResource: true,
          scopeMatchesFixtureAuthority: true,
          lifetimeSeconds: first.lifetime,
          managedSubject: Object.freeze({
            creationKeys: Object.freeze(['expiresIn', 'subjectToken'] as const),
            expiresIn: 600,
            badTarget: Object.freeze({
              status: 400,
              error: 'invalid_target',
              sourcePreserved: true,
            }),
            successAfterBadTarget: true,
            replay: Object.freeze({ status: 400, error: 'invalid_grant' }),
            badActor: Object.freeze({ status: 400, error: 'invalid_grant', sourcePreserved: true }),
            successAfterBadActor: true,
          }),
          personalAccessToken: Object.freeze({
            publicKeys: Object.freeze(
              patKeys as ['createdAt', 'expiresAt', 'name', 'tenantId', 'userId', 'value']
            ),
            expiresAtNull: true,
            listedWithValue: true,
            repeatedResourceExchange: true,
            deleteStatus: 204,
            rejectedAfterDelete: Object.freeze({ status: 400, error: 'invalid_grant' }),
          }),
          opaque: Object.freeze({
            responseKeys: Object.freeze([
              'access_token',
              'expires_in',
              'scope',
              'token_type',
            ] as const),
            lifetimeSeconds: 3600,
            compact: 'opaque',
            scope: 'openid profile',
            userinfoSubject: true,
            introspectionActive: true,
            subjectToResourceJwt: true,
            openidActorClaim: true,
            profileActorRejected: Object.freeze({
              status: 400,
              error: 'invalid_grant',
              sourcePreserved: true,
            }),
            profileSubjectAccepted: true,
            revokedSubjectRejected: Object.freeze({ status: 400, error: 'invalid_grant' }),
            revokedActorRejected: Object.freeze({
              status: 400,
              error: 'invalid_grant',
              sourcePreserved: true,
            }),
            priorOpaqueOutputRemainsActive: true,
          }),
          admissionGrammar: Object.freeze({
            disabled: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: 'grant request is invalid',
            }),
            unknownClientMasksMissingSubject: Object.freeze({
              status: 400,
              error: 'invalid_client',
              errorDescription: 'invalid client unknown-client',
            }),
            publicMissingSubject: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: "missing required parameter 'subject_token'",
            }),
            publicMissingSubjectType: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: "missing required parameter 'subject_token_type'",
            }),
            confidentialMissingProof: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: 'no client authentication mechanism provided',
            }),
            confidentialWrongProof: Object.freeze({
              status: 401,
              error: 'invalid_client',
              errorDescription: 'client authentication failed',
            }),
            confidentialCorrectProofMasksMissingSubject: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription:
                "missing required parameters 'subject_token' and 'subject_token_type'",
            }),
            duplicateSubject: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: "'subject_token' parameter must not be provided twice",
            }),
            duplicateSubjectType: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: "'subject_token_type' parameter must not be provided twice",
            }),
            duplicateActor: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: "'actor_token' parameter must not be provided twice",
            }),
            duplicateActorType: Object.freeze({
              status: 400,
              error: 'invalid_request',
              errorDescription: "'actor_token_type' parameter must not be provided twice",
            }),
            repeatedResourceSelectsOpaque: true,
            requestedTokenTypeIgnored: true,
            metadataRestored: true,
          }),
          organization: Object.freeze({
            organizationOnly: Object.freeze({
              lifetimeSeconds: 3600,
              scope: '',
              audienceMapped: true,
              organizationIdClaimAbsent: true,
            }),
            resourceAndOrganization: Object.freeze({
              lifetimeSeconds: first.lifetime,
              scopePreserved: true,
              audienceIsResource: true,
              organizationIdClaim: true,
            }),
          }),
          customizer: Object.freeze({
            managedTokenShape: true,
            managedUserContext: true,
            managedApplicationContext: true,
            managedOrganizationContext: true,
            managedSubjectTokenContext: true,
            ordinaryJwtSubjectTokenContextAbsent: true,
            personalAccessTokenSubjectTokenContextAbsent: true,
            deny: Object.freeze({ status: 400, error: 'access_denied', sourcePreserved: true }),
            configurationRestored: true,
          }),
          scopeCanonicalization: Object.freeze({
            opaque: Object.freeze({
              duplicateNamesCollapsed: true,
              unknownNamesFiltered: true,
              scope: 'openid profile',
            }),
            resource: Object.freeze({
              duplicateNamesCollapsed: true,
              unknownNamesFiltered: true,
              scopeMatchesFixtureAuthority: true,
            }),
            organization: Object.freeze({
              duplicateNamesCollapsed: true,
              unauthorizedNamesFiltered: true,
              scope: '',
              lifetimeSeconds: 3600,
            }),
          }),
        });
      })()
    );
  } catch (error: unknown) {
    if (error instanceof AggregateError) {
      throw error;
    }
    return fail();
  }
};

export const runTokenExchangeUserJwtForTarget = async (
  input: DriverInput
): Promise<TokenExchangeUserJwtProjection> =>
  observeTokenExchangeUserJwtMatrix(input, realAdapters);
/* eslint-enable complexity, max-lines, no-restricted-syntax, no-await-in-loop, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
