/* eslint-disable complexity, max-lines, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types -- The complete client-credentials publication boundary validates and normalizes hostile HTTP/JWT/state input in one auditable pass. */
import { types as nodeTypes } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  containsCompactJwt,
  type SanitizedTokenObservation,
} from '../clients/client-credentials.js';
import type { Phase2FixturePublic } from '../fixtures.js';

export type Phase2EffectiveAuthorityFacts = Readonly<{
  decision:
    | 'authorized'
    | 'unauthorized-client'
    | 'invalid-target'
    | 'access-denied'
    | 'invalid-request';
  targetKind: 'resource' | 'organization' | 'none';
  target: string | null;
  availableScopes: readonly string[];
  effectiveScopes: readonly string[];
}>;

export type Phase2SigningUseFacts = Readonly<{
  generalKeyUse: 'verified' | 'unchanged';
  oidcIdTokenKeyUse: 'unchanged';
}>;

export type Phase2SideEffectFacts = Readonly<{
  users: 0;
  sessions: 0;
  grants: 0;
  authorizationCodes: 0;
  interactions: 0;
  refreshTokens: 0;
  tokenFamilies: 0;
}>;

export type RawClientCredentialsProjectionInput = Readonly<{
  target: TargetConfig;
  fixture: Phase2FixturePublic;
  response: SanitizedTokenObservation;
  jwtProof?: Phase2VerifiedJwtProof;
  authority: Phase2EffectiveAuthorityFacts;
  signingUse: Phase2SigningUseFacts;
  sideEffects: Phase2SideEffectFacts;
}>;

declare const phase2VerifiedJwtProofBrand: unique symbol;
export type Phase2VerifiedJwtProof = Readonly<{ [phase2VerifiedJwtProofBrand]: true }>;
export type Phase2JwtAudit = Readonly<{
  verify(
    response: SanitizedTokenObservation,
    requestStartedAtMilliseconds: number,
    responseObservedAtMilliseconds: number
  ): Phase2VerifiedJwtProof | undefined;
}>;

export type ClientCredentialsProjection = Readonly<{
  http: Readonly<{
    status: number;
    headers: Readonly<Record<string, string | number>>;
    body: Readonly<Record<string, unknown>>;
  }>;
  jwt: Readonly<{
    header: Readonly<{
      typ: 'at+jwt';
      alg: 'ES384';
      kid: '<verified-es384-key>';
    }>;
    claims: Readonly<{
      iss: '<target-issuer>';
      aud: string;
      sub: string;
      client_id: string;
      scope?: string;
      organization_id?: string;
      iat: '<issued-at>';
      exp: Readonly<{ afterIssuedAtSeconds: 3600 }>;
      jti: '<unique-jti>';
    }>;
    signature: Readonly<{ verified: true; algorithm: 'ES384' }>;
  }> | null;
  authority: Phase2EffectiveAuthorityFacts;
  signingUse: Phase2SigningUseFacts;
  sideEffects: Phase2SideEffectFacts;
}>;

const diagnostic = 'Invalid Phase 2 client credentials projection';
const requestIdPattern = /^[0-9a-f]{16}$/u;
const keyIdPattern = /^[A-Za-z0-9._~-]{1,256}$/u;
const jwtIdPattern = /^[A-Za-z0-9_-]{16,256}$/u;
const maximumJwtObservationWindowMilliseconds = 60_000;
const scopeNamePattern = /^[\u0021\u0023-\u005B\u005D-\u007E]+$/u;
const allowedResponseHeaders = new Set([
  'access-control-allow-origin',
  'access-control-expose-headers',
  'aster-core-request-id',
  'cache-control',
  'connection',
  'content-length',
  'content-type',
  'cross-origin-resource-policy',
  'date',
  'keep-alive',
  'origin-agent-cluster',
  'referrer-policy',
  'strict-transport-security',
  'vary',
  'www-authenticate',
  'x-content-type-options',
  'x-download-options',
  'x-frame-options',
  'x-permitted-cross-domain-policies',
  'x-xss-protection',
]);
const referenceRequestIdHeaders = new Set(['logto-core-request-id', 'x-logto-request-id']);
const candidateRequestIdHeaders = new Set(['aster-core-request-id', 'x-aster-request-id']);
const referenceRequestIdPattern = /^[A-Za-z0-9_-]{16}$/u;
const forbiddenKeyPattern =
  /(?:authorization|proxy.?authorization|cookie|set.?cookie|client.?secret|access.?token|refresh.?token|id.?token|private.?key|sql|raw.?log|bearer|digest|sha256|hash)/iu;
const privateJwkMembers = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']);
const allowedSensitiveMetadataKeys = new Set([
  'authorizationCodes',
  'clearedCookieCount',
  'oidcIdTokenKeyUse',
  'refreshTokens',
  'setCookieCount',
]);
const jwtProofs = new WeakMap<object, Readonly<{ jwt: object; issuedAt: number; jwtId: string }>>();
const consumedJwtProofs = new WeakSet<object>();

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const record = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      return fail();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail();
    }
  }
  return value as Record<string, unknown>;
};

const exactKeys = (
  value: unknown,
  required: readonly string[],
  optional: readonly string[] = []
): Record<string, unknown> => {
  const result = record(value);
  const keys = Object.keys(result);
  const allowed = new Set([...required, ...optional]);
  if (
    keys.length < required.length ||
    keys.length > required.length + optional.length ||
    required.some((key) => !keys.includes(key)) ||
    keys.some((key) => !allowed.has(key))
  ) {
    return fail();
  }
  return result;
};

const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

export const createClientCredentialsJwtAudit = (): Phase2JwtAudit => {
  const seenJwtIds = new Set<string>();
  return Object.freeze({
    verify: (
      response: SanitizedTokenObservation,
      requestStartedAtMilliseconds: number,
      responseObservedAtMilliseconds: number
    ): Phase2VerifiedJwtProof | undefined => {
      if (
        !Number.isSafeInteger(requestStartedAtMilliseconds) ||
        !Number.isSafeInteger(responseObservedAtMilliseconds) ||
        requestStartedAtMilliseconds < 0 ||
        responseObservedAtMilliseconds < requestStartedAtMilliseconds ||
        responseObservedAtMilliseconds - requestStartedAtMilliseconds >
          maximumJwtObservationWindowMilliseconds
      ) {
        return fail();
      }
      if (response.jwt === undefined) {
        return undefined;
      }
      const claims = record(response.jwt.claims);
      const issuedAt = own(claims, 'iat');
      const jwtId = own(claims, 'jti');
      const notBefore = Math.floor(requestStartedAtMilliseconds / 1000);
      const notAfter = Math.ceil(responseObservedAtMilliseconds / 1000);
      if (
        typeof issuedAt !== 'number' ||
        !Number.isSafeInteger(issuedAt) ||
        issuedAt < notBefore ||
        issuedAt > notAfter ||
        typeof jwtId !== 'string' ||
        !jwtIdPattern.test(jwtId) ||
        seenJwtIds.has(jwtId)
      ) {
        return fail();
      }
      seenJwtIds.add(jwtId);
      const proof = Object.freeze({}) as Phase2VerifiedJwtProof;
      jwtProofs.set(proof, Object.freeze({ jwt: response.jwt, issuedAt, jwtId }));
      return proof;
    },
  });
};

const denseStrings = (value: unknown): readonly string[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    Reflect.ownKeys(value).length !== value.length + 1 ||
    value.some((entry) => typeof entry !== 'string')
  ) {
    return fail();
  }
  const entries = value as unknown[];
  return Object.freeze(entries.map((entry) => entry as string));
};

const sortedUniqueScopes = (value: unknown): readonly string[] => {
  const scopes = denseStrings(value);
  if (
    scopes.some((scope) => !scopeNamePattern.test(scope)) ||
    new Set(scopes).size !== scopes.length ||
    scopes.some((scope, index) => scope !== scopes.toSorted()[index])
  ) {
    return fail();
  }
  return scopes;
};

const logicalClientId = (value: unknown, fixture: Phase2FixturePublic): string => {
  if (value === fixture.clients.basic.id) {
    return '<client.basic>';
  }
  if (value === fixture.clients.post.id) {
    return '<client.post>';
  }
  if (value === 'phase2-unknown-client-basic') {
    return '<client.unknown-basic>';
  }
  if (value === 'phase2-unknown-client-post') {
    return '<client.unknown-post>';
  }
  return fail();
};

const logicalOrganizationId = (value: unknown, fixture: Phase2FixturePublic): string =>
  value === fixture.organization.id ? '<organization.primary>' : fail();

const normalizeOrganizationAudience = (value: string, target: TargetConfig): string => {
  if (target.label === 'oracle') {
    if (value === 'urn:logto:resource:organizations') {
      return 'urn:aster:resource:organizations';
    }
    if (value.startsWith('urn:logto:organization:')) {
      return `urn:aster:organization:${value.slice('urn:logto:organization:'.length)}`;
    }
  }
  if (
    value === 'urn:aster:resource:organizations' ||
    value.startsWith('urn:aster:organization:') ||
    value.startsWith('https://')
  ) {
    return value;
  }
  return fail();
};

const normalizeAudience = (
  value: unknown,
  target: TargetConfig,
  fixture: Phase2FixturePublic
): string => {
  if (value === fixture.resources.primary.indicator) {
    return '<resource.primary>';
  }
  if (value === fixture.resources.default.indicator) {
    return '<resource.default>';
  }
  if (typeof value !== 'string') {
    return fail();
  }
  const normalized = normalizeOrganizationAudience(value, target);
  if (normalized.startsWith('urn:aster:organization:')) {
    const organizationId = normalized.slice('urn:aster:organization:'.length);
    if (organizationId === fixture.organization.id) {
      return 'urn:aster:organization:<organization.primary>';
    }
  }
  return normalized;
};

const normalizeIssuer = (value: unknown, target: TargetConfig): '<target-issuer>' => {
  try {
    if (typeof value !== 'string' || value !== new URL('/oidc', target.coreUrl).href) {
      return fail();
    }
  } catch {
    return fail();
  }
  return '<target-issuer>';
};

const projectHeaders = (
  value: unknown,
  target: TargetConfig
): Readonly<Record<string, string | number>> => {
  const source = record(value);
  const projected: Array<readonly [string, string | number]> = [];
  for (const [rawName, rawValue] of Object.entries(source)) {
    if (typeof rawValue !== 'string') {
      return fail();
    }
    const name = rawName.toLowerCase();
    const isReferenceRequestId = target.label === 'oracle' && referenceRequestIdHeaders.has(name);
    const isCandidateRequestId =
      target.label === 'candidate' && candidateRequestIdHeaders.has(name);
    const normalizedName =
      isReferenceRequestId || isCandidateRequestId ? 'aster-core-request-id' : name;
    if (!allowedResponseHeaders.has(normalizedName)) {
      return fail();
    }
    const normalizedValue = (() => {
      if (normalizedName === 'aster-core-request-id') {
        return (
          target.label === 'oracle'
            ? referenceRequestIdPattern.test(rawValue)
            : requestIdPattern.test(rawValue)
        )
          ? '<per-request-id>'
          : fail();
      }
      if (normalizedName === 'content-length') {
        return /^(?:0|[1-9]\d*)$/u.test(rawValue) && Number.isSafeInteger(Number(rawValue))
          ? '<response-body-length>'
          : fail();
      }
      if (normalizedName === 'date') {
        return Number.isFinite(Date.parse(rawValue)) ? '<response-date>' : fail();
      }
      if (normalizedName === 'www-authenticate') {
        const core = new URL(target.coreUrl);
        const expectedRealm = `${core.origin}/oidc`;
        return rawValue.replace(`realm="${expectedRealm}"`, 'realm="<target-issuer>"');
      }
      return rawValue;
    })();
    projected.push([normalizedName, normalizedValue]);
  }
  projected.sort(([left], [right]) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
  if (new Set(projected.map(([name]) => name)).size !== projected.length) {
    return fail();
  }
  return Object.freeze(Object.fromEntries(projected));
};

const projectBody = (value: unknown, successful: boolean): Readonly<Record<string, unknown>> => {
  const body = successful
    ? exactKeys(value, ['expires_in', 'token_type'], ['scope'])
    : exactKeys(value, ['code', 'message', 'error', 'error_description']);
  if (successful) {
    if (
      own(body, 'expires_in') !== 3600 ||
      own(body, 'token_type') !== 'Bearer' ||
      (Object.hasOwn(body, 'scope') && typeof own(body, 'scope') !== 'string')
    ) {
      return fail();
    }
  } else if (Object.values(body).some((entry) => typeof entry !== 'string')) {
    return fail();
  }
  return Object.freeze({ ...body });
};

const projectJwt = (
  response: SanitizedTokenObservation,
  target: TargetConfig,
  fixture: Phase2FixturePublic,
  proof: Phase2VerifiedJwtProof | undefined
): ClientCredentialsProjection['jwt'] => {
  if (response.jwt === undefined) {
    return proof === undefined ? null : fail();
  }
  if (proof === undefined || consumedJwtProofs.has(proof as object)) {
    return fail();
  }
  const verifiedProof = jwtProofs.get(proof as object);
  if (!verifiedProof || verifiedProof.jwt !== response.jwt) {
    return fail();
  }
  if (!/^[0-9a-f]{64}$/u.test(response.jwt.signatureSha256)) {
    return fail();
  }
  const header = exactKeys(response.jwt.header, ['alg', 'kid', 'typ']);
  const kid = own(header, 'kid');
  if (
    own(header, 'alg') !== 'ES384' ||
    own(header, 'typ') !== 'at+jwt' ||
    typeof kid !== 'string' ||
    !keyIdPattern.test(kid)
  ) {
    return fail();
  }
  const claims = exactKeys(
    response.jwt.claims,
    ['aud', 'client_id', 'exp', 'iat', 'iss', 'jti', 'sub'],
    ['scope', 'organization_id']
  );
  const issuedAt = own(claims, 'iat');
  const expiresAt = own(claims, 'exp');
  const jwtId = own(claims, 'jti');
  const clientId = logicalClientId(own(claims, 'client_id'), fixture);
  if (
    typeof issuedAt !== 'number' ||
    !Number.isSafeInteger(issuedAt) ||
    typeof expiresAt !== 'number' ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt - issuedAt !== 3600 ||
    typeof jwtId !== 'string' ||
    !jwtIdPattern.test(jwtId) ||
    issuedAt !== verifiedProof.issuedAt ||
    jwtId !== verifiedProof.jwtId ||
    own(claims, 'sub') !== own(claims, 'client_id')
  ) {
    return fail();
  }
  const scope = own(claims, 'scope');
  const organizationId = own(claims, 'organization_id');
  if (
    (scope !== undefined && typeof scope !== 'string') ||
    (organizationId !== undefined && typeof organizationId !== 'string')
  ) {
    return fail();
  }
  const projection = Object.freeze({
    header: Object.freeze({ typ: 'at+jwt', alg: 'ES384', kid: '<verified-es384-key>' }),
    claims: Object.freeze({
      iss: normalizeIssuer(own(claims, 'iss'), target),
      aud: normalizeAudience(own(claims, 'aud'), target, fixture),
      sub: clientId,
      client_id: clientId,
      ...(scope === undefined ? {} : { scope }),
      ...(organizationId === undefined
        ? {}
        : { organization_id: logicalOrganizationId(organizationId, fixture) }),
      iat: '<issued-at>',
      exp: Object.freeze({ afterIssuedAtSeconds: 3600 as const }),
      jti: '<unique-jti>',
    }),
    signature: Object.freeze({ verified: true, algorithm: 'ES384' }),
  });
  consumedJwtProofs.add(proof as object);
  return projection;
};

const projectAuthority = (
  value: unknown,
  fixture: Phase2FixturePublic
): Phase2EffectiveAuthorityFacts => {
  const authority = exactKeys(value, [
    'decision',
    'targetKind',
    'target',
    'availableScopes',
    'effectiveScopes',
  ]);
  const decision = own(authority, 'decision');
  const targetKind = own(authority, 'targetKind');
  const target = own(authority, 'target');
  if (
    ![
      'authorized',
      'unauthorized-client',
      'invalid-target',
      'access-denied',
      'invalid-request',
    ].includes(String(decision)) ||
    !['resource', 'organization', 'none'].includes(String(targetKind)) ||
    (target !== null && typeof target !== 'string')
  ) {
    return fail();
  }
  const normalizedTarget = (() => {
    if (target === null) {
      return null;
    }
    if (targetKind === 'resource') {
      if (target === fixture.resources.primary.indicator) {
        return '<resource.primary>';
      }
      if (target === fixture.resources.default.indicator) {
        return '<resource.default>';
      }
      return fail();
    }
    return logicalOrganizationId(target, fixture);
  })();
  return Object.freeze({
    decision: decision as Phase2EffectiveAuthorityFacts['decision'],
    targetKind: targetKind as Phase2EffectiveAuthorityFacts['targetKind'],
    target: normalizedTarget,
    availableScopes: sortedUniqueScopes(own(authority, 'availableScopes')),
    effectiveScopes: sortedUniqueScopes(own(authority, 'effectiveScopes')),
  });
};

const projectSigningUse = (value: unknown): Phase2SigningUseFacts => {
  const signing = exactKeys(value, ['generalKeyUse', 'oidcIdTokenKeyUse']);
  if (
    !['verified', 'unchanged'].includes(String(own(signing, 'generalKeyUse'))) ||
    own(signing, 'oidcIdTokenKeyUse') !== 'unchanged'
  ) {
    return fail();
  }
  return Object.freeze({
    generalKeyUse: own(signing, 'generalKeyUse') as Phase2SigningUseFacts['generalKeyUse'],
    oidcIdTokenKeyUse: 'unchanged',
  });
};

const projectSideEffects = (value: unknown): Phase2SideEffectFacts => {
  const effects = exactKeys(value, [
    'users',
    'sessions',
    'grants',
    'authorizationCodes',
    'interactions',
    'refreshTokens',
    'tokenFamilies',
  ]);
  if (Object.values(effects).some((entry) => entry !== 0)) {
    return fail();
  }
  return Object.freeze({
    users: 0,
    sessions: 0,
    grants: 0,
    authorizationCodes: 0,
    interactions: 0,
    refreshTokens: 0,
    tokenFamilies: 0,
  });
};

type EvidenceStringContext = 'ordinary' | 'token-type' | 'challenge';

const inspectEvidence = (
  value: unknown,
  seen = new WeakSet<object>(),
  context: EvidenceStringContext = 'ordinary'
): void => {
  if (typeof value === 'string') {
    const allowedTokenType = context === 'token-type' && value === 'Bearer';
    const allowedChallenge =
      context === 'challenge' &&
      /^Basic realm="<target-issuer>", error="invalid_client", error_description="client authentication failed"$/u.test(
        value
      );
    if (
      containsCompactJwt(value) ||
      (!allowedTokenType &&
        !allowedChallenge &&
        /\b(?:Basic|Bearer)\s+[A-Za-z0-9._~+/-]+=*/u.test(value))
    ) {
      return fail();
    }
    return;
  }
  if (value === null || typeof value !== 'object') {
    return;
  }
  if (seen.has(value)) {
    return fail();
  }
  seen.add(value);
  if (Array.isArray(value)) {
    for (const entry of value) {
      inspectEvidence(entry, seen, 'ordinary');
    }
    return;
  }
  const object = record(value);
  const normalizedKeys = Object.keys(object).map((key) => key.toLowerCase());
  if (
    (typeof object.kty === 'string' && normalizedKeys.some((key) => privateJwkMembers.has(key))) ||
    Object.keys(object).some(
      (key) => forbiddenKeyPattern.test(key) && !allowedSensitiveMetadataKeys.has(key)
    )
  ) {
    return fail();
  }
  for (const [key, nested] of Object.entries(object)) {
    inspectEvidence(
      nested,
      seen,
      key === 'token_type' ? 'token-type' : key === 'www-authenticate' ? 'challenge' : 'ordinary'
    );
  }
};

export const assertClientCredentialsEvidenceIsSanitized = (value: unknown): void => {
  inspectEvidence(value);
};

export const projectClientCredentialsObservation = (
  input: RawClientCredentialsProjectionInput
): ClientCredentialsProjection => {
  const source = exactKeys(
    input,
    ['target', 'fixture', 'response', 'authority', 'signingUse', 'sideEffects'],
    ['jwtProof']
  );
  const target = validateProjectionTarget(own(source, 'target'));
  const fixture = own(source, 'fixture') as Phase2FixturePublic;
  const response = exactKeys(own(source, 'response'), ['status', 'headers', 'body'], ['jwt']);
  const status = own(response, 'status');
  if (typeof status !== 'number' || !Number.isSafeInteger(status) || status < 100 || status > 599) {
    return fail();
  }
  const jwt = projectJwt(
    own(source, 'response') as SanitizedTokenObservation,
    target,
    fixture,
    own(source, 'jwtProof') as Phase2VerifiedJwtProof | undefined
  );
  const successful = status >= 200 && status < 300;
  if (successful !== (jwt !== null)) {
    return fail();
  }
  const projection = Object.freeze({
    http: Object.freeze({
      status,
      headers: projectHeaders(own(response, 'headers'), target),
      body: projectBody(own(response, 'body'), successful),
    }),
    jwt,
    authority: projectAuthority(own(source, 'authority'), fixture),
    signingUse: projectSigningUse(own(source, 'signingUse')),
    sideEffects: projectSideEffects(own(source, 'sideEffects')),
  });
  assertClientCredentialsEvidenceIsSanitized(projection);
  return projection;
};

const validateProjectionTarget = (value: unknown): TargetConfig => {
  const target = exactKeys(value, ['label', 'coreUrl', 'adminUrl']);
  if (
    (own(target, 'label') !== 'oracle' && own(target, 'label') !== 'candidate') ||
    typeof own(target, 'coreUrl') !== 'string' ||
    typeof own(target, 'adminUrl') !== 'string'
  ) {
    return fail();
  }
  return value as TargetConfig;
};

export const createZeroClientCredentialsSideEffects = (): Phase2SideEffectFacts =>
  Object.freeze({
    users: 0,
    sessions: 0,
    grants: 0,
    authorizationCodes: 0,
    interactions: 0,
    refreshTokens: 0,
    tokenFamilies: 0,
  });

/* eslint-enable complexity, max-lines, no-restricted-syntax, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types */
