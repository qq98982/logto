import { z } from 'zod';

import { capabilityGuard, capabilityManifestGuard, type CapabilityManifest } from '../model.js';

import { fixtureSetupCapabilityIds } from './fixture-map.js';
import { oracleCommit, snapshotClosedDataGraph } from './model.js';
import type { Phase1Profile } from './profile-types.js';

const diagnostic = 'Invalid phase 1 capability selection';
const baselineCapabilityCount = 20;
const fixtureSetupCapabilityCount = 21;
const profileOwnedContractCount = 3;
const manifestCapabilityCount = 667;

export const phase1BaselineCapabilityIds = Object.freeze([
  'http.experience-api.get./api/experience/interaction',
  'http.experience-api.post./api/experience/identification',
  'http.experience-api.post./api/experience/submit',
  'http.experience-api.post./api/experience/verification/password',
  'http.experience-api.put./api/experience',
  'http.experience-api.put./api/experience/interaction-event',
  'http.management-api.get./api/.well-known/phrases',
  'http.management-api.get./api/.well-known/sign-in-exp',
  'http.management-api.get./api/applications',
  'http.management-api.get./api/users',
  'http.user-api.get./api/my-account',
  'test.api/interaction/consent/happy-path.test.ts',
  'test.api/oidc/organization-token.test.ts',
  'oidc.grant.authorization_code',
  'oidc.grant.refresh_token',
  'oidc.response_type.code',
  'oidc.response_mode.query',
  'oidc.token_endpoint_auth_method.client_secret_basic',
  'oidc.token_endpoint_auth_method.client_secret_post',
  'oidc.token_endpoint_auth_method.none',
] as const);

export const phase1FixtureSetupCapabilityIds = fixtureSetupCapabilityIds;

export const phase1ProfileOwnedContracts = Object.freeze([
  'GET http://localhost:3002/api/.well-known/endpoints/default',
  'phase1.http.interaction.get./api/interaction/consent',
  'phase1.http.interaction.post./api/interaction/consent',
] as const);

const capabilityIdGuard = z.string().min(1);

export const phase1CapabilityDocumentGuard = z
  .object({
    schemaVersion: z.literal(1),
    referenceCommit: z.literal(oracleCommit),
    baselineCapabilityIds: z.array(capabilityIdGuard).length(baselineCapabilityCount),
    fixtureSetupCapabilityIds: z.array(capabilityIdGuard).length(fixtureSetupCapabilityCount),
    profileOwnedContracts: z.array(z.string().min(1)).length(profileOwnedContractCount),
  })
  .strict();

export type Phase1CapabilityDocument = z.infer<typeof phase1CapabilityDocumentGuard>;

const strictCapabilityManifestGuard = capabilityManifestGuard
  .extend({ capabilities: z.array(capabilityGuard.strict()).length(manifestCapabilityCount) })
  .strict();

const equalStrings = (left: readonly string[], right: readonly string[]): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const uniqueStrings = (values: readonly string[]): readonly string[] =>
  Object.freeze([...new Set(values)]);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const profileSnapshot = (value: unknown): Readonly<Phase1Profile> => {
  const snapshot = snapshotClosedDataGraph<Phase1Profile>(value);

  return snapshot ?? fail();
};

const deriveBaseline = (profile: Readonly<Phase1Profile>): readonly string[] => {
  if (profile.reference.oracleCommit !== oracleCommit) {
    return fail();
  }
  const explicitSourceCapabilities = uniqueStrings([
    ...profile.interactionOperations.flatMap(({ sourceCapabilities }) => sourceCapabilities),
    ...profile.consoleOrganizationTokenRequest.sourceCapabilities,
  ]);
  const result = Object.freeze([
    ...profile.experienceOperations,
    ...profile.experienceBootstrapOperations,
    ...profile.managementOperations,
    ...profile.accountOperations,
    ...explicitSourceCapabilities,
    ...profile.oidc.grants.map((grant) => `oidc.grant.${grant}`),
    ...profile.oidc.responseTypes.map((responseType) => `oidc.response_type.${responseType}`),
    ...profile.oidc.responseModes.map((responseMode) => `oidc.response_mode.${responseMode}`),
    ...profile.oidc.tokenEndpointAuthMethods.map(
      (method) => `oidc.token_endpoint_auth_method.${method}`
    ),
  ]);

  if (
    result.length !== baselineCapabilityCount ||
    new Set(result).size !== result.length ||
    !equalStrings(result, phase1BaselineCapabilityIds)
  ) {
    return fail();
  }

  return result;
};

const parseConsoleRequestLiteral = (value: string): Readonly<{ method: string; url: URL }> => {
  const separator = value.indexOf(' ');

  if (separator <= 0 || value.slice(separator + 1).includes(' ')) {
    return fail();
  }
  const method = value.slice(0, separator);
  const rawUrl = value.slice(separator + 1);

  try {
    const url = new URL(rawUrl);

    if (
      method !== 'GET' ||
      url.protocol !== 'http:' ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      `${method} ${url.href}` !== value
    ) {
      return fail();
    }

    return Object.freeze({ method, url });
  } catch {
    return fail();
  }
};

const assertConsoleRequestContract = (profile: Readonly<Phase1Profile>, literal: string): void => {
  const { method, url } = parseConsoleRequestLiteral(literal);
  const matching = profile.consoleReadRequests.filter(
    (request) => request.path === url.pathname && request.baseUrl === url.origin
  );
  const [request] = matching;

  if (
    matching.length !== 1 ||
    !request ||
    request.method !== method ||
    request.path !== '/api/.well-known/endpoints/default' ||
    Object.keys(request.query).length > 0 ||
    request.authorization !== null ||
    request.expectedStatus !== 200
  ) {
    fail();
  }
};

const deriveProfileOwned = (profile: Readonly<Phase1Profile>): readonly string[] => {
  if (profile.reference.oracleCommit !== oracleCommit) {
    return fail();
  }
  const result = Object.freeze([
    ...profile.consoleBootstrapOperations,
    ...profile.interactionOperations.map(({ id }) => id),
  ]);

  if (
    result.length !== profileOwnedContractCount ||
    new Set(result).size !== result.length ||
    !equalStrings(result, phase1ProfileOwnedContracts)
  ) {
    return fail();
  }
  assertConsoleRequestContract(profile, result[0] ?? fail());

  return result;
};

export const derivePhase1BaselineCapabilityIds = (
  profile: Readonly<Phase1Profile>
): readonly string[] => {
  try {
    return deriveBaseline(profileSnapshot(profile));
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const derivePhase1ProfileOwnedContracts = (
  profile: Readonly<Phase1Profile>
): readonly string[] => {
  try {
    return deriveProfileOwned(profileSnapshot(profile));
  } catch {
    throw new TypeError(diagnostic);
  }
};

const manifestSnapshot = (value: unknown): CapabilityManifest => {
  const snapshot = snapshotClosedDataGraph<unknown>(value);

  if (snapshot === undefined) {
    return fail();
  }
  const parsed = strictCapabilityManifestGuard.safeParse(snapshot);

  if (
    !parsed.success ||
    new Set(parsed.data.capabilities.map(({ id }) => id)).size !== manifestCapabilityCount
  ) {
    return fail();
  }

  return parsed.data;
};

const assertDocumentMatchesAuthorities = (
  document: Phase1CapabilityDocument,
  expectedBaseline: readonly string[],
  expectedProfileOwned: readonly string[],
  manifestIds: ReadonlySet<string>
): void => {
  const arraysHaveExactUniqueEntries =
    equalStrings(document.baselineCapabilityIds, expectedBaseline) &&
    equalStrings(document.fixtureSetupCapabilityIds, phase1FixtureSetupCapabilityIds) &&
    equalStrings(document.profileOwnedContracts, expectedProfileOwned) &&
    new Set(document.baselineCapabilityIds).size === baselineCapabilityCount &&
    new Set(document.fixtureSetupCapabilityIds).size === fixtureSetupCapabilityCount &&
    new Set(document.profileOwnedContracts).size === profileOwnedContractCount;
  const manifestRelationshipIsExact =
    document.baselineCapabilityIds.every((id) => manifestIds.has(id)) &&
    document.fixtureSetupCapabilityIds.every((id) => manifestIds.has(id)) &&
    document.profileOwnedContracts.every((id) => !manifestIds.has(id));

  if (!arraysHaveExactUniqueEntries || !manifestRelationshipIsExact) {
    fail();
  }
};

export const parsePhase1CapabilityDocument = (
  value: unknown,
  profile: Readonly<Phase1Profile>,
  manifest: CapabilityManifest
): Phase1CapabilityDocument => {
  try {
    const snapshot = snapshotClosedDataGraph<unknown>(value);

    if (snapshot === undefined) {
      return fail();
    }
    const parsed = phase1CapabilityDocumentGuard.safeParse(snapshot);

    if (!parsed.success) {
      return fail();
    }
    const profileValue = profileSnapshot(profile);
    const expectedBaseline = deriveBaseline(profileValue);
    const expectedProfileOwned = deriveProfileOwned(profileValue);
    const manifestValue = manifestSnapshot(manifest);
    const manifestIds = new Set(manifestValue.capabilities.map(({ id }) => id));
    const document = parsed.data;

    assertDocumentMatchesAuthorities(document, expectedBaseline, expectedProfileOwned, manifestIds);
    const result = snapshotClosedDataGraph<Phase1CapabilityDocument>(document);

    return result ?? fail();
  } catch {
    throw new TypeError(diagnostic);
  }
};

export const assertPhase1CapabilityDocument = (
  value: unknown,
  profile: Readonly<Phase1Profile>,
  manifest: CapabilityManifest
): void => {
  void parsePhase1CapabilityDocument(value, profile, manifest);
};
