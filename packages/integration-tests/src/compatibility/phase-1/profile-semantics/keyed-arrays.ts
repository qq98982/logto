/* eslint-disable no-restricted-syntax, unicorn/no-array-for-each, prefer-destructuring -- Runtime registry inputs are untrusted and checked field by field before their typed boundary. */
import type { Phase1Profile, Phase1ProfileSemanticContext } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

type KeyedValue = Readonly<Record<string, unknown>>;

const fail = (pointer: string, rule: string): never => {
  throw new Phase1ProfileValidationError('semantic', [pointer], [rule]);
};

const escapePointerToken = (token: string) => token.replaceAll('~', '~0').replaceAll('/', '~1');

const assertUniqueKeys = (values: readonly KeyedValue[], key: string, pointer: string): void => {
  const seen = new Set<unknown>();

  values.forEach((value, index) => {
    const candidate = value[key];

    if (seen.has(candidate)) {
      fail(`${pointer}/${index}/${escapePointerToken(key)}`, 'unique-key');
    }

    seen.add(candidate);
  });
};

const readRegistryEntry = (
  entry: unknown,
  index: number,
  pointer: string,
  rejectOracleStructures: boolean
): string => {
  if (typeof entry === 'string') {
    return entry;
  }

  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    fail(`${pointer}/${index}`, 'registry-entry');
  }

  const definition = entry as Readonly<Record<string, unknown>>;
  const forbiddenFields = ['oracle', 'compare', 'differences', 'oracleComparison'] as const;

  if (rejectOracleStructures) {
    for (const field of forbiddenFields) {
      if (Object.hasOwn(definition, field)) {
        fail(`${pointer}/${index}/${field}`, 'candidate-invariant-no-oracle');
      }
    }

    if (Object.hasOwn(definition, 'target') && definition.target === 'oracle') {
      fail(`${pointer}/${index}/target`, 'candidate-invariant-no-oracle');
    }
  }

  const id = definition.id;

  if (typeof id === 'string') {
    return id;
  }

  return fail(`${pointer}/${index}`, 'registry-entry');
};

const assertExactRegistrySet = (
  profileIds: readonly string[],
  registryEntries: readonly unknown[],
  pointer: string,
  rejectOracleStructures = false
): void => {
  const profileSet = new Set(profileIds);

  if (profileSet.size !== profileIds.length) {
    const duplicateIndex = profileIds.findIndex((id, index) => profileIds.indexOf(id) !== index);
    fail(`${pointer}/${duplicateIndex}`, 'profile-unique-id');
  }

  const registryIds = registryEntries.map((entry, index) =>
    readRegistryEntry(entry, index, pointer, rejectOracleStructures)
  );
  const registrySet = new Set(registryIds);

  if (registrySet.size !== registryIds.length) {
    fail(pointer, 'registry-unique-id');
  }

  profileIds.forEach((id, index) => {
    if (!registrySet.has(id)) {
      fail(`${pointer}/${index}`, 'registry-exact-set');
    }
  });

  if (registryIds.some((id) => !profileSet.has(id))) {
    fail(pointer, 'registry-exact-set');
  }
};

export const assertKeyedArraySemantics = (
  profile: Phase1Profile,
  context: Phase1ProfileSemanticContext
): void => {
  assertUniqueKeys(profile.uiAssetContracts, 'application', '/uiAssetContracts');
  assertUniqueKeys(
    profile.fixtures.dataTenant.applications,
    'id',
    '/fixtures/dataTenant/applications'
  );
  assertUniqueKeys(
    profile.fixtures.dataTenant.resource.scopes,
    'id',
    '/fixtures/dataTenant/resource/scopes'
  );
  assertUniqueKeys(
    profile.fixtures.adminTenant.tenantOrganization.organizationRoles,
    'id',
    '/fixtures/adminTenant/tenantOrganization/organizationRoles'
  );
  assertUniqueKeys(profile.interactionOperations, 'id', '/interactionOperations');
  assertUniqueKeys(profile.browserFlows, 'id', '/browserFlows');
  assertUniqueKeys(profile.browserExecutionGroups, 'id', '/browserExecutionGroups');
  assertUniqueKeys(profile.conformance.staticClients, 'id', '/conformance/staticClients');
  assertUniqueKeys(profile.conformance.plans, 'testPlanName', '/conformance/plans');
  assertExactRegistrySet(
    profile.differentialScenarios,
    context.differentialRegistryIds,
    '/differentialScenarios'
  );
  assertExactRegistrySet(
    profile.candidateInvariantScenarios,
    context.candidateInvariantRegistryIds,
    '/candidateInvariantScenarios',
    true
  );
};

/* eslint-enable no-restricted-syntax, unicorn/no-array-for-each, prefer-destructuring */
