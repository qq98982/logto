/* eslint-disable unicorn/no-array-for-each, prefer-destructuring -- Runtime registry inputs are untrusted and checked field by field before their typed boundary. */
import { snapshotClosedDataGraph } from '../model.js';
import type { Phase1Profile, Phase1ProfileSemanticContext } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

type KeyedValue = Readonly<Record<string, unknown>>;

const isRegistryObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const requireRegistryObject = (
  value: unknown,
  index: number,
  pointer: string
): Readonly<Record<string, unknown>> => {
  if (!isRegistryObject(value)) {
    return fail(`${pointer}/${index}`, 'registry-entry');
  }

  return value;
};

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
  const snapshot = snapshotClosedDataGraph<unknown>(entry);

  if (snapshot === undefined) {
    fail(`${pointer}/${index}`, 'registry-entry');
  }
  if (typeof snapshot === 'string') {
    return snapshot;
  }

  const definition = requireRegistryObject(snapshot, index, pointer);
  const forbiddenFields = [
    'oracle',
    'candidate',
    'compare',
    'differences',
    'oracleComparison',
  ] as const;

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
  options: Readonly<{ rejectOracleStructures?: boolean; requireOrder?: boolean }> = {}
): void => {
  const { rejectOracleStructures = false, requireOrder = false } = options;
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
  if (requireOrder) {
    registryIds.forEach((id, index) => {
      if (id !== profileIds[index]) {
        fail(`${pointer}/${index}`, 'registry-exact-order');
      }
    });
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
    { rejectOracleStructures: true, requireOrder: true }
  );
};

/* eslint-enable unicorn/no-array-for-each, prefer-destructuring */
