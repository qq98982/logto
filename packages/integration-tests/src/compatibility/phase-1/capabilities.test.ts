/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Hostile closed-data fixtures intentionally construct sparse arrays, accessors, proxies, wrong prototypes, and mutable caller graphs. */
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import type { CapabilityManifest } from '../model.js';

import {
  derivePhase1BaselineCapabilityIds,
  derivePhase1ProfileOwnedContracts,
  parsePhase1CapabilityDocument,
  phase1BaselineCapabilityIds,
  phase1FixtureSetupCapabilityIds,
  phase1ProfileOwnedContracts,
  type Phase1CapabilityDocument,
} from './capabilities.js';
import { fixtureSetupCapabilityIds } from './fixture-map.js';
import type { Phase1Profile } from './profile-types.js';

const diagnostic = 'Invalid phase 1 capability selection';
const root = path.resolve(process.cwd(), '../..');

const loadJson = async (relativePath: string): Promise<unknown> =>
  JSON.parse(await readFile(path.join(root, relativePath), 'utf8')) as unknown;

const profileFixture = (): Phase1Profile =>
  ({
    reference: { oracleCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412' },
    experienceOperations: phase1BaselineCapabilityIds.slice(0, 6),
    experienceBootstrapOperations: phase1BaselineCapabilityIds.slice(6, 8),
    managementOperations: phase1BaselineCapabilityIds.slice(8, 10),
    accountOperations: phase1BaselineCapabilityIds.slice(10, 11),
    interactionOperations: [
      {
        id: phase1ProfileOwnedContracts[1],
        sourceEvidence: [
          'packages/integration-tests/src/tests/api/interaction/consent/happy-path.test.ts',
        ],
        sourceCapabilities: [phase1BaselineCapabilityIds[11]],
      },
      {
        id: phase1ProfileOwnedContracts[2],
        sourceEvidence: [
          'packages/integration-tests/src/tests/api/interaction/consent/happy-path.test.ts',
        ],
        sourceCapabilities: [phase1BaselineCapabilityIds[11]],
      },
    ],
    consoleOrganizationTokenRequest: {
      sourceEvidence: ['packages/integration-tests/src/tests/api/oidc/organization-token.test.ts'],
      sourceCapabilities: [phase1BaselineCapabilityIds[12]],
    },
    oidc: {
      grants: ['authorization_code', 'refresh_token'],
      responseTypes: ['code'],
      responseModes: ['query'],
      tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
    },
    consoleBootstrapOperations: [phase1ProfileOwnedContracts[0]],
    consoleReadRequests: [
      {
        method: 'GET',
        baseUrl: 'http://localhost:3002',
        path: '/api/.well-known/endpoints/default',
        query: {},
        authorization: null,
        expectedStatus: 200,
        requiredProjection: { user: 'http://localhost:3001' },
      },
    ],
  }) as unknown as Phase1Profile;

const documentFixture = (): Phase1CapabilityDocument => ({
  schemaVersion: 1,
  referenceCommit: '6852a7b8c8984c5c12b2061e8c51faa310a36412',
  baselineCapabilityIds: [...phase1BaselineCapabilityIds],
  fixtureSetupCapabilityIds: [...phase1FixtureSetupCapabilityIds],
  profileOwnedContracts: [...phase1ProfileOwnedContracts],
});

const loadManifest = async (): Promise<CapabilityManifest> =>
  (await loadJson('compatibility/baseline-manifest.json')) as CapabilityManifest;

const mutableClone = <Value>(value: Value): Value => JSON.parse(JSON.stringify(value)) as Value;

type GraphNode = Record<PropertyKey, unknown> | readonly unknown[];

const recursivelyFrozen = (
  value: unknown,
  visited: WeakSet<GraphNode> = new WeakSet()
): boolean => {
  if (typeof value !== 'object' || value === null) {
    return true;
  }
  const node = value as GraphNode;

  if (visited.has(node)) {
    return true;
  }
  visited.add(node);

  return (
    Object.isFrozen(value) &&
    Reflect.ownKeys(value).every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);

      return Boolean(
        descriptor &&
          Object.hasOwn(descriptor, 'value') &&
          recursivelyFrozen(descriptor.value, visited)
      );
    })
  );
};

const expectInvalid = (
  value: unknown,
  profile: Phase1Profile,
  manifest: CapabilityManifest
): void => {
  let error: unknown;
  try {
    parsePhase1CapabilityDocument(value, profile, manifest);
  } catch (error_: unknown) {
    error = error_;
  }

  expect(error).toBeInstanceOf(TypeError);
  expect(error).toMatchObject({ message: diagnostic });
  expect(String(error)).not.toContain('private-capability-sentinel');
};

describe('phase 1 capability selection', () => {
  it('parses the canonical document from exact profile derivation and manifest authority', async () => {
    const manifest = await loadManifest();
    const value = await loadJson('compatibility/phases/phase-1-capabilities.json');
    const result = parsePhase1CapabilityDocument(value, profileFixture(), manifest);

    expect(result).toEqual(documentFixture());
    expect(derivePhase1BaselineCapabilityIds(profileFixture())).toEqual(
      phase1BaselineCapabilityIds
    );
    expect(derivePhase1ProfileOwnedContracts(profileFixture())).toEqual(
      phase1ProfileOwnedContracts
    );
    expect(phase1FixtureSetupCapabilityIds).toBe(fixtureSetupCapabilityIds);
    expect(recursivelyFrozen(result)).toBe(true);
  });

  it('derives only explicit sourceCapabilities and never overclaims sourceEvidence citations', () => {
    const profile = mutableClone(profileFixture());
    const operations = profile.interactionOperations as unknown as Array<{
      sourceEvidence: string[];
      sourceCapabilities: string[];
    }>;
    operations[0]?.sourceEvidence.push(
      'packages/integration-tests/src/tests/api/oidc/provider-semantics.test.ts'
    );

    expect(derivePhase1BaselineCapabilityIds(profile)).toEqual(phase1BaselineCapabilityIds);

    operations[0]?.sourceCapabilities.push('test.api/oidc/provider-semantics.test.ts');
    expect(() => derivePhase1BaselineCapabilityIds(profile)).toThrow(diagnostic);
  });

  it('binds the selection to the exact oracle reference commit', async () => {
    const manifest = await loadManifest();
    const profile = mutableClone(profileFixture());
    (profile.reference as { oracleCommit: string }).oracleCommit = 'a'.repeat(40);

    expectInvalid(documentFixture(), profile, manifest);
    expect(() => derivePhase1BaselineCapabilityIds(profile)).toThrow(diagnostic);
    expect(() => derivePhase1ProfileOwnedContracts(profile)).toThrow(diagnostic);
  });

  it('rejects missing extra duplicate reordered and cross-category document entries', async () => {
    const manifest = await loadManifest();
    const profile = profileFixture();
    const missing = documentFixture();
    missing.baselineCapabilityIds.pop();
    const extra = { ...documentFixture(), unexpected: 'private-capability-sentinel' };
    const duplicate = documentFixture();
    duplicate.baselineCapabilityIds[1] = duplicate.baselineCapabilityIds[0] ?? '';
    const reordered = documentFixture();
    [reordered.baselineCapabilityIds[0], reordered.baselineCapabilityIds[1]] = [
      reordered.baselineCapabilityIds[1] ?? '',
      reordered.baselineCapabilityIds[0] ?? '',
    ];
    const crossCategory = documentFixture();
    [crossCategory.baselineCapabilityIds[0], crossCategory.fixtureSetupCapabilityIds[0]] = [
      crossCategory.fixtureSetupCapabilityIds[0] ?? '',
      crossCategory.baselineCapabilityIds[0] ?? '',
    ];

    for (const invalid of [missing, extra, duplicate, reordered, crossCategory]) {
      expectInvalid(invalid, profile, manifest);
    }
  });

  it('rejects sparse proxy accessor and wrong-prototype input before field reads', async () => {
    const manifest = await loadManifest();
    const profile = profileFixture();
    const sparse = documentFixture();
    Reflect.deleteProperty(sparse.baselineCapabilityIds, '9');
    const proxied = documentFixture();
    proxied.fixtureSetupCapabilityIds = new Proxy([...proxied.fixtureSetupCapabilityIds], {});
    const accessor = documentFixture();
    Object.defineProperty(accessor.profileOwnedContracts, '0', {
      enumerable: true,
      get: () => phase1ProfileOwnedContracts[0],
    });
    const wrongPrototype = documentFixture();
    Object.setPrototypeOf(wrongPrototype.baselineCapabilityIds, null);

    for (const invalid of [sparse, proxied, accessor, wrongPrototype]) {
      expectInvalid(invalid, profile, manifest);
    }
  });

  it('requires every selected Phase 0 ID and forbids profile-owned manifest entries', async () => {
    const manifest = await loadManifest();
    const missingSelected = mutableClone(manifest);
    const selectedIndex = missingSelected.capabilities.findIndex(
      ({ id }) => id === phase1BaselineCapabilityIds[0]
    );
    const selected = missingSelected.capabilities[selectedIndex];
    if (!selected) {
      throw new Error('Expected selected manifest capability');
    }
    selected.id = 'phase1-test-missing-capability';

    const containingProfileOwned = mutableClone(manifest);
    const filler = containingProfileOwned.capabilities.find(
      ({ id }) =>
        !phase1BaselineCapabilityIds.includes(id as never) &&
        !phase1FixtureSetupCapabilityIds.includes(id as never)
    );
    if (!filler) {
      throw new Error('Expected unselected manifest capability');
    }
    filler.id = phase1ProfileOwnedContracts[0];

    expectInvalid(documentFixture(), profileFixture(), missingSelected);
    expectInvalid(documentFixture(), profileFixture(), containingProfileOwned);
  });

  it('parses and matches the Console literal as an exact request contract', async () => {
    const manifest = await loadManifest();
    const literalVariants = [
      'POST http://localhost:3002/api/.well-known/endpoints/default',
      'GET http://localhost:3001/api/.well-known/endpoints/default',
      'GET http://localhost:3002/api/.well-known/endpoints/default?extra=1',
      'GET http://localhost:3002/api/.well-known/endpoints/default#fragment',
    ];

    for (const literal of literalVariants) {
      const profile = mutableClone(profileFixture());
      (profile.consoleBootstrapOperations as string[])[0] = literal;
      expectInvalid(documentFixture(), profile, manifest);
    }

    const mismatchedRequest = mutableClone(profileFixture());
    const request = mismatchedRequest.consoleReadRequests[0] as unknown as {
      query: Record<string, string>;
    };
    request.query.extra = 'private-capability-sentinel';
    expectInvalid(documentFixture(), mismatchedRequest, manifest);
  });

  it('returns an independent recursively frozen result despite later caller mutation', async () => {
    const manifest = await loadManifest();
    const profile = mutableClone(profileFixture());
    const document = documentFixture();
    const result = parsePhase1CapabilityDocument(document, profile, manifest);

    document.baselineCapabilityIds[0] = 'private-capability-sentinel';
    (profile.experienceOperations as string[])[0] = 'private-capability-sentinel';
    manifest.capabilities[0]!.id = 'private-capability-sentinel';

    expect(result).toEqual(documentFixture());
    expect(Reflect.set(result.baselineCapabilityIds, '0', 'private-capability-sentinel')).toBe(
      false
    );
    expect(recursivelyFrozen(result)).toBe(true);
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
