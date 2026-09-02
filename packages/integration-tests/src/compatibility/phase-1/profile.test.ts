/* eslint-disable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types -- The security-boundary matrix uses isolated mutable filesystem fixtures, deterministic race injection, and WeakSet<object> graph traversal. */
import { createHash, timingSafeEqual } from 'node:crypto';
import { constants as fsConstants, existsSync, realpathSync } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open as openFile,
  readFile,
  realpath as realPath,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { inspect } from 'node:util';
import { createContext, SourceTextModule, SyntheticModule, type Module as VmModule } from 'node:vm';

import { Ajv2020, type AnySchema, type ValidateFunction } from 'ajv/dist/2020.js';
import * as addFormatsModule from 'ajv-formats';

import { phase1ProfileSchemaLock } from './profile-lock.js';
import type {
  Phase1AccountTokenAuthorization,
  Phase1ApplicationReadQuery,
  Phase1ConsoleTokenAuthorization,
  Phase1Profile,
  Phase1UserReadQuery,
} from './profile-types.js';
import {
  createLockedPhase1ProfileLoader,
  createPhase1DesignProfileBundleFromBytes,
  createPhase1ProfileBundleLoader,
  createPhase1ProfileLoader,
  parsePhase1SchemaLockDocument,
  Phase1ProfileValidationError,
  type Phase1InputFileState,
  type Phase1ProfileLoaderDependencies,
  type Phase1ProfileSchemaLock,
} from './profile.js';
import {
  createDesignSyntheticProfile,
  createLockedSyntheticProfile,
  createNestedDuplicateProfileSource,
  syntheticSchemaSha256,
  syntheticSchemaSourceCommit,
  type SyntheticProfile,
} from './testing/mutations.js';

const maximumJsonBytes = 1024 * 1024;
const buildRoot = '/var/tmp/henry-build';
const sourceFixtureDirectory = path.resolve(process.cwd(), 'src/compatibility/phase-1/testing');
const publicSchemaLockPath = path.resolve(
  process.cwd(),
  '../../compatibility/phase-1-schema-lock.json'
);
const createdRoots = new Set<string>();

const phase1ProfileRootKeys = [
  'schemaVersion',
  'profileId',
  'reference',
  'profileSchema',
  'phase1Harness',
  'uiSource',
  'uiAssetContracts',
  'routing',
  'localhostCookiePortContract',
  'fixtures',
  'consoleAuthentication',
  'consoleOrganizationTokenRequest',
  'oidc',
  'managementOperations',
  'accountOperations',
  'experienceBootstrapOperations',
  'consoleBootstrapOperations',
  'consoleReadRequests',
  'experienceBootstrapRequests',
  'consoleAccountRequests',
  'cors',
  'hostIdentityInfrastructure',
  'experienceOperations',
  'interactionOperations',
  'consentSessionBoundaryContract',
  'browserFlows',
  'browserExecutionGroups',
  'differentialScenarios',
  'candidateInvariantScenarios',
  'semanticStateInvariants',
  'conformance',
] as const satisfies ReadonlyArray<keyof Phase1Profile>;

type ProfileRootKey = (typeof phase1ProfileRootKeys)[number];
type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends <Value>() => Value extends Right ? 1 : 2
    ? true
    : false;

const profileHasExactlyTheDeclaredRoots: Equal<keyof Phase1Profile, ProfileRootKey> = true;
const functionNodeFixture = () => true;

const createSyntheticSchemaLockDocument = () => ({
  schemaVersion: 1 as const,
  phase0BaseCommit: '40135e37201f36ac05ece1eff82e37bb6d9649f1',
  schemaSourceCommit: syntheticSchemaSourceCommit,
  schemaSha256: syntheticSchemaSha256,
  phase0AuthorityBlobs: {
    'compatibility/baseline-manifest.json': '4'.repeat(40),
    'docker-compose.compatibility.yml': '4'.repeat(40),
    '.scripts/compatibility/run.sh': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/model.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/scenario.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/config.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/target-client.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/normalize.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/compare.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/evidence.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/cli.ts': '4'.repeat(40),
    'packages/integration-tests/src/compatibility/scenarios/index.ts': '4'.repeat(40),
  },
});

type FixturePaths = Readonly<{
  root: string;
  profilePath: string;
  schemaPath: string;
}>;

const toInputFileState = async (filePath: string): Promise<Phase1InputFileState> => {
  const state = await lstat(filePath);

  return {
    device: state.dev,
    inode: state.ino,
    mode: state.mode,
    size: state.size,
    modifiedMilliseconds: state.mtimeMs,
    isFile: state.isFile(),
    isSymbolicLink: state.isSymbolicLink(),
  };
};

const createPrivateRoot = async () => {
  await mkdir(buildRoot, { recursive: true });
  const root = await mkdtemp(path.join(buildRoot, 'aster-phase1-profile-test-'));
  createdRoots.add(root);
  await chmod(root, 0o700);

  return root;
};

const createFixturePaths = async (): Promise<FixturePaths> => {
  const root = await createPrivateRoot();
  const profilePath = path.join(root, 'profile.json');
  const schemaPath = path.join(root, 'schema.json');
  await Promise.all([
    writeFile(
      profilePath,
      await readFile(path.join(sourceFixtureDirectory, 'synthetic-profile.json'))
    ),
    writeFile(
      schemaPath,
      await readFile(path.join(sourceFixtureDirectory, 'synthetic-profile.schema.json'))
    ),
  ]);

  return { root, profilePath, schemaPath };
};

const createSchemaBoundFixture = async (
  transformSchema: (schema: Record<string, unknown>) => Record<string, unknown>,
  profile: SyntheticProfile = createLockedSyntheticProfile(),
  serializeProfile: (profile: SyntheticProfile) => string = (value) => JSON.stringify(value)
) => {
  const root = await createPrivateRoot();
  const profilePath = path.join(root, 'profile.json');
  const schemaPath = path.join(root, 'schema.json');
  const parsedSchema: unknown = JSON.parse(
    await readFile(path.join(sourceFixtureDirectory, 'synthetic-profile.schema.json'), 'utf8')
  );

  if (typeof parsedSchema !== 'object' || parsedSchema === null || Array.isArray(parsedSchema)) {
    throw new Error('Synthetic schema fixture must be an object');
  }

  // The fixture was parsed from strict committed JSON and narrowed to a non-array object above.
  const schema = transformSchema(parsedSchema as Record<string, unknown>);
  const schemaBytes = Buffer.from(JSON.stringify(schema));
  const lock: Phase1ProfileSchemaLock = {
    sourceCommit: syntheticSchemaSourceCommit,
    sha256: createHash('sha256').update(schemaBytes).digest('hex'),
  };
  const boundProfile: SyntheticProfile = {
    ...profile,
    profileSchema: {
      sourceCommit: lock.sourceCommit,
      sha256: lock.sha256,
    },
  };
  await Promise.all([
    writeFile(schemaPath, schemaBytes),
    writeFile(profilePath, serializeProfile(boundProfile)),
  ]);

  return { paths: { root, profilePath, schemaPath }, lock, profile: boundProfile };
};

type VirtualReadMutation =
  | 'none'
  | 'zero-progress'
  | 'shrink'
  | 'grow'
  | 'grow-over-limit'
  | 'replace'
  | 'oversized-return';

const createChunkedFileSystem = (
  profilePath: string,
  options: Readonly<{ chunkSize: number; mutation?: VirtualReadMutation }>
) => {
  const closedPaths = new Set<string>();
  const positionsByPath = new Map<string, number[]>();
  const mutation = options.mutation ?? 'none';
  const fileSystem: Phase1ProfileLoaderDependencies<SyntheticProfile>['fileSystem'] = {
    openFile: async (filePath) => {
      const originalBytes = await readFile(filePath);
      const initialState = await toInputFileState(filePath);
      const appliesMutation = filePath === profilePath;
      const visibleBytes: Uint8Array =
        appliesMutation && mutation === 'shrink'
          ? originalBytes.subarray(0, -1)
          : appliesMutation && mutation === 'grow'
            ? Buffer.concat([originalBytes, Buffer.from(' ')])
            : appliesMutation && mutation === 'grow-over-limit'
              ? Buffer.alloc(maximumJsonBytes + 1, 0x20)
              : originalBytes;
      const finalState: Phase1InputFileState = {
        ...initialState,
        ...(appliesMutation && ['shrink', 'grow', 'grow-over-limit'].includes(mutation)
          ? {
              size: visibleBytes.length,
              modifiedMilliseconds: initialState.modifiedMilliseconds + 1,
            }
          : {}),
        ...(appliesMutation && mutation === 'replace'
          ? {
              inode: initialState.inode + 1,
              modifiedMilliseconds: initialState.modifiedMilliseconds + 1,
            }
          : {}),
      };
      let stateReads = 0;
      const positions: number[] = [];
      positionsByPath.set(filePath, positions);

      return {
        getState: async () => {
          stateReads += 1;

          return stateReads === 1 ? initialState : finalState;
        },
        read: async (buffer, offset, position) => {
          positions.push(position);

          if (appliesMutation && mutation === 'zero-progress') {
            return 0;
          }

          if (appliesMutation && mutation === 'oversized-return') {
            return buffer.length - offset + 1;
          }

          const bytesRead = Math.min(
            options.chunkSize,
            visibleBytes.length - position,
            buffer.length - offset
          );

          if (bytesRead <= 0) {
            return 0;
          }

          buffer.set(visibleBytes.subarray(position, position + bytesRead), offset);

          return bytesRead;
        },
        close: async () => {
          closedPaths.add(filePath);
        },
      };
    },
  };

  return { fileSystem, closedPaths, positionsByPath };
};

const createDependencies = <Profile extends SyntheticProfile>(events: string[] = []) =>
  ({
    assertSemantics: (profile: Profile) => {
      expect(profile.items).toHaveLength(1);
      events.push('semantic');
    },
    assertProvenance: async (profile: Profile) => {
      expect(profile.transport.kind).toBe('http');
      events.push('provenance');
    },
  }) satisfies Partial<Phase1ProfileLoaderDependencies<Profile>>;

const syntheticSchemaLock: Phase1ProfileSchemaLock = {
  sourceCommit: syntheticSchemaSourceCommit,
  sha256: syntheticSchemaSha256,
};

const loadSynthetic = (
  dependencies: Partial<Phase1ProfileLoaderDependencies<SyntheticProfile>> = createDependencies()
) => createPhase1ProfileLoader<SyntheticProfile>(syntheticSchemaLock, dependencies);

const expectValidationFailure = async (
  operation: Promise<unknown>,
  expected: Readonly<{
    message: string;
    stage: Phase1ProfileValidationError['stage'];
    pointers?: readonly string[];
    rules?: readonly string[];
    absentText?: string;
  }>
) => {
  try {
    await operation;
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    const validationError = error as Phase1ProfileValidationError;
    expect(validationError.message).toBe(expected.message);
    expect(validationError.stage).toBe(expected.stage);

    if (expected.pointers) {
      expect(validationError.pointers).toEqual(expected.pointers);
    }

    if (expected.rules) {
      expect(validationError.rules).toEqual(expected.rules);
    }

    if (expected.absentText) {
      expect(JSON.stringify(validationError)).not.toContain(expected.absentText);
      expect(validationError.stack).not.toContain(expected.absentText);
    }

    return validationError;
  }

  throw new Error('Expected Phase 1 profile validation to fail');
};

const expectStartupFailure = (
  operation: () => unknown,
  expectedStage: Phase1ProfileValidationError['stage'],
  expectedMessage: string
) => {
  try {
    operation();
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    const validationError = error as Phase1ProfileValidationError;
    expect(validationError.stage).toBe(expectedStage);
    expect(validationError.message).toBe(expectedMessage);

    return;
  }

  throw new Error('Expected Phase 1 profile startup to fail');
};

const expectReachableDataGraphFrozen = (root: object) => {
  const visited = new WeakSet<object>();

  const visit = (value: unknown): void => {
    if (typeof value !== 'object' || value === null || visited.has(value)) {
      return;
    }

    visited.add(value);
    expect(Object.isFrozen(value)).toBe(true);

    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);

      if (descriptor && Object.hasOwn(descriptor, 'value')) {
        visit(descriptor.value);
      }
    }
  };

  visit(root);
};

afterEach(async () => {
  await Promise.all(
    [...createdRoots].map(async (root) => {
      await rm(root, { recursive: true, force: true });
      createdRoots.delete(root);
    })
  );
});

describe('Phase 1 profile type boundary', () => {
  it('models exactly 31 named root properties without an open index signature', () => {
    expect(profileHasExactlyTheDeclaredRoots).toBe(true);
    expect(phase1ProfileRootKeys).toHaveLength(31);
    expect(new Set(phase1ProfileRootKeys).size).toBe(31);
  });

  it('keeps selected authorization and query variants structurally closed', () => {
    const consoleAuthorization = {
      issuer: 'https://issuer.example/',
      resource: 'https://resource.example/',
      scope: 'all',
    } satisfies Phase1ConsoleTokenAuthorization;
    const accountAuthorization = {
      issuer: 'https://issuer.example/',
      resource: null,
      tokenFormat: 'opaque',
    } satisfies Phase1AccountTokenAuthorization;
    const applicationQuery = {
      page: '1',
      page_size: '20',
      isThirdParty: 'false',
      types: 'SPA',
    } satisfies Phase1ApplicationReadQuery;
    const userQuery = {
      page: '1',
      page_size: '20',
    } satisfies Phase1UserReadQuery;

    // @ts-expect-error -- Console resource authorization cannot omit its required scope.
    const missingScope: Phase1ConsoleTokenAuthorization = {
      issuer: 'https://issuer.example/',
      resource: 'https://resource.example/',
    };
    const nullConsoleResource: Phase1ConsoleTokenAuthorization = {
      issuer: 'https://issuer.example/',
      // @ts-expect-error -- Console resource authorization cannot target null.
      resource: null,
      scope: 'all',
    };
    const consoleTokenFormat: Phase1ConsoleTokenAuthorization = {
      issuer: 'https://issuer.example/',
      resource: 'https://resource.example/',
      scope: 'all',
      // @ts-expect-error -- tokenFormat belongs only to Account authorization.
      tokenFormat: 'opaque',
    };
    const accountScope: Phase1AccountTokenAuthorization = {
      issuer: 'https://issuer.example/',
      resource: null,
      tokenFormat: 'opaque',
      // @ts-expect-error -- scope belongs only to Console resource authorization.
      scope: 'all',
    };
    // @ts-expect-error -- Application reads require an explicit isThirdParty discriminator.
    const missingThirdParty: Phase1ApplicationReadQuery = { page: '1', page_size: '20' };
    const userExtraQuery: Phase1UserReadQuery = {
      page: '1',
      page_size: '20',
      // @ts-expect-error -- User reads cannot accept application-list query fields.
      isThirdParty: 'false',
    };

    expect([
      consoleAuthorization,
      accountAuthorization,
      applicationQuery,
      userQuery,
      missingScope,
      nullConsoleResource,
      consoleTokenFormat,
      accountScope,
      missingThirdParty,
      userExtraQuery,
    ]).toHaveLength(10);
  });
});

describe('createPhase1ProfileLoader', () => {
  it('validates a design profile from captured bytes without requiring embedded locks', async () => {
    const paths = await createFixturePaths();
    const profileBytes = Buffer.from(`${JSON.stringify(createDesignSyntheticProfile())}\n`);
    const schemaBytes = await readFile(paths.schemaPath);
    const events: string[] = [];
    const bundle = await createPhase1DesignProfileBundleFromBytes<SyntheticProfile>(
      profileBytes,
      schemaBytes,
      syntheticSchemaLock,
      createDependencies(events)
    );

    expect(bundle.profile.profileSchema.sourceCommit).toBeNull();
    expect(bundle.profile.phase1Harness.commit).toBeNull();
    expect(events).toEqual(['semantic', 'provenance']);
    expect(bundle.readProfileBytes()).toEqual(profileBytes);
  });

  it('returns exact immutable-read byte snapshots and hashes from the validated descriptors', async () => {
    const paths = await createFixturePaths();
    const expectedProfileBytes = await readFile(paths.profilePath);
    const expectedSchemaBytes = await readFile(paths.schemaPath);
    const bundle = await createPhase1ProfileBundleLoader<SyntheticProfile>(
      syntheticSchemaLock,
      createDependencies()
    )(paths);
    const firstProfileRead = bundle.readProfileBytes();
    const firstSchemaRead = bundle.readSchemaBytes();

    expect(firstProfileRead).toEqual(expectedProfileBytes);
    expect(firstSchemaRead).toEqual(expectedSchemaBytes);
    expect(bundle.profileSha256).toBe(
      createHash('sha256').update(expectedProfileBytes).digest('hex')
    );
    expect(bundle.schemaSha256).toBe(syntheticSchemaSha256);
    firstProfileRead.fill(0);
    firstSchemaRead.fill(0);
    expect(bundle.readProfileBytes()).toEqual(expectedProfileBytes);
    expect(bundle.readSchemaBytes()).toEqual(expectedSchemaBytes);
    expect(Object.isFrozen(bundle)).toBe(true);
    expect(Object.isFrozen(bundle.profile)).toBe(true);
  });

  it('loads the locked synthetic contract and recursively freezes it after provenance', async () => {
    const paths = await createFixturePaths();
    const events: string[] = [];
    const load = loadSynthetic(createDependencies(events));
    const profile = await load(paths);

    expect(events).toEqual(['semantic', 'provenance']);
    expect(Object.isFrozen(profile)).toBe(true);
    expect(Object.isFrozen(profile.items)).toBe(true);
    expect(Object.isFrozen(profile.items[0])).toBe(true);
    expect(Object.isFrozen(profile.metadata)).toBe(true);
    expect(Object.isFrozen(profile.metadata.nested)).toBe(true);
    expect(Object.isFrozen(profile.transport)).toBe(true);
  });

  it('continues freezing descendants when a validator pre-freezes the root', async () => {
    const paths = await createFixturePaths();
    const profile = await loadSynthetic({
      ...createDependencies(),
      assertSemantics: (candidate) => {
        Object.freeze(candidate);
      },
    })(paths);

    expect(Object.isFrozen(profile)).toBe(true);
    expect(Object.isFrozen(profile.items)).toBe(true);
    expect(Object.isFrozen(profile.items[0])).toBe(true);
    expect(Object.isFrozen(profile.metadata.nested)).toBe(true);
  });

  it('freezes cyclic data graphs without invoking accessor properties', async () => {
    const paths = await createFixturePaths();
    let getterCalls = 0;
    const profile = await loadSynthetic({
      ...createDependencies(),
      assertSemantics: (candidate) => {
        Object.defineProperties(candidate.metadata, {
          cycle: {
            value: candidate,
            enumerable: true,
            configurable: true,
          },
          computed: {
            get: () => {
              getterCalls += 1;

              return { hidden: true };
            },
            enumerable: true,
            configurable: true,
          },
          functionNode: {
            value: functionNodeFixture,
            enumerable: true,
            configurable: true,
          },
        });
      },
    })(paths);

    expect(getterCalls).toBe(0);
    expect(Object.getOwnPropertyDescriptor(profile.metadata, 'cycle')?.value).toBe(profile);
    expect(Object.getOwnPropertyDescriptor(profile.metadata, 'computed')?.get).toBeDefined();
    expect(Object.isFrozen(functionNodeFixture)).toBe(true);
    expectReachableDataGraphFrozen(profile);
    expect(getterCalls).toBe(0);
  });

  it.each([
    ['malformed JSON', '{'],
    ['comments', '{"value": 1 // forbidden\n}'],
    ['trailing commas', '{"value": 1,}'],
    ['invalid UTF-8', Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x7d])],
    ['a byte-order mark', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{}')])],
  ])('rejects %s without echoing parser input', async (_name, source) => {
    const paths = await createFixturePaths();
    await writeFile(paths.profilePath, source);

    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 JSON',
      stage: 'json',
      rules: ['syntax'],
    });
  });

  it('rejects duplicate decoded properties at nested pointers', async () => {
    const paths = await createFixturePaths();
    await writeFile(paths.profilePath, createNestedDuplicateProfileSource());

    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 JSON',
      stage: 'json',
      pointers: ['/metadata/nested/enabled'],
      rules: ['duplicate-property'],
    });
  });

  it('rejects duplicate properties at the profile root', async () => {
    const paths = await createFixturePaths();
    const source = JSON.stringify(createLockedSyntheticProfile()).replace(
      '"schemaVersion":1,',
      '"schemaVersion":1,"schemaVersion":1,'
    );
    await writeFile(paths.profilePath, source);

    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 JSON',
      stage: 'json',
      pointers: ['/schemaVersion'],
      rules: ['duplicate-property'],
    });
  });

  it.each(['__proto__', 'constructor', 'prototype'])(
    'rejects the dangerous %s property',
    async (key) => {
      const paths = await createFixturePaths();
      const profile = createLockedSyntheticProfile();
      const source = JSON.stringify(profile).replace(
        '"nested":{"enabled":true}',
        `"nested":{"enabled":true,"${key}":{}}`
      );
      await writeFile(paths.profilePath, source);

      await expectValidationFailure(loadSynthetic()(paths), {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: [`/metadata/nested/${key}`],
        rules: ['dangerous-property'],
      });
    }
  );

  it.each([
    ['positive first unsafe integer', '9007199254740992'],
    ['positive rounded unsafe integer', '9007199254740993'],
    ['negative rounded unsafe integer', '-9007199254740993'],
    ['100k-digit integer', '9'.repeat(100_000)],
  ])('classifies the %s as unsafe-integer', async (_name, lexicalValue) => {
    const paths = await createFixturePaths();
    await writeFile(paths.profilePath, `{"value":${lexicalValue}}`);
    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 JSON',
      stage: 'json',
      pointers: ['/value'],
      rules: ['unsafe-integer'],
      absentText: lexicalValue,
    });
  });

  it('rejects excessive nesting before schema compilation', async () => {
    const paths = await createFixturePaths();
    await writeFile(paths.profilePath, `${'['.repeat(257)}${']'.repeat(257)}`);
    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 JSON',
      stage: 'json',
      pointers: ['/'],
      rules: ['maximum-depth'],
    });
  });

  it('bounds structural complexity independently of the byte limit', async () => {
    const paths = await createFixturePaths();
    const excessiveArray = `[${'null,'.repeat(10_001)}null]`;
    expect(Buffer.byteLength(excessiveArray)).toBeLessThan(maximumJsonBytes);
    await writeFile(paths.profilePath, excessiveArray);

    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 JSON',
      stage: 'json',
      pointers: ['/'],
      rules: ['maximum-tokens'],
    });
  });

  it.each(['profile', 'schema'] as const)(
    'enforces a separate one MiB limit for %s',
    async (kind) => {
      const paths = await createFixturePaths();
      await writeFile(
        kind === 'profile' ? paths.profilePath : paths.schemaPath,
        Buffer.alloc(maximumJsonBytes + 1, 0x20)
      );

      await expectValidationFailure(loadSynthetic()(paths), {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: [`/${kind}`],
        rules: ['maximum-bytes'],
      });
    }
  );

  it.each([
    [
      'one-byte semantic-preserving mutation',
      (bytes: Uint8Array) =>
        Buffer.from(Buffer.from(bytes).toString().replace('"minLength": 1', '"minLength": 2')),
    ],
    [
      'appended newline',
      (bytes: Uint8Array) => Buffer.concat([Buffer.from(bytes), Buffer.from('\n')]),
    ],
    [
      'CRLF conversion',
      (bytes: Uint8Array) => Buffer.from(Buffer.from(bytes).toString().replaceAll('\n', '\r\n')),
    ],
  ])('hashes exact schema bytes and rejects %s before parse', async (_name, mutate) => {
    const paths = await createFixturePaths();
    const schemaBytes = await readFile(paths.schemaPath);
    await writeFile(paths.schemaPath, mutate(schemaBytes));

    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 schema hash',
      stage: 'schema-hash',
      pointers: ['/'],
      rules: ['sha256'],
    });
  });

  it('checks the schema hash before parsing malformed profile bytes', async () => {
    const paths = await createFixturePaths();
    await Promise.all([
      writeFile(
        paths.schemaPath,
        Buffer.concat([await readFile(paths.schemaPath), Buffer.from('\n')])
      ),
      writeFile(paths.profilePath, '{'),
    ]);

    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 schema hash',
      stage: 'schema-hash',
      pointers: ['/'],
      rules: ['sha256'],
    });
  });

  it('reports an invalid but hash-matched JSON Schema without compiler details', async () => {
    const paths = await createFixturePaths();
    const invalidSchema = Buffer.from('{"type":"not-a-json-schema-type"}');
    const invalidSchemaLock = {
      ...syntheticSchemaLock,
      sha256: createHash('sha256').update(invalidSchema).digest('hex'),
    };
    await writeFile(paths.schemaPath, invalidSchema);

    await expectValidationFailure(
      createPhase1ProfileLoader<SyntheticProfile>(invalidSchemaLock, createDependencies())(paths),
      {
        message: 'Invalid Phase 1 schema',
        stage: 'schema',
        pointers: ['/'],
        rules: ['compile'],
        absentText: 'not-a-json-schema-type',
      }
    );
  });

  it('rejects a malformed expected digest as a fixed schema-hash failure', async () => {
    const paths = await createFixturePaths();
    const load = createPhase1ProfileLoader<SyntheticProfile>(
      { ...syntheticSchemaLock, sha256: 'short' },
      createDependencies()
    );

    await expectValidationFailure(load(paths), {
      message: 'Invalid Phase 1 schema hash',
      stage: 'schema-hash',
      pointers: ['/'],
      rules: ['sha256'],
      absentText: 'short',
    });
  });

  it('sorts and deduplicates schema pointers and keywords without exposing values', async () => {
    const sensitiveValue = 'schema-value-must-not-leak';
    const paths = await createFixturePaths();
    const profile = createLockedSyntheticProfile();
    profile.items = [{ id: sensitiveValue, name: 'temporary' }];
    const source = JSON.stringify(profile)
      .replace('"name":"temporary"', `"unknown":"${sensitiveValue}"`)
      .replace('"label":"synthetic loader contract"', '"label":""');
    await writeFile(paths.profilePath, source);

    await expectValidationFailure(loadSynthetic()(paths), {
      message: 'Invalid Phase 1 schema',
      stage: 'schema',
      pointers: ['/items/0/name', '/items/0/unknown', '/metadata/label'],
      rules: ['additionalProperties', 'minLength', 'required'],
      absentText: sensitiveValue,
    });
  });

  it.each([
    [
      'source commit',
      (profile: SyntheticProfile) => {
        profile.profileSchema.sourceCommit = '3333333333333333333333333333333333333333';
      },
      '/profileSchema/sourceCommit',
    ],
    [
      'schema digest',
      (profile: SyntheticProfile) => {
        profile.profileSchema.sha256 = '3'.repeat(64);
      },
      '/profileSchema/sha256',
    ],
  ] as const)(
    'rejects an embedded %s that differs from the loader lock',
    async (_name, mutate, pointer) => {
      const paths = await createFixturePaths();
      const profile = createLockedSyntheticProfile();
      mutate(profile);
      await writeFile(paths.profilePath, `${JSON.stringify(profile)}\n`);

      await expectValidationFailure(loadSynthetic()(paths), {
        message: 'Invalid Phase 1 semantics',
        stage: 'semantic',
        pointers: [pointer],
        rules: ['profile-lock'],
      });
    }
  );

  it('accepts the design null-lock branch structurally but rejects it before semantic callbacks', async () => {
    const paths = await createFixturePaths();
    const schema: unknown = JSON.parse(await readFile(paths.schemaPath, 'utf8'));
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormatsModule.default.default(ajv);
    const validate = ajv.compile(schema as AnySchema);
    const profile = createDesignSyntheticProfile();
    expect(validate(profile)).toBe(true);
    await writeFile(paths.profilePath, `${JSON.stringify(profile)}\n`);
    let semanticCalls = 0;

    await expectValidationFailure(
      loadSynthetic({
        ...createDependencies(),
        assertSemantics: () => {
          semanticCalls += 1;
        },
      })(paths),
      {
        message: 'Invalid Phase 1 semantics',
        stage: 'semantic',
        pointers: ['/phase1Harness/commit'],
        rules: ['locked-harness'],
      }
    );
    expect(semanticCalls).toBe(0);
  });

  it.each([
    ['semantic', 'Invalid Phase 1 semantics'],
    ['provenance', 'Invalid Phase 1 provenance'],
  ] as const)(
    'rebuilds and sanitizes fixed diagnostics from the %s validator',
    async (stage, message) => {
      const paths = await createFixturePaths();
      const sentinel = 'validator-secret-must-not-leak';
      const secretSymbol = Symbol(sentinel);
      const dependencies = createDependencies<SyntheticProfile>();

      class LeakyValidationError extends Phase1ProfileValidationError {}

      const failure = new LeakyValidationError(stage, ['/items/0'], ['test-rule']);
      Object.defineProperties(failure, {
        cause: { value: new Error(sentinel), enumerable: false },
        extra: { value: sentinel, enumerable: true },
        hidden: { value: sentinel, enumerable: false },
        stack: { value: `LeakyValidationError: ${sentinel}`, enumerable: false },
        [secretSymbol]: { value: sentinel, enumerable: false },
      });
      const load = loadSynthetic({
        ...dependencies,
        ...(stage === 'semantic'
          ? {
              assertSemantics: () => {
                throw failure;
              },
            }
          : {
              assertProvenance: async () => {
                throw failure;
              },
            }),
      });

      const sanitized = await expectValidationFailure(load(paths), {
        message,
        stage,
        pointers: ['/items/0'],
        rules: ['test-rule'],
        absentText: sentinel,
      });
      expect(sanitized).not.toBe(failure);
      expect(Object.getPrototypeOf(sanitized)).toBe(Phase1ProfileValidationError.prototype);
      expect(Reflect.ownKeys(sanitized)).not.toEqual(
        expect.arrayContaining(['cause', 'extra', 'hidden', secretSymbol])
      );
      expect(inspect(sanitized, { customInspect: false })).not.toContain(sentinel);

      const consoleError = import.meta.jest.spyOn(console, 'error').mockImplementation(() => true);

      try {
        console.error(sanitized);
        expect(
          consoleError.mock.calls
            .flatMap((call) => call.map((value) => inspect(value, { customInspect: false })))
            .join('\n')
        ).not.toContain(sentinel);
      } finally {
        consoleError.mockRestore();
      }
    }
  );

  it.each(['semantic', 'provenance'] as const)(
    'falls back to generic %s diagnostics when callback diagnostic access is unsafe',
    async (stage) => {
      const paths = await createFixturePaths();
      const sentinel = 'unsafe-diagnostic-access-sentinel';
      const failure = new Phase1ProfileValidationError(stage, ['/items/0'], ['test-rule']);
      Object.defineProperties(failure, {
        pointers: {
          get: () => {
            throw new Error(sentinel);
          },
        },
        stack: { value: sentinel },
      });
      const load = loadSynthetic({
        ...createDependencies(),
        ...(stage === 'semantic'
          ? {
              assertSemantics: () => {
                throw failure;
              },
            }
          : {
              assertProvenance: async () => {
                throw failure;
              },
            }),
      });

      await expectValidationFailure(load(paths), {
        message: stage === 'semantic' ? 'Invalid Phase 1 semantics' : 'Invalid Phase 1 provenance',
        stage,
        pointers: ['/'],
        rules: [stage === 'semantic' ? 'semantic-validator' : 'provenance-validator'],
        absentText: sentinel,
      });
    }
  );

  it.each([
    [
      'too many pointers',
      (failure: Phase1ProfileValidationError) => {
        Object.defineProperty(failure, 'pointers', {
          value: Array.from({ length: 65 }, (_unused, index) => `/items/${index}`),
        });
      },
    ],
    [
      'a relative pointer',
      (failure: Phase1ProfileValidationError) => {
        Object.defineProperty(failure, 'pointers', { value: ['items/0'] });
      },
    ],
    [
      'an unsafe rule',
      (failure: Phase1ProfileValidationError) => {
        Object.defineProperty(failure, 'rules', { value: ['rule with spaces'] });
      },
    ],
    [
      'a non-string rule',
      (failure: Phase1ProfileValidationError) => {
        Object.defineProperty(failure, 'rules', { value: [42] });
      },
    ],
  ] as const)('uses generic callback diagnostics for %s', async (_name, mutate) => {
    const paths = await createFixturePaths();
    const failure = new Phase1ProfileValidationError('semantic', ['/items/0'], ['test-rule']);
    mutate(failure);

    await expectValidationFailure(
      loadSynthetic({
        ...createDependencies(),
        assertSemantics: () => {
          throw failure;
        },
      })(paths),
      {
        message: 'Invalid Phase 1 semantics',
        stage: 'semantic',
        pointers: ['/'],
        rules: ['semantic-validator'],
      }
    );
  });

  it.each(['semantic', 'provenance'] as const)(
    'keeps non-validation %s callback failures generic and secret-free',
    async (stage) => {
      const paths = await createFixturePaths();
      const sentinel = 'generic-callback-secret-sentinel';
      const load = loadSynthetic({
        ...createDependencies(),
        ...(stage === 'semantic'
          ? {
              assertSemantics: () => {
                throw new Error(sentinel);
              },
            }
          : {
              assertProvenance: async () => {
                throw new Error(sentinel);
              },
            }),
      });

      await expectValidationFailure(load(paths), {
        message: stage === 'semantic' ? 'Invalid Phase 1 semantics' : 'Invalid Phase 1 provenance',
        stage,
        pointers: ['/'],
        rules: [stage === 'semantic' ? 'semantic-validator' : 'provenance-validator'],
        absentText: sentinel,
      });
    }
  );
});

describe('schema lock startup boundary', () => {
  it('strictly parses the public document and matches both embedded literals', async () => {
    const bytes = await readFile(publicSchemaLockPath);
    const document = parsePhase1SchemaLockDocument(bytes);

    expect(document.schemaSourceCommit).toBe(phase1ProfileSchemaLock.sourceCommit);
    expect(document.schemaSha256).toBe(phase1ProfileSchemaLock.sha256);
    expect(Object.keys(document.phase0AuthorityBlobs)).toHaveLength(12);
  });

  it.each([
    ['public source commit', 'document-source'],
    ['public schema digest', 'document-hash'],
    ['embedded source commit', 'embedded-source'],
    ['embedded schema digest', 'embedded-hash'],
  ] as const)('fails startup when the %s copy changes independently', async (_name, mutation) => {
    const bytes = await readFile(publicSchemaLockPath);
    const document = JSON.parse(bytes.toString()) as {
      schemaSourceCommit: string;
      schemaSha256: string;
    };
    const embedded: { sourceCommit: string; sha256: string } = { ...phase1ProfileSchemaLock };

    switch (mutation) {
      case 'document-source': {
        document.schemaSourceCommit = '3'.repeat(40);
        break;
      }
      case 'document-hash': {
        document.schemaSha256 = '3'.repeat(64);
        break;
      }
      case 'embedded-source': {
        embedded.sourceCommit = '3'.repeat(40);
        break;
      }
      case 'embedded-hash': {
        embedded.sha256 = '3'.repeat(64);
        break;
      }
    }

    expectStartupFailure(
      () =>
        createLockedPhase1ProfileLoader<SyntheticProfile>(
          Buffer.from(JSON.stringify(document)),
          embedded,
          createDependencies()
        ),
      'schema-hash',
      'Invalid Phase 1 schema hash'
    );
  });

  it('rejects duplicate and unknown fields in the public lock document', async () => {
    const bytes = await readFile(publicSchemaLockPath);
    const source = bytes.toString();
    const duplicate = source.replace(
      '"schemaVersion": 1,',
      '"schemaVersion": 1,\n  "schemaVersion": 1,'
    );
    const unknown = source.replace(
      '"schemaVersion": 1,',
      '"schemaVersion": 1,\n  "unexpected": true,'
    );

    expectStartupFailure(
      () => parsePhase1SchemaLockDocument(Buffer.from(duplicate)),
      'json',
      'Invalid Phase 1 JSON'
    );
    expectStartupFailure(
      () => parsePhase1SchemaLockDocument(Buffer.from(unknown)),
      'schema-hash',
      'Invalid Phase 1 schema hash'
    );
  });

  it('requires document lock embedded lock and profile lock to agree before returning', async () => {
    const paths = await createFixturePaths();
    const document = {
      schemaVersion: 1 as const,
      phase0BaseCommit: '40135e37201f36ac05ece1eff82e37bb6d9649f1',
      schemaSourceCommit: syntheticSchemaSourceCommit,
      schemaSha256: syntheticSchemaSha256,
      phase0AuthorityBlobs: {
        'compatibility/baseline-manifest.json': '4'.repeat(40),
        'docker-compose.compatibility.yml': '4'.repeat(40),
        '.scripts/compatibility/run.sh': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/model.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/scenario.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/config.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/target-client.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/normalize.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/compare.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/evidence.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/cli.ts': '4'.repeat(40),
        'packages/integration-tests/src/compatibility/scenarios/index.ts': '4'.repeat(40),
      },
    };
    const load = createLockedPhase1ProfileLoader<SyntheticProfile>(
      Buffer.from(JSON.stringify(document)),
      syntheticSchemaLock,
      createDependencies()
    );
    const profile = await load(paths);

    expect(profile.profileSchema).toEqual({
      sourceCommit: document.schemaSourceCommit,
      sha256: document.schemaSha256,
    });
    expect(new Set(Object.values(document.phase0AuthorityBlobs)).size).toBe(1);
  });
});

const addNumberValueToSyntheticSchema = (schema: Record<string, unknown>) => {
  const { properties, required } = schema;

  if (
    !Array.isArray(required) ||
    typeof properties !== 'object' ||
    properties === null ||
    Array.isArray(properties)
  ) {
    throw new Error('Synthetic schema root is incomplete');
  }

  const requiredProperties = required.filter(
    (value: unknown): value is string => typeof value === 'string'
  );

  if (requiredProperties.length !== required.length) {
    throw new Error('Synthetic schema required list is invalid');
  }

  const propertyRecord = properties as Record<string, unknown>;

  return {
    ...schema,
    required: [...requiredProperties, 'numberValue'],
    properties: {
      ...propertyRecord,
      numberValue: { type: 'number' },
    },
  };
};

const serializeSyntheticNumberProfile = (lexicalValue: string) => (profile: SyntheticProfile) =>
  JSON.stringify(profile).replace('"transport":', `"numberValue":${lexicalValue},"transport":`);

describe('schema execution boundary', () => {
  it.each([
    ['schema-valid', () => createLockedSyntheticProfile()],
    [
      'schema-invalid',
      () => {
        const profile = createLockedSyntheticProfile();
        profile.items = [];

        return profile;
      },
    ],
  ] as const)(
    'rejects an exact-hash $async schema before invoking its %s validator',
    async (_name, createProfile) => {
      const fixture = await createSchemaBoundFixture(
        (schema) => ({ ...schema, $async: true }),
        createProfile()
      );
      const unhandledRejections: unknown[] = [];
      const onUnhandledRejection = (reason: unknown) => {
        unhandledRejections.push(reason);
      };
      process.on('unhandledRejection', onUnhandledRejection);

      try {
        await expectValidationFailure(
          createPhase1ProfileLoader<SyntheticProfile>(
            fixture.lock,
            createDependencies()
          )(fixture.paths),
          {
            message: 'Invalid Phase 1 schema',
            stage: 'schema',
            pointers: ['/'],
            rules: ['async-schema'],
          }
        );
        await new Promise<void>((resolve) => {
          setImmediate(resolve);
        });
        expect(unhandledRejections).toEqual([]);
      } finally {
        process.off('unhandledRejection', onUnhandledRejection);
      }
    }
  );

  it.each([
    ['undefined', undefined],
    ['number', 1],
    // eslint-disable-next-line unicorn/no-thenable -- A malformed custom validator thenable is the behavior under test.
    ['thenable', { then: () => true }],
    ['promise', Promise.resolve(true)],
  ])(
    'rejects a non-boolean %s result from a nominally synchronous validator',
    async (_name: string, result: unknown) => {
      const fixture = await createSchemaBoundFixture((schema) => schema);
      const fakeValidator = Object.assign(() => result, {
        $async: false,
        errors: null,
      });
      // This fault injection targets the same Ajv class instance shared by the compiled profile module.
      const compileSpy = import.meta.jest
        .spyOn(Ajv2020.prototype, 'compile')
        .mockReturnValue(fakeValidator as unknown as ValidateFunction);

      try {
        await expectValidationFailure(
          createPhase1ProfileLoader<SyntheticProfile>(
            fixture.lock,
            createDependencies()
          )(fixture.paths),
          {
            message: 'Invalid Phase 1 schema',
            stage: 'schema',
            pointers: ['/'],
            rules: ['validator-result'],
          }
        );
      } finally {
        compileSpy.mockRestore();
      }
    }
  );

  it('absorbs a rejection from a non-boolean native Promise validator result', async () => {
    const fixture = await createSchemaBoundFixture((schema) => schema);
    const sentinel = 'custom-validator-rejection-sentinel';
    const unhandledRejections: unknown[] = [];
    const onUnhandledRejection = (reason: unknown) => {
      unhandledRejections.push(reason);
    };
    const fakeValidator = Object.assign(
      async () => {
        throw new Error(sentinel);
      },
      {
        $async: false,
        errors: null,
      }
    );
    const compileSpy = import.meta.jest
      .spyOn(Ajv2020.prototype, 'compile')
      .mockReturnValue(fakeValidator as unknown as ValidateFunction);
    process.on('unhandledRejection', onUnhandledRejection);

    try {
      await expectValidationFailure(
        createPhase1ProfileLoader<SyntheticProfile>(
          fixture.lock,
          createDependencies()
        )(fixture.paths),
        {
          message: 'Invalid Phase 1 schema',
          stage: 'schema',
          pointers: ['/'],
          rules: ['validator-result'],
          absentText: sentinel,
        }
      );
      await new Promise<void>((resolve) => {
        setImmediate(resolve);
      });
      expect(unhandledRejections).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandledRejection);
      compileSpy.mockRestore();
    }
  });
});

describe('lossless JSON numbers', () => {
  it.each([
    '1.0',
    '1e3',
    '0.1',
    '-0',
    '0e999999999999999999999999',
    '-0e-999999999999999999999999',
    '1.2300e2',
    '5e-324',
    '9007199254740991e0',
  ])('accepts the round-trip-safe decimal %s', async (lexicalValue) => {
    const fixture = await createSchemaBoundFixture(
      addNumberValueToSyntheticSchema,
      createLockedSyntheticProfile(),
      serializeSyntheticNumberProfile(lexicalValue)
    );
    const profile = await createPhase1ProfileLoader<SyntheticProfile>(
      fixture.lock,
      createDependencies()
    )(fixture.paths);

    expect(Object.isFrozen(profile)).toBe(true);
  });

  it.each([
    ['1.0000000000000001', 'lossy-number'],
    ['0.10000000000000001', 'lossy-number'],
    ['1e-324', 'lossy-number'],
    ['1e309', 'lossy-number'],
    ['9007199254740992.0', 'unsafe-integer'],
    ['9.007199254740992e15', 'unsafe-integer'],
  ] as const)('rejects the non-round-tripping decimal %s', async (lexicalValue, rule) => {
    const fixture = await createSchemaBoundFixture(
      addNumberValueToSyntheticSchema,
      createLockedSyntheticProfile(),
      serializeSyntheticNumberProfile(lexicalValue)
    );

    await expectValidationFailure(
      createPhase1ProfileLoader<SyntheticProfile>(
        fixture.lock,
        createDependencies()
      )(fixture.paths),
      {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: ['/numberValue'],
        rules: [rule],
        absentText: lexicalValue,
      }
    );
  });

  it('accepts generated safe-integer decimal and exponent equivalents', async () => {
    const values = Array.from({ length: 17 }, (_unused, index) => index - 8);
    await Promise.all(
      values.flatMap((value) =>
        [`${value}.0`, `${value}e0`].map(async (lexicalValue) => {
          const fixture = await createSchemaBoundFixture(
            addNumberValueToSyntheticSchema,
            createLockedSyntheticProfile(),
            serializeSyntheticNumberProfile(lexicalValue)
          );
          await createPhase1ProfileLoader<SyntheticProfile>(
            fixture.lock,
            createDependencies()
          )(fixture.paths);
        })
      )
    );
  });
});

describe('profile input filesystem boundary', () => {
  it('requires absolute distinct paths', async () => {
    const paths = await createFixturePaths();
    const load = loadSynthetic();

    await expectValidationFailure(
      load({ profilePath: 'relative-profile.json', schemaPath: paths.schemaPath }),
      {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: ['/profile'],
        rules: ['absolute-path'],
      }
    );
    await expectValidationFailure(
      load({ profilePath: paths.profilePath, schemaPath: paths.profilePath }),
      {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: ['/'],
        rules: ['distinct-paths'],
      }
    );
  });

  it.each(['profile', 'schema'] as const)(
    'rejects a %s symlink and its real target',
    async (kind) => {
      const paths = await createFixturePaths();
      const targetPath = kind === 'profile' ? paths.profilePath : paths.schemaPath;
      const linkPath = path.join(paths.root, `${kind}-link.json`);
      await symlink(targetPath, linkPath);

      await expectValidationFailure(
        loadSynthetic()({
          profilePath: kind === 'profile' ? linkPath : paths.profilePath,
          schemaPath: kind === 'schema' ? linkPath : paths.schemaPath,
        }),
        {
          message: 'Invalid Phase 1 JSON',
          stage: 'json',
          pointers: [`/${kind}`],
          rules: ['regular-file'],
        }
      );
    }
  );

  it('rejects a path reached through a symlinked parent directory', async () => {
    const paths = await createFixturePaths();
    const aliasPath = path.join(path.dirname(paths.root), `${path.basename(paths.root)}-alias`);
    createdRoots.add(aliasPath);
    await symlink(paths.root, aliasPath, 'dir');

    await expectValidationFailure(
      loadSynthetic()({
        profilePath: path.join(aliasPath, 'profile.json'),
        schemaPath: paths.schemaPath,
      }),
      {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: ['/profile'],
        rules: ['regular-file'],
      }
    );
  });

  it('rejects non-regular inputs', async () => {
    const paths = await createFixturePaths();

    await expectValidationFailure(
      loadSynthetic()({ profilePath: paths.root, schemaPath: paths.schemaPath }),
      {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: ['/profile'],
        rules: ['regular-file'],
      }
    );
  });

  it('detects path identity changes around the bounded read', async () => {
    const paths = await createFixturePaths();
    let profileStateReads = 0;
    const dependencies: Partial<Phase1ProfileLoaderDependencies<SyntheticProfile>> = {
      ...createDependencies(),
      fileSystem: {
        getPathState: async (filePath) => {
          const state = await toInputFileState(filePath);

          if (filePath === paths.profilePath) {
            profileStateReads += 1;

            if (profileStateReads === 3) {
              return { ...state, inode: state.inode + 1 };
            }
          }

          return state;
        },
      },
    };

    await expectValidationFailure(loadSynthetic(dependencies)(paths), {
      message: 'Invalid Phase 1 JSON',
      stage: 'json',
      pointers: ['/profile'],
      rules: ['file-changed'],
    });
  });

  it.each([1, 7])(
    'accepts complete regular-file reads delivered in %i-byte chunks',
    async (chunkSize) => {
      const paths = await createFixturePaths();
      const harness = createChunkedFileSystem(paths.profilePath, { chunkSize });
      const profile = await loadSynthetic({
        ...createDependencies(),
        fileSystem: harness.fileSystem,
      })(paths);

      expect(profile.items[0]?.id).toBe('one');
      expect(harness.closedPaths).toEqual(new Set([paths.schemaPath, paths.profilePath]));

      for (const positions of harness.positionsByPath.values()) {
        expect(positions[0]).toBe(0);
        expect(
          positions.every(
            (position, index) => index === 0 || position > (positions[index - 1] ?? -1)
          )
        ).toBe(true);
      }
    }
  );

  it.each([
    ['zero-progress', 'file-changed'],
    ['shrink', 'file-changed'],
    ['grow', 'file-changed'],
    ['replace', 'file-changed'],
    ['oversized-return', 'file-changed'],
    ['grow-over-limit', 'maximum-bytes'],
  ] as const)('fails closed on a %s read mutation', async (mutation, rule) => {
    const paths = await createFixturePaths();
    const harness = createChunkedFileSystem(paths.profilePath, {
      chunkSize: 13,
      mutation,
    });

    await expectValidationFailure(
      loadSynthetic({
        ...createDependencies(),
        fileSystem: harness.fileSystem,
      })(paths),
      {
        message: 'Invalid Phase 1 JSON',
        stage: 'json',
        pointers: ['/profile'],
        rules: [rule],
      }
    );
    expect(harness.closedPaths).toContain(paths.profilePath);
  });
});

describe('synthetic fixture integrity', () => {
  it('pins the exact committed synthetic schema bytes', async () => {
    const bytes = await readFile(
      path.join(sourceFixtureDirectory, 'synthetic-profile.schema.json')
    );
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(syntheticSchemaSha256);
  });
});

type CompiledProfileModule = Readonly<{
  Phase1ProfileValidationError: typeof Phase1ProfileValidationError;
  loadPhase1Profile: (paths: FixturePaths) => Promise<unknown>;
  phase1SchemaLockDocument: Readonly<{
    schemaSourceCommit: string;
    schemaSha256: string;
  }>;
}>;

const loadIsolatedCompiledProfileModule = async (
  profileEntryPath: string,
  lockChunkPath: string,
  schemaLockDocumentBytes: Uint8Array
): Promise<CompiledProfileModule> => {
  const context = createContext({ Buffer, TextDecoder, URL, process });
  const moduleCache = new Map<string, Promise<VmModule>>();
  const lockChunkUrl = pathToFileURL(lockChunkPath).href;

  const createNamespaceModule = (
    identifier: string,
    namespace: Readonly<Record<string, unknown>>
  ) => {
    const exportNames = Object.keys(namespace);

    return new SyntheticModule(
      exportNames,
      function () {
        for (const exportName of exportNames) {
          this.setExport(exportName, namespace[exportName]);
        }
      },
      { context, identifier }
    );
  };

  const loadModule = async (identifier: string): Promise<VmModule> => {
    const cached = moduleCache.get(identifier);

    if (cached) {
      return cached;
    }

    if (identifier === lockChunkUrl) {
      const lockModule = createNamespaceModule(identifier, {
        phase1ProfileSchemaLock: syntheticSchemaLock,
      });
      const lockModulePromise = Promise.resolve(lockModule);
      moduleCache.set(identifier, lockModulePromise);

      return lockModule;
    }

    if (!identifier.startsWith('file:')) {
      const hostNamespace: Readonly<Record<string, unknown>> = (() => {
        switch (identifier) {
          case 'crypto': {
            return { createHash, timingSafeEqual };
          }
          case 'fs': {
            return {
              constants: fsConstants,
              existsSync,
              readFileSync: (filePath: string | URL) => {
                const normalizedPath = filePath instanceof URL ? fileURLToPath(filePath) : filePath;

                if (path.basename(normalizedPath) !== 'phase-1-schema-lock.json') {
                  throw new Error('Unexpected synchronous read in profile isolation');
                }

                return Buffer.from(schemaLockDocumentBytes);
              },
              realpathSync,
            };
          }
          case 'fs/promises': {
            return { lstat, open: openFile, realpath: realPath };
          }
          case 'path': {
            return { default: path };
          }
          case 'url': {
            return { fileURLToPath };
          }
          default: {
            throw new Error('Unexpected external module in profile isolation');
          }
        }
      })();
      const hostModule = createNamespaceModule(`host:${identifier}`, hostNamespace);
      const hostModulePromise = Promise.resolve(hostModule);
      moduleCache.set(identifier, hostModulePromise);

      return hostModule;
    }

    const source = await readFile(new URL(identifier), 'utf8');
    const sourceModule = new SourceTextModule(source, {
      context,
      identifier,
      initializeImportMeta: (meta) => {
        meta.url = identifier;
      },
    });
    const sourceModulePromise = Promise.resolve(sourceModule);
    moduleCache.set(identifier, sourceModulePromise);
    await sourceModule.link(async (specifier, referencingModule) => {
      const dependencyIdentifier = specifier.startsWith('.')
        ? new URL(specifier, referencingModule.identifier).href
        : specifier.replace(/^node:/u, '');

      return loadModule(dependencyIdentifier);
    });

    return sourceModule;
  };

  const rootModule = await loadModule(pathToFileURL(profileEntryPath).href);
  await rootModule.evaluate();

  // The exact compiled entry is closed and exports the reviewed profile loader surface.
  return rootModule.namespace as unknown as CompiledProfileModule;
};

describe('loadPhase1Profile default wiring', () => {
  it('uses the startup-verified embedded and public locks before rejecting design state', async () => {
    const paths = await createFixturePaths();
    const designProfile = createDesignSyntheticProfile();
    await writeFile(paths.profilePath, `${JSON.stringify(designProfile)}\n`);

    const schema: unknown = JSON.parse(await readFile(paths.schemaPath, 'utf8'));
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormatsModule.default.default(ajv);
    const validate = ajv.compile(schema as AnySchema);
    expect(validate(designProfile)).toBe(true);

    const profileEntryPath = path.resolve(process.cwd(), 'lib/compatibility/phase-1/profile.js');
    const profileLockEntryPath = path.resolve(
      process.cwd(),
      'lib/compatibility/phase-1/profile-lock.js'
    );
    const profileLockEntrySource = await readFile(profileLockEntryPath, 'utf8');
    const lockChunkSpecifier = /from "(?<specifier>\.\.\/\.\.\/chunk-[A-Z0-9]+\.js)"/u.exec(
      profileLockEntrySource
    )?.groups?.specifier;
    expect(lockChunkSpecifier).toBeDefined();
    const lockChunkPath = path.resolve(
      path.dirname(profileLockEntryPath),
      lockChunkSpecifier ?? ''
    );
    const syntheticLockDocumentBytes = Buffer.from(
      JSON.stringify(createSyntheticSchemaLockDocument())
    );
    const freshProfileModule = await loadIsolatedCompiledProfileModule(
      profileEntryPath,
      lockChunkPath,
      syntheticLockDocumentBytes
    );
    expect(freshProfileModule.phase1SchemaLockDocument).toMatchObject({
      schemaSourceCommit: syntheticSchemaSourceCommit,
      schemaSha256: syntheticSchemaSha256,
    });

    try {
      await freshProfileModule.loadPhase1Profile(paths);
      throw new Error('Expected the design-state default loader to reject');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(freshProfileModule.Phase1ProfileValidationError);
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 semantics',
        stage: 'semantic',
        pointers: ['/phase1Harness/commit'],
        rules: ['locked-harness'],
      });
    }
  });
});

/* eslint-enable max-lines, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types */
