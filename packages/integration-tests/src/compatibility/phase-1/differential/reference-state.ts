/* eslint-disable complexity, max-lines, max-params, no-restricted-syntax, no-control-regex, @typescript-eslint/ban-types, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- The reference projector reduces one bounded database fact set into exact scenario-owned semantic contracts; JSON nulls, recursive validation, and prior family facts are part of this external adapter boundary. */
import path from 'node:path';
import { types as nodeTypes, isDeepStrictEqual } from 'node:util';

import { userClaims } from '@logto/core-kit';

import { jsonValueGuard } from '../../model.js';
import type { JsonObject, JsonValue } from '../../normalize.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../clients/command-provisioner.js';
import {
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  type Phase1FixtureAllocationRole,
  type Phase1FixtureSymbolTables,
} from '../fixture-map.js';
import {
  assertPhase1RuntimeCredentialGraphIsSanitized,
  type ProvisionedPhase1Fixture,
} from '../fixtures.js';
import {
  differentialScenarioIdGuard,
  snapshotClosedDataGraph,
  type Phase1DifferentialScenarioId,
} from '../model.js';
import { projectPhase1NativeScopeForComparison } from '../native-surface-profile.js';
import type { Phase1Profile } from '../profile-types.js';
import type {
  Phase1ScenarioStateProjectionInput,
  Phase1TargetRuntime,
} from '../scenario-runtime.js';
import { phase1DifferentialScenarios } from '../scenarios/index.js';

const referenceModelKinds = Object.freeze([
  'interaction',
  'session',
  'grant',
  'one-time',
  'rotation',
] as const);
type ReferenceModelKind = (typeof referenceModelKinds)[number];
export type Phase1ReferencePostgresService =
  | 'oracle-primary-postgres'
  | 'oracle-foreign-postgres'
  | 'candidate-primary-postgres'
  | 'candidate-foreign-postgres';

export type ReferenceStateResource = Readonly<{
  indicator: string;
  scopes: readonly string[];
}>;

export type ReferenceStateModel = Readonly<{
  kind: ReferenceModelKind;
  tenantId: string;
  clientId: string | null;
  accountId: string | null;
  familyFingerprint: string | null;
  artifactFingerprint: string | null;
  consumed: boolean;
  active: boolean;
  rotation: number | null;
  verificationCount: number;
  identified: boolean;
  oidcScopes: readonly string[];
  resources: readonly ReferenceStateResource[];
}>;

export type ReferenceStateDriverSnapshot = Readonly<{
  schemaVersion: 1;
  scenarioId: Phase1DifferentialScenarioId;
  stepId: string;
  models: readonly ReferenceStateModel[];
  extensions: ReadonlyArray<
    Readonly<{
      tenantId: string;
      accountId: string;
      clientId: string | null;
      loginAccountId: string | null;
      updatedAt: number;
    }>
  >;
  users: ReadonlyArray<Readonly<{ tenantId: string; id: string; applicationId: string | null }>>;
  verificationRecords: ReadonlyArray<
    Readonly<{ tenantId: string; userId: string | null; count: number }>
  >;
}>;

export type ReferenceStateDriverRequest = Readonly<{
  source: 'primary' | 'foreign';
  projectName: string;
  expectedService: Phase1ReferencePostgresService;
  containerId: string;
  scenarioId: Phase1DifferentialScenarioId;
  stepId: string;
  signal: AbortSignal;
}>;

type ReferenceStateProcessRunner = (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;

export type ReferenceStateSnapshotReader = (
  request: ReferenceStateDriverRequest
) => Promise<ReferenceStateDriverSnapshot>;

export type ReferenceScenarioStateProjectorOptions = Readonly<{
  profile: Phase1Profile;
  primaryContainerId: string;
  foreignContainerId?: string;
  projectName: string;
  primaryService: Phase1ReferencePostgresService;
  foreignService?: Phase1ReferencePostgresService;
  symbols: Phase1FixtureSymbolTables;
  driverPath?: string;
  environment?: Readonly<Record<string, string | undefined>>;
  runner?: ReferenceStateProcessRunner;
  readSnapshot?: ReferenceStateSnapshotReader;
}>;

export type ReferenceScenarioStateProjector = (
  input: Parameters<Phase1TargetRuntime['projectScenarioState']>[0]
) => Promise<Phase1ScenarioStateProjectionInput>;

const diagnostic = 'Invalid phase 1 reference state';
const containerIdPattern = /^[0-9a-f]{12,64}$/u;
const projectNamePattern = /^aster-phase1-[0-9a-f]{16}$/u;
const postgresServices = new Set<Phase1ReferencePostgresService>([
  'oracle-primary-postgres',
  'oracle-foreign-postgres',
  'candidate-primary-postgres',
  'candidate-foreign-postgres',
]);
const fingerprintPattern = /^[0-9a-f]{64}$/u;
const safeTextPattern = /^[^\u0000-\u001F\u007F]+$/u;
const maximumModels = 512;
const maximumRows = 256;
const maximumOutputBytes = 512 * 1024;
const noMutation = Object.freeze({ unrelatedMutation: false });

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const exactRecord = (
  value: unknown,
  keys: readonly string[]
): Readonly<Record<string, unknown>> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }
  const ownKeys = Reflect.ownKeys(value);

  if (
    ownKeys.length !== keys.length ||
    ownKeys.some((key) => typeof key !== 'string' || !keys.includes(key))
  ) {
    return fail();
  }

  return value as Readonly<Record<string, unknown>>;
};

const own = (value: Readonly<Record<string, unknown>>, key: string): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);

  return descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable
    ? descriptor.value
    : fail();
};

const safeText = (value: unknown): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= 2048 &&
  safeTextPattern.test(value)
    ? value
    : fail();

const nullableText = (value: unknown): string | null => (value === null ? null : safeText(value));

const nonnegativeInteger = (value: unknown): number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : fail();

const nullableNonnegativeInteger = (value: unknown): number | null =>
  value === null ? null : nonnegativeInteger(value);

const booleanValue = (value: unknown): boolean => (typeof value === 'boolean' ? value : fail());

const denseArray = (value: unknown, maximum: number): readonly unknown[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > maximum ||
    Reflect.ownKeys(value).length !== value.length + 1
  ) {
    return fail();
  }

  return value;
};

const stringArray = (value: unknown): readonly string[] => {
  const result = denseArray(value, maximumRows).map((item) => safeText(item));

  return Object.freeze(result);
};

const parseResource = (value: unknown): ReferenceStateResource => {
  const record = exactRecord(value, ['indicator', 'scopes']);

  return Object.freeze({
    indicator: safeText(own(record, 'indicator')),
    scopes: stringArray(own(record, 'scopes')),
  });
};

const parseModel = (value: unknown): ReferenceStateModel => {
  const record = exactRecord(value, [
    'kind',
    'tenantId',
    'clientId',
    'accountId',
    'familyFingerprint',
    'artifactFingerprint',
    'consumed',
    'active',
    'rotation',
    'verificationCount',
    'identified',
    'oidcScopes',
    'resources',
  ]);
  const kind = safeText(own(record, 'kind'));
  const familyFingerprint = nullableText(own(record, 'familyFingerprint'));
  const artifactFingerprint = nullableText(own(record, 'artifactFingerprint'));

  if (
    !referenceModelKinds.includes(kind as ReferenceModelKind) ||
    (familyFingerprint !== null && !fingerprintPattern.test(familyFingerprint)) ||
    (artifactFingerprint !== null && !fingerprintPattern.test(artifactFingerprint))
  ) {
    return fail();
  }

  return Object.freeze({
    kind: kind as ReferenceModelKind,
    tenantId: safeText(own(record, 'tenantId')),
    clientId: nullableText(own(record, 'clientId')),
    accountId: nullableText(own(record, 'accountId')),
    familyFingerprint,
    artifactFingerprint,
    consumed: booleanValue(own(record, 'consumed')),
    active: booleanValue(own(record, 'active')),
    rotation: nullableNonnegativeInteger(own(record, 'rotation')),
    verificationCount: nonnegativeInteger(own(record, 'verificationCount')),
    identified: booleanValue(own(record, 'identified')),
    oidcScopes: stringArray(own(record, 'oidcScopes')),
    resources: Object.freeze(
      denseArray(own(record, 'resources'), maximumRows).map((item) => parseResource(item))
    ),
  });
};

export const parseReferenceStateDriverSnapshot = (value: unknown): ReferenceStateDriverSnapshot => {
  try {
    const snapshot = snapshotClosedDataGraph<Record<string, unknown>>(value);
    const record = exactRecord(snapshot, [
      'schemaVersion',
      'scenarioId',
      'stepId',
      'models',
      'extensions',
      'users',
      'verificationRecords',
    ]);
    const scenarioId = differentialScenarioIdGuard.parse(own(record, 'scenarioId'));
    const stepId = safeText(own(record, 'stepId'));
    const scenario = phase1DifferentialScenarios.find(({ id }) => id === scenarioId);

    if (
      own(record, 'schemaVersion') !== 1 ||
      !scenario?.orderedSteps.some(({ id }) => id === stepId)
    ) {
      return fail();
    }
    const models = Object.freeze(
      denseArray(own(record, 'models'), maximumModels).map((item) => parseModel(item))
    );
    const extensions = Object.freeze(
      denseArray(own(record, 'extensions'), maximumRows).map((candidate) => {
        const item = exactRecord(candidate, [
          'tenantId',
          'accountId',
          'clientId',
          'loginAccountId',
          'updatedAt',
        ]);

        return Object.freeze({
          tenantId: safeText(own(item, 'tenantId')),
          accountId: safeText(own(item, 'accountId')),
          clientId: nullableText(own(item, 'clientId')),
          loginAccountId: nullableText(own(item, 'loginAccountId')),
          updatedAt: nonnegativeInteger(own(item, 'updatedAt')),
        });
      })
    );
    const users = Object.freeze(
      denseArray(own(record, 'users'), maximumRows).map((candidate) => {
        const item = exactRecord(candidate, ['tenantId', 'id', 'applicationId']);

        return Object.freeze({
          tenantId: safeText(own(item, 'tenantId')),
          id: safeText(own(item, 'id')),
          applicationId: nullableText(own(item, 'applicationId')),
        });
      })
    );
    const verificationRecords = Object.freeze(
      denseArray(own(record, 'verificationRecords'), maximumRows).map((candidate) => {
        const item = exactRecord(candidate, ['tenantId', 'userId', 'count']);

        return Object.freeze({
          tenantId: safeText(own(item, 'tenantId')),
          userId: nullableText(own(item, 'userId')),
          count: nonnegativeInteger(own(item, 'count')),
        });
      })
    );
    const result = Object.freeze({
      schemaVersion: 1 as const,
      scenarioId,
      stepId,
      models,
      extensions,
      users,
      verificationRecords,
    });

    assertPhase1RuntimeCredentialGraphIsSanitized(result, []);

    return result;
  } catch {
    return fail();
  }
};

const validateContainerId = (value: string): string =>
  containerIdPattern.test(value) ? value : fail();

export const readReferenceStateDriver = async (
  request: ReferenceStateDriverRequest,
  options: Readonly<{
    driverPath: string;
    environment?: Readonly<Record<string, string | undefined>>;
    runner?: ReferenceStateProcessRunner;
  }>
): Promise<ReferenceStateDriverSnapshot> => {
  try {
    if (
      request.signal.aborted ||
      !path.isAbsolute(options.driverPath) ||
      path.resolve(options.driverPath) !== options.driverPath
    ) {
      return fail();
    }
    const result = await (options.runner ?? runPhase1FixtureCommand)({
      command: options.driverPath,
      args: Object.freeze([
        '--container-id',
        validateContainerId(request.containerId),
        '--project-name',
        projectNamePattern.test(request.projectName) ? request.projectName : fail(),
        '--expected-service',
        postgresServices.has(request.expectedService) ? request.expectedService : fail(),
        '--scenario-id',
        request.scenarioId,
        '--step-id',
        request.stepId,
      ]),
      stdin: '',
      env: Object.freeze({ PATH: options.environment?.PATH ?? '/usr/bin:/bin' }),
      timeoutMs: 20_000,
      maxStdoutBytes: maximumOutputBytes,
      maxStderrBytes: 4096,
      shell: false,
    });

    if (
      result.exitCode !== 0 ||
      result.signal !== null ||
      result.timedOut ||
      result.killed ||
      !result.reaped ||
      result.stderr.length > 0 ||
      Buffer.byteLength(result.stdout, 'utf8') > maximumOutputBytes
    ) {
      return fail();
    }
    const parsed: unknown = JSON.parse(result.stdout);
    const snapshot = parseReferenceStateDriverSnapshot(parsed);

    if (snapshot.scenarioId !== request.scenarioId || snapshot.stepId !== request.stepId) {
      return fail();
    }

    return snapshot;
  } catch {
    return fail();
  }
};

type SourcedSnapshot = Readonly<{
  source: 'primary' | 'foreign';
  snapshot: ReferenceStateDriverSnapshot;
}>;

type ScenarioHistory = {
  familyFingerprint?: string;
  firstAttemptConsumed?: boolean;
  firstExchangeSucceeded?: boolean;
  rotationObserved?: boolean;
};

const historyByFixture = new WeakMap<
  Record<string, unknown>,
  Map<Phase1DifferentialScenarioId, ScenarioHistory>
>();

const scenarioHistory = (
  fixture: ProvisionedPhase1Fixture,
  scenarioId: Phase1DifferentialScenarioId
): ScenarioHistory => {
  const byScenario: Map<Phase1DifferentialScenarioId, ScenarioHistory> =
    historyByFixture.get(fixture as unknown as Record<string, unknown>) ??
    new Map<Phase1DifferentialScenarioId, ScenarioHistory>();
  historyByFixture.set(fixture as unknown as Record<string, unknown>, byScenario);
  const history: ScenarioHistory = byScenario.get(scenarioId) ?? {};
  byScenario.set(scenarioId, history);

  return history;
};

const allocationFor = (fixture: ProvisionedPhase1Fixture, role: Phase1FixtureAllocationRole) => {
  const allocation = fixture.public.allocations.find((candidate) => candidate.role === role);

  return allocation ?? fail();
};

const identityFor = (
  fixture: ProvisionedPhase1Fixture,
  role: Phase1FixtureAllocationRole,
  userLogicalId: string,
  applicationLogicalId: string
) => {
  const allocation = allocationFor(fixture, role);

  return Object.freeze({
    tenantId: allocation.entities.find(({ kind }) => kind === 'tenant')?.runtimeId ?? fail(),
    userId: getPhase1FixtureRuntimeId(
      fixture.public,
      allocation.allocationId,
      'user',
      userLogicalId
    ),
    clientId: getPhase1FixtureRuntimeId(
      fixture.public,
      allocation.allocationId,
      'application',
      applicationLogicalId
    ),
    allocationId: allocation.allocationId,
  });
};

const dataIdentity = (
  profile: Pick<Phase1Profile, 'fixtures'>,
  fixture: ProvisionedPhase1Fixture
) => {
  const application = profile.fixtures.dataTenant.applications.find(({ isThirdParty }) =>
    Boolean(isThirdParty)
  );

  return identityFor(
    fixture,
    'data',
    profile.fixtures.dataTenant.subject.id,
    application?.id ?? fail()
  );
};

const adminIdentity = (
  profile: Pick<Phase1Profile, 'fixtures'>,
  fixture: ProvisionedPhase1Fixture
) =>
  identityFor(
    fixture,
    'admin',
    profile.fixtures.adminTenant.operator.id,
    profile.fixtures.adminTenant.application.id
  );

const matchingModels = (
  sourced: readonly SourcedSnapshot[],
  source: 'primary' | 'foreign',
  identity: Readonly<{ tenantId: string; userId: string; clientId: string }>
) =>
  sourced
    .filter((entry) => entry.source === source)
    .flatMap(({ snapshot }) => snapshot.models)
    .filter(
      ({ tenantId, accountId, clientId, kind }) =>
        tenantId === identity.tenantId &&
        clientId === identity.clientId &&
        (accountId === identity.userId || (kind === 'interaction' && accountId === null))
    );

const familyFacts = (models: readonly ReferenceStateModel[]) => {
  const grants = models.filter(({ kind }) => kind === 'grant');
  const oneTimes = models.filter(({ kind }) => kind === 'one-time');
  const rotations = models.filter(({ kind }) => kind === 'rotation');
  const familyFingerprints = new Set(
    rotations.flatMap(({ familyFingerprint }) => (familyFingerprint ? [familyFingerprint] : []))
  );
  const replacements = rotations.filter(({ rotation }) => rotation === 1);

  return Object.freeze({
    grants,
    oneTimes,
    rotations,
    replacements,
    familyFingerprints,
    consumedOneTime: oneTimes.some(({ consumed }) => consumed),
    activeRotations: rotations.filter(({ active, consumed }) => active && !consumed),
  });
};

const commonState = (
  persistedState: JsonValue = noMutation,
  semanticState: JsonValue = noMutation,
  sideEffects: JsonValue = noMutation,
  generatedIds: JsonValue = Object.freeze({})
): Phase1ScenarioStateProjectionInput =>
  Object.freeze({
    body: Object.freeze({ observed: true }),
    semanticState,
    persistedState,
    generatedIds,
    sideEffects,
  });

const logicalFamily = (
  fingerprint: string | undefined,
  allocationId: string,
  symbols: Phase1FixtureSymbolTables
): string => {
  const table = symbols.get(allocationId);

  if (!fingerprint || !table) {
    return fail();
  }

  return `<${table.bindOccurrence('token-family', fingerprint)}>`;
};

const interactionId = (
  models: readonly ReferenceStateModel[],
  allocationId: string,
  symbols: Phase1FixtureSymbolTables
): string => {
  const fingerprints = models
    .filter(({ kind, active }) => kind === 'interaction' && active)
    .flatMap(({ artifactFingerprint }) => (artifactFingerprint ? [artifactFingerprint] : []));
  const table = symbols.get(allocationId);
  const [fingerprint] = fingerprints;

  if (fingerprints.length !== 1 || !fingerprint || !table) {
    return fail();
  }

  return `<${table.bindOccurrence('interaction', fingerprint)}>`;
};

const assertJson = (value: unknown): JsonValue =>
  jsonValueGuard.safeParse(value).success ? (value as JsonValue) : fail();

const projectAuthorizationConsentState = (
  options: ReferenceScenarioStateProjectorOptions,
  fixture: ProvisionedPhase1Fixture,
  sourced: readonly SourcedSnapshot[],
  stepId: string
): Phase1ScenarioStateProjectionInput => {
  const identity = dataIdentity(options.profile, fixture);
  const models = matchingModels(sourced, 'primary', identity);

  if (stepId !== 'state') {
    return commonState(
      { unrelatedMutation: false },
      { unrelatedMutation: false },
      { unrelatedMutation: false },
      stepId === 'authorize'
        ? { interaction: interactionId(models, identity.allocationId, options.symbols) }
        : {}
    );
  }
  const grant = models.filter(({ kind }) => kind === 'grant');
  const extensions = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.extensions)
    .filter(
      ({ tenantId, accountId, clientId }) =>
        tenantId === identity.tenantId &&
        accountId === identity.userId &&
        clientId === identity.clientId
    );
  const user = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.users)
    .find(({ tenantId, id }) => tenantId === identity.tenantId && id === identity.userId);
  const application = options.profile.fixtures.dataTenant.applications.find(
    ({ id }) =>
      id ===
      options.profile.fixtures.dataTenant.applications.find(({ isThirdParty }) => isThirdParty)?.id
  );
  const [grantRow] = grant;
  const [extension] = extensions;
  const [resource] = grantRow?.resources ?? [];
  const scope = options.profile.fixtures.dataTenant.resource.scopes[0];
  const expectedResourceIndicator = getPhase1FixtureRuntimeResourceIndicator(
    options.profile.fixtures.dataTenant.resource.indicator,
    identity.allocationId
  );
  const expectedResourceScope = scope
    ? getPhase1FixtureRuntimeText(scope.name, identity.allocationId)
    : fail();

  if (
    !grantRow ||
    grant.length !== 1 ||
    !extension ||
    extensions.length !== 1 ||
    !user ||
    !application?.isThirdParty ||
    !resource ||
    user.applicationId !== identity.clientId ||
    extension.loginAccountId !== identity.userId ||
    !isDeepStrictEqual(grantRow.oidcScopes, application.userConsentScopes) ||
    grantRow.resources.length !== 1 ||
    resource.indicator !== expectedResourceIndicator ||
    !isDeepStrictEqual(resource.scopes, [expectedResourceScope])
  ) {
    return fail();
  }

  return commonState(
    assertJson({
      grant: {
        applicationId: identity.clientId,
        userId: identity.userId,
        oidcScopes: [...grantRow.oidcScopes],
        resource: resource.indicator,
        resourceScopes: [...resource.scopes],
      },
      userFirstConsentedApplicationId: user.applicationId,
      sessionExtension: {
        accountId: identity.userId,
        clientId: identity.clientId,
        lastSubmission: { login: { accountId: extension.loginAccountId } },
      },
    }),
    {
      session: {
        accountId: identity.userId,
        clientId: identity.clientId,
        updatedAt: extension.updatedAt,
      },
    },
    { consentPersisted: true }
  );
};

const projectNoProtocolState = (
  models: readonly ReferenceStateModel[]
): Phase1ScenarioStateProjectionInput => {
  const facts = familyFacts(models);
  const interactionCount = models.filter(({ kind }) => kind === 'interaction').length;

  if (
    interactionCount !== 0 ||
    facts.grants.length > 0 ||
    facts.oneTimes.length > 0 ||
    facts.rotations.length > 0
  ) {
    return fail();
  }

  return commonState(
    { interactionCount: 0, grantCount: 0, familyCount: 0, unrelatedMutation: false },
    { unrelatedMutation: false }
  );
};

const projectPasswordRejectedState = (
  sourced: readonly SourcedSnapshot[],
  identity: ReturnType<typeof dataIdentity>
): Phase1ScenarioStateProjectionInput => {
  const models = matchingModels(sourced, 'primary', identity);
  const interactions = models.filter(({ kind }) => kind === 'interaction');
  const facts = familyFacts(models);
  const extensionCount = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.extensions)
    .filter(
      ({ tenantId, accountId, clientId }) =>
        tenantId === identity.tenantId &&
        accountId === identity.userId &&
        clientId === identity.clientId
    ).length;
  const verificationCount = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.verificationRecords)
    .filter(({ tenantId, userId }) => tenantId === identity.tenantId && userId === identity.userId)
    .reduce((total, { count }) => total + count, 0);

  if (
    interactions.length !== 1 ||
    interactions[0]?.verificationCount !== 0 ||
    interactions[0]?.identified ||
    verificationCount !== 0 ||
    facts.grants.length > 0 ||
    facts.oneTimes.length > 0 ||
    facts.rotations.length > 0 ||
    extensionCount > 0
  ) {
    return fail();
  }

  return commonState(
    {
      verificationRecords: 0,
      identifiedUsers: 0,
      grants: 0,
      issuances: 0,
      sessionExtensions: extensionCount,
    },
    { interactionStatus: 'present' },
    { authenticationState: 'unchanged' }
  );
};

const tokenFamilyState = (
  options: ReferenceScenarioStateProjectorOptions,
  fixture: ProvisionedPhase1Fixture,
  models: readonly ReferenceStateModel[],
  persistedState: JsonObject,
  final: boolean,
  sideEffects: JsonObject = noMutation
): Phase1ScenarioStateProjectionInput => {
  const identity = dataIdentity(options.profile, fixture);
  const facts = familyFacts(models);
  const history = scenarioHistory(fixture, 'token.authorization-code');
  const fingerprint = [...facts.familyFingerprints][0];

  if (fingerprint) {
    history.familyFingerprint = fingerprint;
  }

  return commonState(
    persistedState,
    { unrelatedMutation: false },
    sideEffects,
    final
      ? {
          tokenFamily: logicalFamily(fingerprint, identity.allocationId, options.symbols),
        }
      : {}
  );
};

const projectConsentBoundaryState = (
  options: ReferenceScenarioStateProjectorOptions,
  fixture: ProvisionedPhase1Fixture,
  sourced: readonly SourcedSnapshot[],
  stepId: string
): Phase1ScenarioStateProjectionInput => {
  const thirdParty = options.profile.fixtures.dataTenant.applications.find(({ isThirdParty }) =>
    Boolean(isThirdParty)
  );
  const primaryA = identityFor(
    fixture,
    'data',
    options.profile.fixtures.dataTenant.subject.id,
    thirdParty?.id ?? fail()
  );
  const primaryB = identityFor(
    fixture,
    'data',
    'consent.primary.user-b',
    'consent.primary.client-b'
  );
  const foreign = identityFor(
    fixture,
    'foreign',
    'consent.foreign.user-b',
    'consent.foreign.client-b'
  );
  const factsFor = (source: 'primary' | 'foreign', identity: typeof primaryA) => {
    const models = matchingModels(sourced, source, identity);
    const snapshot = sourced.find((entry) => entry.source === source)?.snapshot ?? fail();

    return Object.freeze({
      interaction: models.some(({ kind, active }) => kind === 'interaction' && active),
      principal: snapshot.users.some(
        ({ tenantId, id }) => tenantId === identity.tenantId && id === identity.userId
      ),
      grants: models.filter(({ kind }) => kind === 'grant').length,
      issuances: models.filter(({ kind }) => kind === 'one-time').length,
      sessionExtensions: snapshot.extensions.filter(
        ({ tenantId, accountId, clientId }) =>
          tenantId === identity.tenantId &&
          accountId === identity.userId &&
          clientId === identity.clientId
      ).length,
      firstConsentBindings: snapshot.users.filter(
        ({ tenantId, id, applicationId }) =>
          tenantId === identity.tenantId &&
          id === identity.userId &&
          applicationId === identity.clientId
      ).length,
    });
  };
  const aFacts = factsFor('primary', primaryA);
  const bFacts = factsFor('primary', primaryB);
  const foreignFacts = factsFor('foreign', foreign);
  const expectedB = stepId === 'post-valid-b' || stepId === 'state' ? 1 : 0;
  const expectedBIssuance = stepId === 'state' ? 1 : 0;

  if (
    !aFacts.principal ||
    !bFacts.principal ||
    !foreignFacts.principal ||
    aFacts.interaction ||
    !foreignFacts.interaction ||
    aFacts.grants !== 1 ||
    aFacts.issuances !== 1 ||
    aFacts.sessionExtensions !== 1 ||
    aFacts.firstConsentBindings !== 1 ||
    bFacts.grants !== expectedB ||
    bFacts.issuances !== expectedBIssuance ||
    bFacts.sessionExtensions !== expectedB ||
    bFacts.firstConsentBindings !== expectedB ||
    foreignFacts.grants !== 0 ||
    foreignFacts.issuances !== 0 ||
    foreignFacts.sessionExtensions !== 0 ||
    foreignFacts.firstConsentBindings !== 0 ||
    bFacts.interaction !== (stepId !== 'state')
  ) {
    return fail();
  }

  return commonState(
    {
      a: {
        grants: aFacts.grants,
        issuances: aFacts.issuances,
        sessionExtensions: aFacts.sessionExtensions,
        firstConsentBindings: aFacts.firstConsentBindings,
      },
      b: {
        grants: bFacts.grants,
        issuances: bFacts.issuances,
        sessionExtensions: bFacts.sessionExtensions,
        firstConsentBindings: bFacts.firstConsentBindings,
      },
      foreign: {
        grants: foreignFacts.grants,
        issuances: foreignFacts.issuances,
        sessionExtensions: foreignFacts.sessionExtensions,
        firstConsentBindings: foreignFacts.firstConsentBindings,
      },
    },
    {
      interactions: {
        a: 'missing',
        b: bFacts.interaction ? 'present' : 'missing',
        foreign: 'present',
      },
      principals: { a: 'active', b: 'active', foreign: 'active' },
    },
    {
      grantDelta: bFacts.grants,
      issuanceDelta: bFacts.issuances,
      sessionExtensionDelta: bFacts.sessionExtensions,
      firstConsentBindingDelta: bFacts.firstConsentBindings,
    }
  );
};

const sortedStrings = (values: readonly string[]) => [...values].sort();

const sortedResources = (resources: readonly ReferenceStateResource[]) =>
  resources
    .map(({ indicator, scopes }) => ({ indicator, scopes: sortedStrings(scopes) }))
    .sort((left, right) =>
      left.indicator === right.indicator ? 0 : left.indicator < right.indicator ? -1 : 1
    );

const userClaimScopeNames = new Set(Object.keys(userClaims));

const isUserClaimScope = (profile: Readonly<Phase1Profile>, scope: string): boolean =>
  userClaimScopeNames.has(projectPhase1NativeScopeForComparison(profile, scope));

const expectedAdminGrantOidcScopes = (profile: Readonly<Phase1Profile>): readonly string[] =>
  profile.consoleAuthentication.effectiveScopes.filter((scope) => isUserClaimScope(profile, scope));

const expectedAdminGrantResources = (
  profile: Readonly<Phase1Profile>
): readonly ReferenceStateResource[] => {
  const effectiveScopeNames = new Set(profile.consoleAuthentication.effectiveScopes);

  return profile.consoleAuthentication.effectiveResources
    .map((indicator) => {
      const configured = profile.fixtures.adminTenant.resources.find(
        (resource) => resource.indicator === indicator
      );

      if (!configured) {
        return fail();
      }

      return Object.freeze({
        indicator,
        scopes: Object.freeze(
          configured.scopes.filter(
            (scope) => effectiveScopeNames.has(scope) && !isUserClaimScope(profile, scope)
          )
        ),
      });
    })
    .filter(({ scopes }) => scopes.length > 0);
};

const adminAutoConsentTopology = (
  scenarioId: Phase1DifferentialScenarioId,
  stepId: string
): 'code-token' | 'refreshed' => {
  if (scenarioId === 'console.admin-auth-resource-refresh') {
    if (stepId === 'code-token') {
      return 'code-token';
    }
    if (stepId === 'management-refresh' || stepId === 'state') {
      return 'refreshed';
    }
  }
  if (
    scenarioId === 'console.admin-organization-token-refresh' &&
    (stepId === 'organization-refresh' || stepId === 'state')
  ) {
    return 'refreshed';
  }

  return fail();
};

const assertAdminPreConsentState = (
  options: ReferenceScenarioStateProjectorOptions,
  fixture: ProvisionedPhase1Fixture,
  sourced: readonly SourcedSnapshot[],
  models: readonly ReferenceStateModel[]
): void => {
  const identity = adminIdentity(options.profile, fixture);
  const interactions = models.filter(({ kind }) => kind === 'interaction');
  const [interaction] = interactions;
  const extensions = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.extensions)
    .filter(
      ({ tenantId, accountId, clientId }) =>
        tenantId === identity.tenantId &&
        accountId === identity.userId &&
        clientId === identity.clientId
    );
  const users = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.users)
    .filter(({ tenantId, id }) => tenantId === identity.tenantId && id === identity.userId);
  const verificationCount = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.verificationRecords)
    .filter(({ tenantId, userId }) => tenantId === identity.tenantId && userId === identity.userId)
    .reduce((total, record) => total + record.count, 0);

  if (
    interactions.length !== 1 ||
    !interaction?.active ||
    interaction.accountId !== null ||
    interaction.identified ||
    interaction.verificationCount !== 0 ||
    models.some(({ kind }) => kind !== 'interaction') ||
    extensions.length > 0 ||
    users.length !== 1 ||
    users[0]?.applicationId !== null ||
    verificationCount !== 0
  ) {
    return fail();
  }
};

const assertAdminAutoConsentState = (
  options: ReferenceScenarioStateProjectorOptions,
  fixture: ProvisionedPhase1Fixture,
  sourced: readonly SourcedSnapshot[],
  models: readonly ReferenceStateModel[],
  scenarioId: Phase1DifferentialScenarioId,
  stepId: string
): void => {
  const identity = adminIdentity(options.profile, fixture);
  const topology = adminAutoConsentTopology(scenarioId, stepId);
  const grants = models.filter(({ kind }) => kind === 'grant');
  const sessions = models.filter(({ kind }) => kind === 'session');
  const oneTimes = models.filter(({ kind }) => kind === 'one-time');
  const rotations = models.filter(({ kind }) => kind === 'rotation');
  const interactions = models.filter(({ kind }) => kind === 'interaction');
  const [grant] = grants;
  const [session] = sessions;
  const [oneTime] = oneTimes;
  const initialRotations = rotations.filter(({ rotation }) => rotation === 0);
  const replacementRotations = rotations.filter(({ rotation }) => rotation === 1);
  const [initialRotation] = initialRotations;
  const [replacementRotation] = replacementRotations;
  const expectedOidcScopes = expectedAdminGrantOidcScopes(options.profile);
  const expectedResources = expectedAdminGrantResources(options.profile);
  const extensions = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.extensions)
    .filter(
      ({ tenantId, accountId, clientId }) =>
        tenantId === identity.tenantId &&
        accountId === identity.userId &&
        clientId === identity.clientId
    );
  const users = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.users)
    .filter(({ tenantId, id }) => tenantId === identity.tenantId && id === identity.userId);
  const verificationCount = sourced
    .filter(({ source }) => source === 'primary')
    .flatMap(({ snapshot }) => snapshot.verificationRecords)
    .filter(({ tenantId, userId }) => tenantId === identity.tenantId && userId === identity.userId)
    .reduce((total, record) => total + record.count, 0);
  const familyFingerprint = grant?.familyFingerprint;
  const commonTopologyValid =
    grants.length === 1 &&
    grant?.active === true &&
    !grant.consumed &&
    grant.rotation === null &&
    typeof familyFingerprint === 'string' &&
    sessions.length === 1 &&
    session?.active === true &&
    !session.consumed &&
    session.rotation === null &&
    session.familyFingerprint === familyFingerprint &&
    oneTimes.length === 1 &&
    oneTime?.active === true &&
    oneTime.consumed &&
    oneTime.rotation === null &&
    oneTime.familyFingerprint === familyFingerprint &&
    interactions.length === 0 &&
    models.every(({ verificationCount }) => verificationCount === 0) &&
    verificationCount === 0;
  const rotationTopologyValid =
    topology === 'code-token'
      ? models.length === 4 &&
        rotations.length === 1 &&
        initialRotations.length === 1 &&
        initialRotation?.active === true &&
        !initialRotation.consumed &&
        initialRotation.familyFingerprint === familyFingerprint
      : models.length === 5 &&
        rotations.length === 2 &&
        initialRotations.length === 1 &&
        initialRotation?.active === true &&
        initialRotation.consumed &&
        initialRotation.familyFingerprint === familyFingerprint &&
        replacementRotations.length === 1 &&
        replacementRotation?.active === true &&
        !replacementRotation.consumed &&
        replacementRotation.familyFingerprint === familyFingerprint;
  const grantProjectionValid =
    grant !== undefined &&
    isDeepStrictEqual(sortedStrings(grant.oidcScopes), sortedStrings(expectedOidcScopes)) &&
    isDeepStrictEqual(sortedResources(grant.resources), sortedResources(expectedResources));

  if (
    !commonTopologyValid ||
    !rotationTopologyValid ||
    !grantProjectionValid ||
    extensions.length !== 1 ||
    extensions[0]?.loginAccountId !== identity.userId ||
    users.length !== 1 ||
    users[0]?.applicationId !== identity.clientId
  ) {
    return fail();
  }
};

const projectScenarioState = (
  options: ReferenceScenarioStateProjectorOptions,
  input: Parameters<Phase1TargetRuntime['projectScenarioState']>[0],
  sourced: readonly SourcedSnapshot[]
): Phase1ScenarioStateProjectionInput => {
  const { scenarioId, stepId, fixture } = input;
  const data = fixture.public.allocations.some(({ role }) => role === 'data')
    ? dataIdentity(options.profile, fixture)
    : undefined;
  const admin = fixture.public.allocations.some(({ role }) => role === 'admin')
    ? adminIdentity(options.profile, fixture)
    : undefined;
  const dataModels = data ? matchingModels(sourced, 'primary', data) : [];
  const adminModels = admin ? matchingModels(sourced, 'primary', admin) : [];
  const history = scenarioHistory(fixture, scenarioId);

  switch (scenarioId) {
    case 'authorization.password-pkce-consent': {
      return projectAuthorizationConsentState(options, fixture, sourced, stepId);
    }
    case 'token.authorization-code': {
      const facts = familyFacts(dataModels);
      const fingerprint = [...facts.familyFingerprints][0];
      if (fingerprint) {
        history.familyFingerprint = fingerprint;
      }
      return tokenFamilyState(
        options,
        fixture,
        dataModels,
        {
          grantConsumed: facts.consumedOneTime,
          familyCount: facts.familyFingerprints.size,
          unrelatedMutation: false,
        },
        stepId === 'state'
      );
    }
    case 'token.refresh-rotation': {
      const facts = familyFacts(dataModels);
      const fingerprint = [...facts.familyFingerprints][0];
      if (fingerprint) {
        history.familyFingerprint = fingerprint;
      }
      const replaced =
        facts.rotations.some(({ consumed, rotation }) => consumed && rotation === 0) &&
        facts.replacements.length === 1;
      return commonState(
        stepId === 'family-state'
          ? {
              rotation: {
                replaced,
                sameFamily:
                  facts.rotations.every(
                    ({ familyFingerprint }) => familyFingerprint === fingerprint
                  ) && Boolean(fingerprint),
              },
              unrelatedMutation: false,
            }
          : { unrelatedMutation: false },
        { unrelatedMutation: false },
        { unrelatedMutation: false },
        stepId === 'family-state'
          ? {
              tokenFamily: logicalFamily(
                fingerprint ?? history.familyFingerprint,
                data?.allocationId ?? fail(),
                options.symbols
              ),
            }
          : {}
      );
    }
    case 'userinfo.openid':
    case 'management.application-read':
    case 'management.user-read':
    case 'account.admin-operator-read':
    case 'cors.management-list':
    case 'token.issuer-audience-scope-rejected': {
      return commonState();
    }
    case 'console.admin-auth-resource-refresh':
    case 'console.admin-organization-token-refresh': {
      if (scenarioId === 'console.admin-auth-resource-refresh' && stepId === 'authorize') {
        assertAdminPreConsentState(options, fixture, sourced, adminModels);
      } else {
        assertAdminAutoConsentState(options, fixture, sourced, adminModels, scenarioId, stepId);
      }
      const facts = familyFacts(adminModels);
      const fingerprint = [...facts.familyFingerprints][0];
      if (fingerprint) {
        history.familyFingerprint = fingerprint;
      }
      if (stepId !== 'state') {
        return commonState(
          { unrelatedMutation: false },
          { unrelatedMutation: false },
          { unrelatedMutation: false },
          stepId === 'authorize'
            ? {
                interaction: interactionId(
                  adminModels,
                  admin?.allocationId ?? fail(),
                  options.symbols
                ),
              }
            : {}
        );
      }
      const predecessorConsumed = facts.rotations.some(
        ({ rotation, consumed }) => rotation === 0 && consumed
      );
      const replaced = predecessorConsumed && facts.replacements.length === 1;
      const sameFamily =
        facts.familyFingerprints.size === 1 &&
        facts.rotations.length > 1 &&
        facts.rotations.every(({ familyFingerprint }) => familyFingerprint === fingerprint);

      if (
        !facts.consumedOneTime ||
        !fingerprint ||
        !replaced ||
        !sameFamily ||
        facts.activeRotations.length !== 1
      ) {
        return fail();
      }
      const persistedState: JsonObject =
        scenarioId === 'console.admin-organization-token-refresh'
          ? {
              grantConsumed: facts.consumedOneTime,
              familyCount: facts.familyFingerprints.size,
              rotation: { replaced, sameFamily },
              tenantMutation: false,
              membershipMutation: false,
              roleMutation: false,
              consentMutation: false,
            }
          : {
              grantConsumed: facts.consumedOneTime,
              familyCount: facts.familyFingerprints.size,
              rotation: { replaced, sameFamily },
              unrelatedMutation: false,
            };
      return commonState(
        persistedState,
        { unrelatedMutation: false },
        { unrelatedMutation: false },
        {
          tokenFamily: logicalFamily(fingerprint, admin?.allocationId ?? fail(), options.symbols),
        }
      );
    }
    case 'cookie.localhost-port-interleaving': {
      const adminInteractions = adminModels.filter(
        ({ kind, active }) => kind === 'interaction' && active
      ).length;
      const dataInteractions = dataModels.filter(
        ({ kind, active }) => kind === 'interaction' && active
      ).length;
      return commonState(
        { crossTenantMutation: false },
        { adminInteractionCount: adminInteractions, dataInteractionCount: dataInteractions },
        { crossTenantMutation: false }
      );
    }
    case 'authorization.redirect-uri-rejected':
    case 'authorization.pkce-method-rejected': {
      return projectNoProtocolState(dataModels);
    }
    case 'token.pkce-verifier-rejected': {
      const facts = familyFacts(dataModels);
      const fingerprint = [...facts.familyFingerprints][0];
      if (fingerprint) {
        history.familyFingerprint = fingerprint;
      }
      if (stepId === 'bad-verifier') {
        if (
          facts.oneTimes.length !== 1 ||
          facts.consumedOneTime ||
          facts.grants.length !== 1 ||
          facts.rotations.length > 0
        ) {
          return fail();
        }
        history.firstAttemptConsumed = false;
      } else if (
        history.firstAttemptConsumed !== false ||
        facts.oneTimes.length !== 1 ||
        !facts.consumedOneTime ||
        facts.grants.length !== 1 ||
        facts.familyFingerprints.size !== 1 ||
        facts.activeRotations.length !== 1
      ) {
        return fail();
      }
      const firstAttemptConsumed = history.firstAttemptConsumed ?? fail();
      const persistedState: JsonValue =
        stepId === 'bad-verifier'
          ? assertJson({
              firstAttemptConsumed,
              grantConsumed: facts.consumedOneTime,
              familyCount: facts.familyFingerprints.size,
              unrelatedMutation: false,
            })
          : stepId === 'valid-verifier-probe'
            ? assertJson({
                firstAttemptConsumed,
                grantConsumed: facts.consumedOneTime,
                familyCount: facts.familyFingerprints.size,
                unrelatedMutation: false,
              })
            : assertJson({
                firstAttemptConsumed,
                validProbeSucceeded: facts.consumedOneTime,
                grantConsumed: facts.consumedOneTime,
                familyCount: facts.familyFingerprints.size,
                unrelatedMutation: false,
              });
      return commonState(
        persistedState,
        { unrelatedMutation: false },
        { unrelatedMutation: false },
        stepId === 'state'
          ? {
              tokenFamily: logicalFamily(
                fingerprint ?? history.familyFingerprint,
                data?.allocationId ?? fail(),
                options.symbols
              ),
            }
          : {}
      );
    }
    case 'token.code-reuse-rejected': {
      const facts = familyFacts(dataModels);
      const fingerprint = [...facts.familyFingerprints][0];
      if (stepId === 'first-exchange') {
        if (!facts.consumedOneTime || facts.familyFingerprints.size !== 1) {
          return fail();
        }
        history.firstExchangeSucceeded = true;
        history.familyFingerprint = fingerprint;
        return commonState({
          firstExchangeSucceeded: true,
          grantConsumed: true,
          familyCount: 1,
          unrelatedMutation: false,
        });
      }
      if (!history.firstExchangeSucceeded || facts.grants.length > 0 || facts.oneTimes.length > 0) {
        return fail();
      }
      return commonState(
        {
          firstExchangeSucceeded: true,
          replayRejected: true,
          grantPresent: false,
          familyCount: 0,
          unrelatedMutation: false,
        },
        { unrelatedMutation: false },
        { grantRevoked: true, unrelatedMutation: false },
        stepId === 'state'
          ? {
              tokenFamily: logicalFamily(
                history.familyFingerprint,
                data?.allocationId ?? fail(),
                options.symbols
              ),
            }
          : {}
      );
    }
    case 'interaction.password-rejected': {
      return projectPasswordRejectedState(sourced, data ?? fail());
    }
    case 'interaction.consent-session-boundary': {
      return projectConsentBoundaryState(options, fixture, sourced, stepId);
    }
    case 'token.refresh-reuse-rejected': {
      const facts = familyFacts(dataModels);
      const fingerprint = [...facts.familyFingerprints][0];
      if (fingerprint) {
        history.familyFingerprint = fingerprint;
      }
      if (stepId === 'code-token') {
        return commonState({
          rotationCount: 0,
          predecessorConsumed: false,
          reuseDetected: false,
          familyRevoked: false,
          activeDescendantCount: facts.activeRotations.length,
          unrelatedMutation: false,
        });
      }
      if (stepId === 'rotate') {
        history.rotationObserved = facts.replacements.length === 1;
        return commonState({
          rotationCount: 1,
          predecessorConsumed: facts.rotations.some(
            ({ rotation, consumed }) => rotation === 0 && consumed
          ),
          reuseDetected: false,
          familyRevoked: false,
          activeDescendantCount: facts.activeRotations.length,
          unrelatedMutation: false,
        });
      }
      if (!history.rotationObserved || facts.grants.length > 0 || facts.rotations.length > 0) {
        return fail();
      }
      const persistedState = {
        rotationCount: 1,
        predecessorConsumed: true,
        reuseDetected: true,
        ...(stepId === 'probe-descendant' || stepId === 'state'
          ? { descendantProbeRejected: true }
          : {}),
        familyRevoked: true,
        activeDescendantCount: 0,
        unrelatedMutation: false,
      };
      return commonState(
        persistedState,
        { unrelatedMutation: false },
        { grantRevoked: true, unrelatedMutation: false },
        stepId === 'state'
          ? {
              tokenFamily: logicalFamily(
                history.familyFingerprint,
                data?.allocationId ?? fail(),
                options.symbols
              ),
            }
          : {}
      );
    }
    case 'token.concurrent-code-single-winner': {
      const facts = familyFacts(dataModels);
      const fingerprint = [...facts.familyFingerprints][0];
      const refreshFingerprints = new Set(
        facts.activeRotations.flatMap(({ artifactFingerprint }) =>
          artifactFingerprint ? [artifactFingerprint] : []
        )
      );
      const sameGrantFamily =
        Boolean(fingerprint) &&
        facts.familyFingerprints.size === 1 &&
        facts.rotations.every(({ familyFingerprint }) => familyFingerprint === fingerprint);
      const doubleSuccess =
        facts.oneTimes.length === 1 &&
        facts.consumedOneTime &&
        facts.grants.length === 1 &&
        facts.activeRotations.length === 2 &&
        refreshFingerprints.size === 2 &&
        sameGrantFamily;
      const revoked =
        facts.grants.length === 0 &&
        facts.oneTimes.length === 0 &&
        facts.familyFingerprints.size === 0;

      if (!doubleSuccess && !revoked) {
        return fail();
      }
      return commonState(
        doubleSuccess
          ? {
              authorizationCodePresent: true,
              authorizationCodeConsumed: true,
              grantPresent: true,
              familyCount: facts.familyFingerprints.size,
              activeRefreshDescendantCount: facts.activeRotations.length,
              unrelatedMutation: false,
            }
          : {
              authorizationCodePresent: false,
              grantPresent: false,
              familyCount: 0,
              activeRefreshDescendantCount: 0,
              ...(facts.rotations.length > 0
                ? { danglingRefreshDescendantCount: facts.rotations.length }
                : {}),
              unrelatedMutation: false,
            },
        { unrelatedMutation: false },
        doubleSuccess
          ? { sameGrantFamily, grantRevoked: false, unrelatedMutation: false }
          : { grantRevoked: true, unrelatedMutation: false }
      );
    }
    case 'token.concurrent-refresh-single-winner': {
      const facts = familyFacts(dataModels);
      const fingerprint = [...facts.familyFingerprints][0];
      if (fingerprint) {
        history.familyFingerprint = fingerprint;
      }
      const ordinals = facts.replacements
        .map(({ rotation }) => rotation ?? fail())
        .toSorted((left, right) => left - right);
      const distinct = new Set(
        facts.replacements.flatMap(({ artifactFingerprint }) =>
          artifactFingerprint ? [artifactFingerprint] : []
        )
      ).size;
      const persistedState = {
        presentationSuccessCount: facts.replacements.length,
        predecessorConsumed: facts.rotations.some(
          ({ rotation, consumed }) => rotation === 0 && consumed
        ),
        replacementRefreshCount: facts.replacements.length,
        distinctReplacementCount: distinct,
        activeDescendantCount: facts.activeRotations.length,
        replacementRotationOrdinals: ordinals,
        familyCount: facts.familyFingerprints.size,
        unrelatedMutation: false,
      };

      return commonState(
        persistedState,
        { unrelatedMutation: false },
        {
          sameGrantFamily:
            facts.rotations.every(({ familyFingerprint }) => familyFingerprint === fingerprint) &&
            Boolean(fingerprint),
          siblingDescendantsCreated: facts.replacements.length === 2 && distinct === 2,
          unrelatedMutation: false,
        },
        stepId === 'state'
          ? {
              tokenFamily: logicalFamily(
                fingerprint ?? history.familyFingerprint,
                data?.allocationId ?? fail(),
                options.symbols
              ),
            }
          : {}
      );
    }
    default: {
      return commonState();
    }
  }
};

export const createReferenceScenarioStateProjector = (
  options: ReferenceScenarioStateProjectorOptions
): ReferenceScenarioStateProjector => {
  const primaryContainerId = validateContainerId(options.primaryContainerId);
  const projectName = projectNamePattern.test(options.projectName) ? options.projectName : fail();
  const primaryService = postgresServices.has(options.primaryService)
    ? options.primaryService
    : fail();
  const foreignContainerId = options.foreignContainerId
    ? validateContainerId(options.foreignContainerId)
    : undefined;
  const { foreignService } = options;

  if (
    (foreignContainerId === undefined) !== (foreignService === undefined) ||
    (foreignService !== undefined && !postgresServices.has(foreignService))
  ) {
    return fail();
  }
  const readSnapshot: ReferenceStateSnapshotReader =
    options.readSnapshot ??
    (async (request) =>
      readReferenceStateDriver(request, {
        driverPath: options.driverPath ?? fail(),
        environment: options.environment,
        runner: options.runner,
      }));

  return async (input) => {
    try {
      if (input.signal.aborted) {
        return fail();
      }
      const primary = await readSnapshot({
        source: 'primary',
        projectName,
        expectedService: primaryService,
        containerId: primaryContainerId,
        scenarioId: input.scenarioId,
        stepId: input.stepId,
        signal: input.signal,
      });
      const sourced: SourcedSnapshot[] = [{ source: 'primary', snapshot: primary }];

      if (input.scenarioId === 'interaction.consent-session-boundary') {
        if (!foreignContainerId) {
          return fail();
        }
        sourced.push({
          source: 'foreign',
          snapshot: await readSnapshot({
            source: 'foreign',
            projectName,
            expectedService: foreignService ?? fail(),
            containerId: foreignContainerId,
            scenarioId: input.scenarioId,
            stepId: input.stepId,
            signal: input.signal,
          }),
        });
      }
      const result = projectScenarioState(options, input, Object.freeze(sourced));
      const snapshot = snapshotClosedDataGraph<Phase1ScenarioStateProjectionInput>(result);

      if (!snapshot || !jsonValueGuard.safeParse(snapshot).success) {
        return fail();
      }
      assertPhase1RuntimeCredentialGraphIsSanitized(snapshot, []);

      return snapshot;
    } catch {
      return fail();
    }
  };
};

export const referenceStateEqualsForTesting = (left: unknown, right: unknown): boolean => {
  if (process.env.NODE_ENV !== 'test') {
    return fail();
  }

  return isDeepStrictEqual(assertJson(left), assertJson(right));
};

/* eslint-enable complexity, max-lines, max-params, no-restricted-syntax, no-control-regex, @typescript-eslint/ban-types, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
