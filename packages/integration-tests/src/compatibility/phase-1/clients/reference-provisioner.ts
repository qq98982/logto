/* eslint-disable max-lines, complexity, max-params, no-restricted-syntax, @silverhand/fp/no-mutating-methods, import/order, no-control-regex, unicorn/escape-case, @typescript-eslint/no-unnecessary-condition, prefer-destructuring, @typescript-eslint/array-type, unicorn/no-array-callback-reference, @typescript-eslint/ban-types, no-await-in-loop, @typescript-eslint/no-non-null-assertion, @silverhand/fp/no-mutation, @silverhand/fp/no-let, unicorn/catch-error-name -- The oracle adapter intentionally keeps its black-box DTOs, sequential dependency order, closed projections, and reverse compensation journal in one private boundary. */
import { randomBytes, randomUUID } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import {
  ApplicationType,
  RoleType,
  SignInIdentifier,
  SignInMode,
  getTenantOrganizationId,
} from '@logto/schemas';
import ky, { HTTPError } from 'ky';

import { validateTargetConfig } from '../../config.js';
import { jsonValueGuard, type TargetConfig } from '../../model.js';
import {
  projectPhase1UserActivityTimestamp,
  resolvePhase1FixtureUserActivityTarget,
  type Phase1BrowserFixtureProvisioner,
} from '../browser/activity-reader.js';
import { snapshotClosedDataGraph } from '../model.js';
import { asterNativeSurfaceContract } from '../native-surface.js';
import type { Phase1Profile } from '../profile-types.js';
import {
  assertPhase1RuntimeCredentialGraphIsSanitized,
  createProvisionedPhase1Fixture,
  phase1TargetOriginsArePairwiseDisjoint,
  revokeProvisionedPhase1Fixture,
  type ProvisionedPhase1Fixture,
  type SemanticStateProjection,
} from '../fixtures.js';
import {
  assertPhase1FixtureMapEntityKeys,
  createExpectedPhase1FixtureStateProjection,
  createPhase1FixtureMap,
  createPhase1FixtureStateProjection,
  getExpectedPhase1FixtureEntityKeys,
  getPhase1FixtureNamespaceSuffix,
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimePhone,
  getPhase1FixtureRuntimeResourceIndicator,
  getPhase1FixtureRuntimeText,
  getPhase1FixtureRuntimeUsername,
  phase1FixtureRecipeDefinitions,
  type Phase1FixtureAllocation,
  type Phase1FixtureAllocationRole,
  type Phase1FixtureEntityId,
  type Phase1FixtureIsolation,
} from '../fixture-map.js';
import type { Phase1FixtureRecipe } from '../model.js';

type ReferenceTargetRole = Phase1FixtureAllocationRole;
type ApplicationRedirectUriMode = 'profile' | 'target';
type SignInExperienceBrandingMode = 'preserve' | 'clear';
type ApplicationOidcClientMetadata =
  Phase1Profile['fixtures']['dataTenant']['applications'][number]['oidcClientMetadata'];

type ReferenceRequest = Readonly<{
  targetRole: ReferenceTargetRole;
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  body?: unknown;
}>;

type ReferenceRequestFunction = (request: ReferenceRequest) => Promise<unknown>;

type ReferenceProvisionerOptions = Readonly<{
  profile: Pick<Phase1Profile, 'fixtures'>;
  target: TargetConfig;
  foreignTarget?: TargetConfig;
  isolation: Readonly<{
    data: Phase1FixtureIsolation;
    admin: Phase1FixtureIsolation;
    foreign?: Phase1FixtureIsolation;
  }>;
  request?: ReferenceRequestFunction;
  createAllocationId?: () => string;
  createSecret?: () => string;
  applicationRedirectUriMode?: ApplicationRedirectUriMode;
  signInExperienceBrandingMode?: SignInExperienceBrandingMode;
}>;

type CleanupStep = {
  targetRole: ReferenceTargetRole;
  method: 'DELETE' | 'PATCH';
  path: string | null;
  body?: unknown;
  allowChildNotFound: boolean;
  signInLeaseToken?: symbol;
};

type SignInExperienceLeaseState = {
  snapshot: unknown;
  tokens: Set<symbol>;
  ready: boolean;
};

type RecoverableCleanupState = {
  cleanupSteps: CleanupStep[];
  allocationIds: readonly string[];
  cleanupPromise?: Promise<void>;
  completed: boolean;
};

type ProvisioningState = RecoverableCleanupState & {
  recipe: Phase1FixtureRecipe;
  observedUserApplicationIds: Map<string, string | null>;
};

type MutableProvisioning = {
  cleanupSteps: CleanupStep[];
  passwords: Array<Readonly<{ logicalId: string; value: string }>>;
  allocations: Phase1FixtureAllocation[];
};

type ProvisionedData = Readonly<{
  allocation: Phase1FixtureAllocation;
  subjectRuntimeId: string;
}>;

type AllocationNamespace = Readonly<{
  allocationId: string;
  suffix: string;
}>;

type SafeRequestFailure = Error & Readonly<{ status: number | undefined }>;

const invalidReferenceConfiguration = 'Invalid reference fixture provisioner configuration';
const invalidReferenceResponse = 'Invalid reference fixture response';
const operationFailure = 'Reference fixture operation failed';
const cleanupOperationFailure = 'Reference fixture cleanup operation failed';
const maximumSnapshotBytes = 65_536;
const safeTextPattern = /^[^\u0000-\u001f\u007f]+$/u;
const acceptsNonJsonMutationAcknowledgement = (request: ReferenceRequest): boolean =>
  request.method === 'POST' &&
  (/^roles\/[^/]+\/users$/u.test(request.path) ||
    /^applications\/[^/]+\/user-consent-scopes$/u.test(request.path));

const fixedUsernamePasswordExperience = Object.freeze({
  signInMode: SignInMode.SignInAndRegister,
  signUp: Object.freeze({
    identifiers: Object.freeze([SignInIdentifier.Username]),
    password: true,
    verify: false,
  }),
  signIn: Object.freeze({
    methods: Object.freeze([
      Object.freeze({
        identifier: SignInIdentifier.Username,
        password: true,
        verificationCode: false,
        isPasswordPrimary: true,
      }),
    ]),
  }),
  passwordPolicy: Object.freeze({}),
});

const safeText = (value: unknown): string => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 1024 ||
    !safeTextPattern.test(value)
  ) {
    throw new TypeError(invalidReferenceConfiguration);
  }

  return value;
};

const safeStatus = (error: unknown): number | undefined => {
  if (error instanceof HTTPError) {
    return error.response.status;
  }
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(error, 'status');

    return descriptor &&
      Object.hasOwn(descriptor, 'value') &&
      typeof descriptor.value === 'number' &&
      Number.isSafeInteger(descriptor.value)
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
};

const safeFailure = (message: string, error: unknown): SafeRequestFailure => {
  const failure = new Error(message) as SafeRequestFailure;
  Object.defineProperty(failure, 'status', {
    configurable: false,
    enumerable: false,
    value: safeStatus(error),
    writable: false,
  });

  return failure;
};

const responseSnapshot = <Value>(value: unknown): Readonly<Value> => {
  const snapshot = snapshotClosedDataGraph<Value>(value);

  if (
    snapshot === undefined ||
    !jsonValueGuard.safeParse(snapshot).success ||
    JSON.stringify(snapshot).length > maximumSnapshotBytes
  ) {
    throw new TypeError(invalidReferenceResponse);
  }

  return snapshot;
};

const responseRecord = (value: unknown): Readonly<Record<string, unknown>> => {
  const snapshot = responseSnapshot<Record<string, unknown>>(value);

  if (typeof snapshot !== 'object' || snapshot === null || Array.isArray(snapshot)) {
    throw new TypeError(invalidReferenceResponse);
  }

  return snapshot;
};

const responseId = (value: unknown): string => {
  const id = responseRecord(value).id;

  if (typeof id !== 'string' || id.length === 0) {
    throw new TypeError(invalidReferenceResponse);
  }
  try {
    assertPhase1RuntimeCredentialGraphIsSanitized(id);
  } catch {
    throw new Error(operationFailure);
  }

  return id;
};

const responseList = (value: unknown): readonly Readonly<Record<string, unknown>>[] => {
  const snapshot = responseSnapshot<unknown[]>(value);

  if (!Array.isArray(snapshot)) {
    throw new TypeError(invalidReferenceResponse);
  }

  return snapshot.map(responseRecord);
};

const responseStringList = (value: unknown): readonly string[] => {
  const snapshot = responseSnapshot<unknown[]>(value);

  if (!Array.isArray(snapshot)) {
    throw new TypeError(invalidReferenceResponse);
  }

  return snapshot.map(safeText);
};

const organizationResourceIndicator =
  asterNativeSurfaceContract.markers.organizationResource.reference;

const reservedAdminResourceProjection = (
  profile: Pick<Phase1Profile, 'fixtures'>,
  indicator: string
):
  | Readonly<{
      resource: Readonly<Record<string, unknown>>;
    }>
  | undefined => {
  if (indicator !== organizationResourceIndicator) {
    return undefined;
  }
  const matches = profile.fixtures.adminTenant.resources.filter(
    (resource) => resource.indicator === indicator
  );
  const [configured] = matches;

  if (matches.length !== 1 || !configured) {
    throw new TypeError(invalidReferenceConfiguration);
  }

  return Object.freeze({
    resource: Object.freeze({ indicator }),
  });
};

const projectAddressProfile = (value: unknown): unknown => {
  const profile = responseRecord(value);

  if (!Object.hasOwn(profile, 'address')) {
    return {};
  }
  const address = responseRecord(profile.address);

  return { address: { formatted: address.formatted, country: address.country } };
};

const projectSignInExperience = (value: unknown): unknown => {
  const signInExperience = responseRecord(value);
  const signUp = responseRecord(signInExperience.signUp);
  const signIn = responseRecord(signInExperience.signIn);
  const methods = responseList(signIn.methods);

  return {
    signInMode: signInExperience.signInMode,
    signUp: {
      identifiers: signUp.identifiers,
      localAuthentication: signUp.password,
      verify: signUp.verify,
    },
    signIn: {
      methods: methods.map((method) => ({
        identifier: method.identifier,
        localAuthentication: method.password,
        verificationCode: method.verificationCode,
        isPrimaryAuthentication: method.isPasswordPrimary,
      })),
    },
    localAuthenticationPolicy: signInExperience.passwordPolicy,
  };
};

const findExactRecord = (
  values: readonly Readonly<Record<string, unknown>>[],
  field: string,
  expected: string
): Readonly<Record<string, unknown>> => {
  const matches = values.filter((value) => value[field] === expected);

  if (matches.length !== 1 || !matches[0]) {
    throw new TypeError(invalidReferenceResponse);
  }

  return matches[0];
};

const recordIds = (value: unknown): readonly string[] =>
  responseList(value)
    .map(({ id }) => responseId({ id }))
    .toSorted();

const snapshotIsolationEvidence = (
  value: unknown,
  requiresForeign: boolean
): ReferenceProvisionerOptions['isolation'] => {
  try {
    const snapshot = responseRecord(value);
    const keys = Object.keys(snapshot);

    if (
      keys.length < 2 ||
      keys.length > 3 ||
      keys.some((key) => !['data', 'admin', 'foreign'].includes(key)) ||
      !Object.hasOwn(snapshot, 'data') ||
      !Object.hasOwn(snapshot, 'admin') ||
      (requiresForeign && !Object.hasOwn(snapshot, 'foreign'))
    ) {
      throw new TypeError(invalidReferenceConfiguration);
    }
    const read = (role: 'data' | 'admin' | 'foreign'): Phase1FixtureIsolation | undefined => {
      const candidate = snapshot[role];

      if (candidate === undefined) {
        return undefined;
      }
      const record = responseRecord(candidate);

      if (
        Object.keys(record).length !== 3 ||
        !Object.hasOwn(record, 'persistenceId') ||
        !Object.hasOwn(record, 'cookieKeyId') ||
        !Object.hasOwn(record, 'signingKeyId')
      ) {
        throw new TypeError(invalidReferenceConfiguration);
      }

      return Object.freeze({
        persistenceId: safeText(record.persistenceId),
        cookieKeyId: safeText(record.cookieKeyId),
        signingKeyId: safeText(record.signingKeyId),
      });
    };
    const data = read('data');
    const admin = read('admin');
    const foreign = read('foreign');

    if (!data || !admin || (requiresForeign && !foreign)) {
      throw new TypeError(invalidReferenceConfiguration);
    }

    return Object.freeze({ data, admin, ...(foreign && { foreign }) });
  } catch {
    throw new TypeError(invalidReferenceConfiguration);
  }
};

const exactNamedRuntimeIds = (value: unknown, names: readonly string[]): readonly string[] => {
  const rows = responseList(value);

  return names.map((name) => {
    const matches = rows.filter(
      (row) => row.name === name && (row.type === RoleType.User || row.type === 'User')
    );

    if (matches.length !== 1 || typeof matches[0]?.id !== 'string') {
      throw new TypeError(invalidReferenceResponse);
    }

    return matches[0].id;
  });
};

const readBoundedResponseText = async (response: Response): Promise<string> => {
  const reader = response.body?.getReader();

  if (!reader) {
    return '';
  }
  const decoder = new TextDecoder('utf8', { fatal: true });
  let bytesRead = 0;
  let text = '';
  let complete = false;

  try {
    while (!complete) {
      const chunk = await reader.read();

      complete = chunk.done;
      if (chunk.done) {
        continue;
      }
      const { value } = chunk;
      bytesRead += value.byteLength;
      if (bytesRead > maximumSnapshotBytes) {
        try {
          await reader.cancel();
        } catch {
          // The response is already rejected; transport cancellation is best effort.
        }
        throw new TypeError(invalidReferenceResponse);
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  } finally {
    reader.releaseLock();
  }
};

const createDefaultRequest = (
  target: TargetConfig,
  foreignTarget: TargetConfig | undefined
): ReferenceRequestFunction => {
  const clients = new Map<ReferenceTargetRole, ReturnType<typeof ky.create>>();
  const baseFor = (role: ReferenceTargetRole) => {
    if (role === 'foreign') {
      if (!foreignTarget) {
        throw new TypeError(invalidReferenceConfiguration);
      }

      return foreignTarget.coreUrl;
    }

    // The existing adminTenantApi helper publishes Admin Tenant Management APIs on the admin origin.
    return role === 'admin' ? target.adminUrl : target.coreUrl;
  };
  const clientFor = (role: ReferenceTargetRole) => {
    const existing = clients.get(role);

    if (existing) {
      return existing;
    }
    const client = ky.create({
      prefixUrl: new URL('/api/', baseFor(role)),
      headers: { 'development-user-id': 'integration-test-admin-user' },
      retry: 0,
    });
    clients.set(role, client);

    return client;
  };

  return async ({ targetRole, method, path, body }) => {
    const client = clientFor(targetRole);
    const options = body === undefined ? undefined : { json: body };

    if (method === 'DELETE') {
      await client.delete(path, options);
      return {};
    }
    const response =
      method === 'GET'
        ? await client.get(path, options)
        : method === 'POST'
          ? await client.post(path, options)
          : await client.patch(path, options);

    const responseText = await readBoundedResponseText(response);
    const acceptsAcknowledgement = acceptsNonJsonMutationAcknowledgement({
      targetRole,
      method,
      path,
      body,
    });

    if (acceptsAcknowledgement && response.status !== 201) {
      throw new TypeError(invalidReferenceResponse);
    }

    if (responseText.length === 0) {
      if (acceptsAcknowledgement) {
        return {};
      }

      throw new TypeError(invalidReferenceResponse);
    }
    const mediaType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();

    if (mediaType !== 'application/json') {
      if (acceptsAcknowledgement) {
        return {};
      }

      throw new TypeError(invalidReferenceResponse);
    }
    return JSON.parse(responseText) as unknown;
  };
};

const isolationFor = (
  role: ReferenceTargetRole,
  isolation: ReferenceProvisionerOptions['isolation']
): Phase1FixtureIsolation => {
  const evidence = isolation[role];

  if (!evidence) {
    throw new TypeError(invalidReferenceConfiguration);
  }

  return Object.freeze({ ...evidence });
};

const entity = (
  kind: Phase1FixtureEntityId['kind'],
  logicalId: string,
  runtimeId: string
): Phase1FixtureEntityId => Object.freeze({ kind, logicalId, runtimeId });

const namespacedText = (value: string, namespace: AllocationNamespace): string =>
  getPhase1FixtureRuntimeText(value, namespace.allocationId);

const namespacedUsername = (value: string, namespace: AllocationNamespace): string =>
  getPhase1FixtureRuntimeUsername(value, namespace.allocationId);

const namespacedEmail = (value: string, namespace: AllocationNamespace): string =>
  getPhase1FixtureRuntimeEmail(value, namespace.allocationId);

const namespacedPhone = (namespace: AllocationNamespace): string =>
  getPhase1FixtureRuntimePhone(namespace.allocationId);

const namespacedResourceIndicator = (value: string, namespace: AllocationNamespace): string =>
  getPhase1FixtureRuntimeResourceIndicator(value, namespace.allocationId);

const assertObservedEquals = (actual: unknown, expected: unknown): void => {
  if (!isDeepStrictEqual(responseSnapshot(actual), responseSnapshot(expected))) {
    throw new TypeError(invalidReferenceResponse);
  }
};

const allocationNamespace = ({ allocationId }: Phase1FixtureAllocation): AllocationNamespace =>
  Object.freeze({
    allocationId,
    suffix: getPhase1FixtureNamespaceSuffix(allocationId),
  });

const runtimeIdForLogical = (
  allocation: Phase1FixtureAllocation,
  kind: Phase1FixtureEntityId['kind'],
  logicalId: string
): string => {
  const matches = allocation.entities.filter(
    (entity) => entity.kind === kind && entity.logicalId === logicalId
  );

  if (matches.length !== 1 || !matches[0]) {
    throw new TypeError(invalidReferenceResponse);
  }

  return matches[0].runtimeId;
};

const logicalIdsForRuntimeIds = (
  allocation: Phase1FixtureAllocation,
  kind: Phase1FixtureEntityId['kind'],
  runtimeIds: readonly string[]
): readonly string[] => {
  const runtimeSet = new Set(runtimeIds);

  return allocation.entities
    .filter((entity) => entity.kind === kind && runtimeSet.has(entity.runtimeId))
    .map(({ logicalId }) => logicalId)
    .toSorted();
};

export const createReferencePhase1FixtureProvisioner = (
  options: ReferenceProvisionerOptions
): Phase1BrowserFixtureProvisioner => {
  const target = validateTargetConfig(options.target);
  const foreignTarget = options.foreignTarget
    ? validateTargetConfig(options.foreignTarget)
    : undefined;
  const applicationRedirectUriMode = options.applicationRedirectUriMode ?? 'profile';
  const signInExperienceBrandingMode = options.signInExperienceBrandingMode ?? 'preserve';

  if (
    !['profile', 'target'].includes(applicationRedirectUriMode) ||
    !['preserve', 'clear'].includes(signInExperienceBrandingMode) ||
    !phase1TargetOriginsArePairwiseDisjoint(target, foreignTarget)
  ) {
    throw new TypeError(invalidReferenceConfiguration);
  }
  try {
    assertPhase1RuntimeCredentialGraphIsSanitized({ target, foreignTarget: foreignTarget ?? null });
  } catch {
    throw new TypeError(invalidReferenceConfiguration);
  }
  const isolation = snapshotIsolationEvidence(options.isolation, foreignTarget !== undefined);
  const request = options.request ?? createDefaultRequest(target, foreignTarget);
  const createAllocationId = options.createAllocationId ?? randomUUID;
  const createSecret = options.createSecret ?? (() => randomBytes(32).toString('base64url'));
  const configuredUsernamePasswordExperience =
    signInExperienceBrandingMode === 'clear'
      ? Object.freeze({ ...fixedUsernamePasswordExperience, branding: Object.freeze({}) })
      : fixedUsernamePasswordExperience;
  const applicationBaseUrl = (role: ReferenceTargetRole): string => {
    const baseUrl =
      role === 'admin'
        ? target.adminUrl
        : role === 'foreign'
          ? foreignTarget?.coreUrl
          : target.coreUrl;

    if (!baseUrl) {
      throw new TypeError(invalidReferenceConfiguration);
    }

    return baseUrl;
  };
  const rebaseApplicationUri = (role: ReferenceTargetRole, value: string): string => {
    const parsed = (() => {
      try {
        return new URL(safeText(value));
      } catch {
        throw new TypeError(invalidReferenceConfiguration);
      }
    })();

    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
      throw new TypeError(invalidReferenceConfiguration);
    }

    const targetUrl = new URL(applicationBaseUrl(role));
    const targetOrigin = targetUrl.origin;
    targetUrl.pathname = parsed.pathname;
    targetUrl.search = parsed.search;
    targetUrl.hash = parsed.hash;

    if (targetUrl.origin !== targetOrigin) {
      throw new TypeError(invalidReferenceConfiguration);
    }

    return targetUrl.href;
  };
  const applicationOidcClientMetadata = (
    role: ReferenceTargetRole,
    metadata: ApplicationOidcClientMetadata
  ): ApplicationOidcClientMetadata =>
    Object.freeze({
      redirectUris: Object.freeze(
        metadata.redirectUris.map((value) =>
          applicationRedirectUriMode === 'target'
            ? rebaseApplicationUri(role, value)
            : safeText(value)
        )
      ),
      postLogoutRedirectUris: Object.freeze(
        metadata.postLogoutRedirectUris.map((value) =>
          applicationRedirectUriMode === 'target'
            ? rebaseApplicationUri(role, value)
            : safeText(value)
        )
      ),
    });
  const applicationOidcClientMetadataFromUnknown = (
    role: ReferenceTargetRole,
    value: unknown
  ): ApplicationOidcClientMetadata => {
    const metadata = responseRecord(value);

    if (
      !isDeepStrictEqual(Object.keys(metadata).toSorted(), [
        'postLogoutRedirectUris',
        'redirectUris',
      ])
    ) {
      throw new TypeError(invalidReferenceConfiguration);
    }

    return applicationOidcClientMetadata(role, {
      redirectUris: responseStringList(metadata.redirectUris),
      postLogoutRedirectUris: responseStringList(metadata.postLogoutRedirectUris),
    });
  };
  const states = new WeakMap<object, ProvisioningState>();
  const claimedAllocationIds = new Set<string>();
  const pendingProvisioningCleanups = new Set<RecoverableCleanupState>();
  let pendingProvisioningRecovery: Promise<void> | undefined;
  const signInExperienceLeases = new Map<ReferenceTargetRole, SignInExperienceLeaseState>();
  let signInExperienceOperation = Promise.resolve();

  const withSignInExperienceLock = async <Result>(
    operation: () => Promise<Result>
  ): Promise<Result> => {
    const previous = signInExperienceOperation;
    // eslint-disable-next-line no-use-extend-native/no-use-extend-native -- Promise.withResolvers is the standard ES2024 deferred primitive, not a prototype extension.
    const { promise: current, resolve: release } = Promise.withResolvers<void>();
    signInExperienceOperation = (async () => {
      await previous;
      await current;
    })();
    await previous;

    try {
      return await operation();
    } finally {
      release();
    }
  };

  const call = async (input: ReferenceRequest, cleanup = false): Promise<unknown> => {
    try {
      return await request(input);
    } catch (error: unknown) {
      throw safeFailure(cleanup ? cleanupOperationFailure : operationFailure, error);
    }
  };

  const releaseSignInExperienceLease = async (
    role: ReferenceTargetRole,
    token: symbol
  ): Promise<void> =>
    withSignInExperienceLock(async () => {
      const state = signInExperienceLeases.get(role);

      if (!state || (!state.tokens.has(token) && state.tokens.size > 0)) {
        throw new Error(cleanupOperationFailure);
      }
      state.tokens.delete(token);
      if (state.tokens.size > 0) {
        return;
      }
      state.ready = false;
      await call(
        { targetRole: role, method: 'PATCH', path: 'sign-in-exp', body: state.snapshot },
        true
      );
      signInExperienceLeases.delete(role);
    });

  const cleanupAll = async (steps: CleanupStep[]): Promise<unknown[]> => {
    const failures: unknown[] = [];
    let dependencyBlocked = false;

    for (let index = steps.length - 1; index >= 0; index -= 1) {
      const step = steps[index];

      if (!step) {
        failures.push(new Error(cleanupOperationFailure));
        dependencyBlocked = true;
        continue;
      }
      if (dependencyBlocked && step.method === 'DELETE') {
        continue;
      }
      if (step.signInLeaseToken) {
        try {
          await releaseSignInExperienceLease(step.targetRole, step.signInLeaseToken);
        } catch (error: unknown) {
          failures.push(error);
          dependencyBlocked = true;
          continue;
        }
        steps.splice(index, 1);
        continue;
      }
      if (step.path === null) {
        failures.push(new Error(cleanupOperationFailure));
        dependencyBlocked = true;
        continue;
      }
      try {
        await call({ ...step, path: step.path }, true);
      } catch (error: unknown) {
        if (step.allowChildNotFound && safeStatus(error) === 404) {
          steps.splice(index, 1);
          continue;
        }
        failures.push(error);
        dependencyBlocked = true;
        continue;
      }
      steps.splice(index, 1);
    }

    return failures;
  };

  const releaseAllocationIds = (allocationIds: readonly string[]): void => {
    for (const allocationId of allocationIds) {
      claimedAllocationIds.delete(allocationId);
    }
  };

  const cleanupState = async (
    state: RecoverableCleanupState,
    fixture?: ProvisionedPhase1Fixture
  ): Promise<void> => {
    if (fixture) {
      revokeProvisionedPhase1Fixture(fixture);
    }
    if (state.completed) {
      pendingProvisioningCleanups.delete(state);
      return;
    }
    if (state.cleanupPromise) {
      return state.cleanupPromise;
    }
    const cleanupPromise = (async () => {
      const failures = await cleanupAll(state.cleanupSteps);

      if (failures.length > 0) {
        throw new AggregateError(failures, 'Reference fixture cleanup failed');
      }
      state.completed = true;
      releaseAllocationIds(state.allocationIds);
      pendingProvisioningCleanups.delete(state);
    })();
    state.cleanupPromise = cleanupPromise;

    try {
      await cleanupPromise;
    } catch (error: unknown) {
      pendingProvisioningCleanups.add(state);
      throw error;
    } finally {
      state.cleanupPromise = undefined;
    }
  };

  const recoverPendingProvisioningCleanups = async (): Promise<void> => {
    if (pendingProvisioningCleanups.size === 0) {
      return;
    }
    if (pendingProvisioningRecovery) {
      return pendingProvisioningRecovery;
    }
    const recovery = (async () => {
      const blockingFailures: unknown[] = [];

      for (const pending of pendingProvisioningCleanups) {
        try {
          await cleanupState(pending);
        } catch (error: unknown) {
          if (pending.cleanupSteps.some(({ method }) => method === 'PATCH')) {
            blockingFailures.push(error);
          }
        }
      }
      if (blockingFailures.length > 0) {
        throw new AggregateError(
          blockingFailures,
          'Reference pending shared fixture cleanup failed'
        );
      }
    })();
    pendingProvisioningRecovery = recovery;

    try {
      await recovery;
    } finally {
      pendingProvisioningRecovery = undefined;
    }
  };

  const createWithCleanup = async (
    input: ReferenceRequest,
    mutable: MutableProvisioning,
    cleanupPath: (runtimeId: string) => string,
    allowChildNotFound = false
  ): Promise<string> => {
    const cleanupStep: CleanupStep = {
      targetRole: input.targetRole,
      method: 'DELETE',
      path: null,
      allowChildNotFound,
    };
    mutable.cleanupSteps.push(cleanupStep);
    const runtimeId = responseId(await call(input));
    cleanupStep.path = cleanupPath(runtimeId);

    return runtimeId;
  };

  const snapshotAndConfigure = async (
    roles: readonly ReferenceTargetRole[],
    mutable: MutableProvisioning
  ): Promise<void> =>
    withSignInExperienceLock(async () => {
      const acquired: Array<
        Readonly<{
          role: ReferenceTargetRole;
          state: SignInExperienceLeaseState;
          newlyCreated: boolean;
        }>
      > = [];

      for (const role of roles) {
        const token = Symbol(`Phase 1 sign-in experience lease: ${role}`);
        const existing = signInExperienceLeases.get(role);

        if (existing) {
          if (!existing.ready || existing.tokens.size === 0) {
            throw new Error(operationFailure);
          }
          existing.tokens.add(token);
          acquired.push({ role, state: existing, newlyCreated: false });
        } else {
          const state: SignInExperienceLeaseState = {
            snapshot: responseRecord(
              await call({ targetRole: role, method: 'GET', path: 'sign-in-exp' })
            ),
            tokens: new Set([token]),
            ready: false,
          };
          signInExperienceLeases.set(role, state);
          acquired.push({ role, state, newlyCreated: true });
        }
        mutable.cleanupSteps.push({
          targetRole: role,
          method: 'PATCH',
          path: 'sign-in-exp',
          allowChildNotFound: false,
          signInLeaseToken: token,
        });
      }
      for (const { role, state, newlyCreated } of acquired) {
        if (!newlyCreated) {
          continue;
        }
        await call({
          targetRole: role,
          method: 'PATCH',
          path: 'sign-in-exp',
          body: configuredUsernamePasswordExperience,
        });
        state.ready = true;
      }
    });

  const provisionData = async (
    mutable: MutableProvisioning,
    namespace: AllocationNamespace
  ): Promise<ProvisionedData> => {
    const fixture = options.profile.fixtures.dataTenant;
    const firstParty = fixture.applications.find(({ isThirdParty }) => !isThirdParty);
    const thirdParty = fixture.applications.find(({ isThirdParty }) => isThirdParty);
    const scope = fixture.resource.scopes[0];

    if (!firstParty || !thirdParty?.isThirdParty || !scope) {
      throw new TypeError(invalidReferenceConfiguration);
    }
    const password = safeText(createSecret());
    const subjectRuntimeId = await createWithCleanup(
      {
        targetRole: 'data',
        method: 'POST',
        path: 'users',
        body: { username: namespacedUsername(fixture.subject.username, namespace), password },
      },
      mutable,
      (runtimeId) => `users/${encodeURIComponent(runtimeId)}`
    );
    mutable.passwords.push({ logicalId: fixture.subject.id, value: password });
    await call({
      targetRole: 'data',
      method: 'PATCH',
      path: `users/${encodeURIComponent(subjectRuntimeId)}`,
      body: {
        name: fixture.subject.name,
        primaryEmail: namespacedEmail(fixture.subject.primaryEmail, namespace),
        primaryPhone: namespacedPhone(namespace),
        profile: fixture.subject.profile,
        applicationId: fixture.subject.applicationId,
        customData: {},
      },
    });

    const resourceRuntimeId = await createWithCleanup(
      {
        targetRole: 'data',
        method: 'POST',
        path: 'resources',
        body: {
          name: namespacedText(fixture.resource.name, namespace),
          indicator: namespacedResourceIndicator(fixture.resource.indicator, namespace),
        },
      },
      mutable,
      (runtimeId) => `resources/${encodeURIComponent(runtimeId)}`
    );
    const scopeRuntimeId = await createWithCleanup(
      {
        targetRole: 'data',
        method: 'POST',
        path: `resources/${encodeURIComponent(resourceRuntimeId)}/scopes`,
        body: { name: namespacedText(scope.name, namespace), description: scope.description },
      },
      mutable,
      (runtimeId) =>
        `resources/${encodeURIComponent(resourceRuntimeId)}/scopes/${encodeURIComponent(runtimeId)}`,
      true
    );
    const roleRuntimeId = await createWithCleanup(
      {
        targetRole: 'data',
        method: 'POST',
        path: 'roles',
        body: {
          name: namespacedText(fixture.resourceScopeRole.name, namespace),
          description: fixture.resourceScopeRole.description,
          type: fixture.resourceScopeRole.type,
          isDefault: fixture.resourceScopeRole.isDefault,
          scopeIds: [scopeRuntimeId],
        },
      },
      mutable,
      (runtimeId) => `roles/${encodeURIComponent(runtimeId)}`
    );
    await call({
      targetRole: 'data',
      method: 'POST',
      path: `roles/${encodeURIComponent(roleRuntimeId)}/users`,
      body: { userIds: [subjectRuntimeId] },
    });

    const firstPartyRuntimeId = await createWithCleanup(
      {
        targetRole: 'data',
        method: 'POST',
        path: 'applications',
        body: {
          name: namespacedText(firstParty.name, namespace),
          type: firstParty.type as ApplicationType,
          isThirdParty: false,
          oidcClientMetadata: applicationOidcClientMetadata('data', firstParty.oidcClientMetadata),
          customClientMetadata: firstParty.customClientMetadata,
        },
      },
      mutable,
      (runtimeId) => `applications/${encodeURIComponent(runtimeId)}`
    );
    const thirdPartyRuntimeId = await createWithCleanup(
      {
        targetRole: 'data',
        method: 'POST',
        path: 'applications',
        body: {
          name: namespacedText(thirdParty.name, namespace),
          type: thirdParty.type as ApplicationType,
          isThirdParty: true,
          oidcClientMetadata: applicationOidcClientMetadata('data', thirdParty.oidcClientMetadata),
          customClientMetadata: thirdParty.customClientMetadata,
        },
      },
      mutable,
      (runtimeId) => `applications/${encodeURIComponent(runtimeId)}`
    );
    await call({
      targetRole: 'data',
      method: 'POST',
      path: `applications/${encodeURIComponent(thirdPartyRuntimeId)}/user-consent-scopes`,
      body: {
        userScopes: thirdParty.userConsentScopes,
        resourceScopes: [scopeRuntimeId],
      },
    });

    const allocation: Phase1FixtureAllocation = Object.freeze({
      allocationId: namespace.allocationId,
      role: 'data',
      target: 'primary',
      isolation: isolationFor('data', isolation),
      entities: Object.freeze([
        entity('tenant', fixture.id, fixture.id),
        entity('user', fixture.subject.id, subjectRuntimeId),
        entity('application', firstParty.id, firstPartyRuntimeId),
        entity('application', thirdParty.id, thirdPartyRuntimeId),
        entity('resource', fixture.resource.id, resourceRuntimeId),
        entity('scope', scope.id, scopeRuntimeId),
        entity('role', fixture.resourceScopeRole.id, roleRuntimeId),
      ]),
    });
    mutable.allocations.push(allocation);

    return Object.freeze({ allocation, subjectRuntimeId });
  };

  const provisionAdmin = async (
    mutable: MutableProvisioning,
    namespace: AllocationNamespace
  ): Promise<void> => {
    const fixture = options.profile.fixtures.adminTenant;
    const password = safeText(createSecret());
    const operatorRuntimeId = await createWithCleanup(
      {
        targetRole: 'admin',
        method: 'POST',
        path: 'users',
        body: { username: namespacedUsername(fixture.operator.username, namespace), password },
      },
      mutable,
      (runtimeId) => `users/${encodeURIComponent(runtimeId)}`
    );
    mutable.passwords.push({ logicalId: fixture.operator.id, value: password });
    await call({
      targetRole: 'admin',
      method: 'PATCH',
      path: `users/${encodeURIComponent(operatorRuntimeId)}`,
      body: {
        primaryEmail: namespacedEmail(fixture.operator.primaryEmail, namespace),
        customData: fixture.operator.customData,
      },
    });
    const roleRuntimeIds = exactNamedRuntimeIds(
      await call({ targetRole: 'admin', method: 'GET', path: 'roles' }),
      fixture.operator.roles
    );

    for (const roleRuntimeId of roleRuntimeIds) {
      await call({
        targetRole: 'admin',
        method: 'POST',
        path: `roles/${encodeURIComponent(roleRuntimeId)}/users`,
        body: { userIds: [operatorRuntimeId] },
      });
    }
    const organizationRole = fixture.tenantOrganization.organizationRoles[0];

    if (!organizationRole) {
      throw new TypeError(invalidReferenceConfiguration);
    }
    const [organizationRoleRuntimeId] = exactNamedRuntimeIds(
      await call({ targetRole: 'admin', method: 'GET', path: 'organization-roles' }),
      [organizationRole.name]
    );

    if (!organizationRoleRuntimeId) {
      throw new TypeError(invalidReferenceResponse);
    }
    const tenantOrganizationId = getTenantOrganizationId('default');
    mutable.cleanupSteps.push({
      targetRole: 'admin',
      method: 'DELETE',
      path: `organizations/${encodeURIComponent(tenantOrganizationId)}/users/${encodeURIComponent(
        operatorRuntimeId
      )}`,
      allowChildNotFound: true,
    });
    await call({
      targetRole: 'admin',
      method: 'POST',
      path: `organizations/${encodeURIComponent(tenantOrganizationId)}/users`,
      body: { userIds: [operatorRuntimeId] },
    });
    await call({
      targetRole: 'admin',
      method: 'POST',
      path: `organizations/${encodeURIComponent(tenantOrganizationId)}/users/${encodeURIComponent(
        operatorRuntimeId
      )}/roles`,
      body: { organizationRoleIds: [organizationRoleRuntimeId] },
    });

    mutable.allocations.push(
      Object.freeze({
        allocationId: namespace.allocationId,
        role: 'admin',
        target: 'primary',
        isolation: isolationFor('admin', isolation),
        entities: Object.freeze([
          entity('tenant', fixture.id, fixture.id),
          entity('user', fixture.operator.id, operatorRuntimeId),
          entity('application', fixture.application.id, fixture.application.id),
          ...fixture.resources.map(({ indicator }, index) =>
            entity('resource', `admin.resource.${index + 1}`, indicator)
          ),
          ...fixture.operator.roles.map((logicalId, index) =>
            entity('role', logicalId, roleRuntimeIds[index]!)
          ),
          entity('organization', fixture.tenantOrganization.id, tenantOrganizationId),
          entity('organization-role', organizationRole.id, organizationRoleRuntimeId),
        ]),
      })
    );
  };

  const provisionConsentPeer = async (
    targetRole: 'data' | 'foreign',
    logicalPrefix: 'consent.primary' | 'consent.foreign',
    mutable: MutableProvisioning,
    namespace: AllocationNamespace,
    targetAllocation?: Phase1FixtureAllocation
  ): Promise<Phase1FixtureAllocation | undefined> => {
    const fixture = options.profile.fixtures.dataTenant;
    const thirdParty = fixture.applications.find(({ isThirdParty }) => isThirdParty);

    if (!thirdParty) {
      throw new TypeError(invalidReferenceConfiguration);
    }
    const password = safeText(createSecret());
    const username = namespacedUsername(`${fixture.subject.username}_boundary_b`, namespace);
    const userRuntimeId = await createWithCleanup(
      {
        targetRole,
        method: 'POST',
        path: 'users',
        body: { username, password },
      },
      mutable,
      (runtimeId) => `users/${encodeURIComponent(runtimeId)}`
    );
    mutable.passwords.push({ logicalId: `${logicalPrefix}.user-b`, value: password });
    const applicationRuntimeId = await createWithCleanup(
      {
        targetRole,
        method: 'POST',
        path: 'applications',
        body: {
          name: namespacedText(`${logicalPrefix} client B`, namespace),
          type: ApplicationType.SPA,
          isThirdParty: true,
          oidcClientMetadata: applicationOidcClientMetadata(
            targetRole,
            thirdParty.oidcClientMetadata
          ),
          customClientMetadata: {},
        },
      },
      mutable,
      (runtimeId) => `applications/${encodeURIComponent(runtimeId)}`
    );
    const peerEntities = [
      entity('user', `${logicalPrefix}.user-b`, userRuntimeId),
      entity('application', `${logicalPrefix}.client-b`, applicationRuntimeId),
    ];

    if (targetAllocation) {
      const replacement = Object.freeze({
        ...targetAllocation,
        entities: Object.freeze([...targetAllocation.entities, ...peerEntities]),
      });
      const index = mutable.allocations.indexOf(targetAllocation);
      mutable.allocations[index] = replacement;
      return undefined;
    }

    const allocation: Phase1FixtureAllocation = Object.freeze({
      allocationId: namespace.allocationId,
      role: 'foreign',
      target: 'foreign',
      isolation: isolationFor('foreign', isolation),
      entities: Object.freeze([entity('tenant', fixture.id, fixture.id), ...peerEntities]),
    });
    mutable.allocations.push(allocation);

    return allocation;
  };

  const provisionForeignTenantBoundary = (
    mutable: MutableProvisioning,
    namespace: AllocationNamespace
  ): void => {
    const fixture = options.profile.fixtures.dataTenant;

    mutable.allocations.push(
      Object.freeze({
        allocationId: namespace.allocationId,
        role: 'foreign',
        target: 'foreign',
        isolation: isolationFor('foreign', isolation),
        entities: Object.freeze([entity('tenant', fixture.id, fixture.id)]),
      })
    );
  };

  return Object.freeze({
    provision: async (recipe: Phase1FixtureRecipe): Promise<ProvisionedPhase1Fixture> => {
      if (!Object.hasOwn(phase1FixtureRecipeDefinitions, recipe)) {
        throw new TypeError(invalidReferenceConfiguration);
      }
      if ((recipe === 'corsBoundary' || recipe === 'consentBoundary') && !foreignTarget) {
        throw new TypeError(invalidReferenceConfiguration);
      }
      await recoverPendingProvisioningCleanups();
      const mutable: MutableProvisioning = { cleanupSteps: [], passwords: [], allocations: [] };
      const allocationRoles: readonly ReferenceTargetRole[] =
        recipe === 'none'
          ? []
          : recipe === 'dataProtocol'
            ? ['data']
            : recipe === 'adminConsole'
              ? ['admin']
              : recipe === 'fullPhase1'
                ? ['data', 'admin']
                : recipe === 'corsBoundary'
                  ? ['data', 'admin', 'foreign']
                  : ['data', 'foreign'];
      const namespaces = new Map<ReferenceTargetRole, AllocationNamespace>();

      try {
        for (const role of allocationRoles) {
          const allocationId = safeText(createAllocationId());

          if (claimedAllocationIds.has(allocationId)) {
            throw new Error(operationFailure);
          }
          claimedAllocationIds.add(allocationId);
          namespaces.set(
            role,
            Object.freeze({
              allocationId,
              suffix: getPhase1FixtureNamespaceSuffix(allocationId),
            })
          );
        }
        const signInRoles: ReferenceTargetRole[] =
          recipe === 'fullPhase1'
            ? ['data', 'admin']
            : recipe === 'corsBoundary'
              ? ['data', 'admin', 'foreign']
              : recipe === 'adminConsole'
                ? ['admin']
                : recipe === 'consentBoundary'
                  ? ['data', 'foreign']
                  : recipe === 'dataProtocol'
                    ? ['data']
                    : [];
        await snapshotAndConfigure(signInRoles, mutable);
        let provisionedData: ProvisionedData | undefined;

        if (
          recipe === 'dataProtocol' ||
          recipe === 'fullPhase1' ||
          recipe === 'corsBoundary' ||
          recipe === 'consentBoundary'
        ) {
          const namespace = namespaces.get('data');
          if (!namespace) {
            throw new TypeError(invalidReferenceConfiguration);
          }
          provisionedData = await provisionData(mutable, namespace);
        }
        if (recipe === 'fullPhase1' || recipe === 'corsBoundary' || recipe === 'adminConsole') {
          const namespace = namespaces.get('admin');
          if (!namespace) {
            throw new TypeError(invalidReferenceConfiguration);
          }
          await provisionAdmin(mutable, namespace);
        }
        if (recipe === 'corsBoundary') {
          provisionForeignTenantBoundary(mutable, namespaces.get('foreign')!);
        } else if (recipe === 'consentBoundary') {
          if (!provisionedData) {
            throw new TypeError(invalidReferenceConfiguration);
          }
          await provisionConsentPeer(
            'data',
            'consent.primary',
            mutable,
            namespaces.get('data')!,
            provisionedData.allocation
          );
          await provisionConsentPeer(
            'foreign',
            'consent.foreign',
            mutable,
            namespaces.get('foreign')!
          );
        }

        const publicMap = createPhase1FixtureMap({
          schemaVersion: 1,
          recipe,
          allocations: mutable.allocations,
        });
        assertPhase1FixtureMapEntityKeys(
          publicMap,
          getExpectedPhase1FixtureEntityKeys(options.profile, recipe)
        );
        const fixture = createProvisionedPhase1Fixture({
          public: publicMap,
          ...((recipe === 'corsBoundary' || recipe === 'consentBoundary') && { foreignTarget }),
          passwords: mutable.passwords,
          clientSecrets: [],
        });
        states.set(fixture as object, {
          recipe,
          cleanupSteps: [...mutable.cleanupSteps],
          allocationIds: Object.freeze(
            publicMap.allocations.map(({ allocationId }) => allocationId)
          ),
          observedUserApplicationIds: new Map(),
          completed: false,
        });

        return fixture;
      } catch (primary: unknown) {
        const safePrimary =
          primary instanceof Error &&
          [operationFailure, invalidReferenceConfiguration, invalidReferenceResponse].includes(
            primary.message
          )
            ? primary
            : new Error(operationFailure);
        const cleanupFailures = await cleanupAll(mutable.cleanupSteps);
        const allocationIds = Object.freeze(
          [...namespaces.values()].map(({ allocationId }) => allocationId)
        );

        if (cleanupFailures.length === 0) {
          releaseAllocationIds(allocationIds);
        }

        if (cleanupFailures.length > 0) {
          pendingProvisioningCleanups.add({
            cleanupSteps: mutable.cleanupSteps,
            allocationIds,
            completed: false,
          });
          throw new AggregateError(
            [safePrimary, ...cleanupFailures],
            'Reference fixture provisioning and cleanup failed',
            { cause: safePrimary }
          );
        }
        throw safePrimary;
      }
    },

    projectState: async (fixture: ProvisionedPhase1Fixture): Promise<SemanticStateProjection> => {
      const state = states.get(fixture as object);

      if (!state) {
        throw new TypeError('Unknown reference fixture');
      }
      const expectedProjection = createExpectedPhase1FixtureStateProjection(
        fixture.public,
        options.profile
      );
      const reservedOrganizationIndicator = organizationResourceIndicator;
      const allocations = [];

      for (const [allocationIndex, allocation] of fixture.public.allocations.entries()) {
        const expectedAllocation = expectedProjection.allocations[allocationIndex];

        if (!expectedAllocation) {
          throw new Error(operationFailure);
        }
        const namespace = allocationNamespace(allocation);
        const signInExperience = projectSignInExperience(
          await call({ targetRole: allocation.role, method: 'GET', path: 'sign-in-exp' })
        );
        assertObservedEquals(signInExperience, expectedAllocation.signInExperience);
        const allResources =
          allocation.role === 'admin'
            ? responseList(
                await call({ targetRole: allocation.role, method: 'GET', path: 'resources' })
              )
            : [];

        if (allResources.some(({ indicator }) => indicator === reservedOrganizationIndicator)) {
          throw new TypeError(invalidReferenceResponse);
        }
        const reservedOrganizationScopes =
          allocation.role === 'admin' &&
          allocation.entities.some(
            ({ kind, runtimeId }) =>
              kind === 'resource' && runtimeId === reservedOrganizationIndicator
          )
            ? responseList(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: 'organization-scopes',
                })
              )
            : [];
        const allOrganizations = allocation.entities.some(({ kind }) => kind === 'organization')
          ? responseList(
              await call({ targetRole: allocation.role, method: 'GET', path: 'organizations' })
            )
          : [];
        const allOrganizationRoles = allocation.entities.some(
          ({ kind }) => kind === 'organization-role'
        )
          ? responseList(
              await call({
                targetRole: allocation.role,
                method: 'GET',
                path: 'organization-roles',
              })
            )
          : [];
        const organization = allocation.entities.find(({ kind }) => kind === 'organization');
        const organizationMembers = organization
          ? responseList(
              await call({
                targetRole: allocation.role,
                method: 'GET',
                path: `organizations/${encodeURIComponent(organization.runtimeId)}/users`,
              })
            )
          : [];
        const memberOrganizationRoleIdsByUserId = new Map<string, readonly string[]>(
          organization
            ? await Promise.all(
                organizationMembers.map(async ({ id }) => {
                  const userId = responseId({ id });
                  const roleIds = recordIds(
                    await call({
                      targetRole: allocation.role,
                      method: 'GET',
                      path: `organizations/${encodeURIComponent(
                        organization.runtimeId
                      )}/users/${encodeURIComponent(userId)}/roles`,
                    })
                  );

                  return [userId, roleIds] as const;
                })
              )
            : []
        );
        const resourceScopes = new Map<string, readonly Readonly<Record<string, unknown>>[]>();
        const readResourceScopes = async (
          resourceRuntimeId: string
        ): Promise<readonly Readonly<Record<string, unknown>>[]> => {
          const existing = resourceScopes.get(resourceRuntimeId);

          if (existing) {
            return existing;
          }
          const scopes = responseList(
            await call({
              targetRole: allocation.role,
              method: 'GET',
              path: `resources/${encodeURIComponent(resourceRuntimeId)}/scopes`,
            })
          );
          resourceScopes.set(resourceRuntimeId, scopes);

          return scopes;
        };
        const entities = [];

        for (const [entityIndex, candidate] of allocation.entities.entries()) {
          const expectedEntity = expectedAllocation.entities[entityIndex];

          if (
            !expectedEntity ||
            expectedEntity.kind !== candidate.kind ||
            expectedEntity.logicalId !== candidate.logicalId
          ) {
            throw new Error(operationFailure);
          }
          const expectedSnapshot = responseRecord(expectedEntity.snapshot);

          switch (candidate.kind) {
            case 'tenant': {
              break;
            }
            case 'user': {
              const result = responseRecord(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: `users/${encodeURIComponent(candidate.runtimeId)}`,
                })
              );
              const applicationLogicalId = expectedSnapshot.applicationLogicalId;
              const expectedApplicationId =
                applicationLogicalId === null
                  ? null
                  : runtimeIdForLogical(allocation, 'application', safeText(applicationLogicalId));
              const expectedUsername = safeText(expectedSnapshot.username);
              const expectedPrimaryEmail =
                expectedSnapshot.primaryEmail === null
                  ? null
                  : namespacedEmail(safeText(expectedSnapshot.primaryEmail), namespace);
              const expectedPrimaryPhone =
                expectedSnapshot.primaryPhone === null ? null : namespacedPhone(namespace);
              const observedApplicationId = result.applicationId;
              const firstConsentApplicationLogicalId =
                allocation.role === 'data' &&
                candidate.logicalId === options.profile.fixtures.dataTenant.subject.id
                  ? options.profile.fixtures.dataTenant.applications.find(
                      ({ isThirdParty }) => isThirdParty
                    )?.id
                  : allocation.role === 'admin' &&
                      candidate.logicalId === options.profile.fixtures.adminTenant.operator.id
                    ? options.profile.fixtures.adminTenant.application.id
                    : undefined;
              const firstConsentApplicationId =
                expectedApplicationId === null && firstConsentApplicationLogicalId
                  ? runtimeIdForLogical(
                      allocation,
                      'application',
                      safeText(firstConsentApplicationLogicalId)
                    )
                  : undefined;

              if (
                (observedApplicationId !== null && typeof observedApplicationId !== 'string') ||
                (observedApplicationId !== expectedApplicationId &&
                  observedApplicationId !== firstConsentApplicationId)
              ) {
                throw new TypeError(invalidReferenceResponse);
              }
              const observedApplicationKey = `${allocation.allocationId}\u0000${candidate.logicalId}`;
              const hasPreviousObservedApplicationId =
                state.observedUserApplicationIds.has(observedApplicationKey);
              const previousObservedApplicationId =
                state.observedUserApplicationIds.get(observedApplicationKey);
              const isExpectedFirstConsentTransition =
                previousObservedApplicationId === null &&
                observedApplicationId === firstConsentApplicationId;

              if (
                hasPreviousObservedApplicationId &&
                previousObservedApplicationId !== observedApplicationId &&
                !isExpectedFirstConsentTransition
              ) {
                throw new TypeError(invalidReferenceResponse);
              }
              state.observedUserApplicationIds.set(observedApplicationKey, observedApplicationId);
              const expectedObservedApplicationId =
                observedApplicationId === firstConsentApplicationId
                  ? firstConsentApplicationId
                  : expectedApplicationId;
              assertObservedEquals(
                {
                  id: result.id,
                  username: result.username,
                  name: result.name,
                  primaryEmail: result.primaryEmail,
                  primaryPhone: result.primaryPhone,
                  profile: projectAddressProfile(result.profile),
                  applicationId: observedApplicationId,
                  customData: result.customData,
                  localAuthenticationPresent: result.hasPassword,
                },
                {
                  id: candidate.runtimeId,
                  username: namespacedUsername(expectedUsername, namespace),
                  name: expectedSnapshot.name,
                  primaryEmail: expectedPrimaryEmail,
                  primaryPhone: expectedPrimaryPhone,
                  profile: expectedSnapshot.profile,
                  applicationId: expectedObservedApplicationId,
                  customData: expectedSnapshot.customData,
                  localAuthenticationPresent: expectedSnapshot.localAuthenticationPresent,
                }
              );
              break;
            }
            case 'application': {
              const result = responseRecord(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: `applications/${encodeURIComponent(candidate.runtimeId)}`,
                })
              );
              const consent = responseRecord(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: `applications/${encodeURIComponent(candidate.runtimeId)}/user-consent-scopes`,
                })
              );
              const fixtureScopeIds = new Set(
                allocation.entities
                  .filter(({ kind }) => kind === 'scope')
                  .map(({ runtimeId }) => runtimeId)
              );
              const resourceScopeIds = responseList(consent.resourceScopes)
                .flatMap(({ scopes }) => responseList(scopes).map(({ id }) => responseId({ id })))
                .filter((scopeId) => fixtureScopeIds.has(scopeId))
                .toSorted();
              const expectedName = expectedSnapshot.name;
              const expectedConsent = responseRecord(expectedSnapshot.consent);
              const expectedUserScopes = responseStringList(expectedConsent.userScopes).toSorted();
              const expectedScopeRuntimeIds = (
                expectedConsent.resourceScopeLogicalIds as readonly unknown[]
              )
                .map((logicalId) => runtimeIdForLogical(allocation, 'scope', safeText(logicalId)))
                .toSorted();
              assertObservedEquals(
                {
                  id: result.id,
                  ...(expectedName === null ? {} : { name: result.name }),
                  type: result.type,
                  isThirdParty: result.isThirdParty,
                  oidcClientMetadata: result.oidcClientMetadata,
                  customClientMetadata: result.customClientMetadata,
                  consent: {
                    organizationScopes: consent.organizationScopes,
                    organizationResourceScopes: consent.organizationResourceScopes,
                    userScopes: responseStringList(consent.userScopes).toSorted(),
                    resourceScopeIds,
                  },
                },
                {
                  id: candidate.runtimeId,
                  ...(expectedName === null
                    ? {}
                    : { name: namespacedText(safeText(expectedName), namespace) }),
                  type: expectedSnapshot.type,
                  isThirdParty: expectedSnapshot.isThirdParty,
                  oidcClientMetadata: applicationOidcClientMetadataFromUnknown(
                    allocation.role,
                    expectedSnapshot.oidcClientMetadata
                  ),
                  customClientMetadata: expectedSnapshot.customClientMetadata,
                  consent: {
                    organizationScopes: [],
                    organizationResourceScopes: [],
                    userScopes: expectedUserScopes,
                    resourceScopeIds: expectedScopeRuntimeIds,
                  },
                }
              );

              break;
            }
            case 'resource': {
              const reserved =
                allocation.role === 'admin'
                  ? reservedAdminResourceProjection(options.profile, candidate.runtimeId)
                  : undefined;
              const result =
                reserved?.resource ??
                (allocation.role === 'admin'
                  ? findExactRecord(allResources, 'indicator', candidate.runtimeId)
                  : responseRecord(
                      await call({
                        targetRole: allocation.role,
                        method: 'GET',
                        path: `resources/${encodeURIComponent(candidate.runtimeId)}`,
                      })
                    ));
              const scopes = reserved
                ? reservedOrganizationScopes
                : await readResourceScopes(safeText(result.id));
              const expectedName = expectedSnapshot.name;
              const expectedIndicator = safeText(expectedSnapshot.indicator);
              const expectedScopeNames = (expectedSnapshot.scopeNames as readonly unknown[])
                .map(safeText)
                .toSorted();
              const observedScopeNames = scopes.map(({ name }) => safeText(name)).toSorted();
              assertObservedEquals(
                {
                  ...(allocation.role === 'data' ? { id: result.id } : {}),
                  ...(expectedName === null ? {} : { name: result.name }),
                  indicator: result.indicator,
                  scopeNames: observedScopeNames,
                },
                {
                  ...(allocation.role === 'data' ? { id: candidate.runtimeId } : {}),
                  ...(expectedName === null
                    ? {}
                    : { name: namespacedText(safeText(expectedName), namespace) }),
                  indicator:
                    allocation.role === 'data'
                      ? namespacedResourceIndicator(expectedIndicator, namespace)
                      : expectedIndicator,
                  scopeNames:
                    allocation.role === 'data'
                      ? expectedScopeNames.map((name) => namespacedText(name, namespace))
                      : expectedScopeNames,
                }
              );

              break;
            }
            case 'scope': {
              const resource = allocation.entities.find(({ kind }) => kind === 'resource');

              if (!resource) {
                throw new Error(operationFailure);
              }
              const result = findExactRecord(
                await readResourceScopes(resource.runtimeId),
                'id',
                candidate.runtimeId
              );
              assertObservedEquals(
                {
                  id: result.id,
                  name: result.name,
                  description: result.description,
                  resourceId: result.resourceId,
                },
                {
                  id: candidate.runtimeId,
                  name: namespacedText(safeText(expectedSnapshot.name), namespace),
                  description: expectedSnapshot.description,
                  resourceId: runtimeIdForLogical(
                    allocation,
                    'resource',
                    safeText(expectedSnapshot.resourceLogicalId)
                  ),
                }
              );

              break;
            }
            case 'role': {
              const result = responseRecord(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: `roles/${encodeURIComponent(candidate.runtimeId)}`,
                })
              );
              const fixtureScopeIds = new Set(
                allocation.entities
                  .filter(({ kind }) => kind === 'scope')
                  .map(({ runtimeId }) => runtimeId)
              );
              const fixtureUserIds = new Set(
                allocation.entities
                  .filter(({ kind }) => kind === 'user')
                  .map(({ runtimeId }) => runtimeId)
              );
              const observedScopeIds = recordIds(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: `roles/${encodeURIComponent(candidate.runtimeId)}/scopes`,
                })
              ).filter((scopeId) => fixtureScopeIds.has(scopeId));
              const observedUserIds = recordIds(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: `roles/${encodeURIComponent(candidate.runtimeId)}/users`,
                })
              ).filter((userId) => fixtureUserIds.has(userId));
              const expectedDescription = expectedSnapshot.description;
              const expectedIsDefault = expectedSnapshot.isDefault;
              assertObservedEquals(
                {
                  id: result.id,
                  name: result.name,
                  ...(expectedDescription === null ? {} : { description: result.description }),
                  type: result.type,
                  ...(expectedIsDefault === null ? {} : { isDefault: result.isDefault }),
                  scopeLogicalIds: logicalIdsForRuntimeIds(allocation, 'scope', observedScopeIds),
                  userLogicalIds: logicalIdsForRuntimeIds(allocation, 'user', observedUserIds),
                },
                {
                  id: candidate.runtimeId,
                  name:
                    allocation.role === 'data'
                      ? namespacedText(safeText(expectedSnapshot.name), namespace)
                      : expectedSnapshot.name,
                  ...(expectedDescription === null ? {} : { description: expectedDescription }),
                  type: expectedSnapshot.type,
                  ...(expectedIsDefault === null ? {} : { isDefault: expectedIsDefault }),
                  scopeLogicalIds: expectedSnapshot.scopeLogicalIds,
                  userLogicalIds: expectedSnapshot.userLogicalIds,
                }
              );

              break;
            }
            case 'organization': {
              const result = findExactRecord(allOrganizations, 'id', candidate.runtimeId);
              const memberUserIds = organizationMembers
                .map(({ id }) => responseId({ id }))
                .filter((userId) =>
                  allocation.entities.some(
                    (entity) => entity.kind === 'user' && entity.runtimeId === userId
                  )
                )
                .toSorted();
              const memberOrganizationRoleIds = memberUserIds
                .flatMap((userId) => memberOrganizationRoleIdsByUserId.get(userId) ?? [])
                .toSorted();
              assertObservedEquals(
                {
                  id: result.id,
                  name: result.name,
                  memberUserLogicalIds: logicalIdsForRuntimeIds(allocation, 'user', memberUserIds),
                  memberOrganizationRoleLogicalIds: logicalIdsForRuntimeIds(
                    allocation,
                    'organization-role',
                    memberOrganizationRoleIds
                  ),
                },
                {
                  id: candidate.runtimeId,
                  name: expectedSnapshot.name,
                  memberUserLogicalIds: expectedSnapshot.memberUserLogicalIds,
                  memberOrganizationRoleLogicalIds:
                    expectedSnapshot.memberOrganizationRoleLogicalIds,
                }
              );

              break;
            }
            default: {
              const result = findExactRecord(allOrganizationRoles, 'id', candidate.runtimeId);
              const expectedScopeNames = (expectedSnapshot.scopeNames as readonly unknown[])
                .map(safeText)
                .toSorted();
              const expectedScopeNameSet = new Set(expectedScopeNames);
              const scopeNames = responseList(
                await call({
                  targetRole: allocation.role,
                  method: 'GET',
                  path: `organization-roles/${encodeURIComponent(candidate.runtimeId)}/scopes`,
                })
              )
                .map(({ name }) => safeText(name))
                .filter((name) => expectedScopeNameSet.has(name))
                .toSorted();
              const userIds = [...memberOrganizationRoleIdsByUserId.entries()]
                .filter(([, roleIds]) => roleIds.includes(candidate.runtimeId))
                .map(([userId]) => userId)
                .toSorted();
              assertObservedEquals(
                {
                  id: result.id,
                  name: result.name,
                  type: result.type,
                  scopeNames,
                  userLogicalIds: logicalIdsForRuntimeIds(allocation, 'user', userIds),
                },
                {
                  id: candidate.runtimeId,
                  name: expectedSnapshot.name,
                  type: expectedSnapshot.type,
                  scopeNames: expectedScopeNames,
                  userLogicalIds: expectedSnapshot.userLogicalIds,
                }
              );
            }
          }
          entities.push({
            kind: candidate.kind,
            logicalId: candidate.logicalId,
            snapshot: expectedEntity.snapshot,
          });
        }
        allocations.push({
          role: allocation.role,
          target: allocation.target,
          signInExperience: expectedAllocation.signInExperience,
          entities,
        });
      }

      try {
        const projection = createPhase1FixtureStateProjection(
          { schemaVersion: 1, recipe: state.recipe, allocations },
          fixture.public,
          options.profile
        );
        assertObservedEquals(projection, expectedProjection);
        assertPhase1RuntimeCredentialGraphIsSanitized(projection);
        return projection;
      } catch {
        throw new Error(operationFailure);
      }
    },

    readUserActivityState: async (fixture: ProvisionedPhase1Fixture, logicalUserId: string) => {
      if (!states.has(fixture as object)) {
        throw new TypeError('Unknown reference fixture');
      }
      const { targetRole, runtimeUserId } = resolvePhase1FixtureUserActivityTarget(
        fixture,
        logicalUserId
      );
      const user = responseRecord(
        await call({
          targetRole,
          method: 'GET',
          path: `users/${encodeURIComponent(runtimeUserId)}`,
        })
      );
      try {
        assertPhase1RuntimeCredentialGraphIsSanitized(user);
      } catch {
        throw new TypeError(invalidReferenceResponse);
      }

      return projectPhase1UserActivityTimestamp(user.lastSignInAt);
    },

    cleanup: async (fixture: ProvisionedPhase1Fixture): Promise<void> => {
      const state = states.get(fixture as object);

      if (!state) {
        throw new TypeError('Unknown reference fixture');
      }
      await cleanupState(state, fixture);
    },
  });
};

/* eslint-enable max-lines, complexity, max-params, no-restricted-syntax, @silverhand/fp/no-mutating-methods, import/order, no-control-regex, unicorn/escape-case, @typescript-eslint/no-unnecessary-condition, prefer-destructuring, @typescript-eslint/array-type, unicorn/no-array-callback-reference, @typescript-eslint/ban-types, no-await-in-loop, @typescript-eslint/no-non-null-assertion, @silverhand/fp/no-mutation, @silverhand/fp/no-let, unicorn/catch-error-name */
