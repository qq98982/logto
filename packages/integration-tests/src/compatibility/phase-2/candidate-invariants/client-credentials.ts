/* eslint-disable max-lines, no-restricted-syntax, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, unicorn/consistent-function-scoping -- This candidate-only boundary owns an exact private driver protocol, per-invariant invocation closures, four closed projections, and their positive/negative controls. */
import { constants as fsConstants } from 'node:fs';
import { access, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { TargetConfig } from '../../model.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../../phase-1/clients/command-provisioner.js';
import { phase2InvariantRequestKind, phase2InvariantTerminalKind } from '../driver-protocol.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2CandidateInvariantId, Phase2ProfileRegistries } from '../profile.js';
import { assertClientCredentialsEvidenceIsSanitized } from '../projections/client-credentials.js';
import type { Phase2TopologyIdentity } from '../provenance.js';
import type { Phase2InvocationFence } from '../runtime.js';

export const clientCredentialsCandidateInvariantIds = Object.freeze([
  'client-credentials.cross-tenant-authority-rejected',
  'client-credentials.request-role-write-rejected',
  'client-credentials.signing-failure-rolls-back',
  'client-credentials.user-authority-unchanged',
  'logout-session.verification-storage-closed',
] as const satisfies readonly Phase2CandidateInvariantId[]);

type ClientCredentialsCandidateInvariantId =
  (typeof clientCredentialsCandidateInvariantIds)[number];

export type ClientCredentialsCandidateInvariantProjection =
  | Readonly<{
      invariant: 'cross-tenant-authority-rejected';
      foreignCredential: 'rejected';
      response: Readonly<{ status: 400; error: 'invalid_client' }>;
      primaryAuthority: 'unchanged';
      foreignSigningUse: 'unchanged';
    }>
  | Readonly<{
      invariant: 'request-role-write-rejected';
      role: 'aster_request';
      insert: 'rejected';
      update: 'rejected';
      delete: 'rejected';
      authority: 'unchanged';
    }>
  | Readonly<{
      invariant: 'signing-failure-rolls-back';
      response: Readonly<{ status: 503; error: 'temporarily_unavailable' }>;
      credentialAccepted: true;
      tokenPublished: false;
      signingUse: 'unchanged';
      authority: 'unchanged';
    }>
  | Readonly<{
      invariant: 'user-authority-unchanged';
      successfulMachineGrant: true;
      users: 'unchanged';
      sessions: 'unchanged';
      grants: 'unchanged';
      authorizationCodes: 'unchanged';
      interactions: 'unchanged';
    }>
  | Readonly<{
      invariant: 'verification-storage-closed';
      forcedRls: true;
      clearMaterial: 'absent';
      requestPrivileges: 'insert-select';
      records: 'empty';
    }>;

export type CandidateInvariantControlEvidence = Readonly<{
  id: ClientCredentialsCandidateInvariantId;
  candidate: ClientCredentialsCandidateInvariantProjection;
  positiveControl: Readonly<{ detected: true }>;
  negativeControl: Readonly<{ detected: true; pointer: string }>;
}>;

export type CandidateInvariantDriverOptions = Readonly<{
  target: TargetConfig;
  foreignTarget: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  driverPath: string;
  controlSocket: string;
  topology?: Phase2TopologyIdentity;
  identityFence?: Phase2InvocationFence;
  environment?: Readonly<Record<string, string | undefined>>;
  runner?: (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;
}>;

const diagnostic = 'Invalid Phase 2 candidate invariant';
const maximumOutputBytes = 65_536;
const timeoutMs = 120_000;
const terminalKeys = Object.freeze([
  'schemaVersion',
  'kind',
  'invariantId',
  'projection',
  'attestation',
]);
const resultKeys = Object.freeze([
  'exitCode',
  'signal',
  'stdout',
  'stderr',
  'timedOut',
  'killed',
  'reaped',
]);
const allowedSensitiveFactKeys = new Set(['authorizationCodes', 'tokenPublished']);
const forbiddenEvidenceKey =
  /(?:client.?secret|access.?token|refresh.?token|id.?token|authorization|cookie|private.?key|sql|raw.?log|hash|digest)/iu;

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const record = (value: unknown): Record<string, unknown> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.prototype.toString.call(value) !== '[object Object]'
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

const exactRecord = (value: unknown, keys: readonly string[]): Record<string, unknown> => {
  const result = record(value);
  const actual = Object.keys(result);
  return actual.length === keys.length && actual.every((key) => keys.includes(key))
    ? result
    : fail();
};

const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.getOwnPropertyDescriptor(value, key)?.value;

const expectedProjections: Readonly<
  Record<ClientCredentialsCandidateInvariantId, ClientCredentialsCandidateInvariantProjection>
> = Object.freeze({
  'client-credentials.cross-tenant-authority-rejected': Object.freeze({
    invariant: 'cross-tenant-authority-rejected',
    foreignCredential: 'rejected',
    response: Object.freeze({ status: 400, error: 'invalid_client' }),
    primaryAuthority: 'unchanged',
    foreignSigningUse: 'unchanged',
  }),
  'client-credentials.request-role-write-rejected': Object.freeze({
    invariant: 'request-role-write-rejected',
    role: 'aster_request',
    insert: 'rejected',
    update: 'rejected',
    delete: 'rejected',
    authority: 'unchanged',
  }),
  'client-credentials.signing-failure-rolls-back': Object.freeze({
    invariant: 'signing-failure-rolls-back',
    response: Object.freeze({ status: 503, error: 'temporarily_unavailable' }),
    credentialAccepted: true,
    tokenPublished: false,
    signingUse: 'unchanged',
    authority: 'unchanged',
  }),
  'client-credentials.user-authority-unchanged': Object.freeze({
    invariant: 'user-authority-unchanged',
    successfulMachineGrant: true,
    users: 'unchanged',
    sessions: 'unchanged',
    grants: 'unchanged',
    authorizationCodes: 'unchanged',
    interactions: 'unchanged',
  }),
  'logout-session.verification-storage-closed': Object.freeze({
    invariant: 'verification-storage-closed',
    forcedRls: true,
    clearMaterial: 'absent',
    requestPrivileges: 'insert-select',
    records: 'empty',
  }),
});

const negativePointers: Readonly<Record<ClientCredentialsCandidateInvariantId, string>> =
  Object.freeze({
    'client-credentials.cross-tenant-authority-rejected': '/foreignCredential',
    'client-credentials.request-role-write-rejected': '/insert',
    'client-credentials.signing-failure-rolls-back': '/tokenPublished',
    'client-credentials.user-authority-unchanged': '/users',
    'logout-session.verification-storage-closed': '/clearMaterial',
  });

const assertInvariantEvidenceSafe = (value: unknown, secrets: readonly string[]): void => {
  const inspect = (current: unknown, seen: WeakSet<object>): void => {
    if (typeof current === 'string') {
      if (
        secrets.some((secret) => current.includes(secret)) ||
        /\b(?:Basic|Bearer)\s+[A-Za-z0-9._~+/-]+=*/u.test(current)
      ) {
        return fail();
      }
      return;
    }
    if (current === null || typeof current !== 'object') {
      return;
    }
    if (seen.has(current)) {
      return fail();
    }
    seen.add(current);
    if (Array.isArray(current)) {
      for (const entry of current) {
        inspect(entry, seen);
      }
      return;
    }
    const object = record(current);
    if (
      Object.keys(object).some(
        (key) => forbiddenEvidenceKey.test(key) && !allowedSensitiveFactKeys.has(key)
      )
    ) {
      return fail();
    }
    for (const nested of Object.values(object)) {
      inspect(nested, seen);
    }
  };
  inspect(value, new WeakSet());
  assertClientCredentialsEvidenceIsSanitized(value);
};

const validateExecutable = async (value: string): Promise<string> => {
  if (!path.isAbsolute(value) || path.normalize(value) !== value) {
    return fail();
  }
  const [state, resolved] = await Promise.all([lstat(value), realpath(value)]).catch(fail);
  if (state.isSymbolicLink() || !state.isFile() || resolved !== value) {
    return fail();
  }
  await access(value, fsConstants.X_OK).catch(fail);
  return value;
};

const validateSocketPath = (value: string): string =>
  path.isAbsolute(value) && path.normalize(value) === value && Buffer.byteLength(value) <= 4096
    ? value
    : fail();

const validateTargetPair = (primary: TargetConfig, foreign: TargetConfig): void => {
  if (
    primary.label !== 'candidate' ||
    foreign.label !== 'candidate' ||
    primary.coreUrl === foreign.coreUrl ||
    primary.adminUrl === foreign.adminUrl
  ) {
    fail();
  }
};

const requireResult = (value: unknown): CommandRunnerResult => {
  const result = exactRecord(value, resultKeys);
  const stdout = own(result, 'stdout');
  const stderr = own(result, 'stderr');
  if (
    own(result, 'exitCode') !== 0 ||
    own(result, 'signal') !== null ||
    typeof stdout !== 'string' ||
    typeof stderr !== 'string' ||
    stderr !== '' ||
    Buffer.byteLength(stdout) > maximumOutputBytes ||
    Buffer.byteLength(stderr) > maximumOutputBytes ||
    own(result, 'timedOut') !== false ||
    own(result, 'killed') !== false ||
    own(result, 'reaped') !== true
  ) {
    return fail();
  }
  return value as CommandRunnerResult;
};

const parseTerminal = (
  stdout: string,
  id: ClientCredentialsCandidateInvariantId,
  secrets: readonly string[],
  topology: Phase2TopologyIdentity
): ClientCredentialsCandidateInvariantProjection => {
  if (stdout.length === 0 || /[\r\n]/u.test(stdout)) {
    return fail();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout) as unknown;
  } catch {
    return fail();
  }
  const terminal = exactRecord(parsed, terminalKeys);
  if (
    own(terminal, 'schemaVersion') !== 1 ||
    own(terminal, 'kind') !== phase2InvariantTerminalKind ||
    own(terminal, 'invariantId') !== id ||
    JSON.stringify(own(terminal, 'attestation')) !== JSON.stringify(topology)
  ) {
    return fail();
  }
  const projection = own(terminal, 'projection');
  assertInvariantEvidenceSafe(projection, secrets);
  if (!isDeepStrictEqual(projection, expectedProjections[id])) {
    return fail();
  }
  return projection as ClientCredentialsCandidateInvariantProjection;
};

const mutation = (
  id: ClientCredentialsCandidateInvariantId,
  projection: ClientCredentialsCandidateInvariantProjection
): unknown => {
  const copy = JSON.parse(JSON.stringify(projection)) as Record<string, unknown>;
  switch (id) {
    case 'client-credentials.cross-tenant-authority-rejected': {
      copy.foreignCredential = 'accepted';
      break;
    }
    case 'client-credentials.request-role-write-rejected': {
      copy.insert = 'accepted';
      break;
    }
    case 'client-credentials.signing-failure-rolls-back': {
      copy.tokenPublished = true;
      break;
    }
    case 'client-credentials.user-authority-unchanged': {
      copy.users = 'changed';
      break;
    }
    case 'logout-session.verification-storage-closed': {
      copy.clearMaterial = 'present';
      break;
    }
  }
  return copy;
};

const differencePointer = (
  expected: unknown,
  actual: unknown,
  pointer = ''
): string | undefined => {
  if (isDeepStrictEqual(expected, actual)) {
    return undefined;
  }
  if (recordLike(expected) && recordLike(actual)) {
    for (const key of [...new Set([...Object.keys(expected), ...Object.keys(actual)])].toSorted()) {
      const nested = differencePointer(
        expected[key],
        actual[key],
        `${pointer}/${key.replaceAll('~', '~0').replaceAll('/', '~1')}`
      );
      if (nested) {
        return nested;
      }
    }
  }
  return pointer || '/';
};

const recordLike = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export const runClientCredentialsCandidateInvariantControls = (
  id: ClientCredentialsCandidateInvariantId,
  candidate: ClientCredentialsCandidateInvariantProjection
): CandidateInvariantControlEvidence => {
  const expected = expectedProjections[id];
  if (!isDeepStrictEqual(candidate, expected)) {
    return fail();
  }
  const pointer = differencePointer(expected, mutation(id, expected));
  if (pointer !== negativePointers[id]) {
    return fail();
  }
  const evidence = Object.freeze({
    id,
    candidate,
    positiveControl: Object.freeze({ detected: true as const }),
    negativeControl: Object.freeze({ detected: true as const, pointer }),
  });
  assertInvariantEvidenceSafe(evidence, []);
  return evidence;
};

export const runClientCredentialsCandidateInvariants = async (
  profile: Phase2ProfileRegistries,
  options: CandidateInvariantDriverOptions
): Promise<readonly CandidateInvariantControlEvidence[]> => {
  if (
    profile.candidateInvariantScenarios.length !== clientCredentialsCandidateInvariantIds.length ||
    profile.candidateInvariantScenarios.some(
      (id, index) => id !== clientCredentialsCandidateInvariantIds[index]
    )
  ) {
    return fail();
  }
  const start = profile.candidateInvariantScenarios.indexOf(
    clientCredentialsCandidateInvariantIds[0]
  );
  const segment = profile.candidateInvariantScenarios.slice(
    start,
    start + clientCredentialsCandidateInvariantIds.length
  );
  if (
    start < 0 ||
    segment.length !== clientCredentialsCandidateInvariantIds.length ||
    segment.some((id, index) => id !== clientCredentialsCandidateInvariantIds[index])
  ) {
    return fail();
  }
  validateTargetPair(options.target, options.foreignTarget);
  const driverPath = await validateExecutable(options.driverPath);
  const controlSocket = validateSocketPath(options.controlSocket);
  const runner = options.runner ?? runPhase1FixtureCommand;
  const environment = Object.freeze({
    ASTER_PHASE2_CONTROL_SOCKET: controlSocket,
    ASTER_CORE_URL: options.target.coreUrl,
    ASTER_ADMIN_URL: options.target.adminUrl,
    ASTER_FOREIGN_CORE_URL: options.foreignTarget.coreUrl,
    ASTER_FOREIGN_ADMIN_URL: options.foreignTarget.adminUrl,
    LC_ALL: 'C',
  });
  const results: CandidateInvariantControlEvidence[] = [];

  await options.fixture.withSecretLease(async (lease) => {
    const secrets = Object.freeze([lease.getClientSecret('basic'), lease.getClientSecret('post')]);
    for (const id of clientCredentialsCandidateInvariantIds) {
      const descriptor = Object.freeze({
        schemaVersion: 1,
        kind: phase2InvariantRequestKind,
        invariantId: id,
        target: Object.freeze({
          primary: options.target,
          foreign: options.foreignTarget,
        }),
        fixture: options.fixture.public,
        credentials: Object.freeze({
          basic: secrets[0],
          post: secrets[1],
        }),
      });
      const invoke = async () =>
        requireResult(
          await runner({
            command: driverPath,
            args: Object.freeze([]),
            stdin: JSON.stringify(descriptor),
            env: environment,
            timeoutMs,
            maxStdoutBytes: maximumOutputBytes,
            maxStderrBytes: maximumOutputBytes,
            shell: false,
          })
        );
      const raw = options.identityFence ? await options.identityFence.run(invoke) : await invoke();
      assertInvariantEvidenceSafe({ stdout: raw.stdout, stderr: raw.stderr }, secrets);
      const projection = parseTerminal(raw.stdout, id, secrets, options.topology ?? fail());
      results.push(runClientCredentialsCandidateInvariantControls(id, projection));
    }
  });
  return Object.freeze(results);
};

export const clientCredentialsCandidateInvariantExpectedProjection = (
  id: ClientCredentialsCandidateInvariantId
): ClientCredentialsCandidateInvariantProjection => expectedProjections[id];

/* eslint-enable max-lines, no-restricted-syntax, no-await-in-loop, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/ban-types, unicorn/consistent-function-scoping */
