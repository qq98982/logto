/* eslint-disable max-lines, max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types -- This bounded parser and file-identity boundary is cohesive, and its explicit nulls model the JSON lock contract. */
import { createHash, timingSafeEqual } from 'node:crypto';
import { constants, existsSync, readFileSync, realpathSync, type Stats } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Ajv2020, type AnySchema, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import * as addFormatsModule from 'ajv-formats';
import { getLocation, parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';
import { z } from 'zod';

import { phase1ProfileSchemaLock } from './profile-lock.js';
import type {
  Phase1Profile,
  Phase1ProfilePaths,
  Phase1ProfileSchemaLock,
  Phase1ProfileValidationStage,
} from './profile-types.js';

export type {
  Phase1Profile,
  Phase1ProfilePaths,
  Phase1ProfileSchemaLock,
  Phase1ProfileSemanticContext,
  Phase1ProfileValidationStage,
  Phase1ProvenanceMode,
} from './profile-types.js';

const maximumProfileBytes = 1024 * 1024;
const maximumSchemaBytes = 1024 * 1024;
const maximumNestingDepth = 256;
const maximumStructuralTokens = 20_000;
const commitPattern = /^[\da-f]{40}$/u;
const sha256Pattern = /^[\da-f]{64}$/u;
const dangerousPropertyNames = new Set(['__proto__', 'constructor', 'prototype']);
const validationMessages = {
  json: 'Invalid Phase 1 JSON',
  'schema-hash': 'Invalid Phase 1 schema hash',
  schema: 'Invalid Phase 1 schema',
  semantic: 'Invalid Phase 1 semantics',
  provenance: 'Invalid Phase 1 provenance',
} as const satisfies Record<Phase1ProfileValidationStage, string>;

const phase0AuthorityBlobPaths = [
  'compatibility/baseline-manifest.json',
  'docker-compose.compatibility.yml',
  '.scripts/compatibility/run.sh',
  'packages/integration-tests/src/compatibility/model.ts',
  'packages/integration-tests/src/compatibility/scenario.ts',
  'packages/integration-tests/src/compatibility/config.ts',
  'packages/integration-tests/src/compatibility/target-client.ts',
  'packages/integration-tests/src/compatibility/normalize.ts',
  'packages/integration-tests/src/compatibility/compare.ts',
  'packages/integration-tests/src/compatibility/evidence.ts',
  'packages/integration-tests/src/compatibility/cli.ts',
  'packages/integration-tests/src/compatibility/scenarios/index.ts',
] as const;

type LockBearingProfile = Readonly<{
  profileSchema: Readonly<{
    sourceCommit: string | null;
    sha256: string | null;
  }>;
  phase1Harness: Readonly<{
    commit: string | null;
  }>;
}>;

export type Phase1InputFileState = Readonly<{
  device: number;
  inode: number;
  mode: number;
  size: number;
  modifiedMilliseconds: number;
  isFile: boolean;
  isSymbolicLink: boolean;
}>;

type Phase1OpenedInputFile = Readonly<{
  getState: () => Promise<Phase1InputFileState>;
  read: (buffer: Uint8Array, offset: number, position: number) => Promise<number>;
  close: () => Promise<void>;
}>;

type Phase1ProfileFileSystem = Readonly<{
  getPathState: (filePath: string) => Promise<Phase1InputFileState>;
  getRealPath: (filePath: string) => Promise<string>;
  openFile: (filePath: string) => Promise<Phase1OpenedInputFile>;
}>;

export type Phase1ProfileLoaderDependencies<Profile extends LockBearingProfile = Phase1Profile> =
  Readonly<{
    assertSemantics: (profile: Profile) => void;
    assertProvenance: (profile: Profile) => Promise<void>;
    fileSystem: Partial<Phase1ProfileFileSystem>;
  }>;

export type Phase1ProfileBundle<Profile extends LockBearingProfile = Phase1Profile> = Readonly<{
  profile: Readonly<Profile>;
  profileSha256: string;
  schemaSha256: string;
  readProfileBytes: () => Uint8Array;
  readSchemaBytes: () => Uint8Array;
}>;

const validatedPhase1ProfileBundles = new WeakSet<object>();

export function assertValidatedPhase1ProfileBundle(
  value: unknown
): asserts value is Phase1ProfileBundle {
  if (typeof value !== 'object' || value === null || !validatedPhase1ProfileBundles.has(value)) {
    throw new TypeError('Invalid Phase 1 profile bundle');
  }
}

export type Phase1SchemaLockDocument = Readonly<{
  schemaVersion: 1;
  phase0BaseCommit: string;
  schemaSourceCommit: string;
  schemaSha256: string;
  phase0AuthorityBlobs: Readonly<Record<(typeof phase0AuthorityBlobPaths)[number], string>>;
}>;

export class Phase1ProfileValidationError extends Error {
  readonly stage: Phase1ProfileValidationStage;
  readonly pointers: readonly string[];
  readonly rules: readonly string[];

  constructor(
    stage: Phase1ProfileValidationStage,
    pointers: readonly string[] = ['/'],
    rules: readonly string[] = []
  ) {
    super(validationMessages[stage]);
    this.name = 'Phase1ProfileValidationError';
    this.stage = stage;
    const uniquePointers = [...new Set(pointers)];
    const uniqueRules = [...new Set(rules)];
    // These arrays are fresh constructor-local values, so in-place sorting cannot escape.
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods
    this.pointers = Object.freeze(uniquePointers.sort());
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods
    this.rules = Object.freeze(uniqueRules.sort());
  }
}

const fail = (
  stage: Phase1ProfileValidationStage,
  pointers: readonly string[] = ['/'],
  rules: readonly string[] = []
): never => {
  throw new Phase1ProfileValidationError(stage, pointers, rules);
};

const escapePointerToken = (token: string | number) =>
  String(token).replaceAll('~', '~0').replaceAll('/', '~1');

const toPointer = (tokens: ReadonlyArray<string | number>) =>
  tokens.length === 0 ? '/' : `/${tokens.map((token) => escapePointerToken(token)).join('/')}`;

const appendPointer = (pointer: string, token: string | number) =>
  pointer === '/' ? `/${escapePointerToken(token)}` : `${pointer}/${escapePointerToken(token)}`;

type CanonicalDecimal = Readonly<{
  negative: boolean;
  digits: string;
  exponent: number;
}>;

const jsonNumberPattern =
  /^(?<negative>-?)(?<integer>0|[1-9]\d*)(?:\.(?<fraction>\d+))?(?:[eE](?<exponent>[+-]?\d+))?$/u;
const pureJsonIntegerPattern = /^-?(?:0|[1-9]\d*)$/u;

const parseBoundedDecimalExponent = (rawExponent: string | undefined) => {
  if (rawExponent === undefined) {
    return 0;
  }

  const negative = rawExponent.startsWith('-');
  const unsignedExponent = /^[+-]/u.test(rawExponent) ? rawExponent.slice(1) : rawExponent;
  const significantExponent = unsignedExponent.replace(/^0+/u, '');

  if (significantExponent.length === 0) {
    return 0;
  }

  if (significantExponent.length > 7) {
    return null;
  }

  const magnitude = Number(significantExponent);

  if (!Number.isSafeInteger(magnitude) || magnitude > maximumProfileBytes) {
    return null;
  }

  return negative ? -magnitude : magnitude;
};

const canonicalizeDecimal = (lexicalValue: string): CanonicalDecimal | null => {
  const match = jsonNumberPattern.exec(lexicalValue);

  if (!match?.groups) {
    return null;
  }

  const fraction = match.groups.fraction ?? '';
  const rawDigits = `${match.groups.integer ?? ''}${fraction}`;
  const firstSignificantIndex = rawDigits.search(/[1-9]/u);

  if (firstSignificantIndex === -1) {
    return {
      negative: match.groups.negative === '-',
      digits: '0',
      exponent: 0,
    };
  }

  const explicitExponent = parseBoundedDecimalExponent(match.groups.exponent);

  if (explicitExponent === null) {
    return null;
  }

  const significantDigits = rawDigits.slice(firstSignificantIndex);
  const trailingZeroCount = /0+$/u.exec(significantDigits)?.[0].length ?? 0;

  return {
    negative: match.groups.negative === '-',
    digits:
      trailingZeroCount === 0 ? significantDigits : significantDigits.slice(0, -trailingZeroCount),
    exponent: explicitExponent - fraction.length + trailingZeroCount,
  };
};

// eslint-disable-next-line complexity -- Diagnostic priority distinguishes pure integers, unsafe parsed integers, and lossy decimals.
const classifyJsonNumber = (lexicalValue: string): 'lossless' | 'lossy' | 'unsafe-integer' => {
  const numericValue = Number(lexicalValue);

  if (pureJsonIntegerPattern.test(lexicalValue)) {
    const unsignedLength = lexicalValue.startsWith('-')
      ? lexicalValue.length - 1
      : lexicalValue.length;

    return unsignedLength > 16 || !Number.isSafeInteger(numericValue)
      ? 'unsafe-integer'
      : 'lossless';
  }

  if (Number.isInteger(numericValue) && !Number.isSafeInteger(numericValue)) {
    return 'unsafe-integer';
  }

  const canonicalInput = canonicalizeDecimal(lexicalValue);

  if (!canonicalInput || !Number.isFinite(numericValue)) {
    return 'lossy';
  }

  const roundTripLexical = Object.is(numericValue, -0) ? '-0' : numericValue.toString();
  const canonicalRoundTrip = canonicalizeDecimal(roundTripLexical);

  if (
    !canonicalRoundTrip ||
    canonicalInput.negative !== canonicalRoundTrip.negative ||
    canonicalInput.digits !== canonicalRoundTrip.digits ||
    canonicalInput.exponent !== canonicalRoundTrip.exponent
  ) {
    return 'lossy';
  }

  return 'lossless';
};

// eslint-disable-next-line complexity -- Every branch represents one strict JSON lexical state transition.
const enforceLexicalBudgets = (source: string): void => {
  let depth = 0;
  let escaped = false;
  let insidePrimitive = false;
  let insideString = false;
  let tokenCount = 0;

  for (const character of source) {
    if (insideString) {
      if (escaped) {
        escaped = false;
      } else if (character === '\\') {
        escaped = true;
      } else if (character === '"') {
        insideString = false;
      }

      continue;
    }

    switch (character) {
      case '"': {
        insidePrimitive = false;
        insideString = true;
        tokenCount += 1;
        break;
      }
      case '{':
      case '[': {
        insidePrimitive = false;
        depth += 1;
        tokenCount += 1;

        if (depth > maximumNestingDepth) {
          fail('json', ['/'], ['maximum-depth']);
        }

        break;
      }
      case '}':
      case ']': {
        insidePrimitive = false;
        depth -= 1;
        tokenCount += 1;
        break;
      }
      case ',':
      case ':': {
        insidePrimitive = false;
        tokenCount += 1;
        break;
      }
      default: {
        if (/\s/u.test(character)) {
          insidePrimitive = false;
        } else if (!insidePrimitive) {
          insidePrimitive = true;
          tokenCount += 1;
        }
      }
    }

    if (tokenCount > maximumStructuralTokens) {
      fail('json', ['/'], ['maximum-tokens']);
    }
  }
};

// eslint-disable-next-line complexity -- Object, array, and numeric JSON nodes require distinct security checks.
const inspectJsonNode = (
  node: JsonNode | undefined,
  source: string,
  pointer: Array<string | number> = []
) => {
  if (!node) {
    throw new Phase1ProfileValidationError('json', ['/'], ['syntax']);
  }

  if (node.type === 'object') {
    const propertyNames = new Set<string>();

    for (const property of node.children ?? []) {
      const [nameNode, valueNode] = property.children ?? [];
      const name: unknown = nameNode?.value;

      if (typeof name !== 'string') {
        throw new Phase1ProfileValidationError('json', [toPointer(pointer)], ['syntax']);
      }

      const propertyPointer = [...pointer, name];

      if (propertyNames.has(name)) {
        fail('json', [toPointer(propertyPointer)], ['duplicate-property']);
      }

      if (dangerousPropertyNames.has(name)) {
        fail('json', [toPointer(propertyPointer)], ['dangerous-property']);
      }

      propertyNames.add(name);
      inspectJsonNode(valueNode, source, propertyPointer);
    }

    return;
  }

  if (node.type === 'array') {
    for (const [index, child] of (node.children ?? []).entries()) {
      inspectJsonNode(child, source, [...pointer, index]);
    }

    return;
  }

  if (node.type === 'number') {
    const lexicalValue = source.slice(node.offset, node.offset + node.length);
    const classification = classifyJsonNumber(lexicalValue);

    if (classification === 'unsafe-integer') {
      fail('json', [toPointer(pointer)], ['unsafe-integer']);
    }

    if (classification === 'lossy') {
      fail('json', [toPointer(pointer)], ['lossy-number']);
    }
  }
};

const parseErrorPointer = (source: string, errors: readonly ParseError[]) => {
  try {
    return toPointer(getLocation(source, errors[0]?.offset ?? 0).path);
  } catch {
    return '/';
  }
};

// eslint-disable-next-line complexity -- Strict JSON decoding keeps all bounded failure classes in one boundary.
const parseStrictJson = (bytes: Uint8Array, maximumBytes: number): unknown => {
  if (bytes.length === 0 || bytes.length > maximumBytes) {
    fail('json', ['/'], [bytes.length === 0 ? 'empty-input' : 'maximum-bytes']);
  }

  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail('json', ['/'], ['syntax']);
  }

  const source = (() => {
    try {
      return new TextDecoder('utf8', { fatal: true }).decode(bytes);
    } catch {
      return fail('json', ['/'], ['syntax']);
    }
  })();

  enforceLexicalBudgets(source);
  const errors: ParseError[] = [];
  let root: JsonNode | undefined;

  try {
    root = parseTree(source, errors, {
      allowEmptyContent: false,
      allowTrailingComma: false,
      disallowComments: true,
    });
  } catch {
    fail('json', ['/'], ['syntax']);
  }

  if (!root || errors.length > 0) {
    throw new Phase1ProfileValidationError('json', [parseErrorPointer(source, errors)], ['syntax']);
  }

  inspectJsonNode(root, source);

  try {
    const parsed: unknown = JSON.parse(source);

    return parsed;
  } catch {
    fail('json', ['/'], ['syntax']);
  }
};

const toInputFileState = (state: Stats): Phase1InputFileState => ({
  device: state.dev,
  inode: state.ino,
  mode: state.mode,
  size: state.size,
  modifiedMilliseconds: state.mtimeMs,
  isFile: state.isFile(),
  isSymbolicLink: state.isSymbolicLink(),
});

const defaultFileSystem: Phase1ProfileFileSystem = {
  getPathState: async (filePath) => toInputFileState(await lstat(filePath)),
  getRealPath: realpath,
  openFile: async (filePath) => {
    // O_NOFOLLOW is part of the reviewed final-component symlink defense.
    // eslint-disable-next-line no-bitwise
    const handle = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);

    return {
      getState: async () => toInputFileState(await handle.stat({ bigint: false })),
      read: async (buffer, offset, position) => {
        const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, position);

        return bytesRead;
      },
      close: async () => handle.close(),
    };
  },
};

const sameFileIdentity = (left: Phase1InputFileState, right: Phase1InputFileState) =>
  left.device === right.device && left.inode === right.inode;

const sameFileSnapshot = (left: Phase1InputFileState, right: Phase1InputFileState) =>
  sameFileIdentity(left, right) &&
  left.size === right.size &&
  left.modifiedMilliseconds === right.modifiedMilliseconds;

const assertRegularFileState = (state: Phase1InputFileState, pointer: string) => {
  if (!state.isFile || state.isSymbolicLink) {
    fail('json', [pointer], ['regular-file']);
  }
};

const readToBoundedBuffer = async (
  openedFile: Phase1OpenedInputFile,
  maximumBytes: number,
  pointer: '/schema' | '/profile'
) => {
  const boundedBuffer = Buffer.allocUnsafe(maximumBytes + 1);
  let totalBytesRead = 0;

  while (totalBytesRead < boundedBuffer.length) {
    const remainingBytes = boundedBuffer.length - totalBytesRead;
    // Reads must remain sequential so each returned chunk has a stable file position.
    // eslint-disable-next-line no-await-in-loop
    const bytesRead = await openedFile.read(boundedBuffer, totalBytesRead, totalBytesRead);

    if (!Number.isSafeInteger(bytesRead) || bytesRead < 0 || bytesRead > remainingBytes) {
      fail('json', [pointer], ['file-changed']);
    }

    if (bytesRead === 0) {
      break;
    }

    totalBytesRead += bytesRead;

    if (totalBytesRead > maximumBytes) {
      fail('json', [pointer], ['maximum-bytes']);
    }
  }

  return {
    bytes: boundedBuffer.subarray(0, totalBytesRead),
    bytesRead: totalBytesRead,
  };
};

// eslint-disable-next-line complexity -- Identity, size, and cleanup checks are one TOCTOU boundary.
const readBoundedRegularFile = async (
  filePath: string,
  pointer: '/schema' | '/profile',
  maximumBytes: number,
  overrides: Partial<Phase1ProfileFileSystem>
) => {
  const fileSystem = { ...defaultFileSystem, ...overrides };
  let openedFile: Phase1OpenedInputFile | undefined;

  try {
    const resolvedPath = path.resolve(filePath);
    const initialPathState = await fileSystem.getPathState(filePath);
    assertRegularFileState(initialPathState, pointer);

    if ((await fileSystem.getRealPath(filePath)) !== resolvedPath) {
      fail('json', [pointer], ['regular-file']);
    }

    if (initialPathState.size > maximumBytes) {
      fail('json', [pointer], ['maximum-bytes']);
    }

    openedFile = await fileSystem.openFile(filePath);
    const openedState = await openedFile.getState();
    const postOpenPathState = await fileSystem.getPathState(filePath);
    assertRegularFileState(openedState, pointer);
    assertRegularFileState(postOpenPathState, pointer);

    if (
      !sameFileSnapshot(initialPathState, openedState) ||
      !sameFileSnapshot(openedState, postOpenPathState)
    ) {
      fail('json', [pointer], ['file-changed']);
    }

    const { bytes, bytesRead } = await readToBoundedBuffer(openedFile, maximumBytes, pointer);

    const finalOpenedState = await openedFile.getState();
    const finalPathState = await fileSystem.getPathState(filePath);
    assertRegularFileState(finalOpenedState, pointer);
    assertRegularFileState(finalPathState, pointer);

    if (
      !sameFileSnapshot(openedState, finalOpenedState) ||
      !sameFileSnapshot(finalOpenedState, finalPathState) ||
      finalOpenedState.size !== bytesRead ||
      (await fileSystem.getRealPath(filePath)) !== resolvedPath
    ) {
      fail('json', [pointer], ['file-changed']);
    }

    return bytes;
  } catch (error: unknown) {
    if (error instanceof Phase1ProfileValidationError) {
      throw error;
    }

    return fail('json', [pointer], ['regular-file']);
  } finally {
    if (openedFile) {
      try {
        await openedFile.close();
      } catch {
        // The read result is already isolated in memory; close failures expose no filesystem detail.
      }
    }
  }
};

const hashSha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

const fixedLengthHexEqual = (left: string, right: string, length: number) => {
  if (
    left.length !== length ||
    right.length !== length ||
    !/^[\da-f]+$/u.test(left) ||
    !/^[\da-f]+$/u.test(right)
  ) {
    return false;
  }

  return timingSafeEqual(Buffer.from(left, 'hex'), Buffer.from(right, 'hex'));
};

const diagnosticPointer = (error: ErrorObject) => {
  if (error.keyword === 'required' && 'missingProperty' in error.params) {
    return appendPointer(error.instancePath || '/', String(error.params.missingProperty));
  }

  if (error.keyword === 'additionalProperties' && 'additionalProperty' in error.params) {
    return appendPointer(error.instancePath || '/', String(error.params.additionalProperty));
  }

  return error.instancePath || '/';
};

const compileSchema = (schema: unknown): ValidateFunction => {
  try {
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormatsModule.default.default(ajv);
    // Ajv owns the runtime schema validation; the input remains unknown until compile succeeds.
    // eslint-disable-next-line no-restricted-syntax
    const schemaToCompile = schema as AnySchema;

    return ajv.compile(schemaToCompile);
  } catch {
    return fail('schema', ['/'], ['compile']);
  }
};

const validateProfile = (schema: unknown, profile: unknown): void => {
  const validate = compileSchema(schema);
  const asyncMarker: unknown = Object.getOwnPropertyDescriptor(validate, '$async')?.value;

  if (asyncMarker === true) {
    fail('schema', ['/'], ['async-schema']);
  }

  let validationResult: unknown;

  try {
    validationResult = validate(profile);
  } catch {
    fail('schema', ['/'], ['validator-result']);
  }

  if (validationResult === false) {
    const errors = validate.errors ?? [];
    fail(
      'schema',
      errors.map((error) => diagnosticPointer(error)),
      errors.map(({ keyword }) => keyword)
    );
  }

  if (validationResult !== true) {
    if (validationResult instanceof Promise) {
      // An illegal native Promise result may already be rejected; consume it without delaying failure.
      // eslint-disable-next-line promise/prefer-await-to-then
      validationResult.catch(() => false);
    }

    fail('schema', ['/'], ['validator-result']);
  }
};

const assertEmbeddedProfileLocks = (profile: LockBearingProfile, lock: Phase1ProfileSchemaLock) => {
  if (!commitPattern.test(profile.phase1Harness.commit ?? '')) {
    fail('semantic', ['/phase1Harness/commit'], ['locked-harness']);
  }

  if (profile.profileSchema.sourceCommit !== lock.sourceCommit) {
    fail('semantic', ['/profileSchema/sourceCommit'], ['profile-lock']);
  }

  if (profile.profileSchema.sha256 !== lock.sha256) {
    fail('semantic', ['/profileSchema/sha256'], ['profile-lock']);
  }
};

const deepFreeze = <Value>(
  value: Value,
  visited: WeakSet<object> = new WeakSet()
): Readonly<Value> => {
  if (
    ((typeof value !== 'object' || value === null) && typeof value !== 'function') ||
    visited.has(value)
  ) {
    return value;
  }

  visited.add(value);

  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (descriptor && Object.hasOwn(descriptor, 'value')) {
      deepFreeze(descriptor.value, visited);
    }
  }

  return Object.isFrozen(value) ? value : Object.freeze(value);
};

const maximumCallbackDiagnosticEntries = 64;
const maximumCallbackPointerLength = 512;
const maximumCallbackRuleLength = 128;
const absoluteJsonPointerPattern = /^(?:\/(?:[^~]|~[01])*)+$/u;
const callbackRulePattern = /^[A-Za-z][A-Za-z0-9._-]*$/u;
const containsUnsafeDiagnosticCharacter = (value: string) =>
  [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;

    return codePoint <= 31 || codePoint === 127;
  });

// eslint-disable-next-line complexity -- Every guard prevents an accessor, proxy, or unbounded diagnostic from crossing the callback boundary.
const readSafeDiagnosticArray = (
  error: Phase1ProfileValidationError,
  property: 'pointers' | 'rules',
  isSafeValue: (value: string) => boolean
): readonly string[] | undefined => {
  const propertyDescriptor = Object.getOwnPropertyDescriptor(error, property);

  if (!propertyDescriptor || !Object.hasOwn(propertyDescriptor, 'value')) {
    return undefined;
  }

  const values: unknown = propertyDescriptor.value;

  if (!Array.isArray(values)) {
    return undefined;
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(values, 'length');
  const length: unknown = lengthDescriptor?.value;

  if (
    !Number.isSafeInteger(length) ||
    typeof length !== 'number' ||
    length < 1 ||
    length > maximumCallbackDiagnosticEntries
  ) {
    return undefined;
  }

  const sanitized: string[] = [];

  for (let index = 0; index < length; index += 1) {
    const itemDescriptor = Object.getOwnPropertyDescriptor(values, String(index));

    if (!itemDescriptor || !Object.hasOwn(itemDescriptor, 'value')) {
      return undefined;
    }

    const item: unknown = itemDescriptor.value;

    if (typeof item !== 'string' || !isSafeValue(item)) {
      return undefined;
    }

    // This local array is never exposed until every entry has passed validation.
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods
    sanitized.push(item);
  }

  return sanitized;
};

const sanitizeCallbackValidationError = (
  error: unknown,
  stage: 'semantic' | 'provenance',
  genericRule: 'semantic-validator' | 'provenance-validator'
) => {
  try {
    if (!(error instanceof Phase1ProfileValidationError)) {
      return new Phase1ProfileValidationError(stage, ['/'], [genericRule]);
    }

    const stageDescriptor = Object.getOwnPropertyDescriptor(error, 'stage');

    if (
      !stageDescriptor ||
      !Object.hasOwn(stageDescriptor, 'value') ||
      stageDescriptor.value !== stage
    ) {
      return new Phase1ProfileValidationError(stage, ['/'], [genericRule]);
    }

    const pointers = readSafeDiagnosticArray(
      error,
      'pointers',
      (value) =>
        value.length <= maximumCallbackPointerLength &&
        absoluteJsonPointerPattern.test(value) &&
        !containsUnsafeDiagnosticCharacter(value)
    );
    const rules = readSafeDiagnosticArray(
      error,
      'rules',
      (value) =>
        value.length <= maximumCallbackRuleLength &&
        callbackRulePattern.test(value) &&
        !containsUnsafeDiagnosticCharacter(value)
    );

    return pointers && rules
      ? new Phase1ProfileValidationError(stage, pointers, rules)
      : new Phase1ProfileValidationError(stage, ['/'], [genericRule]);
  } catch {
    return new Phase1ProfileValidationError(stage, ['/'], [genericRule]);
  }
};

const acceptSemantics = () => true;
const acceptProvenance = async () => {
  acceptSemantics();
};

const validateProfileBundleBytes = async <Profile extends LockBearingProfile>(
  profileBytes: Uint8Array,
  schemaBytes: Uint8Array,
  lock: Phase1ProfileSchemaLock,
  dependencies: Phase1ProfileLoaderDependencies<Profile>,
  requireEmbeddedLocks: boolean
): Promise<Phase1ProfileBundle<Profile>> => {
  const schemaHash = hashSha256(schemaBytes);

  if (!fixedLengthHexEqual(schemaHash, lock.sha256, 64)) {
    fail('schema-hash', ['/'], ['sha256']);
  }

  const schema = parseStrictJson(schemaBytes, maximumSchemaBytes);
  const parsedProfile = parseStrictJson(profileBytes, maximumProfileBytes);
  validateProfile(schema, parsedProfile);
  // Ajv has validated the unknown JSON against the caller-pinned schema before this type boundary.
  // eslint-disable-next-line no-restricted-syntax
  const profile = parsedProfile as Profile;

  if (requireEmbeddedLocks) {
    assertEmbeddedProfileLocks(profile, lock);
  }

  try {
    dependencies.assertSemantics(profile);
  } catch (error: unknown) {
    throw sanitizeCallbackValidationError(error, 'semantic', 'semantic-validator');
  }

  try {
    await dependencies.assertProvenance(profile);
  } catch (error: unknown) {
    throw sanitizeCallbackValidationError(error, 'provenance', 'provenance-validator');
  }

  const frozenProfile = deepFreeze(profile);
  const preservedProfileBytes = Buffer.from(profileBytes);
  const preservedSchemaBytes = Buffer.from(schemaBytes);

  const bundle = Object.freeze({
    profile: frozenProfile,
    profileSha256: hashSha256(preservedProfileBytes),
    schemaSha256: schemaHash,
    readProfileBytes: () => Buffer.from(preservedProfileBytes),
    readSchemaBytes: () => Buffer.from(preservedSchemaBytes),
  });
  validatedPhase1ProfileBundles.add(bundle);

  return bundle;
};

export const createPhase1ProfileBundleFromBytes = async <
  Profile extends LockBearingProfile = Phase1Profile,
>(
  profileBytes: Uint8Array,
  schemaBytes: Uint8Array,
  lock: Phase1ProfileSchemaLock,
  dependencies: Partial<Phase1ProfileLoaderDependencies<Profile>> = {}
): Promise<Phase1ProfileBundle<Profile>> =>
  validateProfileBundleBytes(
    Buffer.from(profileBytes),
    Buffer.from(schemaBytes),
    lock,
    {
      assertSemantics: dependencies.assertSemantics ?? acceptSemantics,
      assertProvenance: dependencies.assertProvenance ?? acceptProvenance,
      fileSystem: dependencies.fileSystem ?? {},
    },
    true
  );

export const createPhase1DesignProfileBundleFromBytes = async <
  Profile extends LockBearingProfile = Phase1Profile,
>(
  profileBytes: Uint8Array,
  schemaBytes: Uint8Array,
  lock: Phase1ProfileSchemaLock,
  dependencies: Partial<Phase1ProfileLoaderDependencies<Profile>> = {}
): Promise<Phase1ProfileBundle<Profile>> =>
  validateProfileBundleBytes(
    Buffer.from(profileBytes),
    Buffer.from(schemaBytes),
    lock,
    {
      assertSemantics: dependencies.assertSemantics ?? acceptSemantics,
      assertProvenance: dependencies.assertProvenance ?? acceptProvenance,
      fileSystem: dependencies.fileSystem ?? {},
    },
    false
  );

const createProfileBundleLoader = <Profile extends LockBearingProfile = Phase1Profile>(
  lock: Phase1ProfileSchemaLock,
  dependencies: Partial<Phase1ProfileLoaderDependencies<Profile>>,
  requireEmbeddedLocks: boolean
): ((paths: Phase1ProfilePaths) => Promise<Phase1ProfileBundle<Profile>>) => {
  const resolvedDependencies: Phase1ProfileLoaderDependencies<Profile> = {
    assertSemantics: dependencies.assertSemantics ?? acceptSemantics,
    assertProvenance: dependencies.assertProvenance ?? acceptProvenance,
    fileSystem: dependencies.fileSystem ?? {},
  };

  return async ({ profilePath, schemaPath }) => {
    if (!path.isAbsolute(profilePath) || path.resolve(profilePath) !== profilePath) {
      fail('json', ['/profile'], ['absolute-path']);
    }

    if (!path.isAbsolute(schemaPath) || path.resolve(schemaPath) !== schemaPath) {
      fail('json', ['/schema'], ['absolute-path']);
    }

    if (profilePath === schemaPath) {
      fail('json', ['/'], ['distinct-paths']);
    }

    const schemaBytes = await readBoundedRegularFile(
      schemaPath,
      '/schema',
      maximumSchemaBytes,
      resolvedDependencies.fileSystem
    );
    const profileBytes = await readBoundedRegularFile(
      profilePath,
      '/profile',
      maximumProfileBytes,
      resolvedDependencies.fileSystem
    );

    return validateProfileBundleBytes(
      profileBytes,
      schemaBytes,
      lock,
      resolvedDependencies,
      requireEmbeddedLocks
    );
  };
};

export const createPhase1ProfileBundleLoader = <Profile extends LockBearingProfile = Phase1Profile>(
  lock: Phase1ProfileSchemaLock,
  dependencies: Partial<Phase1ProfileLoaderDependencies<Profile>> = {}
): ((paths: Phase1ProfilePaths) => Promise<Phase1ProfileBundle<Profile>>) =>
  createProfileBundleLoader(lock, dependencies, true);

export const createPhase1DesignProfileBundleLoader = <
  Profile extends LockBearingProfile = Phase1Profile,
>(
  lock: Phase1ProfileSchemaLock,
  dependencies: Partial<Phase1ProfileLoaderDependencies<Profile>> = {}
): ((paths: Phase1ProfilePaths) => Promise<Phase1ProfileBundle<Profile>>) =>
  createProfileBundleLoader(lock, dependencies, false);

export const createPhase1ProfileLoader = <Profile extends LockBearingProfile = Phase1Profile>(
  lock: Phase1ProfileSchemaLock,
  dependencies: Partial<Phase1ProfileLoaderDependencies<Profile>> = {}
): ((paths: Phase1ProfilePaths) => Promise<Readonly<Profile>>) => {
  const loadBundle = createPhase1ProfileBundleLoader(lock, dependencies);

  return async (paths) => {
    const bundle = await loadBundle(paths);

    return bundle.profile;
  };
};

const authorityBlobGuard = z
  .object({
    'compatibility/baseline-manifest.json': z.string().regex(commitPattern),
    'docker-compose.compatibility.yml': z.string().regex(commitPattern),
    '.scripts/compatibility/run.sh': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/model.ts': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/scenario.ts': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/config.ts': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/target-client.ts': z
      .string()
      .regex(commitPattern),
    'packages/integration-tests/src/compatibility/normalize.ts': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/compare.ts': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/evidence.ts': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/cli.ts': z.string().regex(commitPattern),
    'packages/integration-tests/src/compatibility/scenarios/index.ts': z
      .string()
      .regex(commitPattern),
  })
  .strict();

const schemaLockDocumentGuard = z
  .object({
    schemaVersion: z.literal(1),
    phase0BaseCommit: z.literal('40135e37201f36ac05ece1eff82e37bb6d9649f1'),
    schemaSourceCommit: z.string().regex(commitPattern),
    schemaSha256: z.string().regex(sha256Pattern),
    phase0AuthorityBlobs: authorityBlobGuard,
  })
  .strict();

export const parsePhase1SchemaLockDocument = (bytes: Uint8Array): Phase1SchemaLockDocument => {
  const parsed = parseStrictJson(bytes, maximumSchemaBytes);
  const result = schemaLockDocumentGuard.safeParse(parsed);

  if (!result.success) {
    throw new Phase1ProfileValidationError(
      'schema-hash',
      result.error.issues.map(({ path: issuePath }) => toPointer(issuePath)),
      ['lock-document']
    );
  }

  return deepFreeze(result.data);
};

const assertSchemaLockConsistency = (
  document: Phase1SchemaLockDocument,
  embeddedLock: Phase1ProfileSchemaLock
) => {
  if (
    !fixedLengthHexEqual(document.schemaSourceCommit, embeddedLock.sourceCommit, 40) ||
    !fixedLengthHexEqual(document.schemaSha256, embeddedLock.sha256, 64)
  ) {
    fail('schema-hash', ['/'], ['lock-copy']);
  }
};

export const createLockedPhase1ProfileLoader = <Profile extends LockBearingProfile = Phase1Profile>(
  schemaLockDocumentBytes: Uint8Array,
  embeddedLock: Phase1ProfileSchemaLock,
  dependencies: Partial<Phase1ProfileLoaderDependencies<Profile>> = {}
) => {
  const document = parsePhase1SchemaLockDocument(schemaLockDocumentBytes);
  assertSchemaLockConsistency(document, embeddedLock);

  return createPhase1ProfileLoader<Profile>(embeddedLock, dependencies);
};

const findIntegrationTestsPackageRoot = () => {
  let currentDirectory = path.dirname(realpathSync(fileURLToPath(import.meta.url)));

  for (let remainingParents = 8; remainingParents > 0; remainingParents -= 1) {
    if (
      path.basename(currentDirectory) === 'integration-tests' &&
      path.basename(path.dirname(currentDirectory)) === 'packages' &&
      existsSync(path.join(currentDirectory, 'package.json'))
    ) {
      return currentDirectory;
    }

    currentDirectory = path.dirname(currentDirectory);
  }

  throw new Phase1ProfileValidationError('schema-hash', ['/'], ['lock-document']);
};

const integrationTestsPackageRoot = findIntegrationTestsPackageRoot();
const publicSchemaLockPath = path.resolve(
  integrationTestsPackageRoot,
  '../../compatibility/phase-1-schema-lock.json'
);

const defaultSchemaLockDocumentBytes = (() => {
  try {
    return readFileSync(publicSchemaLockPath);
  } catch {
    return fail('schema-hash', ['/'], ['lock-document']);
  }
})();

export const phase1SchemaLockDocument = parsePhase1SchemaLockDocument(
  defaultSchemaLockDocumentBytes
);

assertSchemaLockConsistency(phase1SchemaLockDocument, phase1ProfileSchemaLock);

export const loadPhase1Profile: (paths: Phase1ProfilePaths) => Promise<Readonly<Phase1Profile>> =
  createPhase1ProfileLoader(phase1ProfileSchemaLock);

/* eslint-enable max-lines, max-params, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/ban-types */
