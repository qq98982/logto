/* eslint-disable complexity -- Strict byte, tree, prototype, and descriptor checks deliberately remain at one package-authority boundary. */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

import { getNodeValue, parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

type AuthorityJsonPrimitive =
  | boolean
  | number
  | string
  // eslint-disable-next-line @typescript-eslint/ban-types -- JSON null is distinct from an absent manifest property.
  | null;
type AuthorityJsonValue =
  | AuthorityJsonPrimitive
  | readonly AuthorityJsonValue[]
  | AuthorityJsonObject;
/* eslint-disable @typescript-eslint/consistent-indexed-object-style, @typescript-eslint/consistent-type-definitions -- An interface permits recursive package JSON values. */
interface AuthorityJsonObject {
  [key: string]: AuthorityJsonValue;
}
/* eslint-enable @typescript-eslint/consistent-indexed-object-style, @typescript-eslint/consistent-type-definitions */

const isAuthorityArray = (value: AuthorityJsonValue): value is readonly AuthorityJsonValue[] =>
  Array.isArray(value);

const diagnostic = 'Invalid Phase 1 package authority';
const maximumManifestBytes = 1024 * 1024;
const integrationLockfileSha256 =
  'f55d821d06980b776ce94d09150fda67bcfcac7f66985a9b39a1dad52c48beda';
const dangerousKeys = new Set(['__proto__', 'constructor', 'prototype']);
const scriptAdditions = Object.freeze({
  'compatibility:phase1': 'node ./lib/compatibility/phase-1/cli.js',
  'test:compatibility:phase1':
    'pnpm test:only -i --config=jest.config.compatibility.js ./lib/compatibility/phase-1/',
});
const dependencyAdditions = Object.freeze({
  '@playwright/test': '1.62.1',
  ajv: '8.20.0',
  'ajv-formats': '3.0.1',
  'jsonc-parser': '3.3.1',
  parse5: '7.2.1',
  'tough-cookie': '5.1.2',
  yaml: '2.9.0',
});

export class Phase1PackageAuthorityError extends Error {
  readonly pointer: string;
  readonly rule: string;

  constructor(pointer: string, rule: string) {
    super(diagnostic);
    this.name = 'Phase1PackageAuthorityError';
    this.pointer = pointer;
    this.rule = rule;
    this.stack = this.message;
  }
}

const fail = (pointer: string, rule: string): never => {
  throw new Phase1PackageAuthorityError(pointer, rule);
};

const inspectTree = (node: JsonNode, pointer: string): void => {
  if (node.type === 'object') {
    const names = new Set<string>();

    for (const property of node.children ?? []) {
      const [nameNode, valueNode] = property.children ?? [];
      const name: unknown = nameNode?.value;

      if (
        property.type !== 'property' ||
        property.children?.length !== 2 ||
        typeof name !== 'string' ||
        !valueNode
      ) {
        return fail(pointer, 'json-shape');
      }
      if (names.has(name)) {
        return fail(pointer, 'duplicate-key');
      }
      if (dangerousKeys.has(name)) {
        return fail(pointer, 'dangerous-key');
      }
      names.add(name);
      inspectTree(valueNode, pointer);
    }

    return;
  }

  for (const child of node.children ?? []) {
    inspectTree(child, pointer);
  }
};

const snapshotValue = (value: unknown, pointer: string): AuthorityJsonValue => {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value) && Number.isSafeInteger(value))
  ) {
    return value;
  }
  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      return fail(pointer, 'prototype');
    }
    const ownKeys = Reflect.ownKeys(value);
    const expectedKeys = new Set(['length', ...value.map((_item, index) => String(index))]);

    if (
      ownKeys.length !== expectedKeys.size ||
      ownKeys.some((key) => typeof key !== 'string' || !expectedKeys.has(key))
    ) {
      return fail(pointer, 'array-shape');
    }

    return Object.freeze(value.map((item) => snapshotValue(item, pointer)));
  }
  if (typeof value !== 'object') {
    return fail(pointer, 'value');
  }
  const prototype: unknown = Object.getPrototypeOf(value);

  if (prototype !== Object.prototype && prototype !== null) {
    return fail(pointer, 'prototype');
  }
  const entries = Reflect.ownKeys(value).map((key): readonly [string, AuthorityJsonValue] => {
    if (typeof key !== 'string' || dangerousKeys.has(key)) {
      return fail(pointer, 'dangerous-key');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);

    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
      return fail(pointer, 'object-shape');
    }

    return Object.freeze([key, snapshotValue(descriptor.value, pointer)] as const);
  });

  return Object.freeze(Object.fromEntries(entries));
};

const parseManifest = (bytes: Uint8Array, source: 'base' | 'harness'): AuthorityJsonObject => {
  const pointer = `/${source}`;

  try {
    if (
      !(bytes instanceof Uint8Array) ||
      bytes.byteLength === 0 ||
      bytes.byteLength > maximumManifestBytes ||
      (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf)
    ) {
      return fail(pointer, 'bytes');
    }
    const text = new TextDecoder('utf8', { fatal: true }).decode(bytes);
    const errors: ParseError[] = [];
    const tree = parseTree(text, errors, {
      allowEmptyContent: false,
      allowTrailingComma: false,
      disallowComments: true,
    });

    if (!tree || errors.length > 0) {
      return fail(pointer, 'json');
    }
    inspectTree(tree, pointer);
    // eslint-disable-next-line no-restricted-syntax -- jsonc-parser exposes a legacy `any`; the value immediately crosses the strict recursive snapshot boundary as unknown.
    const parsed: unknown = getNodeValue(tree) as unknown;
    const snapshot = snapshotValue(parsed, pointer);

    if (typeof snapshot !== 'object' || snapshot === null || isAuthorityArray(snapshot)) {
      return fail(pointer, 'root');
    }

    return snapshot;
  } catch (error: unknown) {
    if (error instanceof Phase1PackageAuthorityError) {
      throw error;
    }

    return fail(pointer, 'json');
  }
};

const requireObjectMember = (manifest: AuthorityJsonObject, name: string): AuthorityJsonObject => {
  const value = manifest[name];

  return typeof value === 'object' && value !== null && !isAuthorityArray(value)
    ? value
    : fail('/base', 'base-shape');
};

const extendAuthoritySection = (
  section: AuthorityJsonObject,
  additions: Readonly<Record<string, string>>
): AuthorityJsonObject => {
  if (Object.keys(additions).some((key) => Object.hasOwn(section, key))) {
    return fail('/base', 'base-overlap');
  }

  return Object.freeze(
    Object.fromEntries([
      ...Object.entries(section),
      ...Object.entries(additions).map(([key, value]) => [key, value] as const),
    ])
  );
};

const expectedHarnessManifest = (base: AuthorityJsonObject): AuthorityJsonObject => {
  const scripts = extendAuthoritySection(requireObjectMember(base, 'scripts'), scriptAdditions);
  const devDependencies = extendAuthoritySection(
    requireObjectMember(base, 'devDependencies'),
    dependencyAdditions
  );

  return Object.freeze(
    Object.fromEntries(
      Object.entries(base).map(([key, value]) => [
        key,
        key === 'scripts' ? scripts : key === 'devDependencies' ? devDependencies : value,
      ])
    )
  );
};

export const assertPhase1IntegrationManifestDelta = (
  baseBytes: Uint8Array,
  harnessBytes: Uint8Array
): void => {
  const base = parseManifest(baseBytes, 'base');
  const harness = parseManifest(harnessBytes, 'harness');

  if (!isDeepStrictEqual(harness, expectedHarnessManifest(base))) {
    return fail('/harness', 'manifest-delta');
  }
};

export const assertPhase1IntegrationLockAuthority = (bytes: Uint8Array): void => {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength === 0 ||
    bytes.byteLength > maximumManifestBytes
  ) {
    return fail('/lockfile', 'lockfile-bytes');
  }

  try {
    if (createHash('sha256').update(bytes).digest('hex') !== integrationLockfileSha256) {
      return fail('/lockfile', 'lockfile-sha256');
    }
  } catch (error: unknown) {
    if (error instanceof Phase1PackageAuthorityError) {
      throw error;
    }

    return fail('/lockfile', 'lockfile-bytes');
  }
};

/* eslint-enable complexity */
