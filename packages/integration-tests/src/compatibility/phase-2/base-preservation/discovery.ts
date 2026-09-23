/* eslint-disable complexity, no-control-regex, no-restricted-syntax, @silverhand/fp/no-mutation, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition -- The closed adapter validates hostile descriptors and control characters, narrows unknown JSON through explicit assertions, and keeps literal contract checks visible. */
import { createHash } from 'node:crypto';
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import { parseTree, type Node as JsonNode, type ParseError } from 'jsonc-parser';

import type { TargetConfig } from '../../model.js';
import type {
  ProtocolRequestOptions,
  RawProtocolHeaders,
  RawProtocolResponse,
} from '../../phase-1/clients/oidc.js';
import type { Phase1DifferentialScenarioId } from '../../phase-1/model.js';
import type { Phase1ProtocolSession } from '../../phase-1/scenario-runtime.js';

const diagnostic = 'Invalid Phase 2 base-preservation discovery';
const maximumBodyBytes = 1024 * 1024;
const discoveryOperations = Object.freeze({
  'discovery-openid': 'openid',
  'discovery-oauth-authorization-server': 'oauth',
} as const);
const sessionKeys = Object.freeze([
  'publicOidc',
  'publicSymbols',
  'forAllocation',
  'symbolsFor',
] as const);

type DiscoveryOperation = keyof typeof discoveryOperations;
type DiscoveryKind = (typeof discoveryOperations)[DiscoveryOperation];

export type Phase2BaseDiscoveryAppendProof = Readonly<{
  operation: DiscoveryOperation;
  requestPath: string;
  rawDocumentSha256: string;
  baseDocumentSha256: string;
  rawGrantTypes: readonly string[];
  baseGrantTypes: readonly string[];
}>;

export type Phase2BaseDiscoverySession = Readonly<{
  session: Phase1ProtocolSession;
  proofs(): readonly Phase2BaseDiscoveryAppendProof[];
}>;

export type Phase2BaseDiscoverySessionInput = Readonly<{
  target: TargetConfig;
  scenarioId: Phase1DifferentialScenarioId;
  session: Phase1ProtocolSession;
  acceptedGrantTypes: readonly string[];
  appendGrantType: 'client_credentials';
  stillAbsent: readonly string[];
  paths: Readonly<{ openid: string; oauth: string; jwks: string }>;
}>;

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const ownData = (value: object, key: PropertyKey): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);

  return descriptor && Object.hasOwn(descriptor, 'value') && descriptor.enumerable
    ? descriptor.value
    : fail();
};

const assertExactSession = (session: Phase1ProtocolSession): void => {
  if (
    typeof session !== 'object' ||
    session === null ||
    Array.isArray(session) ||
    nodeTypes.isProxy(session) ||
    Object.getPrototypeOf(session) !== Object.prototype ||
    Reflect.ownKeys(session).length !== sessionKeys.length ||
    Reflect.ownKeys(session).some(
      (key) => typeof key !== 'string' || !sessionKeys.includes(key as (typeof sessionKeys)[number])
    ) ||
    typeof ownData(session, 'forAllocation') !== 'function' ||
    typeof ownData(session, 'symbolsFor') !== 'function'
  ) {
    fail();
  }
  const publicOidc = ownData(session, 'publicOidc');

  if (
    (typeof publicOidc !== 'object' && typeof publicOidc !== 'function') ||
    publicOidc === null ||
    typeof Reflect.get(publicOidc, 'request') !== 'function' ||
    Reflect.get(publicOidc, 'allocationRole') !== undefined
  ) {
    fail();
  }
};

const inspectJsonNode = (node: JsonNode): void => {
  if (node.type === 'object') {
    const names = new Set<string>();

    for (const property of node.children ?? []) {
      const [nameNode, valueNode] = property.children ?? [];
      const nameValue: unknown = nameNode?.value;
      const name = typeof nameValue === 'string' ? nameValue : fail();
      const child = valueNode ?? fail();

      if (names.has(name)) {
        fail();
      }
      names.add(name);
      inspectJsonNode(child);
    }
  } else if (node.type === 'array') {
    for (const child of node.children ?? []) {
      inspectJsonNode(child);
    }
  }
};

const strictJsonObject = (body: string): Record<string, unknown> => {
  if (Buffer.byteLength(body) === 0 || Buffer.byteLength(body) > maximumBodyBytes) {
    return fail();
  }
  const errors: ParseError[] = [];
  const tree = parseTree(body, errors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true,
  });

  if (!tree || errors.length > 0 || tree.type !== 'object') {
    return fail();
  }
  inspectJsonNode(tree);
  const value: unknown = JSON.parse(body);

  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return fail();
  }

  return value as Record<string, unknown>;
};

const headerValues = (headers: RawProtocolHeaders, name: string): readonly string[] =>
  headers.filter(([header]) => header.toLowerCase() === name).map(([, value]) => value);

const assertRawResponse = (response: RawProtocolResponse): Record<string, unknown> => {
  const contentTypes = headerValues(response.headers, 'content-type').map((value) =>
    value.split(';', 1)[0]?.trim().toLowerCase()
  );
  const lengths = headerValues(response.headers, 'content-length');

  if (
    response.status !== 200 ||
    contentTypes.length !== 1 ||
    contentTypes[0] !== 'application/json' ||
    lengths.length > 1 ||
    (lengths.length === 1 &&
      (!/^(?:0|[1-9][0-9]*)$/u.test(lengths[0] ?? '') ||
        Number(lengths[0]) !== Buffer.byteLength(response.body)))
  ) {
    return fail();
  }

  return strictJsonObject(response.body);
};

const exactStringArray = (value: unknown): readonly string[] => {
  if (
    !Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    Reflect.ownKeys(value).length !== value.length + 1 ||
    value.some((item) => typeof item !== 'string')
  ) {
    return fail();
  }

  return value as string[];
};

const rewriteContentLength = (headers: RawProtocolHeaders, body: string): RawProtocolHeaders =>
  Object.freeze(
    headers.map(([name, value]) =>
      Object.freeze([
        name,
        name.toLowerCase() === 'content-length' ? String(Buffer.byteLength(body)) : value,
      ] as const)
    )
  );

const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');

export const createPhase2BaseDiscoverySession = (
  input: Phase2BaseDiscoverySessionInput
): Phase2BaseDiscoverySession => {
  if (
    input.target.label !== 'candidate' ||
    input.scenarioId !== 'discovery.config' ||
    input.appendGrantType !== 'client_credentials' ||
    input.acceptedGrantTypes.length === 0 ||
    new Set(input.acceptedGrantTypes).size !== input.acceptedGrantTypes.length ||
    input.stillAbsent.length === 0 ||
    new Set(input.stillAbsent).size !== input.stillAbsent.length ||
    Object.values(input.paths).some(
      (value) =>
        typeof value !== 'string' ||
        value.length === 0 ||
        value.startsWith('/') ||
        /[\u0000-\u001F\u007F]/u.test(value)
    )
  ) {
    return fail();
  }
  assertExactSession(input.session);
  const sourceOidc = input.session.publicOidc;
  const sourceRequest = sourceOidc.request.bind(sourceOidc);
  const proofs = new Map<DiscoveryKind, Phase2BaseDiscoveryAppendProof>();
  const rawDocuments = new Map<DiscoveryKind, Record<string, unknown>>();
  const operationPaths = Object.freeze({
    'discovery-openid': input.paths.openid,
    'discovery-oauth-authorization-server': input.paths.oauth,
    'discovery-jwks': input.paths.jwks,
  } as const);

  const request = async (
    operation: string,
    requestPath: string,
    options: ProtocolRequestOptions = {}
  ): Promise<RawProtocolResponse> => {
    if (!Object.hasOwn(operationPaths, operation)) {
      return fail();
    }
    const expectedPath = operationPaths[operation as keyof typeof operationPaths];

    if (requestPath !== expectedPath) {
      return fail();
    }
    const response = await sourceRequest(operation, requestPath, options);

    if (operation === 'discovery-jwks') {
      return response;
    }
    const kind = discoveryOperations[operation as DiscoveryOperation];

    if (proofs.has(kind)) {
      return fail();
    }
    const rawDocument = assertRawResponse(response);
    const grants = exactStringArray(rawDocument.grant_types_supported);
    const expected = [...input.acceptedGrantTypes, input.appendGrantType];

    if (
      grants.length !== expected.length ||
      grants.some((value, index) => value !== expected[index]) ||
      new Set(grants).size !== grants.length ||
      input.stillAbsent.some((field) => Object.hasOwn(rawDocument, field))
    ) {
      return fail();
    }
    const otherKind: DiscoveryKind = kind === 'openid' ? 'oauth' : 'openid';
    const otherDocument = rawDocuments.get(otherKind);

    if (otherDocument && !isDeepStrictEqual(otherDocument, rawDocument)) {
      return fail();
    }
    rawDocuments.set(kind, rawDocument);
    const baseDocument = structuredClone(rawDocument);

    baseDocument.grant_types_supported = [...input.acceptedGrantTypes];
    const baseBody = JSON.stringify(baseDocument);
    const proof = Object.freeze({
      operation: operation as DiscoveryOperation,
      requestPath,
      rawDocumentSha256: sha256(response.body),
      baseDocumentSha256: sha256(baseBody),
      rawGrantTypes: Object.freeze([...grants]),
      baseGrantTypes: Object.freeze([...input.acceptedGrantTypes]),
    });
    proofs.set(kind, proof);

    return Object.freeze({
      status: response.status,
      headers: rewriteContentLength(response.headers, baseBody),
      body: baseBody,
    });
  };
  const session = Object.freeze({
    publicOidc: Object.freeze({ request, allocationRole: undefined }),
    publicSymbols: input.session.publicSymbols,
    forAllocation: input.session.forAllocation,
    symbolsFor: input.session.symbolsFor,
  });

  return Object.freeze({
    session,
    proofs: () => {
      const openid = proofs.get('openid');
      const oauth = proofs.get('oauth');

      if (!openid || !oauth || proofs.size !== 2) {
        return fail();
      }

      return Object.freeze([openid, oauth]);
    },
  });
};

/* eslint-enable complexity, no-control-regex, no-restricted-syntax, @silverhand/fp/no-mutation, @typescript-eslint/ban-types, @typescript-eslint/no-unnecessary-condition */
