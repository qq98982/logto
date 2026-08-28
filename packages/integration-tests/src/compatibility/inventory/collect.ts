/* eslint-disable max-lines */
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';

import ky from 'ky';
import { z } from 'zod';

import {
  capabilityGuard,
  capabilityManifestGuard,
  type CapabilityManifest,
  type TargetConfig,
} from '../model.js';

type Capability = CapabilityManifest['capabilities'][number];
type OpenApiSurface = Extract<
  Capability['surface'],
  'management-api' | 'experience-api' | 'user-api'
>;

type FetchOptions = {
  headers?: Readonly<Record<string, string>>;
};

type InventoryDependencies = {
  testRoot: string;
  manualCapabilitiesPath: string;
  fetchJson?: (url: URL, options?: FetchOptions) => Promise<unknown>;
  readFiles?: (testRoot: string) => Promise<string[]>;
  readManualCapabilities?: (manualCapabilitiesPath: string) => Promise<unknown>;
};

const referenceCommit = '6852a7b8c8984c5c12b2061e8c51faa310a36412';
const oidcSource = '/oidc/.well-known/openid-configuration';
const integrationTestSourcePrefix = 'packages/integration-tests/src/tests/';
const httpMethods = ['delete', 'get', 'patch', 'post', 'put'] as const;

const isPlainRecord = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false;
  }

  const prototype: unknown = Object.getPrototypeOf(value);

  return prototype === Object.prototype || prototype === null;
};

const plainRecordGuard = z.custom<Record<string, unknown>>(isPlainRecord, {
  message: 'Expected a plain object',
});
const runtimePathItemGuard = plainRecordGuard.superRefine((pathItem, context) => {
  for (const method of httpMethods) {
    if (Object.hasOwn(pathItem, method) && !isPlainRecord(pathItem[method])) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [method],
        message: `Expected ${method} operation to be a non-null plain object`,
      });
    }
  }
});
const runtimeOpenApiDocumentGuard = plainRecordGuard.pipe(
  z
    .object({
      paths: plainRecordGuard
        .pipe(z.record(runtimePathItemGuard))
        .refine((paths) => Object.keys(paths).length > 0, 'Expected paths to be nonempty'),
    })
    .passthrough()
);
const responseTypeGuard = z
  .string()
  .min(1)
  .regex(
    /^\w+(?: \w+)*$/,
    'response_types_supported entries must use single-space-separated response type tokens'
  );

const openApiDocumentGuard = z
  .object({ paths: z.record(z.record(z.unknown())).optional() })
  .passthrough();
const oidcDocumentGuard = z
  .object({
    grant_types_supported: z.array(z.string().min(1)).optional(),
    response_types_supported: z.array(responseTypeGuard).optional(),
    response_modes_supported: z.array(z.string().min(1)).optional(),
    token_endpoint_auth_methods_supported: z.array(z.string().min(1)).optional(),
  })
  .passthrough();
const runtimeOidcDocumentGuard = plainRecordGuard.pipe(
  z
    .object({
      grant_types_supported: z.array(z.string().min(1)).nonempty(),
      response_types_supported: z.array(responseTypeGuard).nonempty(),
      response_modes_supported: z.array(z.string().min(1)).nonempty(),
      token_endpoint_auth_methods_supported: z.array(z.string().min(1)).nonempty(),
    })
    .passthrough()
);
const connectorFactoryGuard = z.object({
  id: z
    .string()
    .min(1)
    .refine((id) => id.trim() === id, 'Connector factory ID must not have surrounding whitespace'),
});

const compareStrings = (left: string, right: string) => (left < right ? -1 : left > right ? 1 : 0);
const compareCapabilityIds = (left: Capability, right: Capability) =>
  compareStrings(left.id, right.id);

const rejectDuplicateIds = (capabilities: readonly Capability[]) => {
  const seen = new Set<string>();

  for (const { id } of capabilities) {
    if (seen.has(id)) {
      throw new Error(`Duplicate capability ID: ${id}`);
    }

    seen.add(id);
  }
};

export const extractOpenApiCapabilities = (
  surface: OpenApiSurface,
  source: string,
  document: unknown
): Capability[] => {
  const { paths = {} } = openApiDocumentGuard.parse(document);

  return Object.entries(paths)
    .flatMap(([route, item]) =>
      httpMethods.flatMap((method) =>
        item[method]
          ? [
              {
                id: `http.${surface}.${method}.${route}`,
                surface,
                source,
                existingEvidence: [],
              } satisfies Capability,
            ]
          : []
      )
    )
    .toSorted(compareCapabilityIds);
};

const oidcCapabilityFields = [
  ['grant_types_supported', 'grant'],
  ['response_types_supported', 'response_type'],
  ['response_modes_supported', 'response_mode'],
  ['token_endpoint_auth_methods_supported', 'token_endpoint_auth_method'],
] as const;

const isAsciiWhitespace = (character: string) => {
  const codePoint = character.codePointAt(0);

  return codePoint === 32 || (codePoint !== undefined && codePoint >= 9 && codePoint <= 13);
};

const canonicalizeOidcValue = (field: (typeof oidcCapabilityFields)[number][0], value: string) => {
  if (field === 'response_types_supported') {
    return value.replaceAll(' ', '+');
  }

  if ([...value].some((character) => isAsciiWhitespace(character))) {
    throw new Error(`${field} entry must not contain ASCII whitespace`);
  }

  return value;
};

export const extractOidcCapabilities = (document: unknown): Capability[] => {
  const parsedDocument = oidcDocumentGuard.parse(document);
  const capabilities = oidcCapabilityFields.flatMap(([field, idSegment]) =>
    (parsedDocument[field] ?? []).map(
      (value) =>
        ({
          id: `oidc.${idSegment}.${canonicalizeOidcValue(field, value)}`,
          surface: 'oidc',
          source: oidcSource,
          existingEvidence: [],
        }) satisfies Capability
    )
  );

  rejectDuplicateIds(capabilities);

  return capabilities.toSorted(compareCapabilityIds);
};

export const extractConnectorCapabilities = (document: unknown): Capability[] => {
  if (!Array.isArray(document)) {
    throw new TypeError('Connector factory response must be an array');
  }

  const capabilities = document.map((connector, index) => {
    const result = connectorFactoryGuard.safeParse(connector);

    if (!result.success) {
      throw new TypeError(
        `Invalid connector factory at index ${index}: expected a non-empty string id`
      );
    }

    return {
      id: `connector.${result.data.id}`,
      surface: 'connector',
      source: '/api/connector-factories',
      existingEvidence: [],
    } satisfies Capability;
  });

  return capabilities.toSorted(compareCapabilityIds);
};

const readIntegrationTestFiles = async (testRoot: string): Promise<string[]> => {
  const visit = async (directory: string, prefix = ''): Promise<string[]> => {
    const entries = await readdir(directory, { withFileTypes: true });

    const files = await Promise.all(
      entries
        .toSorted((left, right) => compareStrings(left.name, right.name))
        .map(async (entry): Promise<string[]> => {
          const relativePath = prefix ? path.posix.join(prefix, entry.name) : entry.name;

          if (entry.isDirectory()) {
            return visit(path.join(directory, entry.name), relativePath);
          }

          return entry.isFile() && entry.name.endsWith('.test.ts') ? [relativePath] : [];
        })
    );

    return files.flat();
  };

  return visit(testRoot);
};

const normalizeTestFile = (file: string) => {
  const normalized = file.replaceAll('\\', '/').replace(/^\.\//, '');
  const relativePath = normalized.startsWith('src/tests/')
    ? normalized.slice('src/tests/'.length)
    : normalized;

  if (
    path.posix.isAbsolute(relativePath) ||
    relativePath.length === 0 ||
    relativePath
      .split('/')
      .some((segment) => segment.length === 0 || segment === '.' || segment === '..') ||
    !relativePath.endsWith('.test.ts')
  ) {
    throw new TypeError(`Invalid integration test path: ${file}`);
  }

  return relativePath;
};

export const collectIntegrationTestCapabilities = async (
  testRoot: string,
  {
    readFiles = readIntegrationTestFiles,
  }: { readFiles?: (testRoot: string) => Promise<string[]> } = {}
): Promise<Capability[]> => {
  const files = await readFiles(testRoot);

  return files
    .map((file) => normalizeTestFile(file))
    .map((relativePath) => {
      const source = `${integrationTestSourcePrefix}${relativePath}`;

      return {
        id: `test.${relativePath}`,
        surface: 'integration-test',
        source,
        existingEvidence: [source],
      } satisfies Capability;
    })
    .toSorted(compareCapabilityIds);
};

export const mergeCapabilities = (
  ...capabilityGroups: ReadonlyArray<readonly unknown[]>
): Capability[] => {
  const capabilities = capabilityGuard
    .array()
    .parse(capabilityGroups.flat())
    .toSorted(compareCapabilityIds);

  rejectDuplicateIds(capabilities);

  return capabilities;
};

const defaultFetchJson = async (url: URL, options?: FetchOptions) =>
  ky.get(url, options === undefined ? undefined : { headers: options.headers }).json();

const defaultReadManualCapabilities = async (manualCapabilitiesPath: string) => {
  const source = await readFile(manualCapabilitiesPath, 'utf8');

  return z.unknown().parse(JSON.parse(source));
};

const extractManualCapabilities = (document: unknown): Capability[] => {
  const capabilities = capabilityGuard.array().parse(document);
  const invalidCapability = capabilities.find(({ surface }) => surface !== 'manual');

  if (invalidCapability) {
    throw new TypeError(`Manual capability ${invalidCapability.id} must use the manual surface`);
  }

  return capabilities;
};

export const collectCapabilityManifest = async (
  target: TargetConfig,
  {
    testRoot,
    manualCapabilitiesPath,
    fetchJson = defaultFetchJson,
    readFiles = readIntegrationTestFiles,
    readManualCapabilities = defaultReadManualCapabilities,
  }: InventoryDependencies
): Promise<CapabilityManifest> => {
  const experienceSource = '/api/.well-known/experience.openapi.json';
  const managementSource = '/api/.well-known/management.openapi.json';
  const userSource = '/api/.well-known/user.openapi.json';
  const connectorSource = '/api/connector-factories';

  const experienceDocument = runtimeOpenApiDocumentGuard.parse(
    await fetchJson(new URL(experienceSource, target.coreUrl))
  );
  const managementDocument = runtimeOpenApiDocumentGuard.parse(
    await fetchJson(new URL(managementSource, target.adminUrl))
  );
  const userDocument = runtimeOpenApiDocumentGuard.parse(
    await fetchJson(new URL(userSource, target.adminUrl))
  );
  const oidcDocument = runtimeOidcDocumentGuard.parse(
    await fetchJson(new URL(oidcSource, target.coreUrl))
  );
  const connectorDocument = await fetchJson(new URL(connectorSource, target.adminUrl), {
    headers: { 'development-user-id': 'integration-test-admin-user' },
  });
  const integrationTestCapabilities = await collectIntegrationTestCapabilities(testRoot, {
    readFiles,
  });
  const manualCapabilities = extractManualCapabilities(
    await readManualCapabilities(manualCapabilitiesPath)
  );
  const capabilities = mergeCapabilities(
    extractOpenApiCapabilities('experience-api', experienceSource, experienceDocument),
    extractOpenApiCapabilities('management-api', managementSource, managementDocument),
    extractOpenApiCapabilities('user-api', userSource, userDocument),
    extractOidcCapabilities(oidcDocument),
    extractConnectorCapabilities(connectorDocument),
    integrationTestCapabilities,
    manualCapabilities
  );

  return capabilityManifestGuard.parse({
    schemaVersion: 1,
    referenceCommit,
    capabilities,
  });
};
/* eslint-enable max-lines */
