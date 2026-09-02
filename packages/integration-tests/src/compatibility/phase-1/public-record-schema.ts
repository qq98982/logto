/* eslint-disable complexity, no-restricted-syntax, curly, prefer-destructuring, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-non-null-assertion, @typescript-eslint/no-unnecessary-boolean-literal-compare, unicorn/no-thenable, unicorn/no-array-for-each, unicorn/no-array-callback-reference, unicorn/explicit-length-check -- The public acceptance schema and its non-JSON-Schema relational checks are one closed audited boundary. */
import { types as nodeTypes } from 'node:util';

import { Ajv2020, type AnySchema } from 'ajv/dist/2020.js';
import { format } from 'prettier';

import { assertEvidenceIsSanitized } from '../evidence.js';

import { bytewiseCompare, phase1EvidenceFileNames } from './artifact-contract.js';
import { phase1ConformanceAdapterControlIds } from './conformance/runner.js';
import { snapshotClosedDataGraph } from './model.js';

export const phase1MirrorStatement =
  'Mirror control only; this record does not claim Aster runtime compatibility or OpenID Foundation certification.';
export const phase1RuntimeCandidateStatement =
  'Aster Phase 1 acceptance passed for the pinned profile, schema, harness, images, and evidence.';
export const phase1PublicArtifactFiles = phase1EvidenceFileNames;
export const phase1PublicAdapterIds = phase1ConformanceAdapterControlIds;

const sha256 = { type: 'string', pattern: '^[0-9a-f]{64}$' } as const;
const commit = { type: 'string', pattern: '^[0-9a-f]{40}$' } as const;
const imageDigest = { type: 'string', pattern: '^sha256:[0-9a-f]{64}$' } as const;
const nonEmptyString = {
  type: 'string',
  minLength: 1,
  maxLength: 256,
  pattern: '^[^\\u0000-\\u001f\\u007f]+$',
} as const;
const aggregate = (countKey: 'scenarioCount' | 'flowCount') => ({
  type: 'object',
  additionalProperties: false,
  required: [countKey, 'differenceCount', 'aggregateSha256'],
  properties: {
    [countKey]: { type: 'integer', const: countKey === 'scenarioCount' ? 22 : 4 },
    differenceCount: { type: 'integer', const: 0 },
    aggregateSha256: { $ref: '#/$defs/sha256' },
  },
});
const artifactItem = (filename: (typeof phase1PublicArtifactFiles)[number]) => ({
  type: 'object',
  additionalProperties: false,
  required: ['filename', 'sha256', 'size'],
  properties: {
    filename: { const: filename },
    sha256: { $ref: '#/$defs/sha256' },
    size: { type: 'integer', minimum: 1, maximum: 1_048_576 },
  },
});

export const createPhase1PublicRecordSchema = () =>
  ({
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'urn:aster:compatibility:phase-1-public-record:1',
    title: 'Aster Phase 1 public acceptance record',
    type: 'object',
    additionalProperties: false,
    required: [
      'schemaVersion',
      'mode',
      'profileId',
      'asterCommit',
      'schemaSourceCommit',
      'harnessCommit',
      'profileSha256',
      'schemaSha256',
      'oracleImageDigest',
      'candidateImageDigest',
      'uiSource',
      'differential',
      'candidateInvariantControls',
      'browser',
      'conformance',
      'evidenceManifestSha256',
      'artifactFiles',
      'statement',
      'asterGovernanceSatisfied',
      'asterPrivateRecordSha256',
    ],
    properties: {
      schemaVersion: { const: 1 },
      mode: { enum: ['runtime-candidate', 'mirror-control'] },
      profileId: { $ref: '#/$defs/nonEmptyString' },
      asterCommit: { $ref: '#/$defs/commit' },
      schemaSourceCommit: { $ref: '#/$defs/commit' },
      harnessCommit: { $ref: '#/$defs/commit' },
      profileSha256: { $ref: '#/$defs/sha256' },
      schemaSha256: { $ref: '#/$defs/sha256' },
      oracleImageDigest: { $ref: '#/$defs/imageDigest' },
      candidateImageDigest: { $ref: '#/$defs/imageDigest' },
      uiSource: { $ref: '#/$defs/uiSource' },
      differential: { $ref: '#/$defs/differential' },
      candidateInvariantControls: { $ref: '#/$defs/candidateInvariantControls' },
      browser: { $ref: '#/$defs/browser' },
      conformance: { $ref: '#/$defs/conformance' },
      evidenceManifestSha256: { $ref: '#/$defs/sha256' },
      artifactFiles: {
        type: 'array',
        minItems: 4,
        maxItems: 4,
        uniqueItems: true,
        prefixItems: phase1PublicArtifactFiles.map((filename) => artifactItem(filename)),
        items: false,
      },
      statement: { $ref: '#/$defs/nonEmptyString' },
      asterGovernanceSatisfied: { const: true },
      asterPrivateRecordSha256: { $ref: '#/$defs/sha256' },
    },
    allOf: [
      {
        if: {
          type: 'object',
          properties: { mode: { const: 'mirror-control' } },
          required: ['mode'],
        },
        then: {
          type: 'object',
          properties: {
            conformance: {
              type: 'object',
              properties: { officialPlanIds: { type: 'array', maxItems: 0 } },
            },
            statement: { const: phase1MirrorStatement },
          },
        },
      },
      {
        if: {
          type: 'object',
          properties: { mode: { const: 'runtime-candidate' } },
          required: ['mode'],
        },
        then: {
          type: 'object',
          properties: {
            conformance: {
              type: 'object',
              properties: { officialPlanIds: { type: 'array', minItems: 2, maxItems: 2 } },
            },
            statement: { const: phase1RuntimeCandidateStatement },
          },
        },
      },
    ],
    $defs: {
      nonEmptyString,
      commit,
      sha256,
      imageDigest,
      gitObject: commit,
      uiSource: {
        type: 'object',
        additionalProperties: false,
        required: ['consoleTree', 'experienceTree', 'demoAppTree', 'pnpmLockBlob'],
        properties: {
          consoleTree: { $ref: '#/$defs/gitObject' },
          experienceTree: { $ref: '#/$defs/gitObject' },
          demoAppTree: { $ref: '#/$defs/gitObject' },
          pnpmLockBlob: { $ref: '#/$defs/gitObject' },
        },
      },
      differential: aggregate('scenarioCount'),
      candidateInvariantControls: {
        type: 'object',
        additionalProperties: false,
        required: ['scenarioCount', 'allDetected', 'aggregateSha256'],
        properties: {
          scenarioCount: { type: 'integer', const: 18 },
          allDetected: { const: true },
          aggregateSha256: { $ref: '#/$defs/sha256' },
        },
      },
      browser: aggregate('flowCount'),
      opaqueResultId: { type: 'string', pattern: '^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$' },
      conformance: {
        type: 'object',
        additionalProperties: false,
        required: ['adapterIds', 'officialPlanIds'],
        properties: {
          adapterIds: {
            type: 'array',
            minItems: 3,
            maxItems: 3,
            uniqueItems: true,
            prefixItems: phase1PublicAdapterIds.map((id) => ({ const: id })),
            items: false,
          },
          officialPlanIds: {
            type: 'array',
            minItems: 0,
            maxItems: 2,
            uniqueItems: true,
            items: { $ref: '#/$defs/opaqueResultId' },
          },
        },
      },
    },
  }) as const;

export const serializePhase1PublicRecordSchema = async (): Promise<string> =>
  format(JSON.stringify(createPhase1PublicRecordSchema()), {
    filepath: 'mirror-control.schema.json',
  });

const validator = new Ajv2020({ allErrors: true, strict: true }).compile(
  createPhase1PublicRecordSchema() as AnySchema
);
const exactKeys = (value: Record<string, unknown>, keys: readonly string[]) =>
  Reflect.ownKeys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const publicKeys = Object.freeze([
  'schemaVersion',
  'mode',
  'profileId',
  'asterCommit',
  'schemaSourceCommit',
  'harnessCommit',
  'profileSha256',
  'schemaSha256',
  'oracleImageDigest',
  'candidateImageDigest',
  'uiSource',
  'differential',
  'candidateInvariantControls',
  'browser',
  'conformance',
  'evidenceManifestSha256',
  'artifactFiles',
  'statement',
  'asterGovernanceSatisfied',
  'asterPrivateRecordSha256',
]);
const forbiddenPublicKey =
  /(?:governance|reviewer|pullrequest|ruleset|checkdetail|approvingreviewer)/iu;

export const assertPhase1PublicRecordSemantics = (input: unknown): void => {
  try {
    const value = snapshotClosedDataGraph<Record<string, unknown>>(input);
    if (
      !value ||
      Array.isArray(value) ||
      nodeTypes.isProxy(value) ||
      !exactKeys(value, publicKeys) ||
      !validator(value)
    ) {
      throw new TypeError('invalid');
    }
    assertEvidenceIsSanitized(value);
    const visit = (candidate: unknown): void => {
      if (Array.isArray(candidate)) return candidate.forEach(visit);
      if (candidate && typeof candidate === 'object') {
        for (const [key, nested] of Object.entries(candidate)) {
          if (key !== 'asterGovernanceSatisfied' && forbiddenPublicKey.test(key)) {
            throw new TypeError('invalid');
          }
          visit(nested);
        }
      }
    };
    visit(value);
    const mode = value.mode;
    const files = value.artifactFiles as Array<{ filename: string }>;
    const conformance = value.conformance as { adapterIds: string[]; officialPlanIds: string[] };
    const differential = value.differential as { scenarioCount: number; differenceCount: number };
    const controls = value.candidateInvariantControls as {
      scenarioCount: number;
      allDetected: boolean;
    };
    const browser = value.browser as { flowCount: number; differenceCount: number };
    if (
      JSON.stringify(files.map(({ filename }) => filename)) !==
        JSON.stringify(phase1PublicArtifactFiles) ||
      JSON.stringify(conformance.adapterIds) !== JSON.stringify(phase1PublicAdapterIds) ||
      conformance.officialPlanIds.some(
        (id, index, ids) => index > 0 && bytewiseCompare(ids[index - 1]!, id) >= 0
      ) ||
      differential.scenarioCount !== 22 ||
      differential.differenceCount !== 0 ||
      controls.scenarioCount !== 18 ||
      controls.allDetected !== true ||
      browser.flowCount !== 4 ||
      browser.differenceCount !== 0 ||
      (mode === 'mirror-control' && value.oracleImageDigest !== value.candidateImageDigest) ||
      (mode === 'mirror-control' && conformance.officialPlanIds.length !== 0) ||
      (mode === 'runtime-candidate' &&
        (conformance.officialPlanIds.length !== 2 ||
          conformance.officialPlanIds.some((id) =>
            [
              'oidcc-basic-certification-test-plan',
              'oidcc-config-certification-test-plan',
            ].includes(id)
          )))
    )
      throw new TypeError('invalid');
  } catch {
    throw new TypeError('Invalid phase 1 public record');
  }
};

/* eslint-enable complexity, no-restricted-syntax, curly, prefer-destructuring, @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-non-null-assertion, @typescript-eslint/no-unnecessary-boolean-literal-compare, unicorn/no-thenable, unicorn/no-array-for-each, unicorn/no-array-callback-reference, unicorn/explicit-length-check */
