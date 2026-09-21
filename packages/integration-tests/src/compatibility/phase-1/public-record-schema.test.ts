/* eslint-disable @typescript-eslint/no-confusing-void-expression, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Each hostile case mutates one isolated public-record fixture. */
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { Ajv2020, type AnySchema } from 'ajv/dist/2020.js';

import {
  assertPhase1PublicRecordSemantics,
  createPhase1PublicRecordSchema,
  phase1MirrorStatement,
  phase1RuntimeCandidateStatement,
  serializePhase1PublicRecordSchema,
} from './public-record-schema.js';

const hash = 'a'.repeat(64);
const commit = 'b'.repeat(40);
const digest = `sha256:${'c'.repeat(64)}`;
const artifactNames = [
  'phase-1-browser.json',
  'phase-1-candidate-invariants.json',
  'phase-1-conformance.json',
  'phase-1-differential.json',
];
const record = (mode: 'mirror-control' | 'runtime-candidate' = 'mirror-control') => ({
  schemaVersion: 1,
  mode,
  profileId: 'aster.phase-1.password-pkce',
  asterCommit: commit,
  schemaSourceCommit: commit,
  harnessCommit: commit,
  profileSha256: hash,
  schemaSha256: hash,
  oracleImageDigest: digest,
  candidateImageDigest: digest,
  uiSource: {
    consoleTree: commit,
    experienceTree: commit,
    demoAppTree: commit,
    pnpmLockBlob: commit,
  },
  differential: { scenarioCount: 22, differenceCount: 0, aggregateSha256: hash },
  candidateInvariantControls: { scenarioCount: 18, allDetected: true, aggregateSha256: hash },
  browser: { flowCount: 4, differenceCount: 0, aggregateSha256: hash },
  conformance: {
    adapterIds: ['oidf-basic-1', 'oidf-basic-2', 'oidf-post-1'],
    officialPlanIds:
      mode === 'mirror-control' ? [] : ['official-result-alpha', 'official-result-beta'],
  },
  evidenceManifestSha256: hash,
  artifactFiles: artifactNames.map((filename) => ({ filename, sha256: hash, size: 123 })),
  statement: mode === 'mirror-control' ? phase1MirrorStatement : phase1RuntimeCandidateStatement,
  asterGovernanceSatisfied: true,
  asterPrivateRecordSha256: hash,
});

describe('Phase 1 public acceptance schema', () => {
  it('contains no unused artifact-file definition', () => {
    expect(Object.hasOwn(createPhase1PublicRecordSchema().$defs, 'artifactFile')).toBe(false);
  });

  it('keeps committed schema bytes exactly equal to deterministic generator output', async () => {
    const committed = await readFile(
      path.resolve(
        process.cwd(),
        '../../compatibility/phase-1-acceptance/mirror-control.schema.json'
      ),
      'utf8'
    );

    expect(committed).toBe(await serializePhase1PublicRecordSchema());
  });

  it.each(['mirror-control', 'runtime-candidate'] as const)(
    'accepts the closed valid %s record',
    (mode) => {
      const value = record(mode);
      const validate = new Ajv2020({ strict: true, allErrors: true }).compile(
        createPhase1PublicRecordSchema() as AnySchema
      );

      expect(validate(value)).toBe(true);
      expect(() => assertPhase1PublicRecordSemantics(value)).not.toThrow();
    }
  );

  it('schema rejects private governance crossover, unknown roots, missing fields and reordered artifacts', () => {
    const validate = new Ajv2020({ strict: true, allErrors: true }).compile(
      createPhase1PublicRecordSchema() as AnySchema
    );
    const extra = { ...record(), governance: { reviewer: 'private-reviewer' } };
    const missing = record();
    Reflect.deleteProperty(missing, 'schemaSha256');
    const reordered = record();
    reordered.artifactFiles.reverse();

    expect(validate(extra)).toBe(false);
    expect(validate(missing)).toBe(false);
    expect(validate(reordered)).toBe(false);
    expect(validate({ ...record(), mode: 'review-candidate' })).toBe(false);
  });

  it.each([
    [
      'unequal mirror images',
      (value: ReturnType<typeof record>) => {
        value.candidateImageDigest = `sha256:${'d'.repeat(64)}`;
      },
    ],
    [
      'wrong mirror statement',
      (value: ReturnType<typeof record>) => {
        value.statement = phase1RuntimeCandidateStatement;
      },
    ],
    [
      'credential string',
      (value: ReturnType<typeof record>) => {
        value.profileId = 'Bearer private-secret-value';
      },
    ],
    [
      'reviewer field',
      (value: ReturnType<typeof record>) => {
        (value.uiSource as typeof value.uiSource & { reviewer: string }).reviewer = 'private';
      },
    ],
  ] as const)('procedural guard rejects %s', (_name, mutate) => {
    const value = record();
    mutate(value);
    expect(() => assertPhase1PublicRecordSemantics(value)).toThrow('Invalid phase 1 public record');
  });

  it.each([
    ['duplicate IDs', ['official-result-alpha', 'official-result-alpha']],
    ['reordered IDs', ['official-result-beta', 'official-result-alpha']],
    ['plan-name ID', ['oidcc-basic-certification-test-plan', 'official-result-alpha']],
  ] as const)('runtime guard rejects %s', (_name, officialPlanIds) => {
    const value = record('runtime-candidate');
    value.conformance.officialPlanIds = [...officialPlanIds];
    expect(() => assertPhase1PublicRecordSemantics(value)).toThrow('Invalid phase 1 public record');
  });
});

/* eslint-enable @typescript-eslint/no-confusing-void-expression, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
