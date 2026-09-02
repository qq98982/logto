/* eslint-disable @silverhand/fp/no-mutation -- Negative controls mutate isolated snapshot inputs. */
import { canonicalBrowserFlows } from '../browser/index.js';
import { differentialScenarioIds, oracleCommit } from '../model.js';

import {
  assertOracleSnapshotSet,
  createOracleSnapshotSet,
  oracleSnapshotIds,
  type OracleSnapshotInput,
} from './oracle.js';

const digest = `sha256:${'a'.repeat(64)}`;
const input = (): OracleSnapshotInput => ({
  recordOracle: true,
  referenceCommit: oracleCommit,
  imageDigest: digest,
  harnessClean: true,
  sanitizerSuccess: true,
  projections: oracleSnapshotIds.map((id) => ({ id, value: { passed: true } })),
});

describe('Phase 1 oracle snapshots', () => {
  it('locks the exact 22 scenario and four browser projection identities', () => {
    const result = createOracleSnapshotSet(input());

    expect(differentialScenarioIds).toHaveLength(22);
    expect(canonicalBrowserFlows).toHaveLength(4);
    expect(result.snapshots.map(({ id }) => id)).toEqual(oracleSnapshotIds.toSorted());
    expect(
      result.snapshots.every(({ projectionSha256 }) => /^[0-9a-f]{64}$/u.test(projectionSha256))
    ).toBe(true);
    expect(assertOracleSnapshotSet(JSON.parse(JSON.stringify(result)) as unknown)).toEqual(result);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it.each([
    ['implicit recording', (value: OracleSnapshotInput) => ({ ...value, recordOracle: false })],
    [
      'wrong commit',
      (value: OracleSnapshotInput) => ({ ...value, referenceCommit: 'b'.repeat(40) }),
    ],
    ['mutable image', (value: OracleSnapshotInput) => ({ ...value, imageDigest: 'oracle:latest' })],
    ['dirty harness', (value: OracleSnapshotInput) => ({ ...value, harnessClean: false })],
    ['failed sanitizer', (value: OracleSnapshotInput) => ({ ...value, sanitizerSuccess: false })],
    [
      'missing projection',
      (value: OracleSnapshotInput) => ({ ...value, projections: value.projections.slice(1) }),
    ],
    [
      'secret projection',
      (value: OracleSnapshotInput) => ({
        ...value,
        projections: [
          { ...value.projections[0]!, value: { accessToken: 'private-token-value' } },
          ...value.projections.slice(1),
        ],
      }),
    ],
  ] as const)('rejects %s with one fixed diagnostic', (_name, mutate) => {
    expect(() => createOracleSnapshotSet(mutate(input()))).toThrow(
      /^Invalid phase 1 oracle snapshot$/u
    );
  });

  it('rejects a modified persisted projection hash', () => {
    const value = JSON.parse(JSON.stringify(createOracleSnapshotSet(input()))) as {
      snapshots: Array<{ projectionSha256: string }>;
    };
    value.snapshots[0]!.projectionSha256 = '0'.repeat(64);

    expect(() => assertOracleSnapshotSet(value)).toThrow(/^Invalid phase 1 oracle snapshot$/u);
  });

  it('rejects extra persisted snapshot-envelope fields', () => {
    const value = JSON.parse(JSON.stringify(createOracleSnapshotSet(input()))) as {
      snapshots: Array<Record<string, unknown>>;
    };
    value.snapshots[0]!.rawResult = 'private-result';

    expect(() => assertOracleSnapshotSet(value)).toThrow(/^Invalid phase 1 oracle snapshot$/u);
  });
});

/* eslint-enable @silverhand/fp/no-mutation */
