/* eslint-disable @silverhand/fp/no-mutation -- Negative controls mutate isolated snapshot inputs. */
import type { JsonObject } from '../../normalize.js';
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

const inputWithBoundedTimestamp = (
  timestamp: number,
  tolerance = 30,
  source = 'application'
): OracleSnapshotInput => ({
  ...input(),
  projections: oracleSnapshotIds.map((id, index) => {
    const value: JsonObject =
      index === 0
        ? {
            observedAt: { $timestamp: timestamp, $toleranceSeconds: tolerance },
            exactLookalike: {
              $timestamp: 1_600_000_000,
              $toleranceSeconds: 30,
              source,
            },
          }
        : { passed: true };

    return { id, value };
  }),
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

  it('canonicalizes only exact bounded timestamp envelopes while retaining their tolerance', () => {
    const first = createOracleSnapshotSet(inputWithBoundedTimestamp(1_700_000_000));
    const second = createOracleSnapshotSet(inputWithBoundedTimestamp(1_800_000_000));
    const changedTolerance = createOracleSnapshotSet(inputWithBoundedTimestamp(1_800_000_000, 31));
    const changedLookalike = createOracleSnapshotSet(
      inputWithBoundedTimestamp(1_800_000_000, 30, 'changed')
    );

    expect(first).toEqual(second);
    expect(changedTolerance).not.toEqual(first);
    expect(changedLookalike).not.toEqual(first);
    expect(first.snapshots.find(({ id }) => id === oracleSnapshotIds[0])?.value).toEqual({
      observedAt: { $boundedTimestamp: 30 },
      exactLookalike: {
        $timestamp: 1_600_000_000,
        $toleranceSeconds: 30,
        source: 'application',
      },
    });
  });

  it('rejects a raw projection that forges the snapshot-only timestamp marker', () => {
    const forged = input();
    const projections = [...forged.projections];

    projections[0] = {
      id: projections[0]!.id,
      value: { nested: [{ $boundedTimestamp: 30 }] },
    };

    expect(() => createOracleSnapshotSet({ ...forged, projections })).toThrow(
      /^Invalid phase 1 oracle snapshot$/u
    );
  });

  it.each([
    { $boundedTimestamp: 30, extra: true },
    { $boundedTimestamp: true },
    { $boundedTimestamp: -1 },
  ] as const)('rejects an invalid persisted timestamp marker %#', (invalidMarker) => {
    const persisted = JSON.parse(
      JSON.stringify(createOracleSnapshotSet(inputWithBoundedTimestamp(1_700_000_000)))
    ) as {
      snapshots: Array<{ id: string; value: Record<string, unknown> }>;
    };
    const snapshot = persisted.snapshots.find(({ id }) => id === oracleSnapshotIds[0]);

    expect(snapshot).toBeDefined();
    snapshot!.value.observedAt = invalidMarker;
    expect(() => assertOracleSnapshotSet(persisted)).toThrow(/^Invalid phase 1 oracle snapshot$/u);
  });

  it('rejects a persisted raw timestamp envelope even when its canonical hash still matches', () => {
    const persisted = JSON.parse(
      JSON.stringify(createOracleSnapshotSet(inputWithBoundedTimestamp(1_700_000_000)))
    ) as {
      snapshots: Array<{ id: string; value: Record<string, unknown> }>;
    };
    const snapshot = persisted.snapshots.find(({ id }) => id === oracleSnapshotIds[0]);

    expect(snapshot).toBeDefined();
    snapshot!.value.observedAt = { $timestamp: 1_700_000_000, $toleranceSeconds: 30 };
    expect(() => assertOracleSnapshotSet(persisted)).toThrow(/^Invalid phase 1 oracle snapshot$/u);
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
