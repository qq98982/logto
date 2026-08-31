/* eslint-disable @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-array-for-each -- Exact registry mutation tests intentionally cross readonly and literal-type boundaries. */
import {
  candidateInvariantScenarioIds,
  defineCandidateInvariant,
  differentialScenarioIds,
  type CandidateInvariantContract,
} from '../model.js';

import { assertExactCandidateInvariantRegistry, candidateInvariantAuthorities } from './index.js';

const contractFor = (
  id: (typeof candidateInvariantScenarioIds)[number]
): CandidateInvariantContract => ({
  id,
  evidenceKind: 'candidate-invariant',
  executor: 'aster',
  livePrecondition: { description: 'Task 14 live precondition' },
  perturbation: { description: 'Task 14 deterministic perturbation' },
  expectedPublicOutcome: { accepted: false },
  expectedPersistedOutcome: { mutationCount: 0 },
  forbiddenOutcome: { accepted: true },
  cleanup: { description: 'Task 14 deterministic cleanup' },
  sanitizedProjection: { fields: ['accepted', 'mutationCount'] },
  projectionVersion: 1,
  positiveControl: {
    kind: 'positive',
    name: 'positive control',
    input: { fault: false },
    expectedProjection: { accepted: false },
    expectedDifferencePointer: null,
  },
  negativeControl: {
    kind: 'negative',
    name: 'negative control',
    input: { fault: true },
    expectedProjection: { accepted: true },
    expectedDifferencePointer: '/control/accepted',
  },
});

const mutate = (index: number, update: (copy: any) => void) =>
  candidateInvariantAuthorities.map((authority, authorityIndex) => {
    if (authorityIndex !== index) {
      return authority;
    }
    const copy = { ...authority };
    update(copy);
    return copy;
  });

describe('phase 1 candidate invariant authority registry', () => {
  it('rejects sparse array-like accessor proxy extra-key and wrong-prototype registries', () => {
    const valid = candidateInvariantAuthorities;
    const holeAt = (index: number) => {
      const value = [...valid];
      Reflect.deleteProperty(value, String(index));
      return value;
    };
    const extra = [...valid];
    Object.defineProperty(extra, 'extra', { enumerable: true, value: true });
    const symbol = [...valid];
    Object.defineProperty(symbol, Symbol('extra'), { enumerable: true, value: true });
    const accessor = [...valid];
    Object.defineProperty(accessor, '0', { enumerable: true, get: () => valid[0] });
    const wrongPrototype = [...valid];
    Object.setPrototypeOf(wrongPrototype, null);
    const invalid = [
      holeAt(0),
      holeAt(Math.floor(valid.length / 2)),
      holeAt(valid.length - 1),
      { 0: valid[0], length: valid.length, some: Array.prototype.some },
      extra,
      symbol,
      accessor,
      new Proxy([...valid], {
        ownKeys: () => {
          throw new Error('must not escape');
        },
      }),
      new Proxy([...valid], {
        getOwnPropertyDescriptor: () => {
          throw new Error('must not escape');
        },
      }),
      wrongPrototype,
    ];

    expect(() => assertExactCandidateInvariantRegistry(Object.freeze([...valid]))).not.toThrow();
    for (const registry of invalid) {
      expect(() => assertExactCandidateInvariantRegistry(registry as never)).toThrow(
        /^Invalid phase 1 candidate invariant registry$/u
      );
    }
  });

  it('rejects unsafe authority records before Zod or equality reads them', () => {
    const canonical = candidateInvariantAuthorities[0]!;
    const nonEnumerable = { ...canonical };
    Object.defineProperty(nonEnumerable, 'injected', { enumerable: false, value: true });
    const symbol = { ...canonical };
    Object.defineProperty(symbol, Symbol('injected'), { enumerable: true, value: true });
    const accessor = { ...canonical };
    Object.defineProperty(accessor, 'id', { enumerable: true, get: () => canonical.id });
    const wrongPrototype = { ...canonical };
    Object.setPrototypeOf(wrongPrototype, null);
    const invalid = [
      { ...canonical, injected: true },
      nonEnumerable,
      symbol,
      accessor,
      new Proxy({ ...canonical }, {}),
      new Proxy(
        { ...canonical },
        {
          getOwnPropertyDescriptor: () => {
            throw new Error('must not escape');
          },
        }
      ),
      wrongPrototype,
    ];

    for (const malformed of invalid) {
      expect(() =>
        assertExactCandidateInvariantRegistry([
          malformed,
          ...candidateInvariantAuthorities.slice(1),
        ] as never)
      ).toThrow(/^Invalid phase 1 candidate invariant registry$/u);
    }
  });

  it('contains the exact ordered 18 candidate-only IDs', () => {
    expect(candidateInvariantAuthorities.map(({ id }) => id)).toEqual(
      candidateInvariantScenarioIds
    );
    expect(new Set(candidateInvariantAuthorities.map(({ id }) => id)).size).toBe(18);
    expect(
      candidateInvariantAuthorities.every(
        ({ evidenceKind, implementation }) =>
          evidenceKind === 'candidate-invariant' && implementation === 'contract-pending'
      )
    ).toBe(true);
  });

  it('does not represent pending authorities as implemented live invariants', () => {
    for (const authority of candidateInvariantAuthorities) {
      expect(Object.keys(authority)).toEqual(['id', 'evidenceKind', 'implementation']);
      expect(authority).not.toHaveProperty('executor');
      expect(authority).not.toHaveProperty('livePrecondition');
      expect(authority).not.toHaveProperty('positiveControl');
      expect(authority).not.toHaveProperty('negativeControl');
    }
  });

  it('keeps every exact ID compatible with the Task 14 full contract constructor', () => {
    for (const id of candidateInvariantScenarioIds) {
      const contract = defineCandidateInvariant(contractFor(id));

      expect(contract.id).toBe(id);
      expect(contract.executor).toBe('aster');
      expect(contract.projectionVersion).toBe(1);
      expect(Object.isFrozen(contract)).toBe(true);
    }
  });

  it('rejects every ID evidence-kind and implementation mutation', () => {
    candidateInvariantAuthorities.forEach((_authority, index) => {
      const mutations: Array<(copy: any) => void> = [
        (copy) => {
          copy.id = `${copy.id}.mutated`;
        },
        (copy) => {
          copy.evidenceKind = 'differential';
        },
        (copy) => {
          copy.implementation = 'live';
        },
      ];

      for (const update of mutations) {
        expect(() => assertExactCandidateInvariantRegistry(mutate(index, update))).toThrow(
          /^Invalid phase 1 candidate invariant registry$/u
        );
      }
    });
  });

  it('rejects empty missing duplicate extra reordered and cross-kind registries', () => {
    const first = candidateInvariantAuthorities[0]!;
    const second = candidateInvariantAuthorities[1]!;
    const crossKind = mutate(0, (copy) => {
      copy.id = differentialScenarioIds[0];
      copy.evidenceKind = 'differential';
    })[0]!;
    const variants = [
      [],
      candidateInvariantAuthorities.slice(0, -1),
      [...candidateInvariantAuthorities, first],
      [first, first, ...candidateInvariantAuthorities.slice(2)],
      [second, first, ...candidateInvariantAuthorities.slice(2)],
      [crossKind, ...candidateInvariantAuthorities.slice(1)],
    ];

    for (const variant of variants) {
      expect(() => assertExactCandidateInvariantRegistry(variant)).toThrow(
        /^Invalid phase 1 candidate invariant registry$/u
      );
    }
  });

  it('is recursively frozen', () => {
    expect(Object.isFrozen(candidateInvariantAuthorities)).toBe(true);
    expect(candidateInvariantAuthorities.every((authority) => Object.isFrozen(authority))).toBe(
      true
    );
  });

  it('does not alter a fresh Phase 0 registry identity or content on import', async () => {
    await import.meta.jest.isolateModulesAsync(async () => {
      const beforeModule = await import('../../scenarios/index.js');
      const before = beforeModule.defaultCompatibilityScenarios;
      const contents = before.map(({ id, run }) => ({ id, run }));

      await import('./index.js');
      const afterModule = await import('../../scenarios/index.js');
      const after = afterModule.defaultCompatibilityScenarios;

      expect(after).toBe(before);
      expect(after.map(({ id, run }) => ({ id, run }))).toEqual(contents);
    });
  });
});

/* eslint-enable @typescript-eslint/no-confusing-void-expression, @typescript-eslint/no-explicit-any, @typescript-eslint/no-unnecessary-condition, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, unicorn/no-array-for-each */
