/* eslint-disable @silverhand/fp/no-mutating-methods -- Registry controls deliberately construct hostile arrays, clones, descriptors, and cross-kind records. */
import { candidateInvariantScenarioIds, differentialScenarioIds } from '../model.js';

import {
  assertExactCandidateInvariantRegistry,
  candidateInvariantAuthorities,
  candidateInvariantContracts,
  candidateInvariantRegistryIds,
  getCandidateInvariantContract,
} from './index.js';

const diagnostic = /^Invalid phase 1 candidate invariant registry$/u;

describe('phase 1 candidate invariant registry', () => {
  it('contains the exact ordered eighteen canonical module identities', () => {
    expect(candidateInvariantContracts.map(({ id }) => id)).toEqual(candidateInvariantScenarioIds);
    expect(candidateInvariantRegistryIds).toEqual(candidateInvariantScenarioIds);
    expect(candidateInvariantAuthorities).toBe(candidateInvariantContracts);
    expect(new Set(candidateInvariantContracts).size).toBe(18);
    expect(() => {
      assertExactCandidateInvariantRegistry(candidateInvariantContracts);
    }).not.toThrow();

    for (const [index, id] of candidateInvariantScenarioIds.entries()) {
      expect(getCandidateInvariantContract(id)).toBe(candidateInvariantContracts[index]);
    }
  });

  it('replaces every pending authority with a complete frozen contract', () => {
    for (const contract of candidateInvariantContracts) {
      expect(Object.keys(contract)).toEqual([
        'id',
        'evidenceKind',
        'executor',
        'livePrecondition',
        'perturbation',
        'expectedPublicOutcome',
        'expectedPersistedOutcome',
        'forbiddenOutcome',
        'cleanup',
        'sanitizedProjection',
        'projectionVersion',
        'positiveControl',
        'negativeControl',
      ]);
      expect(contract.evidenceKind).toBe('candidate-invariant');
      expect(contract.executor).toBe('aster');
      expect(contract.projectionVersion).toBe(1);
      expect(Object.isFrozen(contract)).toBe(true);
      expect(Object.isFrozen(contract.positiveControl.expectedProjection)).toBe(true);
      expect(Object.isFrozen(contract.negativeControl.expectedProjection)).toBe(true);
    }
  });

  it.each([
    ['empty', () => []],
    ['missing', () => candidateInvariantContracts.slice(0, -1)],
    ['extra', () => [...candidateInvariantContracts, candidateInvariantContracts[0]]],
    [
      'duplicate',
      () => [
        candidateInvariantContracts[0],
        candidateInvariantContracts[0],
        ...candidateInvariantContracts.slice(2),
      ],
    ],
    [
      'reordered',
      () => [
        candidateInvariantContracts[1],
        candidateInvariantContracts[0],
        ...candidateInvariantContracts.slice(2),
      ],
    ],
    [
      'cloned-contract',
      () => [{ ...candidateInvariantContracts[0] }, ...candidateInvariantContracts.slice(1)],
    ],
    [
      'cross-kind',
      () => [
        { ...candidateInvariantContracts[0], id: differentialScenarioIds[0] },
        ...candidateInvariantContracts.slice(1),
      ],
    ],
  ] as const)('rejects the %s registry', (_name, create) => {
    expect(() => {
      assertExactCandidateInvariantRegistry(create());
    }).toThrow(diagnostic);
  });

  it('rejects sparse array-like extra-key symbol accessor proxy and wrong-prototype registries', () => {
    const hole = [...candidateInvariantContracts];
    Reflect.deleteProperty(hole, '8');
    const extra = [...candidateInvariantContracts];
    Object.defineProperty(extra, 'extra', { enumerable: true, value: true });
    const symbol = [...candidateInvariantContracts];
    Object.defineProperty(symbol, Symbol('extra'), { enumerable: true, value: true });
    const accessor = [...candidateInvariantContracts];
    Object.defineProperty(accessor, '0', {
      enumerable: true,
      get: () => candidateInvariantContracts[0],
    });
    const wrongPrototype = [...candidateInvariantContracts];
    Object.setPrototypeOf(wrongPrototype, null);
    const invalid = [
      hole,
      { 0: candidateInvariantContracts[0], length: candidateInvariantContracts.length },
      extra,
      symbol,
      accessor,
      new Proxy([...candidateInvariantContracts], {}),
      wrongPrototype,
    ];

    for (const registry of invalid) {
      expect(() => {
        assertExactCandidateInvariantRegistry(registry);
      }).toThrow(diagnostic);
    }
  });

  it('rejects unknown and cross-kind lookups with a fixed diagnostic', () => {
    for (const id of ['unknown', differentialScenarioIds[0]]) {
      expect(() => getCandidateInvariantContract(id)).toThrow(diagnostic);
    }
  });

  it('does not alter the Phase 0 scenario registry on import', async () => {
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

/* eslint-enable @silverhand/fp/no-mutating-methods */
