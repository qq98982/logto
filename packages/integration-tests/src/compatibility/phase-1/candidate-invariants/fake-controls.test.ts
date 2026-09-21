/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation -- Hostile controls capture fixed errors and cross canonical ID and closed-data type boundaries. */
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { assertPhase1EvidenceIsSanitized } from '../evidence.js';
import {
  candidateInvariantScenarioIds,
  defineCandidateInvariant,
  type CandidateInvariantContract,
} from '../model.js';

import { candidateInvariantEvidenceGuard } from './evidence.js';
import {
  applyCandidateInvariantFaultForTesting,
  runAllCandidateInvariantFakeControls,
  runCandidateInvariantFakeControls,
  runCandidateInvariantFakeControlsForTesting,
} from './fake-controls.js';
import { candidateInvariantContracts } from './index.js';

const diagnostic = /^Invalid phase 1 candidate invariant fake control$/u;

describe('phase 1 candidate invariant fake controls', () => {
  it('detects exactly one declared pointer for every invariant', () => {
    const evidence = runAllCandidateInvariantFakeControls();

    expect(evidence.map(({ scenarioId }) => scenarioId)).toEqual(candidateInvariantScenarioIds);
    expect(evidence).toHaveLength(18);
    for (const [index, result] of evidence.entries()) {
      const contract = candidateInvariantContracts[index];

      if (!contract) {
        throw new Error('Candidate invariant registry is incomplete');
      }

      expect(candidateInvariantEvidenceGuard.safeParse(result).success).toBe(true);
      expect(result.candidate.outcome).toEqual(contract.positiveControl.expectedProjection);
      expect(result.positiveControl).toEqual({ passed: true, differences: [] });
      expect(result.negativeControl.passed).toBe(true);
      expect(result.negativeControl.differences).toHaveLength(1);
      expect(result.negativeControl.differences[0]?.path).toBe(
        contract.negativeControl.expectedDifferencePointer
      );
      expect(Object.isFrozen(result)).toBe(true);
      expect(Object.isFrozen(result.candidate.outcome)).toBe(true);
      expect(() => {
        assertPhase1EvidenceIsSanitized(result);
      }).not.toThrow();
    }
  });

  it('resolves only canonical IDs and emits fixed redacted diagnostics', () => {
    for (const hostile of ['unknown', 'Bearer private-value']) {
      let error: unknown;
      try {
        runCandidateInvariantFakeControls(hostile as never);
      } catch (error_: unknown) {
        error = error_;
      }
      expect(error).toBeInstanceOf(TypeError);
      expect((error as TypeError).message).toMatch(diagnostic);
      expect((error as TypeError).message).not.toContain(hostile);
    }
  });

  it.each([
    {
      name: 'wrong fault pointer',
      mutate: (contract: CandidateInvariantContract) => ({
        ...contract,
        negativeControl: {
          ...contract.negativeControl,
          input: {
            variant: 'negative',
            fault: { operation: 'replace', path: '/activation/currentEpoch', value: 9 },
          },
        },
      }),
    },
    {
      name: 'zero effective differences',
      mutate: (contract: CandidateInvariantContract) => ({
        ...contract,
        negativeControl: {
          ...contract.negativeControl,
          expectedProjection: contract.positiveControl.expectedProjection,
        },
      }),
    },
    {
      name: 'two effective differences',
      mutate: (contract: CandidateInvariantContract) => ({
        ...contract,
        negativeControl: {
          ...contract.negativeControl,
          expectedProjection: {
            ...(contract.negativeControl.expectedProjection as Record<string, unknown>),
            extraChangedField: true,
          },
        },
      }),
    },
  ])('rejects $name with one fixed diagnostic', ({ mutate }) => {
    const invalid = defineCandidateInvariant(
      mutate(candidateInvariantContracts[1]) as CandidateInvariantContract
    );

    expect(() => runCandidateInvariantFakeControlsForTesting(invalid)).toThrow(diagnostic);
  });

  it('decodes escaped JSON-pointer segments without importing Phase 0 comparison semantics', () => {
    expect(
      applyCandidateInvariantFaultForTesting(
        { 'a/b': { '~key': false } },
        { operation: 'replace', path: '/a~1b/~0key', value: true }
      )
    ).toEqual({ 'a/b': { '~key': true } });
  });

  it('keeps the candidate evidence and fake executor source free of Phase 0 comparison imports', async () => {
    const sources = await Promise.all(
      ['evidence.ts', 'fake-controls.ts'].map(async (filename) =>
        readFile(
          path.resolve(process.cwd(), 'src/compatibility/phase-1/candidate-invariants', filename),
          'utf8'
        )
      )
    );

    for (const source of sources) {
      expect(source).not.toMatch(/from\s+['"][^'"]*compare\.js['"]/u);
    }
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
