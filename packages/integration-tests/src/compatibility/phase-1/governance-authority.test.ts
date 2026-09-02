/* eslint-disable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Each hostile fixture mutates one isolated canonical CODEOWNERS block. */
import {
  assertPhase1CodeownersGovernanceAuthority,
  phase1CodeownersCoveragePaths,
  Phase1GovernanceAuthorityError,
} from './governance-authority.js';

const encoder = new TextEncoder();
const base = encoder.encode('/existing/ @existing-owner\n');
const reviewer = 'independent-reviewer';
const canonicalBlock = (login = reviewer) =>
  `\n# Aster Phase 1 acceptance authority\n${phase1CodeownersCoveragePaths
    .map((path) => `${path} @qq98982 @${login}`)
    .join('\n')}\n`;
const governance = (block = canonicalBlock()) =>
  encoder.encode(`${new TextDecoder().decode(base)}${block}`);

describe('Phase 1 CODEOWNERS governance authority', () => {
  it('accepts exactly the Phase 0 bytes plus one canonical two-owner coverage block', () => {
    expect(assertPhase1CodeownersGovernanceAuthority(base, governance())).toBe(reviewer);
    expect(assertPhase1CodeownersGovernanceAuthority(base, governance(), reviewer)).toBe(reviewer);
    expect(phase1CodeownersCoveragePaths).toHaveLength(21);
    expect(Object.isFrozen(phase1CodeownersCoveragePaths)).toBe(true);
  });

  it.each([
    ['owner drift', () => governance(canonicalBlock().replace('@qq98982', '@other-owner'))],
    [
      'reviewer drift',
      () => governance(canonicalBlock().replace(`@${reviewer}`, '@another-reviewer')),
    ],
    [
      'duplicate path',
      () => {
        const lines = canonicalBlock().trimEnd().split('\n');
        lines.splice(3, 0, lines[2] ?? '');
        return governance(`${lines.join('\n')}\n`);
      },
    ],
    [
      'missing path',
      () => {
        const lines = canonicalBlock().trimEnd().split('\n');
        lines.splice(3, 1);
        return governance(`${lines.join('\n')}\n`);
      },
    ],
    [
      'reordered paths',
      () => {
        const lines = canonicalBlock().trimEnd().split('\n');
        const first = lines[2];
        lines[2] = lines[3] ?? '';
        lines[3] = first ?? '';
        return governance(`${lines.join('\n')}\n`);
      },
    ],
    ['missing blank line', () => governance(canonicalBlock().slice(1))],
    [
      'wrong heading',
      () => governance(canonicalBlock().replace('Aster Phase 1', 'Other authority')),
    ],
    ['missing final newline', () => governance(canonicalBlock().slice(0, -1))],
    ['extra content', () => governance(`${canonicalBlock()}/extra/ @qq98982 @${reviewer}\n`)],
  ] as const)('rejects %s', (_name, createGovernance) => {
    expect(() =>
      assertPhase1CodeownersGovernanceAuthority(base, createGovernance(), reviewer)
    ).toThrow(/^Invalid Phase 1 governance authority$/u);
  });

  it.each([
    '',
    'qq98982',
    '-reviewer',
    'reviewer-',
    'reviewer--two',
    'reviewer_name',
    'a'.repeat(40),
  ])('rejects noncanonical or non-distinct reviewer %j', (invalidReviewer) => {
    expect(() =>
      assertPhase1CodeownersGovernanceAuthority(base, governance(), invalidReviewer)
    ).toThrow(/^Invalid Phase 1 governance authority$/u);
  });

  it('keeps diagnostics fixed and non-echoing', () => {
    const marker = 'private-governance-authority-marker';

    try {
      assertPhase1CodeownersGovernanceAuthority(
        base,
        governance(`${canonicalBlock()}# ${marker}\n`),
        reviewer
      );
      throw new Error('Expected governance authority rejection');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(Phase1GovernanceAuthorityError);
      expect(error).toMatchObject({
        message: 'Invalid Phase 1 governance authority',
        pointer: '/codeowners',
        rule: 'canonical-block',
      });
      expect(String(error)).not.toContain(marker);
      expect((error as Error).stack).not.toContain(marker);
    }
  });
});

/* eslint-enable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
