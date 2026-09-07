/* eslint-disable @silverhand/fp/no-mutating-methods, no-await-in-loop -- Record mock calls and exercise response failures sequentially. */
import { createProductionPhase1GithubReader } from './github-reader.js';

const repository = 'https://github.com/qq98982/logto.git';
const revision = 'a'.repeat(40);
const head = 'b'.repeat(40);
const pr = {
  number: 7,
  state: 'closed',
  merged_at: '2026-09-07T00:00:00Z',
  merge_commit_sha: revision,
  user: { login: 'Author' },
  head: { sha: head },
  base: { sha: 'c'.repeat(40), ref: 'main' },
};
const approval = { id: 1, user: { login: 'Reviewer' }, commit_id: head, state: 'APPROVED' };
const passed = { id: 1, name: 'phase1-pr', head_sha: head, conclusion: 'success' };

const fixture = (reviews: unknown[] = [approval], checks: unknown[] = [passed]) => {
  const calls: string[] = [];
  const request: typeof fetch = async (input, options) => {
    const url = String(input);
    calls.push(url);
    expect(url.startsWith('https://api.github.com/repos/qq98982/logto/')).toBe(true);
    expect(options?.credentials).toBe('omit');
    expect(options?.redirect).toBe('error');
    expect(options?.headers).not.toHaveProperty('authorization');
    const value = url.includes('/pulls?')
      ? [pr]
      : url.includes('/reviews?')
        ? reviews
        : { check_runs: checks };
    return new Response(JSON.stringify(value));
  };
  return { calls, reader: createProductionPhase1GithubReader(request) };
};

it('reads public exact-commit evidence without credentials or branch-rule queries', async () => {
  const { reader, calls } = fixture();
  const result = await reader.acceptedHarnessAuthority(repository, revision);
  expect(result.pullRequests[0]).toMatchObject({
    mergeCommit: revision,
    headCommit: head,
    evaluatedCommit: head,
    author: 'author',
    approvals: [{ reviewer: 'reviewer', state: 'APPROVED', commit: head }],
    requiredChecks: ['compatibility', 'phase1-pr'],
  });
  expect(calls).toHaveLength(3);
  expect(calls.some((url) => /rules|protection|CODEOWNERS/u.test(url))).toBe(false);
});

it('keeps the latest conclusive review and check instead of an earlier approval or success', async () => {
  const { reader } = fixture(
    [
      { ...approval, id: 4, state: 'DISMISSED' },
      approval,
      { ...approval, id: 5, state: 'COMMENTED' },
    ],
    [{ ...passed, id: 4, conclusion: 'failure' }, passed]
  );
  const result = await reader.acceptedHarnessAuthority(repository, revision);
  expect(result.pullRequests[0]?.approvals[0]?.state).toBe('DISMISSED');
  expect(result.pullRequests[0]?.checks[0]?.conclusion).toBe('failure');
});

it('rejects other repositories and malformed commits before network access', async () => {
  const { reader, calls } = fixture();
  await expect(
    reader.acceptedHarnessAuthority('https://github.com/qq98982/aster.git', revision)
  ).rejects.toThrow('Phase 1 GitHub evidence unavailable');
  await expect(reader.acceptedHarnessAuthority(repository, '../main')).rejects.toThrow();
  expect(calls).toHaveLength(0);
});

it('rejects checks from another commit and does not promote pending checks to success', async () => {
  await expect(
    fixture([], [{ ...passed, head_sha: revision }]).reader.acceptedHarnessAuthority(
      repository,
      revision
    )
  ).rejects.toThrow();
  const result = await fixture(
    [],
    [{ ...passed, conclusion: null }]
  ).reader.acceptedHarnessAuthority(repository, revision);
  expect(result.pullRequests[0]?.checks[0]?.conclusion).toBe('failure');
});

it.each([403, 429, 500])(
  'fails closed on HTTP %s without exposing the response',
  async (status) => {
    const reader = createProductionPhase1GithubReader(
      async () => new Response('sensitive body', { status })
    );
    await expect(reader.acceptedHarnessAuthority(repository, revision)).rejects.toThrow(
      /^Phase 1 GitHub evidence unavailable$/u
    );
  }
);

it('bounds and sanitizes invalid, oversized and failed response bodies', async () => {
  for (const body of ['not-json', 'x'.repeat(1024 * 1024 + 1), '{}']) {
    const reader = createProductionPhase1GithubReader(async () => new Response(body));
    await expect(reader.acceptedHarnessAuthority(repository, revision)).rejects.toThrow(
      /^Phase 1 GitHub evidence unavailable$/u
    );
  }
});

it('reads later review and check pages before choosing the latest outcome', async () => {
  const calls: string[] = [];
  const reader = createProductionPhase1GithubReader(async (input) => {
    const url = String(input);
    calls.push(url);
    const secondPage = new URL(url).searchParams.get('page') === '2';
    if (url.includes('/pulls?')) {
      return new Response(JSON.stringify([pr]));
    }
    if (url.includes('/reviews?')) {
      return new Response(
        JSON.stringify(
          secondPage
            ? [{ ...approval, id: 101, state: 'CHANGES_REQUESTED' }]
            : Array.from({ length: 100 }, (_, index) => ({ ...approval, id: index + 1 }))
        )
      );
    }
    return new Response(
      JSON.stringify({
        check_runs: secondPage
          ? [{ ...passed, id: 101, conclusion: 'cancelled' }]
          : Array.from({ length: 100 }, (_, index) => ({ ...passed, id: index + 1 })),
      })
    );
  });
  const result = await reader.acceptedHarnessAuthority(repository, revision);
  expect(result.pullRequests[0]?.approvals[0]?.state).toBe('CHANGES_REQUESTED');
  expect(result.pullRequests[0]?.checks[0]?.conclusion).toBe('failure');
  expect(calls).toHaveLength(5);
});

it.each([
  { name: 'missing', pullRequests: [] },
  { name: 'ambiguous', pullRequests: [pr, pr] },
  { name: 'wrong-commit', pullRequests: [{ ...pr, merge_commit_sha: head }] },
])('rejects $name merged pull requests', async ({ pullRequests }) => {
  const reader = createProductionPhase1GithubReader(
    async () => new Response(JSON.stringify(pullRequests))
  );
  await expect(reader.acceptedHarnessAuthority(repository, revision)).rejects.toThrow(
    /^Phase 1 GitHub evidence unavailable$/u
  );
});
/* eslint-enable @silverhand/fp/no-mutating-methods, no-await-in-loop */
