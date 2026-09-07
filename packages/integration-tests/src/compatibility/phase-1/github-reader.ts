/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop -- Bounded response streaming and pagination accumulate data sequentially. */
import { z } from 'zod';

import type { Phase1Approval, Phase1GithubReader } from './profile-semantics/provenance.js';

const repository = 'https://github.com/qq98982/logto.git';
const api = 'https://api.github.com/repos/qq98982/logto';
const commit = z.string().regex(/^[\da-f]{40}$/u);
const login = z.string().min(1).max(100);
const identity = z.object({ login });
const pullRequest = z.object({
  number: z.number().int().positive(),
  state: z.enum(['open', 'closed']),
  merged_at: z.string().nullable(),
  merge_commit_sha: commit.nullable(),
  user: identity,
  head: z.object({ sha: commit }),
  base: z.object({ sha: commit, ref: z.string().min(1).max(255) }),
});
const review = z.object({
  id: z.number().int().positive(),
  user: identity,
  commit_id: commit,
  state: z.enum(['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED', 'COMMENTED', 'PENDING']),
});
const check = z.object({
  id: z.number().int().positive(),
  name: z.string().min(1).max(256),
  head_sha: commit,
  conclusion: z.string().nullable(),
});
const maximumBytes = 1024 * 1024;
const unavailable = () => new Error('Phase 1 GitHub evidence unavailable');

// The public harness needs no token; never forward runner credentials or follow redirects.
export const createProductionPhase1GithubReader = (
  request: typeof fetch = fetch
): Phase1GithubReader => {
  const read = async (path: string): Promise<unknown> => {
    const response = await request(`${api}${path}`, {
      headers: { accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
      credentials: 'omit',
      redirect: 'error',
      signal: AbortSignal.timeout(8000),
    });
    if (!response.ok || !response.body) {
      await response.body?.cancel();
      throw unavailable();
    }
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          break;
        }
        size += value.byteLength;
        if (size > maximumBytes) {
          throw unavailable();
        }
        chunks.push(value);
      }
      const value: unknown = JSON.parse(
        new TextDecoder('utf8', { fatal: true }).decode(Buffer.concat(chunks))
      );
      return value;
    } finally {
      await reader.cancel();
      reader.releaseLock();
    }
  };

  const pages = async <T>(path: string, schema: z.ZodType<T>, key?: string): Promise<T[]> => {
    const result: T[] = [];
    for (let page = 1; page <= 11; page += 1) {
      const value = await read(`${path}?per_page=100&page=${page}`);
      const items = z
        .array(schema)
        .max(100)
        .parse(key ? z.record(z.unknown()).parse(value)[key] : value);
      result.push(...items);
      if (result.length > 1000) {
        throw unavailable();
      }
      if (items.length < 100) {
        return result;
      }
    }
    throw unavailable();
  };

  return {
    // eslint-disable-next-line complexity -- Keep the small evidence reduction together with its failure boundary.
    acceptedHarnessAuthority: async (source, revision) => {
      try {
        if (source !== repository || !commit.safeParse(revision).success) {
          throw unavailable();
        }
        const linked = await pages(`/commits/${revision}/pulls`, pullRequest);
        const candidates = linked.filter(
          (item) =>
            item.state === 'closed' && item.merged_at !== null && item.merge_commit_sha === revision
        );
        const [pr] = candidates;
        if (candidates.length !== 1 || !pr) {
          throw unavailable();
        }
        const reviews = await pages(`/pulls/${pr.number}/reviews`, review);
        const checks = await pages(`/commits/${pr.head.sha}/check-runs`, check, 'check_runs');
        const latestReviews = new Map<string, { id: number; approval: Phase1Approval }>();
        for (const entry of reviews) {
          const { state } = entry;
          if (state === 'COMMENTED' || state === 'PENDING') {
            continue;
          }
          const reviewer = entry.user.login.toLowerCase();
          if ((latestReviews.get(reviewer)?.id ?? 0) < entry.id) {
            latestReviews.set(reviewer, {
              id: entry.id,
              approval: { reviewer, state, commit: entry.commit_id },
            });
          }
        }
        const latestChecks = new Map<string, z.infer<typeof check>>();
        for (const entry of checks) {
          if (entry.head_sha !== pr.head.sha) {
            throw unavailable();
          }
          if ((latestChecks.get(entry.name)?.id ?? 0) < entry.id) {
            latestChecks.set(entry.name, entry);
          }
        }
        return {
          pullRequests: [
            {
              number: pr.number,
              state: 'closed',
              author: pr.user.login.toLowerCase(),
              mergeCommit: revision,
              headCommit: pr.head.sha,
              evaluatedCommit: pr.head.sha,
              baseCommit: pr.base.sha,
              baseBranch: pr.base.ref,
              approvals: [...latestReviews.values()].map(({ approval }) => approval),
              requiredChecks: ['compatibility', 'phase1-pr'],
              checks: [...latestChecks.values()].map((entry) => ({
                name: entry.name,
                conclusion: entry.conclusion === 'success' ? 'success' : 'failure',
                headSha: entry.head_sha,
              })),
            },
          ],
        };
      } catch {
        throw unavailable();
      }
    },
  };
};
/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, no-await-in-loop */
