/* eslint-disable @silverhand/fp/no-mutating-methods -- The request log records observable cleanup calls. */
import type { Phase2AdminRequestFunction } from '../fixtures.js';

import { cleanupCommonCompletionOwnedApplications } from './common-completion-target-driver.js';

describe('Common completion owned application cleanup', () => {
  it('leaves Candidate applications to isolated fixture teardown without unsupported public deletion', async () => {
    const calls: unknown[] = [];
    const request = (async (input: unknown) => {
      calls.push(input);
    }) as Phase2AdminRequestFunction;

    await expect(
      cleanupCommonCompletionOwnedApplications({ label: 'candidate' }, request, new Set(['owned']))
    ).resolves.toEqual([]);
    expect(calls).toEqual([]);
  });

  it('deletes each Reference application once with the observed no-content or missing contract', async () => {
    const calls: unknown[] = [];
    const request = (async (input: unknown) => {
      calls.push(input);
    }) as Phase2AdminRequestFunction;

    await expect(
      cleanupCommonCompletionOwnedApplications(
        { label: 'oracle' },
        request,
        new Set(['owned-one', 'owned-two'])
      )
    ).resolves.toEqual([]);
    expect(calls).toEqual([
      {
        method: 'DELETE',
        path: 'applications/owned-one',
        expectedStatuses: [204, 404],
        responseKind: 'status',
      },
      {
        method: 'DELETE',
        path: 'applications/owned-two',
        expectedStatuses: [204, 404],
        responseKind: 'status',
      },
    ]);
  });

  it('continues Reference cleanup after rejection and returns redacted failures for body-error aggregation', async () => {
    const calls: unknown[] = [];
    const request = (async (input: unknown) => {
      calls.push(input);
      throw new Error('private request detail');
    }) as Phase2AdminRequestFunction;

    const failures = await cleanupCommonCompletionOwnedApplications(
      { label: 'oracle' },
      request,
      new Set(['owned-one', 'owned-two'])
    );
    expect(calls).toHaveLength(2);
    expect(failures).toHaveLength(2);
    expect(failures.every((error) => error instanceof TypeError)).toBe(true);
    expect(failures.map((error) => error.message)).toEqual([
      'Owned Common completion application cleanup failed',
      'Owned Common completion application cleanup failed',
    ]);
  });
});
/* eslint-enable @silverhand/fp/no-mutating-methods */
