/* eslint-disable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression -- Each case deliberately applies one isolated browser-registry mutation. */
import type { Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

import { assertBrowserSemantics } from './browser.js';

const required = <Value>(value: Value | undefined): Value => {
  if (value === undefined) {
    throw new Error('Synthetic browser fixture is incomplete');
  }

  return value;
};

const browserProfile = () =>
  ({
    browserFlows: [
      { id: 'flow-a', executionGroup: 'group-a' },
      { id: 'flow-b', executionGroup: 'group-b' },
      { id: 'flow-c', executionGroup: 'group-b' },
    ],
    browserExecutionGroups: [
      { id: 'group-a', orderedFlows: ['flow-a'] },
      { id: 'group-b', orderedFlows: ['flow-b', 'flow-c'] },
    ],
  }) as unknown as Phase1Profile;

const expectBrowserFailure = (profile: Phase1Profile, pointer: string, rule: string) => {
  try {
    assertBrowserSemantics(profile);
    throw new Error('Expected browser validation to fail');
  } catch (error: unknown) {
    expect(error).toBeInstanceOf(Phase1ProfileValidationError);
    expect(error).toMatchObject({
      message: 'Invalid Phase 1 semantics',
      stage: 'semantic',
      pointers: [pointer],
      rules: [rule],
    });
  }
};

describe('Phase 1 browser execution-group semantics', () => {
  it('accepts exact group membership in profile order', () => {
    expect(() => assertBrowserSemantics(browserProfile())).not.toThrow();
  });

  it('rejects an omitted flow at its profile pointer', () => {
    const profile = browserProfile();
    (required(profile.browserExecutionGroups.at(1)).orderedFlows as string[]).splice(1, 1);
    expectBrowserFailure(profile, '/browserFlows/2/id', 'browser-flow-exact-membership');
  });

  it('rejects duplicate membership at its second group pointer', () => {
    const profile = browserProfile();
    (required(profile.browserExecutionGroups.at(1)).orderedFlows as string[])[1] = 'flow-b';
    expectBrowserFailure(
      profile,
      '/browserExecutionGroups/1/orderedFlows/1',
      'browser-flow-exact-membership'
    );
  });

  it('rejects an extra flow at the exact group pointer', () => {
    const profile = browserProfile();
    (required(profile.browserExecutionGroups.at(1)).orderedFlows as string[]).push('flow-extra');
    expectBrowserFailure(
      profile,
      '/browserExecutionGroups/1/orderedFlows/2',
      'browser-flow-exact-membership'
    );
  });

  it('rejects a flow that names the wrong group', () => {
    const profile = browserProfile();
    (required(profile.browserFlows.at(1)) as { executionGroup: string }).executionGroup = 'group-a';
    expectBrowserFailure(profile, '/browserFlows/1/executionGroup', 'browser-flow-group');
  });

  it('rejects reordered membership at the first displaced pointer', () => {
    const profile = browserProfile();
    const flows = required(profile.browserExecutionGroups.at(1)).orderedFlows as string[];
    const first = required(flows.at(0));
    const second = required(flows.at(1));
    [flows[0], flows[1]] = [second, first];
    expectBrowserFailure(profile, '/browserExecutionGroups/1/orderedFlows/0', 'browser-flow-order');
  });

  it('rejects a flow that references no existing group', () => {
    const profile = browserProfile();
    (required(profile.browserFlows.at(0)) as { executionGroup: string }).executionGroup = 'missing';
    expectBrowserFailure(profile, '/browserFlows/0/executionGroup', 'browser-flow-group');
  });
});

/* eslint-enable @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/no-confusing-void-expression */
