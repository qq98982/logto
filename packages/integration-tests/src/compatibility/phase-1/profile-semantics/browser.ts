/* eslint-disable no-restricted-syntax, unicorn/no-array-for-each, @silverhand/fp/no-mutating-methods -- The closed registry walk records first occurrence and exact flattened order. */
import type { Phase1Profile } from '../profile-types.js';
import { Phase1ProfileValidationError } from '../profile.js';

const fail = (pointer: string, rule: string): never => {
  throw new Phase1ProfileValidationError('semantic', [pointer], [rule]);
};

const requireValue = <Value>(value: Value, pointer: string, rule: string): NonNullable<Value> =>
  value === undefined || value === null ? fail(pointer, rule) : (value as NonNullable<Value>);

export const assertBrowserSemantics = (profile: Phase1Profile): void => {
  const groupsById = new Map<string, Phase1Profile['browserExecutionGroups'][number]>(
    profile.browserExecutionGroups.map((group) => [group.id, group])
  );

  profile.browserFlows.forEach((flow, index) => {
    if (!groupsById.has(flow.executionGroup)) {
      fail(`/browserFlows/${index}/executionGroup`, 'browser-flow-group');
    }
  });

  const flowIndexById = new Map<string, number>(
    profile.browserFlows.map((flow, index) => [flow.id, index])
  );
  const encountered = new Set<string>();
  const flattened: Array<Readonly<{ id: string; pointer: string }>> = [];

  profile.browserExecutionGroups.forEach((group, groupIndex) => {
    group.orderedFlows.forEach((flowId, flowIndex) => {
      const pointer = `/browserExecutionGroups/${groupIndex}/orderedFlows/${flowIndex}`;
      const profileFlowIndex = flowIndexById.get(flowId);

      if (profileFlowIndex === undefined || encountered.has(flowId)) {
        fail(pointer, 'browser-flow-exact-membership');
      }

      const resolvedIndex = requireValue(
        profileFlowIndex,
        pointer,
        'browser-flow-exact-membership'
      );
      const flow = requireValue(
        profile.browserFlows.at(resolvedIndex),
        pointer,
        'browser-flow-exact-membership'
      );

      if (flow.executionGroup !== group.id) {
        fail(`/browserFlows/${resolvedIndex}/executionGroup`, 'browser-flow-group');
      }

      encountered.add(flowId);
      flattened.push({ id: flowId, pointer });
    });
  });

  profile.browserFlows.forEach((flow, index) => {
    if (!encountered.has(flow.id)) {
      fail(`/browserFlows/${index}/id`, 'browser-flow-exact-membership');
    }
  });

  flattened.forEach(({ id, pointer }, index) => {
    if (profile.browserFlows[index]?.id !== id) {
      fail(pointer, 'browser-flow-order');
    }
  });
};

/* eslint-enable no-restricted-syntax, unicorn/no-array-for-each, @silverhand/fp/no-mutating-methods */
