/* eslint-disable complexity -- The flow independently validates API identity, visible row fields, activity, and persisted-state stability. */
import { isDeepStrictEqual } from 'node:util';

import { assertEvidenceIsSanitized } from '../../../evidence.js';
import type { JsonObject } from '../../../normalize.js';
import {
  getPhase1FixtureRuntimeEmail,
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeUsername,
  type Phase1FixtureAllocation,
} from '../../fixture-map.js';
import type { Phase1BrowserFlowModule } from '../contracts.js';

export const consoleUserReadSourcePaths = Object.freeze([
  'packages/console/src/App.tsx',
  'packages/console/src/contexts/AppDataProvider.tsx',
  'packages/console/src/hooks/use-api.ts',
  'packages/console/src/hooks/use-current-user.ts',
  'packages/console/src/pages/Users/index.tsx',
  'packages/integration-tests/src/tests/console/user-management.test.ts',
] as const);

const rowSelector = 'table tbody tr';
const nameSelector = 'table tbody tr td:first-child a';
const emailSelector = 'table tbody tr td:first-child div[class*="subtitle"]';
const latestSignInSelector = 'table tbody tr td:nth-child(3) span';

const requireDataAllocation = (
  allocations: readonly Phase1FixtureAllocation[]
): Phase1FixtureAllocation => {
  const matches = allocations.filter(({ role }) => role === 'data');

  if (matches.length !== 1 || !matches[0]) {
    throw new Error('Phase 1 Console data allocation is invalid');
  }

  return matches[0];
};

export const consoleUserRead: Phase1BrowserFlowModule = Object.freeze({
  id: 'console.user-read',
  executionGroup: 'console',
  sourcePaths: consoleUserReadSourcePaths,
  run: async (context): Promise<JsonObject> => {
    const flow = context.profile.browserFlows.find(
      (candidate) => candidate.id === 'console.user-read'
    );

    if (
      !flow ||
      flow.executionGroup !== 'console' ||
      flow.routes.length !== 1 ||
      !flow.routes[0] ||
      !isDeepStrictEqual(flow.sourceEvidence, consoleUserReadSourcePaths)
    ) {
      throw new Error('Phase 1 Console user profile is invalid');
    }
    const route = flow.routes[0];
    const allocation = requireDataAllocation(context.fixture.public.allocations);
    const { subject } = context.profile.fixtures.dataTenant;
    const runtimeUser = Object.freeze({
      id: getPhase1FixtureRuntimeId(
        context.fixture.public,
        allocation.allocationId,
        'user',
        subject.id
      ),
      username: getPhase1FixtureRuntimeUsername(subject.username, allocation.allocationId),
      primaryEmail: getPhase1FixtureRuntimeEmail(subject.primaryEmail, allocation.allocationId),
    });
    const beforeActivity = await context.readActivityState(subject.id);

    if (beforeActivity.lastSignInState !== 'never') {
      throw new Error('Phase 1 Console data subject activity is invalid');
    }
    const before = await context.projectState();
    await context.session.navigate('console-users-open', 'admin', route);
    await context.session.waitForExactRoute('console-users-route', 'admin', route);
    const facts = await context.session.waitForNetworkFacts(
      'console-user-facts',
      ({ userReads }) => userReads.length > 0
    );

    if (facts.userReads.length !== 1) {
      throw new Error('Phase 1 Console user API facts are invalid');
    }
    const [read] = facts.userReads;
    const row = read?.rows[0];

    if (
      !read ||
      read.authority !== 'core' ||
      read.status !== 200 ||
      !read.queryShapeExact ||
      !read.originMatches ||
      !read.languageMatches ||
      !read.accessMatchesManagement ||
      read.total !== 1 ||
      read.rows.length !== 1 ||
      !row ||
      row.id !== runtimeUser.id ||
      row.name !== subject.name ||
      row.username !== runtimeUser.username ||
      row.primaryEmail !== runtimeUser.primaryEmail ||
      row.lastSignInState !== 'never'
    ) {
      throw new Error('Phase 1 Console user API fact is invalid');
    }
    await context.session.expectCount('console-users-count', rowSelector, 1);
    await context.session.expectText('console-users-name', nameSelector, subject.name);
    await context.session.expectText(
      'console-users-email',
      emailSelector,
      runtimeUser.primaryEmail
    );
    await context.session.expectText('console-users-latest-sign-in', latestSignInSelector, '-');
    const after = await context.projectState();

    if (!isDeepStrictEqual(before, after)) {
      throw new Error('Phase 1 Console user state changed');
    }
    const afterActivity = await context.readActivityState(subject.id);

    if (afterActivity.lastSignInState !== 'never') {
      throw new Error('Phase 1 Console data subject activity is invalid');
    }

    const observation = Object.freeze({
      route,
      userRead: Object.freeze({
        status: read.status,
        total: read.total,
        row: Object.freeze({
          id: subject.id,
          username: subject.username,
          primaryEmail: subject.primaryEmail,
          lastSignInState: 'never',
        }),
      }),
      display: Object.freeze({
        name: subject.name,
        primaryEmail: subject.primaryEmail,
        latestSignIn: 'never',
      }),
      unchanged: true,
    });

    assertEvidenceIsSanitized(observation);
    return observation;
  },
});

export const consoleUserReadFlow = consoleUserRead;

export default consoleUserRead;

/* eslint-enable complexity */
