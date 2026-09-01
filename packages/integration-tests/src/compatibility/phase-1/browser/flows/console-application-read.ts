/* eslint-disable complexity -- The flow validates the closed first-party, third-party, and SAML probe contracts before projecting them. */
import { isDeepStrictEqual } from 'node:util';

import { assertEvidenceIsSanitized } from '../../../evidence.js';
import type { JsonObject } from '../../../normalize.js';
import {
  getPhase1FixtureRuntimeId,
  getPhase1FixtureRuntimeText,
  type Phase1FixtureAllocation,
} from '../../fixture-map.js';
import type { Phase1BrowserApplicationReadFact, Phase1BrowserFlowModule } from '../contracts.js';

export const consoleApplicationReadSourcePaths = Object.freeze([
  'packages/console/src/App.tsx',
  'packages/console/src/contexts/AppDataProvider.tsx',
  'packages/console/src/hooks/use-api.ts',
  'packages/console/src/hooks/use-current-user.ts',
  'packages/console/src/pages/Applications/hooks/use-application-data.ts',
  'packages/console/src/pages/Applications/index.tsx',
  'packages/integration-tests/src/tests/console/applications/index.test.ts',
] as const);

const rowSelector = 'table tbody tr';
const nameSelector = 'table tbody tr td:first-child a';
const idSelector = 'table tbody tr td:nth-child(2) div[class*="content"]';
const thirdPartyTabSelector = 'a[href$="/console/applications/third-party-applications"]';

const requireDataAllocation = (
  allocations: readonly Phase1FixtureAllocation[]
): Phase1FixtureAllocation => {
  const matches = allocations.filter(({ role }) => role === 'data');

  if (matches.length !== 1 || !matches[0]) {
    throw new Error('Phase 1 Console data allocation is invalid');
  }

  return matches[0];
};

const requireSingleRead = (
  reads: readonly Phase1BrowserApplicationReadFact[],
  predicate: (read: Phase1BrowserApplicationReadFact) => boolean
): Phase1BrowserApplicationReadFact => {
  const matches = reads.filter((read) => predicate(read));

  if (matches.length !== 1 || !matches[0]) {
    throw new Error('Phase 1 Console application API facts are invalid');
  }

  return matches[0];
};

const assertApplicationRead = (
  read: Phase1BrowserApplicationReadFact,
  expected: Readonly<{ id: string; name: string }>
): void => {
  const [row] = read.rows;

  if (
    read.authority !== 'core' ||
    read.status !== 200 ||
    !read.queryShapeExact ||
    !read.originMatches ||
    !read.languageMatches ||
    !read.accessMatchesManagement ||
    read.total !== 1 ||
    read.rows.length !== 1 ||
    !row ||
    row.id !== expected.id ||
    row.name !== expected.name
  ) {
    throw new Error('Phase 1 Console application API fact is invalid');
  }
};

export const consoleApplicationRead: Phase1BrowserFlowModule = Object.freeze({
  id: 'console.application-read',
  executionGroup: 'console',
  sourcePaths: consoleApplicationReadSourcePaths,
  run: async (context): Promise<JsonObject> => {
    const flow = context.profile.browserFlows.find(
      (candidate) => candidate.id === 'console.application-read'
    );

    if (
      !flow ||
      flow.executionGroup !== 'console' ||
      flow.routes.length !== 2 ||
      !isDeepStrictEqual(flow.sourceEvidence, consoleApplicationReadSourcePaths)
    ) {
      throw new Error('Phase 1 Console application profile is invalid');
    }
    const [firstPartyRoute, thirdPartyRoute] = flow.routes;

    if (!firstPartyRoute || !thirdPartyRoute) {
      throw new Error('Phase 1 Console application profile is invalid');
    }
    const allocation = requireDataAllocation(context.fixture.public.allocations);
    const firstPartyApplications = context.profile.fixtures.dataTenant.applications.filter(
      ({ isThirdParty }) => !isThirdParty
    );
    const thirdPartyApplications = context.profile.fixtures.dataTenant.applications.filter(
      ({ isThirdParty }) => isThirdParty
    );
    const firstParty = firstPartyApplications[0];
    const thirdParty = thirdPartyApplications[0];

    if (
      firstPartyApplications.length !== 1 ||
      thirdPartyApplications.length !== 1 ||
      !firstParty ||
      !thirdParty
    ) {
      throw new Error('Phase 1 Console application fixture is invalid');
    }
    const runtimeFirstParty = Object.freeze({
      id: getPhase1FixtureRuntimeId(
        context.fixture.public,
        allocation.allocationId,
        'application',
        firstParty.id
      ),
      name: getPhase1FixtureRuntimeText(firstParty.name, allocation.allocationId),
    });
    const runtimeThirdParty = Object.freeze({
      id: getPhase1FixtureRuntimeId(
        context.fixture.public,
        allocation.allocationId,
        'application',
        thirdParty.id
      ),
      name: getPhase1FixtureRuntimeText(thirdParty.name, allocation.allocationId),
    });
    const before = await context.projectState();

    await context.session.assertExactRoute(
      'console-applications-first-route',
      'admin',
      firstPartyRoute
    );
    const facts = await context.session.waitForNetworkFacts(
      'console-application-facts',
      ({ applicationReads }) => applicationReads.length >= 3
    );

    if (facts.applicationReads.length !== 3) {
      throw new Error('Phase 1 Console application API facts are invalid');
    }
    const firstPartyRead = requireSingleRead(
      facts.applicationReads,
      ({ isThirdParty, isSamlProbe }) => !isThirdParty && !isSamlProbe
    );
    const thirdPartyRead = requireSingleRead(
      facts.applicationReads,
      ({ isThirdParty, isSamlProbe }) => isThirdParty && !isSamlProbe
    );
    const samlRead = requireSingleRead(
      facts.applicationReads,
      ({ isThirdParty, isSamlProbe }) => !isThirdParty && isSamlProbe
    );
    assertApplicationRead(firstPartyRead, runtimeFirstParty);
    assertApplicationRead(thirdPartyRead, runtimeThirdParty);

    if (
      samlRead.authority !== 'core' ||
      samlRead.status !== 200 ||
      !samlRead.queryShapeExact ||
      !samlRead.originMatches ||
      !samlRead.languageMatches ||
      !samlRead.accessMatchesManagement ||
      samlRead.total !== 0 ||
      samlRead.rows.length > 0
    ) {
      throw new Error('Phase 1 Console SAML application probe is invalid');
    }
    await context.session.expectCount('console-applications-first-count', rowSelector, 1);
    await context.session.expectText(
      'console-applications-first-name',
      nameSelector,
      runtimeFirstParty.name
    );
    await context.session.expectText(
      'console-applications-first-id',
      idSelector,
      runtimeFirstParty.id
    );
    await context.session.click(
      'console-applications-third-tab',
      thirdPartyTabSelector,
      Object.freeze({ endpoint: 'admin', paths: Object.freeze([firstPartyRoute]) })
    );
    await context.session.waitForExactRoute(
      'console-applications-third-route',
      'admin',
      thirdPartyRoute
    );
    await context.session.expectCount('console-applications-third-count', rowSelector, 1);
    await context.session.expectText(
      'console-applications-third-name',
      nameSelector,
      runtimeThirdParty.name
    );
    await context.session.expectText(
      'console-applications-third-id',
      idSelector,
      runtimeThirdParty.id
    );
    const after = await context.projectState();

    if (!isDeepStrictEqual(before, after)) {
      throw new Error('Phase 1 Console application state changed');
    }

    const observation = Object.freeze({
      routes: [firstPartyRoute, thirdPartyRoute],
      applicationReads: [
        Object.freeze({
          kind: 'first-party',
          status: firstPartyRead.status,
          total: firstPartyRead.total,
          rows: [Object.freeze({ id: firstParty.id, name: firstParty.name })],
        }),
        Object.freeze({
          kind: 'third-party',
          status: thirdPartyRead.status,
          total: thirdPartyRead.total,
          rows: [Object.freeze({ id: thirdParty.id, name: thirdParty.name })],
        }),
        Object.freeze({
          kind: 'saml-probe',
          status: samlRead.status,
          total: samlRead.total,
          rows: [],
        }),
      ],
      unchanged: true,
    });

    assertEvidenceIsSanitized(observation);
    return observation;
  },
});

export const consoleApplicationReadFlow = consoleApplicationRead;

export default consoleApplicationRead;

/* eslint-enable complexity */
