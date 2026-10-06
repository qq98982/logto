import type {
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  runCommonEmailCodeSignIn,
  type CommonEmailCodeControlResult,
  type CommonEmailCodeProjection,
} from './common-email-code-sign-in.js';
import { adaptPhase1SessionForEmailCode } from './email-code-phase1-session-adapter.js';
import {
  withSelectedEmailCodeFixture,
  type SelectedEmailCodeIdentity,
} from './selected-email-code-fixture.js';

export type CommonEmailCodeRunnerInput = Readonly<{
  fixture: ProvisionedPhase2Fixture;
  managementRequest: Phase2AdminRequestFunction;
  session: Phase1BrowserSession;
  configuration: Readonly<{
    storageKey: string;
    demo: Phase1ProfiledDemoConfiguration;
    expectedIssuer: string;
    redirectUri: string;
    initialResponseScope: string;
    resourceScope: string;
  }>;
  takePasscode(recipient: string): Promise<string>;
  runControls(identity: SelectedEmailCodeIdentity): Promise<CommonEmailCodeControlResult>;
}>;

export const runCommonEmailCodeScenario = async (
  input: CommonEmailCodeRunnerInput
): Promise<CommonEmailCodeProjection> =>
  withSelectedEmailCodeFixture({
    fixture: input.fixture,
    request: input.managementRequest,
    browser: {
      clientId: input.configuration.demo.appId,
      redirectUri: input.configuration.redirectUri,
    },
    use: async (identity) =>
      runCommonEmailCodeSignIn({
        session: adaptPhase1SessionForEmailCode(input.session, {
          ...input.configuration,
          expectedSubject: identity.id,
          canonicalEmail: identity.primaryEmail,
          resource: input.configuration.demo.resource,
        }),
        email: identity.primaryEmail.replace(/^common/u, 'Common'),
        canonicalEmail: identity.primaryEmail,
        expectedSubject: identity.id,
        takePasscode: input.takePasscode,
        runControls: async () => input.runControls(identity),
      }),
  });
