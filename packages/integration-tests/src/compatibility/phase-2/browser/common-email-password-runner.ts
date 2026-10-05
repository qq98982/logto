import type {
  Phase1BrowserSession,
  Phase1ProfiledDemoConfiguration,
} from '../../phase-1/browser/contracts.js';
import type { Phase2AdminRequestFunction, ProvisionedPhase2Fixture } from '../fixtures.js';

import {
  runCommonEmailPasswordSignIn,
  type CommonEmailPasswordControls,
  type CommonEmailPasswordProjection,
} from './common-email-password-sign-in.js';
import { adaptPhase1SessionForEmailPassword } from './phase1-session-adapter.js';
import {
  withSelectedEmailPasswordFixture,
  type SelectedEmailPasswordIdentity,
} from './selected-email-password-fixture.js';

export type CommonEmailPasswordCredentialLease = Readonly<{
  getSelectedEmailPassword(): string;
  getInvalidEmailPassword(): string;
  getPreservedUsernamePassword(): string;
}>;

export type CommonEmailPasswordRunnerInput = Readonly<{
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
  preservedUsername: Readonly<{ identifier: string; subject: string }>;
  withCredentialLease<Result>(
    use: (lease: CommonEmailPasswordCredentialLease) => Promise<Result>
  ): Promise<Result>;
  createControlDriver(
    identity: SelectedEmailPasswordIdentity
  ): Pick<
    CommonEmailPasswordControls,
    'assertInvalidPassword' | 'assertSuspended' | 'authenticateUsername'
  >;
}>;

export const runCommonEmailPasswordScenario = async (
  input: CommonEmailPasswordRunnerInput
): Promise<CommonEmailPasswordProjection> =>
  input.withCredentialLease(async (lease) =>
    withSelectedEmailPasswordFixture({
      fixture: input.fixture,
      request: input.managementRequest,
      getPassword: lease.getSelectedEmailPassword,
      browser: {
        clientId: input.configuration.demo.appId,
        redirectUri: input.configuration.redirectUri,
      },
      use: async (identity) => {
        const controls: CommonEmailPasswordControls = {
          ...input.createControlDriver(identity),
          setSuspended: async (userId, suspended) => {
            if (userId !== identity.id) {
              throw new TypeError('Invalid Common email password suspension owner');
            }
            const response = await input.managementRequest({
              method: 'PATCH',
              path: `users/${encodeURIComponent(userId)}/is-suspended`,
              body: { isSuspended: suspended },
              expectedStatuses: [200],
              responseKind: 'object',
            });
            if (
              typeof response !== 'object' ||
              response === null ||
              Reflect.get(response, 'id') !== identity.id ||
              Reflect.get(response, 'isSuspended') !== suspended
            ) {
              throw new TypeError('Invalid Common email password suspension response');
            }
          },
        };
        return runCommonEmailPasswordSignIn({
          session: adaptPhase1SessionForEmailPassword(input.session, {
            ...input.configuration,
            expectedSubject: identity.id,
            canonicalEmail: identity.primaryEmail,
            resource: input.configuration.demo.resource,
          }),
          email: identity.primaryEmail.replace(/^common/u, 'Common'),
          canonicalEmail: identity.primaryEmail,
          password: lease.getSelectedEmailPassword,
          invalidPassword: lease.getInvalidEmailPassword,
          expectedSubject: identity.id,
          controls,
          usernameControl: {
            identifier: input.preservedUsername.identifier,
            password: lease.getPreservedUsernamePassword,
            expectedSubject: input.preservedUsername.subject,
          },
        });
      },
    })
  );
