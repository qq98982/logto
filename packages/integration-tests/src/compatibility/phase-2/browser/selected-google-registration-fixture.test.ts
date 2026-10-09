/* eslint-disable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions -- Stateful HTTP fake proves the new-owner lifecycle and cleanup. */
import type { Phase2AdminRequest } from '../fixtures.js';

import { withSelectedGoogleRegistrationFixture } from './selected-google-registration-fixture.js';

class ClosedStatusError extends Error {
  // eslint-disable-next-line @typescript-eslint/class-literal-property-style -- Production reads the fixed status from an own data descriptor.
  readonly responseStatus = 503;
}

test.each([false, true, undefined] as const)(
  'requires hasPassword false after registration (%s)',
  async (hasPassword) => {
    let targets = ['github'];
    let signInMode = 'SignInAndRegister';
    let signUp: unknown = { identifiers: [], password: false, verify: false };
    let branding: unknown = { logoUrl: 'https://legacy.invalid/logo.svg' };
    let metadata: Record<string, unknown> = { redirectUris: ['https://old.invalid/callback'] };
    let user: Record<string, unknown> | undefined;
    let roleDefault: unknown;
    let stopped = false;
    let cleanupDiagnosticStatus: number | undefined;
    const request = async (input: Phase2AdminRequest): Promise<unknown> => {
      if (input.method === 'GET' && input.path === 'applications/browser') {
        return { id: 'browser', type: 'SPA', oidcClientMetadata: metadata };
      }
      if (input.method === 'PATCH' && input.path === 'applications/browser') {
        metadata = (input.body as { oidcClientMetadata: Record<string, unknown> })
          .oidcClientMetadata;
        return { oidcClientMetadata: metadata };
      }
      if (input.method === 'GET' && input.path === 'resources') {
        return [{ id: 'resource', scopes: [{ id: 'scope', name: 'read:profile' }] }];
      }
      if (input.method === 'POST' && input.path === 'roles') {
        roleDefault = (input.body as { isDefault: unknown }).isDefault;
        return { id: 'role', type: 'User', isDefault: roleDefault };
      }
      if (input.method === 'DELETE' && input.path === 'roles/role') {
        return undefined;
      }
      if (input.method === 'GET' && input.path === 'sign-in-exp') {
        return { branding, signInMode, signUp, socialSignInConnectorTargets: targets };
      }
      if (input.method === 'PATCH' && input.path === 'sign-in-exp') {
        branding = (input.body as { branding: unknown }).branding;
        if (Object.hasOwn(input.body as Record<string, unknown>, 'signInMode')) {
          signInMode = (input.body as { signInMode: string }).signInMode;
        }
        if (Object.hasOwn(input.body as Record<string, unknown>, 'signUp')) {
          signUp = (input.body as { signUp: unknown }).signUp;
        }
        targets = [
          ...(input.body as { socialSignInConnectorTargets: string[] })
            .socialSignInConnectorTargets,
        ];
        return { branding, signInMode, signUp, socialSignInConnectorTargets: targets };
      }
      if (input.method === 'POST' && input.path === 'connectors') {
        return { id: 'google-instance', connectorId: 'google-universal' };
      }
      if (input.method === 'DELETE' && input.path === 'connectors/google-instance') {
        if (hasPassword === undefined) {
          throw new ClosedStatusError('closed status');
        }
        return undefined;
      }
      if (input.method === 'GET' && input.path === 'users') {
        expect(input.query).toEqual({ page: '1', page_size: '100' });
        return [
          { id: 'unrelated', primaryEmail: 'other@example.invalid' },
          ...(user ? [user] : []),
        ];
      }
      if (input.method === 'DELETE' && input.path === 'users/new-owner') {
        user = undefined;
        return undefined;
      }
      throw new Error(`unexpected ${input.method} ${input.path}`);
    };

    const operation = withSelectedGoogleRegistrationFixture({
      fixture: {
        public: { allocationId: 'a' },
        status: { resource: { id: 'resource', scopeName: 'read:profile' } },
      } as never,
      request,
      targetOrigin: 'https://core.example',
      browser: { clientId: 'browser', redirectUri: 'https://core.example/demo-app' },
      clientId: 'client',
      clientSecret: 'private',
      googleSubject: 'google-subject',
      originalEmail: 'new-owner@example.invalid',
      controlEmail: 'unverified@example.invalid',
      prepareConnector: async () => ({
        associationData: { code: 'unused-for-registration' },
        assertChangedEmailProviderCase: async () => {
          expect(stopped).toBe(false);
        },
        assertPrimaryRegistrationProviderCase: async () => {
          expect(stopped).toBe(false);
        },
        takeUnverifiedEmailControlCode: async () => 'unverified-code',
        takeOccupiedEmailControlCode: async () => 'occupied-code',
        stop: async () => {
          stopped = true;
        },
      }),
      takeBrowserCode: async () => 'provider-code',
      takeUnverifiedEmailControlCode: async () => 'unverified-code',
      takeOccupiedEmailControlCode: async () => 'occupied-code',
      onDeleteConnectorFailure: async (status) => {
        cleanupDiagnosticStatus = status;
      },
      use: async (value) => {
        expect(user).toBeUndefined();
        user = {
          id: 'new-owner',
          primaryEmail: 'new-owner@example.invalid',
          ...(hasPassword === undefined ? {} : { hasPassword }),
          identities: { google: { userId: 'google-subject' } },
        };
        await value.assertRegisteredOwner('new-owner');
        return 'registered' as const;
      },
    });
    await (hasPassword === false
      ? expect(operation).resolves.toBe('registered')
      : expect(operation).rejects.toThrow(
          hasPassword === undefined
            ? 'Selected Google connector cleanup failed'
            : 'Selected Google connector fixture failed'
        ));
    expect(roleDefault).toBe(true);
    expect(stopped).toBe(true);
    expect(user).toBeUndefined();
    expect(targets).toEqual(['github']);
    expect(signInMode).toBe('SignInAndRegister');
    expect(signUp).toEqual({ identifiers: [], password: false, verify: false });
    expect(metadata).toEqual({ redirectUris: ['https://old.invalid/callback'] });
    expect(cleanupDiagnosticStatus).toBe(hasPassword === undefined ? 503 : undefined);
  }
);
/* eslint-enable complexity, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @typescript-eslint/consistent-type-assertions */
