import { assert, fixture, html, waitUntil } from '@open-wc/testing';

import { createMockAccountApi } from '../__mocks__/account-api.js';
import { type LogtoAccountProvider } from '../providers/logto-account-provider.js';

import { LogtoAccountCenter } from './logto-account-center.js';

suite('aster-account-center', () => {
  test('is defined', () => {
    const element = document.createElement(LogtoAccountCenter.tagName);
    assert.instanceOf(element, LogtoAccountCenter);
  });

  test('should render error message when account context is not available', async () => {
    const element = await fixture<LogtoAccountCenter>(
      html`<aster-account-center></aster-account-center>`
    );
    await element.updateComplete;

    assert.equal(element.shadowRoot?.textContent.trim(), 'Unable to retrieve account context.');
  });

  test('should render components correctly based on user info', async () => {
    const mockAccountApi = createMockAccountApi({
      fetchUserProfile: async () => ({
        username: 'testuser',
        primaryEmail: 'test@example.com',
        primaryPhone: '1234567890',
        hasPassword: true,
        identities: {
          google: {
            userId: 'google-123',
            details: { name: 'John Doe', email: 'john@example.com' },
          },
          facebook: {
            userId: 'facebook-123',
            details: { name: 'Jane Doe', email: 'jane@example.com' },
          },
        },
      }),
    });

    const provider = await fixture<LogtoAccountProvider>(
      html`<aster-account-provider .accountApi=${mockAccountApi}>
        <aster-account-center></aster-account-center>
      </aster-account-provider>`
    );

    await provider.updateComplete;

    const accountCenter = provider.querySelector<LogtoAccountCenter>(LogtoAccountCenter.tagName);
    await accountCenter?.updateComplete;

    await waitUntil(() => {
      const shadowRoot = accountCenter?.shadowRoot;
      return (
        shadowRoot?.querySelector('aster-username') &&
        shadowRoot.querySelector('aster-user-email') &&
        shadowRoot.querySelector('aster-user-phone') &&
        shadowRoot.querySelector('aster-user-password') &&
        shadowRoot.querySelectorAll('aster-social-identity').length === 2
      );
    }, 'Unable to render all expected components');
  });

  test('should only render components for existing user info', async () => {
    const mockAccountApi = createMockAccountApi({
      fetchUserProfile: async () => ({
        username: 'testuser',
        primaryEmail: undefined,
        primaryPhone: undefined,
        hasPassword: undefined,
        identities: {},
      }),
    });

    const provider = await fixture<LogtoAccountProvider>(
      html`<aster-account-provider .accountApi=${mockAccountApi}>
        <aster-account-center></aster-account-center>
      </aster-account-provider>`
    );

    await provider.updateComplete;

    const accountCenter = provider.querySelector<LogtoAccountCenter>(LogtoAccountCenter.tagName);
    await accountCenter?.updateComplete;

    const shadowRoot = accountCenter?.shadowRoot;
    assert.exists(shadowRoot?.querySelector('aster-username'));
    assert.notExists(shadowRoot.querySelector('aster-user-email'));
    assert.notExists(shadowRoot.querySelector('aster-user-phone'));
    assert.notExists(shadowRoot.querySelector('aster-user-password'));
    assert.notExists(shadowRoot.querySelector('aster-social-identity'));
  });
});
