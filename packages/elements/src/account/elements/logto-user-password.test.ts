import { assert, fixture, html, waitUntil } from '@open-wc/testing';

import { createMockAccountApi } from '../__mocks__/account-api.js';
import { type LogtoAccountProvider } from '../providers/logto-account-provider.js';

import { LogtoUserPassword } from './logto-user-password.js';

suite('aster-user-password', () => {
  test('is defined', () => {
    const element = document.createElement(LogtoUserPassword.tagName);
    assert.instanceOf(element, LogtoUserPassword);
  });

  test('should render error message when account context is not available', async () => {
    const element = await fixture<LogtoUserPassword>(
      html`<aster-user-password></aster-user-password>`
    );
    await element.updateComplete;

    assert.equal(element.shadowRoot?.textContent, 'Unable to retrieve account context.');
  });

  test('should render configured status when user has password', async () => {
    const mockAccountApi = createMockAccountApi({
      fetchUserProfile: async () => ({
        hasPassword: true,
      }),
    });

    const provider = await fixture<LogtoAccountProvider>(
      html`<aster-account-provider .accountApi=${mockAccountApi}>
        <aster-user-password></aster-user-password>
      </aster-account-provider>`
    );

    await provider.updateComplete;

    const logtoUserPassword = provider.querySelector<LogtoUserPassword>(LogtoUserPassword.tagName);

    await waitUntil(
      () =>
        logtoUserPassword?.shadowRoot?.querySelector('.status')?.textContent.includes('Configured'),
      'Unable to get password status from account context'
    );
  });

  test('should not render status when user has no password', async () => {
    const mockAccountApi = createMockAccountApi({
      fetchUserProfile: async () => ({
        hasPassword: false,
      }),
    });

    const provider = await fixture<LogtoAccountProvider>(
      html`<aster-account-provider .accountApi=${mockAccountApi}>
        <aster-user-password></aster-user-password>
      </aster-account-provider>`
    );

    await provider.updateComplete;
    const logtoUserPassword = provider.querySelector<LogtoUserPassword>(LogtoUserPassword.tagName);

    await logtoUserPassword?.updateComplete;
    assert.isNull(logtoUserPassword?.shadowRoot?.querySelector('.status'));
  });
});
