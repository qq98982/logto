import { consume } from '@lit/context';
import { css, html, LitElement } from 'lit';
import { customElement } from 'lit/decorators.js';

import {
  logtoAccountContext,
  type LogtoAccountContextType,
} from '../providers/logto-account-provider.js';

const tagName = 'aster-account-center';

@customElement(tagName)
export class LogtoAccountCenter extends LitElement {
  static tagName = tagName;

  static styles = css`
    :host {
      display: flex;
      flex-direction: column;
      gap: var(--aster-account-center-item-spacing, var(--aster-spacing-md));
    }
  `;

  @consume({ context: logtoAccountContext, subscribe: true })
  private readonly accountContext?: LogtoAccountContextType;

  render() {
    if (!this.accountContext) {
      return html`<span>Unable to retrieve account context.</span>`;
    }

    const {
      userProfile: { username, primaryEmail, primaryPhone, hasPassword, identities },
    } = this.accountContext;

    return html`
      ${username !== undefined && html`<aster-username></aster-username>`}
      ${primaryEmail !== undefined && html`<aster-user-email></aster-user-email>`}
      ${primaryPhone !== undefined && html`<aster-user-phone></aster-user-phone>`}
      ${hasPassword !== undefined && html`<aster-user-password></aster-user-password>`}
      ${identities !== undefined &&
      Object.entries(identities).map(
        ([target]) => html`<aster-social-identity target=${target}></aster-social-identity>`
      )}
    `;
  }
}

declare global {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface HTMLElementTagNameMap {
    [tagName]: LogtoAccountCenter;
  }
}
