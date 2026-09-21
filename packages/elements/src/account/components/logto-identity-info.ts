import { css, html, LitElement } from 'lit';
import { customElement, property, state } from 'lit/decorators.js';

import fallbackAvatar from '../icons/fallback-avatar.svg';

const tagName = 'aster-identity-info';

@customElement(tagName)
export class LogtoIdentityInfo extends LitElement {
  static tagName = tagName;

  static styles = css`
    :host {
      display: flex;
      align-items: center;
      gap: var(--aster-spacing-sm);
    }

    .avatar {
      --aster-icon-size: var(--aster-identity-info-avatar-size, 36px);

      > img {
        display: block;
        width: var(--aster-identity-info-avatar-size, 36px);
        height: var(--aster-identity-info-avatar-size, 36px);
        border-radius: var(--aster-identity-info-avatar-shape, var(--aster-shape-corner-md));
      }
    }

    .info {
      flex: 1;
      flex-direction: column;

      .name {
        font: var(--aster-identity-info-name-font-size, var(--aster-font-body-md));
        color: var(
          --aster-identity-info-name-color,
          var(--aster-color---aster-color-typeface-primary)
        );
      }

      .email {
        font: var(--aster-identity-info-email-font, var(--aster-font-body-sm));
        color: var(
          --aster-identity-info-email-color,
          var(--aster-color---aster-color-typeface-primary)
        );
      }
    }
  `;

  @property({ type: String })
  avatar = '';

  @property({ type: String })
  name = '';

  @property({ type: String })
  email = '';

  @state()
  failedToLoadAvatar = false;

  render() {
    return html`
      <div class="avatar">
        ${this.avatar && !this.failedToLoadAvatar
          ? html`<img src="${this.avatar}" alt="user avatar" @error=${this.handleAvatarError} />`
          : html`<aster-icon>${fallbackAvatar}</aster-icon>`}
      </div>
      <div class="info">
        <div class="name">${this.name}</div>
        <div class="email">${this.email}</div>
      </div>
    `;
  }

  private handleAvatarError() {
    this.failedToLoadAvatar = true;
  }
}

declare global {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface HTMLElementTagNameMap {
    [tagName]: LogtoIdentityInfo;
  }
}
