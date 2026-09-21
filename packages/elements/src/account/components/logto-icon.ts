import { css, html, LitElement } from 'lit';
import { customElement } from 'lit/decorators.js';

const tagName = 'aster-icon';

/**
 * LogtoIcon: A custom element for consistent icon rendering
 *
 * It allows configuring the icon size within the shadow DOM using the `--aster-icon-size` CSS variable,
 * which is necessary because external CSS cannot affect styles inside the shadow DOM
 */
@customElement(tagName)
export class LogtoIcon extends LitElement {
  static tagName = tagName;

  static styles = css`
    ::slotted(svg) {
      display: block;
      width: var(--aster-icon-size, 24px);
      height: var(--aster-icon-size, 24px);
    }
  `;

  render() {
    return html`<slot></slot>`;
  }
}

declare global {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface HTMLElementTagNameMap {
    [tagName]: LogtoIcon;
  }
}
