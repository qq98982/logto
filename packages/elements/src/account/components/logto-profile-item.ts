import { css, html, LitElement } from 'lit';
import { customElement } from 'lit/decorators.js';

const tagName = 'aster-profile-item';

/**
 * LogtoProfileItem: A custom element for displaying profile information
 *
 * It provides a consistent layout and styling for profile-related items
 *
 * Example usage:
 *
 * <aster-profile-item>
 *   <aster-icon slot="label-icon">...</aster-icon>
 *   <div slot="label-text">Label</div>
 *   <div slot="content">Content</div>
 * </aster-profile-item>
 */
@customElement(tagName)
export class LogtoProfileItem extends LitElement {
  static tagName = tagName;

  static styles = css`
    :host {
      display: flex;
      align-items: center;
      background-color: var(--aster-profile-item-container-color, var(--aster-color-background));
      border-radius: var(--aster-profile-item-container-shape, var(--aster-shape-corner-lg));
      padding-inline-start: var(
        --aster-profile-item-container-leading-space,
        var(--aster-spacing-xl)
      );
      padding-inline-end: var(
        --aster-profile-item-container-trailing-space,
        var(--aster-spacing-xl)
      );
      height: var(--aster-profile-item-height, 64px);
    }

    .label {
      flex: 1;
      display: flex;
      align-items: center;
      gap: var(--aster-profile-item-label-gap, var(--aster-spacing-sm));
    }

    ::slotted([slot='label-icon']) {
      color: var(--aster-profile-item-label-icon-color, var(--aster-color-typeface-secondary));

      --aster-icon-size: var(--aster-profile-item-label-icon-size, 24px);
    }

    ::slotted([slot='label-text']) {
      font: var(--aster-profile-item-label-font, var(--aster-font-label-md));
      color: var(--aster-profile-item-label-color, var(--aster-color-typeface-primary));
    }

    ::slotted([slot='content']),
    slot[name='content'] {
      display: flex;
      flex: 2;
      font: var(--aster-profile-item-value-font, var(--aster-font-body-md));
      color: var(--aster-profile-item--color, var(--aster-color-typeface-primary));
    }

    .no-value {
      font: var(--aster-profile-item-no-value-font, var(--aster-font-body-md));
      color: var(--aster-profile-item-no-value-color, var(--aster-color-typeface-secondary));
    }

    ::slotted([slot='actions']) {
      display: flex;
      flex: 1;
    }
  `;

  render() {
    return html`
      <div class="label">
        <slot name="label-icon"></slot>
        <slot name="label-text"></slot>
      </div>
      <slot name="content"><span class="no-value">Not set</span></slot>
      <slot name="actions"></slot>
    `;
  }
}

declare global {
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  interface HTMLElementTagNameMap {
    [tagName]: LogtoProfileItem;
  }
}
