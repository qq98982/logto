/**
 * Stable (non-hashed) class names for key account center elements,
 * so that custom CSS injected via `customCss` can target them easily.
 *
 * Mirrors the pattern used by the sign-in experience package
 * (`packages/experience/src/utils/consts.ts` → `layoutClassNames`).
 */
export const layoutClassNames = Object.freeze({
  /** Root `<div>` wrapping the entire account center app. */
  app: 'aster_ac-app',
  /** Full-page layout wrapper used across account center routes. */
  pageContainer: 'aster_ac-page-container',
  /** `<main>` that holds the primary content area. */
  mainContent: 'aster_ac-main-content',
  /** Card-style container used on sub-pages (email, phone, password…). */
  cardContainer: 'aster_ac-card-container',
  /** Card-style `<main>` inside the card container. */
  cardMain: 'aster_ac-card-main',
  /** Aster signature / branding footer. */
  signature: 'aster_ac-signature',
  /** Top-level page header (logo + app name bar). */
  pageHeader: 'aster_ac-page-header',
  /** Page title text (on Security / Home page). */
  pageTitle: 'aster_ac-page-title',
  /** Page description text (on Security / Home page). */
  pageDescription: 'aster_ac-page-description',
  /** Scrollable content area on the Security / Home page. */
  pageContent: 'aster_ac-page-content',
  /** Each logical section (username, email/phone, password, MFA, social, delete). */
  section: 'aster_ac-section',
  /** Section heading text. */
  sectionTitle: 'aster_ac-section-title',
  /** Card that groups rows inside a section. */
  card: 'aster_ac-card',
  /** A single row inside a card. */
  row: 'aster_ac-row',
  /** Wrapper for the secondary (sub-page) layout. */
  secondaryPageWrapper: 'aster_ac-secondary-page-wrapper',
  /** Secondary page title. */
  secondaryPageTitle: 'aster_ac-secondary-page-title',
  /** Secondary page description. */
  secondaryPageDescription: 'aster_ac-secondary-page-description',
  /** Sidebar navigation on the Security / Profile page. */
  sidebar: 'aster_ac-sidebar',
  /** A navigation item inside the sidebar. */
  sidebarItem: 'aster_ac-sidebar-item',
  /** Full-page layout with multiple account nav destinations (sidebar or mobile tabs). */
  withTabNav: 'aster_ac-with-tab-nav',
  /** Mobile top tab navigation on the Security / Profile page. */
  mobileTabNav: 'aster_ac-mobile-tab-nav',
  /** A tab item inside the mobile tab navigation. */
  mobileTabNavItem: 'aster_ac-mobile-tab-nav-item',
});
