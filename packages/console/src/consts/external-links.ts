import { asterDocumentationUrl, asterSupportEmail, asterWebsiteUrl } from './env';

const resolveConfiguredLink = (root: string | undefined, pagePath: string) => {
  if (!root) {
    return;
  }

  try {
    return new URL(pagePath, root.endsWith('/') ? root : `${root}/`).href;
  } catch {}
};

export const resolveAsterDocumentationLink = (pagePath: string) =>
  resolveConfiguredLink(asterDocumentationUrl, pagePath);

export const contactEmailLink = asterSupportEmail ? `mailto:${asterSupportEmail}` : undefined;
export const trustAndSecurityLink = resolveConfiguredLink(asterWebsiteUrl, 'trust-and-security');
export const officialWebsiteContactPageLink = resolveConfiguredLink(asterWebsiteUrl, 'contact');
export const entityPolicyLink = resolveAsterDocumentationLink('system-limit');
export const selfHostedFeatureSupportLink = resolveAsterDocumentationLink(
  'self-hosted/feature-support'
);

/** Docs link */
export const organizationsFeatureLink = '/organizations';
export const organizationConfigGuideLink =
  '/authorization/organization-template/configure-organization-template';
export const thirdPartyGuideLink = '/identity-provider/';
export const thirdPartyAppPermissionsLink = '/identity-provider/permissions-management/';
export const thirdPartyAppBrandingLink = '/identity-provider/branding-customization/';
export const appSpecificBrandingLink =
  '/docs/recipes/customize-sie/match-your-brand/#app-specific-branding';
export const organizationBrandingLink =
  '/customization/match-your-brand#organization-specific-branding';
export const organizationLogosForExperienceLink =
  '/docs/recipes/customize-sie/match-your-brand/#organization-specific-logos';
export const signingKeysLink = '/docs/references/openid-connect/signing-keys-rotation/';
export const organizationTemplateLink = '/authorization/organization-template';
export const organizationRoleLink =
  '/docs/recipes/organizations/understand-how-it-works/#organization-role';
export const organizationPermissionLink =
  '/docs/recipes/organizations/understand-how-it-works/#organization-permission';
export const profilePropertyReferenceLink = '/docs/references/users/#profile-1';
export const organizationJit = Object.freeze({
  enterpriseSso:
    '/docs/recipes/organizations/just-in-time-provisioning/#enterprise-sso-provisioning',
  emailDomain: '/docs/recipes/organizations/just-in-time-provisioning/#email-domain-provisioning',
});
export const integrationGuide = '/integration';
export const applicationDataStructure = '/integration/application-data-structure';
export const thirdPartyApp =
  '/integration/third-party-applications/oidc-oauth-third-party-applications';
export const protectedApp = '/integration/protected-app';
export const protectedAppLocalDev = '/integration/protected-app#local-development';
export const protectOriginServer = '/integration/protected-app#protect-your-origin-server';
export const appLevelAccessControl = '/integration/app-level-access-control';
export const deviceFlow = '/quick-starts/device-flow';
export const backchannelLogout = '/end-user-flows/sign-out#federated-sign-out-back-channel-logout';
export const authFlows = '/end-user-flows#authentication-flows';
export const termsAndPrivacy = '/end-user-flows/sign-up-and-sign-in/terms-and-privacy';
export const mfa = '/end-user-flows/mfa';
export const collectUserProfile = '/end-user-flows/collect-user-profile';
export const connectors = '/connectors';
export const socialConnectors = '/connectors/social-connectors';
export const emailConnectors = '/connectors/email-connectors';
export const builtInEmailService = '/connectors/email-connectors/built-in-email-service';
export const enterpriseSso = '/connectors/enterprise-connectors';
export const security = '/security';
export const captcha = '/security/captcha';
export const recaptchaEnterpriseBringYourUi =
  '/security/captcha/recaptcha-enterprise#bring-your-ui';
export const turnstileBringYourUi = '/security/captcha/turnstile#bring-your-ui';
export const sentinel = '/security/identifier-lockout';
export const emailBlocklist = '/security/blocklist';
export const passwordPolicy = '/security/password-policy';
export const spInitiatedSsoFlow = '/end-user-flows/enterprise-sso/sp-initiated-sso';
export const apiResources = '/authorization/global-api-resources';
export const rbac = '/authorization/role-based-access-control';
export const manageRolePermissions =
  '/authorization/role-based-access-control/configure-permissions#manage-role-permissions';
export const userManagement = '/user-management';
export const userCustomData = '/user-management/user-data#custom-data';
export const personalAccessToken = '/user-management/personal-access-token';
export const customIdToken = '/developers/custom-id-token';
export const userImpersonation = '/developers/user-impersonation';
export const webhooks = '/developers/webhooks';
export const secureWebhooks = '/developers/webhooks/secure-webhooks';
export const auditLogs = '/developers/audit-logs';
export const hostedService = '/hosted-service';
export const hostedServiceTenantSettings = '/hosted-service/tenant-settings';
export const hostedServiceDevTenantDataRetention = '/hosted-service/dev-tenant-data-retention';
export const customDomain = '/hosted-service/custom-domain#use-custom-domain';
export const customDomainFeatureLink = '/hosted-service/custom-domain';
export const retrieveTokenStorage = '/secret-vault/federated-token-set#token-retrieval';

export const addOnPricingExplanationLink = resolveAsterDocumentationLink(
  'hosted-service/billing-and-pricing'
);

export const dateFnsDocumentationLink = 'https://date-fns.org/v2.30.0/docs/format';
