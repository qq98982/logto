import { yes } from '@silverhand/essentials';

import { storageKeys } from './storage';

const normalizeEnv = (value: unknown) =>
  value === null || value === undefined ? undefined : String(value);

export const isProduction = import.meta.env.PROD;
const isHostedDeployment = (): boolean => false;

export const isCloud = isHostedDeployment();
export const isProtectedAppLocalDevEnabled =
  !isProduction && yes(normalizeEnv(import.meta.env.PROTECTED_APP_LOCAL_DEV));
export const isProtectedAppEnabled = isProtectedAppLocalDevEnabled;
export const adminEndpoint = normalizeEnv(import.meta.env.ADMIN_ENDPOINT);

export const isDevFeaturesEnabled =
  !isProduction ||
  yes(normalizeEnv(import.meta.env.DEV_FEATURES_ENABLED)) ||
  yes(localStorage.getItem(storageKeys.isDevFeaturesEnabled));

export const postHogKey = normalizeEnv(import.meta.env.POSTHOG_PUBLIC_KEY);
/**
 * The PostHog API host URL. When using a self-hosted PostHog instance or a custom domain,
 * {@link postHogUiHost} should also be set accordingly.
 *
 * @see https://posthog.com/docs/libraries/js/config for more details.
 */
export const postHogHost = normalizeEnv(import.meta.env.POSTHOG_PUBLIC_HOST);
/**
 * The PostHog UI host URL. If {@link postHogHost} is set to a custom host, this should also be set accordingly.
 *
 * @see https://posthog.com/docs/libraries/js/config for more details.
 */
export const postHogUiHost = normalizeEnv(import.meta.env.POSTHOG_PUBLIC_UI_HOST);
export const asterDocumentationUrl = normalizeEnv(import.meta.env.ASTER_DOCUMENTATION_URL);
export const asterWebsiteUrl = normalizeEnv(import.meta.env.ASTER_WEBSITE_URL);
export const asterSupportEmail = normalizeEnv(import.meta.env.ASTER_SUPPORT_EMAIL);
export const asterSurveyEndpoint = normalizeEnv(import.meta.env.ASTER_OSS_SURVEY_ENDPOINT);
