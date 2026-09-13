import {
  connectorMetadataGuard,
  type ConnectorMetadata,
  type GoogleOneTapConfig,
  googleOneTapConfigGuard,
} from '@logto/connector-kit';
import { z } from 'zod';

import {
  type CustomProfileField,
  CustomProfileFields,
  type SignInExperience,
  SignInExperiences,
} from '../db-entries/index.js';
import {
  aliyunCaptchaConfigGuard,
  type AliyunCaptchaConfig,
  recaptchaEnterpriseConfigGuard,
  type RecaptchaEnterpriseConfig,
  turnstileConfigGuard,
  type TurnstileConfig,
} from '../foundations/jsonb-types/index.js';
import { type ToZodObject } from '../utils/zod.js';

import { type SsoConnectorMetadata, ssoConnectorMetadataGuard } from './sso-connector.js';

type ForgotPassword = {
  phone: boolean;
  email: boolean;
};

export type PublicCaptchaConfig =
  | Pick<TurnstileConfig, 'type' | 'siteKey'>
  | Pick<RecaptchaEnterpriseConfig, 'type' | 'siteKey' | 'domain' | 'mode'>
  | Pick<AliyunCaptchaConfig, 'type' | 'region' | 'prefix' | 'sceneId'>;

export const publicCaptchaConfigGuard = z.discriminatedUnion('type', [
  turnstileConfigGuard.pick({ type: true, siteKey: true }).strict(),
  recaptchaEnterpriseConfigGuard
    .pick({ type: true, siteKey: true, domain: true, mode: true })
    .strict(),
  aliyunCaptchaConfigGuard.pick({ type: true, region: true, prefix: true, sceneId: true }).strict(),
]);

/**
 * Basic information about a social connector for sign-in experience rendering. This type can avoid
 * the need to load the full connector metadata that is not needed for rendering.
 */
export type ExperienceSocialConnector = Omit<
  ConnectorMetadata,
  'description' | 'configTemplate' | 'formItems' | 'readme' | 'customData'
>;

export type FullSignInExperience = Omit<
  SignInExperience,
  'emailBlocklistPolicy' | 'forgotPasswordMethods'
> & {
  socialConnectors: ExperienceSocialConnector[];
  ssoConnectors: SsoConnectorMetadata[];
  forgotPassword: ForgotPassword;
  isDevelopmentTenant: boolean;
  /**
   * The Google One Tap configuration if the Google connector is enabled and configured.
   *
   * @remarks
   * We need to use a standalone property for the Google One Tap configuration because it needs
   * data from database entries that other connectors don't need. Thus we manually extract the
   * minimal data needed here.
   */
  googleOneTap?: GoogleOneTapConfig & { clientId: string; connectorId: string };
  captchaConfig?: PublicCaptchaConfig;
  /**
   * Custom profile fields selected for the sign-up (Collect user profile) flow.
   */
  customProfileFields?: Readonly<CustomProfileField[]>;
  /**
   * Full custom profile field catalog used to resolve field metadata (for example `required`
   * and `type`) outside the sign-up field list, such as the account center profile page.
   */
  customProfileFieldCatalog?: Readonly<CustomProfileField[]>;
};

export const fullSignInExperienceGuard = SignInExperiences.guard
  .omit({ emailBlocklistPolicy: true, forgotPasswordMethods: true })
  .extend({
    socialConnectors: connectorMetadataGuard
      .omit({
        description: true,
        configTemplate: true,
        formItems: true,
        readme: true,
        customData: true,
      })
      .array(),
    ssoConnectors: ssoConnectorMetadataGuard.array(),
    forgotPassword: z.object({ phone: z.boolean(), email: z.boolean() }),
    isDevelopmentTenant: z.boolean(),
    googleOneTap: googleOneTapConfigGuard
      .extend({ clientId: z.string(), connectorId: z.string() })
      .optional(),
    captchaConfig: publicCaptchaConfigGuard.optional(),
    customProfileFields: CustomProfileFields.guard.array(),
    customProfileFieldCatalog: CustomProfileFields.guard.array().optional(),
  }) satisfies ToZodObject<FullSignInExperience>;
