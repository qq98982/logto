import { TemplateType } from '@logto/connector-kit';
import {
  AlternativeSignUpIdentifier,
  CaptchaPolicyScope,
  InteractionEvent,
  SignInIdentifier,
  verificationCodeIdentifierGuard,
} from '@logto/schemas';
import type Router from 'koa-router';
import { z } from 'zod';

import koaGuard from '#src/middleware/koa-guard.js';
import type TenantContext from '#src/tenants/TenantContext.js';

import { codeVerificationIdentifierRecordTypeMap } from '../classes/utils.js';
import {
  createNewCodeVerificationRecord,
  createNewMfaCodeVerificationRecord,
  getTemplateTypeByEvent,
} from '../classes/verifications/code-verification.js';
import { experienceRoutes } from '../const.js';
import { type ExperienceInteractionRouterContext } from '../types.js';

import {
  sendCode,
  verifyCode,
  getMfaIdentifier,
  getMfaVerificationType,
} from './verification-code-helpers.js';

const maximumCaptchaTokenBytes = 16 * 1024;
const captchaTokenGuard = z.string().refine((token) => {
  const byteLength = Buffer.byteLength(token, 'utf8');
  return byteLength > 0 && byteLength <= maximumCaptchaTokenBytes;
});

export default function verificationCodeRoutes<T extends ExperienceInteractionRouterContext>(
  router: Router<unknown, T>,
  { libraries, queries, sentinel }: TenantContext
) {
  router.post(
    `${experienceRoutes.verification}/verification-code`,
    koaGuard({
      body: z.object({
        identifier: verificationCodeIdentifierGuard,
        interactionEvent: z.nativeEnum(InteractionEvent),
        captchaToken: captchaTokenGuard.optional(),
      }),
      response: z.object({
        verificationId: z.string(),
      }),
      // 429: rate limited; 501: connector not found
      status: [200, 400, 404, 422, 429, 501],
    }),
    async (ctx, next) => {
      const { identifier, interactionEvent, captchaToken } = ctx.guard.body;
      if (captchaToken !== undefined) {
        await ctx.experienceInteraction.verifyCaptcha(captchaToken);
      }

      await ctx.experienceInteraction.guardCaptcha(
        CaptchaPolicyScope.PhoneVerificationCode,
        identifier.type
      );

      // Check if email/phone is in sign up identifiers, to determine if it's binding email/phone for MFA
      const { signUp } =
        await ctx.experienceInteraction.signInExperienceValidator.getSignInExperienceData();
      // If the interaction already identified a user, and email/phone is not in sign up identifiers,
      // then the sign-up/sign-in flow is complete and we are binding a new MFA verification
      const isBindingEmailForMfa =
        ctx.experienceInteraction.identifiedUserId &&
        !signUp.identifiers.includes(identifier.type) &&
        !signUp.secondaryIdentifiers?.some(
          ({ identifier: id }) =>
            id === identifier.type || id === AlternativeSignUpIdentifier.EmailOrPhone
        );

      ctx.body = await sendCode({
        identifier,
        interactionEvent,
        createVerificationRecord: () =>
          createNewCodeVerificationRecord(
            libraries,
            queries,
            identifier,
            // If the interaction already identified a user, we are binding a new MFA verification
            isBindingEmailForMfa ? TemplateType.BindMfa : getTemplateTypeByEvent(interactionEvent)
          ),
        libraries,
        queries,
        ctx,
      });

      await next();
    }
  );

  router.post(
    `${experienceRoutes.verification}/verification-code/verify`,
    koaGuard({
      body: z.object({
        identifier: verificationCodeIdentifierGuard,
        verificationId: z.string(),
        code: z.string(),
      }),
      response: z.object({
        verificationId: z.string(),
      }),
      // 501: connector not found
      status: [200, 400, 404, 501],
    }),
    async (ctx, next) => {
      const { verificationId, code, identifier } = ctx.guard.body;

      ctx.body = await verifyCode({
        verificationId,
        code,
        identifier,
        verificationType: codeVerificationIdentifierRecordTypeMap[identifier.type],
        sentinel,
        ctx,
      });

      return next();
    }
  );

  router.post(
    `${experienceRoutes.verification}/mfa-verification-code`,
    koaGuard({
      body: z.object({
        identifierType: z.enum([SignInIdentifier.Email, SignInIdentifier.Phone]),
      }),
      response: z.object({
        verificationId: z.string(),
      }),
      // 429: rate limited; 501: connector not found
      status: [200, 400, 404, 429, 501],
    }),
    async (ctx, next) => {
      const { identifierType } = ctx.guard.body;
      const { experienceInteraction } = ctx;

      // CAPTCHA is intentionally exempt: the server resolves the recipient from the identified user.
      const identifier = await getMfaIdentifier({
        identifierType,
        experienceInteraction,
        queries,
      });

      ctx.body = await sendCode({
        identifier,
        createVerificationRecord: () =>
          createNewMfaCodeVerificationRecord(libraries, queries, identifier),
        libraries,
        queries,
        ctx,
      });

      await next();
    }
  );

  router.post(
    `${experienceRoutes.verification}/mfa-verification-code/verify`,
    koaGuard({
      body: z.object({
        verificationId: z.string(),
        code: z.string(),
        identifierType: z.enum([SignInIdentifier.Email, SignInIdentifier.Phone]),
      }),
      response: z.object({
        verificationId: z.string(),
      }),
      status: [200, 400, 404, 501],
    }),
    async (ctx, next) => {
      const { verificationId, code, identifierType } = ctx.guard.body;
      const { experienceInteraction } = ctx;

      const mfaVerificationType = getMfaVerificationType(identifierType);

      // Get the verification record to extract the identifier value
      const codeVerificationRecord = experienceInteraction.getVerificationRecordByTypeAndId(
        mfaVerificationType,
        verificationId
      );

      const identifier = {
        type: identifierType,
        value: codeVerificationRecord.identifier.value,
      };

      ctx.body = await verifyCode({
        verificationId,
        code,
        identifier,
        verificationType: mfaVerificationType,
        sentinel,
        ctx,
      });

      return next();
    }
  );
}
