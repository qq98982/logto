/* eslint-disable max-lines -- Keep the stateful CAPTCHA integration scenarios in one isolated suite. */
import { TemplateType } from '@logto/connector-kit';
import {
  CaptchaPolicyScope,
  ConnectorType,
  InteractionEvent,
  SignInIdentifier,
  SignInMode,
} from '@logto/schemas';
import { generateStandardId } from '@logto/shared';

import { mockSocialConnectorId } from '#src/__mocks__/connectors-mock.js';
import { deleteUser } from '#src/api/admin-user.js';
import { createOneTimeToken } from '#src/api/one-time-token.js';
import { updateSignInExperience } from '#src/api/sign-in-experience.js';
import { SsoConnectorApi } from '#src/api/sso-connector.js';
import { setAlwaysFailCaptcha, setAlwaysPassCaptcha } from '#src/helpers/captcha.js';
import { initExperienceClient, processSession } from '#src/helpers/client.js';
import {
  clearConnectorsByTypes,
  setEmailConnector,
  setSmsConnector,
  setSocialConnector,
} from '#src/helpers/connector.js';
import {
  registerNewUserUsernamePassword,
  identifyUserWithUsernamePassword,
  signInWithEnterpriseSso,
  signInWithPassword,
  signInWithSocial,
} from '#src/helpers/experience/index.js';
import {
  expectRejects,
  readConnectorMessage,
  readSmsConnectorSendCount,
  resetSmsConnectorSendCount,
} from '#src/helpers/index.js';
import {
  disableCaptcha,
  enableAllPasswordSignInMethods,
  enableCaptcha,
} from '#src/helpers/sign-in-experience.js';
import { UserApiTest, generateNewUser, generateNewUserProfile } from '#src/helpers/user.js';
import { generateEmail, generatePhone } from '#src/utils.js';

import { successfullySendVerificationCode } from '../../../../helpers/experience/verification-code.js';

describe('captcha', () => {
  beforeAll(async () => {
    await enableAllPasswordSignInMethods();
    await updateSignInExperience({
      signUp: {
        identifiers: [SignInIdentifier.Username],
        password: true,
        verify: false,
      },
      passwordPolicy: {},
    });
    await enableCaptcha();
    await setAlwaysPassCaptcha();
  });

  afterEach(async () => {
    await setAlwaysPassCaptcha();
  });

  afterAll(async () => {
    await disableCaptcha();
  });

  describe('basic sign in and captcha verification failure', () => {
    it('should sign-in successfully with captcha token', async () => {
      const { userProfile, user } = await generateNewUser({
        username: true,
        password: true,
      });

      await signInWithPassword({
        identifier: {
          type: SignInIdentifier.Username,
          value: userProfile.username,
        },
        password: userProfile.password,
        captchaToken: 'captcha-token',
      });

      await deleteUser(user.id);
    });

    it('should fail to sign-in if no captcha token', async () => {
      const { userProfile, user } = await generateNewUser({
        username: true,
        password: true,
      });

      await expectRejects(
        signInWithPassword({
          identifier: {
            type: SignInIdentifier.Username,
            value: userProfile.username,
          },
          password: userProfile.password,
        }),
        {
          code: 'session.captcha_required',
          status: 422,
        }
      );

      await deleteUser(user.id);
    });

    it('should fail to sign-in if captcha token is invalid', async () => {
      await setAlwaysFailCaptcha();
      const { userProfile, user } = await generateNewUser({
        username: true,
        password: true,
      });

      await expectRejects(
        signInWithPassword({
          identifier: { type: SignInIdentifier.Username, value: userProfile.username },
          password: userProfile.password,
          captchaToken: 'captcha-token',
        }),
        {
          code: 'session.captcha_failed',
          status: 422,
        }
      );

      await deleteUser(user.id);
    });
  });

  describe('register', () => {
    it('should register successfully with captcha token', async () => {
      const { username, password } = generateNewUserProfile({ username: true, password: true });
      const userId = await registerNewUserUsernamePassword(username, password, 'captcha-token');

      await signInWithPassword({
        identifier: {
          type: SignInIdentifier.Username,
          value: username,
        },
        password,
        captchaToken: 'captcha-token',
      });

      await deleteUser(userId);
    });

    it('should fail to register if no captcha token is provided', async () => {
      const { username, password } = generateNewUserProfile({ username: true, password: true });
      await expectRejects(registerNewUserUsernamePassword(username, password), {
        code: 'session.captcha_required',
        status: 422,
      });

      // Register again with the same username, ensure the user is not created
      const userId = await registerNewUserUsernamePassword(username, password, 'captcha-token');
      await deleteUser(userId);
    });
  });

  describe('social verification', () => {
    const connectorIdMap = new Map<string, string>();
    const socialUserId = generateStandardId();

    beforeAll(async () => {
      await clearConnectorsByTypes([ConnectorType.Social]);
      const { id: socialConnectorId } = await setSocialConnector();
      connectorIdMap.set(mockSocialConnectorId, socialConnectorId);
      await updateSignInExperience({
        signUp: {
          identifiers: [],
          password: true,
          verify: false,
        },
        passwordPolicy: {},
      });
    });

    afterAll(async () => {
      await clearConnectorsByTypes([ConnectorType.Social]);
    });

    it('should skip captcha for social registration', async () => {
      const userId = await signInWithSocial(
        connectorIdMap.get(mockSocialConnectorId)!,
        {
          id: socialUserId,
        },
        {
          registerNewUser: true,
        }
      );
      await deleteUser(userId);
    });
  });

  describe('enterprise sso verification', () => {
    const ssoConnectorApi = new SsoConnectorApi();
    const domain = 'foo.com';
    const enterpriseSsoIdentityId = generateStandardId();
    const email = generateEmail(domain);
    const userApi = new UserApiTest();

    beforeAll(async () => {
      await ssoConnectorApi.createMockOidcConnector([domain]);
      await updateSignInExperience({
        singleSignOnEnabled: true,
        signUp: { identifiers: [], password: false, verify: false },
      });
    });

    afterAll(async () => {
      await Promise.all([ssoConnectorApi.cleanUp(), userApi.cleanUp()]);
    });

    it('should skip captcha for enterprise sso verification', async () => {
      const userId = await signInWithEnterpriseSso(
        ssoConnectorApi.firstConnectorId!,
        {
          sub: enterpriseSsoIdentityId,
          email,
          email_verified: true,
        },
        true
      );
      await deleteUser(userId);
    });
  });

  describe('one-time token verification', () => {
    beforeAll(async () => {
      await setEmailConnector();
      await updateSignInExperience({
        signInMode: SignInMode.SignInAndRegister,
        signUp: {
          identifiers: [SignInIdentifier.Email],
          password: false,
          verify: true,
        },
        signIn: {
          methods: [
            {
              identifier: SignInIdentifier.Username,
              password: true,
              verificationCode: false,
              isPasswordPrimary: true,
            },
            {
              identifier: SignInIdentifier.Email,
              password: true,
              verificationCode: true,
              isPasswordPrimary: false,
            },
          ],
        },
      });
    });

    afterAll(async () => {
      await clearConnectorsByTypes([ConnectorType.Email]);
    });

    it('should skip captcha for one-time token registration', async () => {
      const client = await initExperienceClient({
        interactionEvent: InteractionEvent.Register,
      });

      const oneTimeToken = await createOneTimeToken({
        email: 'foo@logto.io',
      });

      const { verificationId } = await client.verifyOneTimeToken({
        token: oneTimeToken.token,
        identifier: {
          type: SignInIdentifier.Email,
          value: 'foo@logto.io',
        },
      });

      await client.identifyUser({ verificationId });

      const { redirectTo } = await client.submitInteraction();
      const userId = await processSession(client, redirectTo);
      await deleteUser(userId);
    });
  });

  describe('verification code', () => {
    beforeAll(async () => {
      await setEmailConnector();
    });

    it('should fail to send verification code without captcha token', async () => {
      const { userProfile } = await generateNewUser({
        primaryEmail: true,
        password: true,
      });

      const client = await initExperienceClient({
        interactionEvent: InteractionEvent.Register,
      });

      await expectRejects(
        client.sendVerificationCode({
          identifier: {
            type: SignInIdentifier.Email,
            value: userProfile.primaryEmail,
          },
          interactionEvent: InteractionEvent.Register,
        }),
        {
          code: 'session.captcha_required',
          status: 422,
        }
      );
    });

    it('should be able to send verification code with captcha token', async () => {
      const { userProfile } = await generateNewUser({
        primaryEmail: true,
        password: true,
      });

      const client = await initExperienceClient({
        interactionEvent: InteractionEvent.Register,
        captchaToken: 'captcha-token',
      });

      await successfullySendVerificationCode(client, {
        identifier: { type: SignInIdentifier.Email, value: userProfile.primaryEmail },
        interactionEvent: InteractionEvent.Register,
      });
    });
  });

  describe('phone verification-code captcha policy', () => {
    const connectorIdMap = new Map<string, string>();

    beforeAll(async () => {
      await clearConnectorsByTypes([ConnectorType.Email, ConnectorType.Sms, ConnectorType.Social]);
      const [{ id: socialConnectorId }] = await Promise.all([
        setSocialConnector(),
        setEmailConnector(),
        setSmsConnector(),
      ]);
      connectorIdMap.set(mockSocialConnectorId, socialConnectorId);
      await updateSignInExperience({
        captchaPolicy: {
          enabled: true,
          scope: CaptchaPolicyScope.PhoneVerificationCode,
        },
      });
    });

    beforeEach(async () => {
      await resetSmsConnectorSendCount();
    });

    afterAll(async () => {
      await clearConnectorsByTypes([ConnectorType.Email, ConnectorType.Sms, ConnectorType.Social]);
    });

    it('rejects a phone code without captcha before the SMS connector is called', async () => {
      const client = await initExperienceClient({ interactionEvent: InteractionEvent.Register });
      const interactionBeforeSend = await client.getInteractionData();

      await expectRejects(
        client.sendVerificationCode({
          identifier: { type: SignInIdentifier.Phone, value: generatePhone() },
          interactionEvent: InteractionEvent.Register,
        }),
        { code: 'session.captcha_required', status: 422 }
      );

      await expect(readSmsConnectorSendCount()).resolves.toBe(0);
      const interactionAfterSend = await client.getInteractionData();
      expect(interactionAfterSend).toEqual(interactionBeforeSend);
    });

    it('sends exactly one phone code after captcha is verified', async () => {
      const phone = generatePhone();
      const client = await initExperienceClient({
        interactionEvent: InteractionEvent.Register,
        captchaToken: 'captcha-token',
      });

      const result = await client.sendVerificationCode({
        identifier: { type: SignInIdentifier.Phone, value: phone },
        interactionEvent: InteractionEvent.Register,
      });

      expect(result.verificationId).toBeTruthy();
      await expect(readSmsConnectorSendCount()).resolves.toBe(1);
      await expect(readConnectorMessage('Sms')).resolves.toMatchObject({ phone });
    });

    it('allows an email code without captcha under the phone-only policy', async () => {
      const email = generateEmail();
      const client = await initExperienceClient({ interactionEvent: InteractionEvent.Register });

      const result = await client.sendVerificationCode({
        identifier: { type: SignInIdentifier.Email, value: email },
        interactionEvent: InteractionEvent.Register,
      });

      expect(result.verificationId).toBeTruthy();
      await expect(readConnectorMessage('Email')).resolves.toMatchObject({
        address: email,
        type: TemplateType.Register,
      });
      await expect(readSmsConnectorSendCount()).resolves.toBe(0);
    });

    it('rejects a client-selected phone after password identification without trusted skip', async () => {
      const { userProfile, user } = await generateNewUser({ username: true, password: true });
      const client = await initExperienceClient({ interactionEvent: InteractionEvent.SignIn });
      await identifyUserWithUsernamePassword(client, userProfile.username, userProfile.password);
      const interactionBeforeSend = await client.getInteractionData();

      await expectRejects(
        client.sendVerificationCode({
          identifier: { type: SignInIdentifier.Phone, value: generatePhone() },
          interactionEvent: InteractionEvent.SignIn,
        }),
        { code: 'session.captcha_required', status: 422 }
      );

      await expect(readSmsConnectorSendCount()).resolves.toBe(0);
      await expect(client.getInteractionData()).resolves.toEqual(interactionBeforeSend);
      await deleteUser(user.id);
    });

    it('sends phone MFA to the identified user stored phone without captcha', async () => {
      const { userProfile, user } = await generateNewUser({
        username: true,
        password: true,
        primaryPhone: true,
      });
      const client = await initExperienceClient({ interactionEvent: InteractionEvent.SignIn });
      await identifyUserWithUsernamePassword(client, userProfile.username, userProfile.password);

      const result = await client.sendMfaVerificationCode({
        identifierType: SignInIdentifier.Phone,
        phone: '15555550123',
      } as unknown as Parameters<typeof client.sendMfaVerificationCode>[0]);

      expect(result.verificationId).toBeTruthy();
      await expect(readSmsConnectorSendCount()).resolves.toBe(1);
      await expect(readConnectorMessage('Sms')).resolves.toMatchObject({
        phone: userProfile.primaryPhone,
        type: TemplateType.MfaVerification,
      });
      await deleteUser(user.id);
    });

    it('allows verified social registration to bind a phone without a second captcha', async () => {
      await updateSignInExperience({
        signUp: {
          identifiers: [SignInIdentifier.Phone],
          password: false,
          verify: true,
        },
      });

      const connectorId = connectorIdMap.get(mockSocialConnectorId)!;
      const client = await initExperienceClient();
      const state = 'state';
      const redirectUri = 'http://localhost:3000';
      const { verificationId } = await client.getSocialAuthorizationUri(connectorId, {
        redirectUri,
        state,
      });

      await client.verifySocialAuthorization(connectorId, {
        verificationId,
        connectorData: {
          state,
          redirectUri,
          code: 'fake_code',
          userId: generateStandardId(),
        },
      });
      await expectRejects(client.identifyUser({ verificationId }), {
        code: 'user.identity_not_exist',
        status: 404,
      });
      await client.updateInteractionEvent({ interactionEvent: InteractionEvent.Register });
      await expectRejects(client.identifyUser({ verificationId }), {
        code: 'user.missing_profile',
        status: 422,
      });

      const result = await client.sendVerificationCode({
        identifier: { type: SignInIdentifier.Phone, value: generatePhone() },
        interactionEvent: InteractionEvent.Register,
      });

      expect(result.verificationId).toBeTruthy();
      await expect(readSmsConnectorSendCount()).resolves.toBe(1);
    });

    it('does not allow a direct caller to forge the server-owned captcha skip state', async () => {
      const client = await initExperienceClient({ interactionEvent: InteractionEvent.Register });

      await client.initInteraction({
        interactionEvent: InteractionEvent.Register,
        captcha: { verified: false, skipped: true },
      } as unknown as Parameters<typeof client.initInteraction>[0]);

      await expectRejects(
        client.sendVerificationCode({
          identifier: { type: SignInIdentifier.Phone, value: generatePhone() },
          interactionEvent: InteractionEvent.Register,
        }),
        { code: 'session.captcha_required', status: 422 }
      );

      await expect(readSmsConnectorSendCount()).resolves.toBe(0);
    });
  });
});
/* eslint-enable max-lines */
