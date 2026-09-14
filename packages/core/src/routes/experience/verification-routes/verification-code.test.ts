import { CaptchaPolicyScope, InteractionEvent, SignInIdentifier } from '@logto/schemas';
import { createMockUtils } from '@logto/shared/esm';
import { type z } from 'zod';

const { jest } = import.meta;
const { mockEsm } = createMockUtils(jest);

type Next = () => Promise<unknown>;
type RouteHandler = (ctx: Record<string, unknown>, next: Next) => Promise<unknown>;
type RouterLike = {
  post: jest.Mock<void, [string, ...unknown[]]>;
};

const passThroughMiddleware = async (_ctx: unknown, next: Next) => next();
async function resolveVoid(): Promise<void> {
  await Promise.resolve();
}
const koaGuard = jest.fn((_options: unknown) => passThroughMiddleware);
const phoneLockMiddleware = async (_ctx: unknown, next: Next) => next();
const koaPhoneVerificationCodeLock = jest.fn(() => phoneLockMiddleware);
const sendCode = jest.fn(async ({ prepareCodeSend }: { prepareCodeSend?: () => void }) => {
  prepareCodeSend?.();

  return { verificationId: 'verification-id' };
});
const verifyCode = jest.fn(async ({ onCodeVerified }: { onCodeVerified?: () => void }) => {
  onCodeVerified?.();

  return { verificationId: 'verification-id' };
});

mockEsm('#src/middleware/koa-guard.js', () => ({ default: koaGuard }));
mockEsm('../middleware/koa-phone-verification-code-lock.js', () => ({
  default: koaPhoneVerificationCodeLock,
}));
mockEsm('../classes/verifications/code-verification.js', () => ({
  createNewCodeVerificationRecord: jest.fn(),
  createNewMfaCodeVerificationRecord: jest.fn(),
  getTemplateTypeByEvent: jest.fn(),
}));
mockEsm('./verification-code-helpers.js', () => ({
  sendCode,
  verifyCode,
  getMfaIdentifier: jest.fn(),
  getMfaVerificationType: jest.fn(),
}));

const { default: verificationCodeRoutes } = await import('./verification-code.js');

const createRouter = (): RouterLike => ({
  post: jest.fn<void, [string, ...unknown[]]>(),
});

const registerRoute = (path = '/experience/verification/verification-code') => {
  const router = createRouter();
  verificationCodeRoutes(router as never, { libraries: {}, queries: {}, sentinel: {} } as never);
  const route = router.post.mock.calls.find(([registeredPath]) => registeredPath === path);
  const handler = route?.at(-1);

  if (typeof handler !== 'function') {
    throw new TypeError('Verification-code send route is not registered');
  }

  return handler as RouteHandler;
};

const identifier = { type: SignInIdentifier.Phone, value: '13800138000' } as const;
const createContext = (captchaToken: string | undefined = 'captcha-token') => ({
  guard: {
    body: {
      identifier,
      interactionEvent: InteractionEvent.SignIn,
      captchaToken: captchaToken as string | undefined,
    },
  },
  experienceInteraction: {
    identifiedUserId: undefined,
    verifyCaptcha: jest.fn().mockImplementation(resolveVoid),
    guardCaptcha: jest.fn().mockImplementation(resolveVoid),
    consumeCaptchaForPhoneSend: jest.fn(),
    markCaptchaVerified: jest.fn(),
    signInExperienceValidator: {
      getSignInExperienceData: jest.fn(async () => ({ signUp: { identifiers: [] } })),
    },
  },
  body: undefined as unknown,
});

describe('verification-code send CAPTCHA token', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('accepts only non-empty CAPTCHA tokens of at most 16384 UTF-8 bytes', () => {
    registerRoute();
    const guardOptions = koaGuard.mock.calls[0]?.[0] as { body: z.ZodType } | undefined;
    const exactToken = `${'界'.repeat(5461)}a`;
    const oversizedToken = `${exactToken}a`;

    expect(
      guardOptions?.body.safeParse({
        identifier,
        interactionEvent: InteractionEvent.SignIn,
        captchaToken: exactToken,
      }).success
    ).toBe(true);
    expect(
      guardOptions?.body.safeParse({
        identifier,
        interactionEvent: InteractionEvent.SignIn,
        captchaToken: oversizedToken,
      }).success
    ).toBe(false);
    expect(
      guardOptions?.body.safeParse({
        identifier,
        interactionEvent: InteractionEvent.SignIn,
        captchaToken: '',
      }).success
    ).toBe(false);
    expect(Buffer.byteLength(exactToken, 'utf8')).toBe(16 * 1024);
    expect(Buffer.byteLength(oversizedToken, 'utf8')).toBe(16 * 1024 + 1);
    expect(sendCode).not.toHaveBeenCalled();
  });

  it('registers the phone lock after the request body guard and before the send handler', () => {
    const router = createRouter();
    const tenant = {
      libraries: {},
      queries: {},
      sentinel: {},
    };
    verificationCodeRoutes(router as never, tenant as never);
    const route = router.post.mock.calls.find(
      ([registeredPath]) => registeredPath === '/experience/verification/verification-code'
    );

    expect(koaPhoneVerificationCodeLock).toHaveBeenCalledWith(tenant);
    expect(route?.at(-2)).toBe(phoneLockMiddleware);
  });

  it('verifies a POST token before the phone cost guard and send work', async () => {
    const handler = registerRoute();
    const ctx = createContext();

    await handler(ctx, jest.fn().mockImplementation(resolveVoid));

    expect(ctx.experienceInteraction.verifyCaptcha).toHaveBeenCalledWith('captcha-token');
    expect(ctx.experienceInteraction.guardCaptcha).toHaveBeenCalledWith(
      CaptchaPolicyScope.PhoneVerificationCode,
      SignInIdentifier.Phone,
      true
    );
    expect(ctx.experienceInteraction.verifyCaptcha.mock.invocationCallOrder[0]).toBeLessThan(
      ctx.experienceInteraction.guardCaptcha.mock.invocationCallOrder[0] ?? 0
    );
    expect(ctx.experienceInteraction.guardCaptcha.mock.invocationCallOrder[0]).toBeLessThan(
      sendCode.mock.invocationCallOrder[0] ?? 0
    );
    expect(sendCode.mock.invocationCallOrder[0]).toBeLessThan(
      ctx.experienceInteraction.consumeCaptchaForPhoneSend.mock.invocationCallOrder[0] ?? 0
    );
    expect(sendCode).toHaveBeenCalledTimes(1);
  });

  it('marks a tokenless phone send as lacking fresh proof for the server-owned skip check', async () => {
    const handler = registerRoute();
    const ctx = createContext();
    ctx.guard.body.captchaToken = undefined;

    await handler(ctx, jest.fn().mockImplementation(resolveVoid));

    expect(ctx.experienceInteraction.verifyCaptcha).not.toHaveBeenCalled();
    expect(ctx.experienceInteraction.guardCaptcha).toHaveBeenCalledWith(
      CaptchaPolicyScope.PhoneVerificationCode,
      SignInIdentifier.Phone,
      false
    );
    expect(sendCode).toHaveBeenCalledTimes(1);
  });

  it('restores interaction trust after a protected phone code is verified', async () => {
    const handler = registerRoute('/experience/verification/verification-code/verify');
    const experienceInteraction = {
      markCaptchaVerified: jest.fn(),
    };
    const ctx = {
      guard: {
        body: {
          identifier,
          verificationId: 'verification-id',
          code: '123456',
        },
      },
      experienceInteraction,
      body: undefined as unknown,
    };

    await handler(ctx, jest.fn().mockImplementation(resolveVoid));

    expect(verifyCode).toHaveBeenCalledWith(
      expect.objectContaining({
        identifier,
      })
    );
    expect(typeof verifyCode.mock.calls[0]?.[0].onCodeVerified).toBe('function');
    expect(experienceInteraction.markCaptchaVerified).toHaveBeenCalledTimes(1);
  });

  it('delegates phone authorization consumption to the send helper', async () => {
    const handler = registerRoute();
    const ctx = createContext();

    await handler(ctx, jest.fn().mockImplementation(resolveVoid));

    expect(ctx.experienceInteraction.consumeCaptchaForPhoneSend).toHaveBeenCalledTimes(1);
  });

  it('does not enter the phone guard or send work when token verification rejects', async () => {
    const handler = registerRoute();
    const ctx = createContext('invalid-sensitive-token');
    const verificationError = new Error('captcha rejected');
    ctx.experienceInteraction.verifyCaptcha.mockRejectedValueOnce(verificationError);

    await expect(handler(ctx, jest.fn().mockImplementation(resolveVoid))).rejects.toBe(
      verificationError
    );

    expect(ctx.experienceInteraction.guardCaptcha).not.toHaveBeenCalled();
    expect(ctx.experienceInteraction.consumeCaptchaForPhoneSend).not.toHaveBeenCalled();
    expect(sendCode).not.toHaveBeenCalled();
    expect(ctx.body).toBeUndefined();
  });
});
