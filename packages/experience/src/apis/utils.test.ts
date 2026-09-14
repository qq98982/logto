import { InteractionEvent, SignInIdentifier } from '@logto/schemas';

import { UserFlow } from '@/types';

import { initInteraction, sendVerificationCode } from './experience';
import { sendVerificationCodeApi } from './utils';

jest.mock('./experience', () => ({
  initInteraction: jest.fn(),
  sendVerificationCode: jest.fn(),
}));

const identifier = { type: SignInIdentifier.Phone, value: 'test-phone' } as const;

describe('sendVerificationCodeApi', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it.each([
    [UserFlow.Register, InteractionEvent.Register],
    [UserFlow.SignIn, InteractionEvent.SignIn],
    [UserFlow.ForgotPassword, InteractionEvent.ForgotPassword],
  ])(
    'initializes %s without CAPTCHA and sends the proof on the phone POST',
    async (flow, event) => {
      const getCaptchaToken = jest.fn().mockResolvedValue('captcha-token');
      jest.mocked(initInteraction).mockResolvedValueOnce({} as never);
      jest
        .mocked(sendVerificationCode)
        .mockResolvedValueOnce({ verificationId: 'verification-id' });

      await sendVerificationCodeApi(flow, identifier, undefined, getCaptchaToken);

      expect(initInteraction).toHaveBeenCalledWith(event);
      expect(getCaptchaToken).toHaveBeenCalledTimes(1);
      expect(sendVerificationCode).toHaveBeenCalledWith(event, identifier, 'captcha-token');
      expect(jest.mocked(initInteraction).mock.invocationCallOrder[0]).toBeLessThan(
        getCaptchaToken.mock.invocationCallOrder[0] ?? 0
      );
      expect(getCaptchaToken.mock.invocationCallOrder[0]).toBeLessThan(
        jest.mocked(sendVerificationCode).mock.invocationCallOrder[0] ?? 0
      );
    }
  );

  it('keeps Continue on the existing interaction and sends its CAPTCHA proof', async () => {
    jest.mocked(sendVerificationCode).mockResolvedValueOnce({ verificationId: 'verification-id' });

    await sendVerificationCodeApi(
      UserFlow.Continue,
      identifier,
      InteractionEvent.Register,
      'captcha-token'
    );

    expect(initInteraction).not.toHaveBeenCalled();
    expect(sendVerificationCode).toHaveBeenCalledWith(
      InteractionEvent.Register,
      identifier,
      'captcha-token'
    );
  });
});
