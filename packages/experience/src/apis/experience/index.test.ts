import { InteractionEvent, SignInIdentifier } from '@logto/schemas';

import api from '../api';

import { sendVerificationCode } from '.';
import { experienceApiRoutes } from './const';

jest.mock('../api', () => ({
  __esModule: true,
  default: {
    post: jest.fn(),
  },
}));

const mockedApiPost = api.post as jest.MockedFunction<typeof api.post>;

describe('verification-code experience API', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('posts the optional CAPTCHA token with the verification-code request', async () => {
    const response = { verificationId: 'verification-id' };
    const json = jest.fn().mockResolvedValue(response);
    const identifier = { type: SignInIdentifier.Phone, value: '+8613800138000' } as const;
    mockedApiPost.mockReturnValueOnce({ json } as unknown as ReturnType<typeof api.post>);

    await expect(
      sendVerificationCode(InteractionEvent.SignIn, identifier, 'captcha-token')
    ).resolves.toEqual(response);

    expect(mockedApiPost).toHaveBeenCalledWith(
      `${experienceApiRoutes.verification}/verification-code`,
      {
        json: {
          interactionEvent: InteractionEvent.SignIn,
          identifier,
          captchaToken: 'captcha-token',
        },
      }
    );
    expect(json).toHaveBeenCalledTimes(1);
  });
});
