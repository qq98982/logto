/* eslint-disable @silverhand/fp/no-mutation -- Browser SDK stubs and the context probe require controlled test-only assignment. */
/* eslint-disable max-lines -- Provider lifecycle and adaptive Continue behavior share one SDK harness. */
import {
  CaptchaPolicyScope,
  CaptchaType,
  InteractionEvent,
  SignInIdentifier,
} from '@logto/schemas';
import { act, render, renderHook, waitFor } from '@testing-library/react';
import { HTTPError } from 'ky';
import { useContext } from 'react';
import { MemoryRouter } from 'react-router-dom';

import { mockSignInExperienceSettings } from '@/__mocks__/logto';
import { initInteraction, sendVerificationCode } from '@/apis/experience';
import CaptchaBox from '@/containers/CaptchaBox';
import useSendVerificationCode from '@/hooks/use-send-verification-code';
import { UserFlow, type SignInExperienceResponse } from '@/types';

import PageContextProvider from '../PageContextProvider';

import CaptchaContextProvider from '.';
import CaptchaContext, { type CaptchaContextType } from './CaptchaContext';
import {
  aliyunCaptchaButtonId,
  aliyunCaptchaElementId,
  aliyunCaptchaScriptUrl,
  scriptId,
} from './constant';

jest.mock('@/apis/experience', () => ({
  initInteraction: jest.fn(),
  sendVerificationCode: jest.fn(async () => ({ verificationId: 'verification-id' })),
}));

const mockedInitInteraction = jest.mocked(initInteraction);
const mockedSendVerificationCode = jest.mocked(sendVerificationCode);

const aliyunCaptchaConfig = {
  type: CaptchaType.Aliyun,
  region: 'cn',
  prefix: 'test-prefix',
  sceneId: 'phone-scene',
} as const;

const createSettings = (
  scope: CaptchaPolicyScope | undefined = CaptchaPolicyScope.PhoneVerificationCode,
  captchaConfig: SignInExperienceResponse['captchaConfig'] = aliyunCaptchaConfig
): SignInExperienceResponse => ({
  ...mockSignInExperienceSettings,
  captchaPolicy: { enabled: true, scope },
  captchaConfig,
});

type AliyunOptions = Parameters<NonNullable<Window['initAliyunCaptcha']>>[0];

const createAliyunInstance = (): AliyunCaptchaInstance => ({
  startTracelessVerification: jest.fn(),
  destroyCaptcha: jest.fn(),
});

const installAliyunSdk = (getInstance = true) => {
  const instances: AliyunCaptchaInstance[] = [];
  const initAliyunCaptcha = jest.fn((options: AliyunOptions) => {
    if (!getInstance) {
      return;
    }

    const instance = createAliyunInstance();
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- Record SDK-created instances for lifecycle assertions.
    instances.push(instance);
    options.getInstance(instance);
  });

  window.initAliyunCaptcha = initAliyunCaptcha;

  return { initAliyunCaptcha, instances };
};

const captchaApi: Pick<CaptchaContextType, 'executeCaptcha'> = {
  executeCaptcha: async () => 'uninitialized',
};

const ContextProbe = () => {
  captchaApi.executeCaptcha = useContext(CaptchaContext).executeCaptcha;

  return null;
};

const ProviderWrapper = ({
  settings,
  children,
}: {
  readonly settings: SignInExperienceResponse;
  readonly children?: React.ReactNode;
}) => (
  <MemoryRouter>
    <PageContextProvider preset={{ experienceSettings: settings }}>
      <CaptchaContextProvider>{children}</CaptchaContextProvider>
    </PageContextProvider>
  </MemoryRouter>
);

const renderProvider = (settings = createSettings()) =>
  render(
    <ProviderWrapper settings={settings}>
      <ContextProbe />
    </ProviderWrapper>
  );

const getLatestOptions = (initAliyunCaptcha: jest.Mock<void, [AliyunOptions]>) => {
  const options = initAliyunCaptcha.mock.calls.at(-1)?.[0];

  if (!options) {
    throw new Error('Alibaba CAPTCHA was not initialized');
  }

  return options;
};

const createRequestError = (code: string) => {
  const body = { code, message: code };
  const clonedResponse = {
    status: 422,
    statusText: 'Unprocessable Entity',
    json: async () => body,
  } as unknown as Response;
  const response = {
    status: 422,
    statusText: 'Unprocessable Entity',
    json: async () => body,
    clone: () => clonedResponse,
  } as unknown as Response;

  return new HTTPError(response, {} as Request, {} as never);
};

const renderSendHook = (flow: UserFlow, settings = createSettings()) =>
  renderHook(() => useSendVerificationCode(flow), {
    wrapper: ({ children }) => <ProviderWrapper settings={settings}>{children}</ProviderWrapper>,
  });

const submitPhone = (
  settings = createSettings(),
  flow: UserFlow.SignIn | UserFlow.Register = UserFlow.SignIn
) => {
  const rendered = renderSendHook(flow, settings);
  const submission = rendered.result.current.onSubmit({
    identifier: SignInIdentifier.Phone,
    value: '+8613800138000',
  });

  return { ...rendered, submission };
};

describe('CaptchaContextProvider Alibaba CAPTCHA', () => {
  afterEach(() => {
    jest.useRealTimers();
    jest.clearAllMocks();
    document.querySelector(`#${scriptId}`)?.remove();
    Reflect.deleteProperty(window, 'initAliyunCaptcha');
    Reflect.deleteProperty(window, 'AliyunCaptchaConfig');
    Reflect.deleteProperty(window, 'turnstile');
    document.body.textContent = '';
  });

  it('initializes the exact mainland popup contract once and renders hidden fixed targets', async () => {
    const instance = createAliyunInstance();
    const initAliyunCaptcha = jest.fn((options: AliyunOptions) => {
      expect(window.AliyunCaptchaConfig).toEqual({
        region: 'cn',
        prefix: aliyunCaptchaConfig.prefix,
      });
      options.getInstance(instance);
    });
    window.initAliyunCaptcha = initAliyunCaptcha;

    const { container } = renderProvider();

    await waitFor(() => {
      expect(initAliyunCaptcha).toHaveBeenCalledTimes(1);
    });

    const options = getLatestOptions(initAliyunCaptcha);
    expect(Object.keys(options).slice().sort()).toEqual(
      [
        'SceneId',
        'button',
        'delayBeforeSuccess',
        'element',
        'fail',
        'getInstance',
        'language',
        'mode',
        'onClose',
        'onError',
        'slideStyle',
        'success',
        'timeout',
      ]
        .slice()
        .sort()
    );
    /* eslint-disable @typescript-eslint/no-unsafe-assignment -- Jest asymmetric function matchers are intentionally untyped. */
    expect(options).toEqual({
      SceneId: aliyunCaptchaConfig.sceneId,
      mode: 'popup',
      element: `#${aliyunCaptchaElementId}`,
      button: `#${aliyunCaptchaButtonId}`,
      success: expect.any(Function),
      fail: expect.any(Function),
      getInstance: expect.any(Function),
      slideStyle: { width: 360, height: 40 },
      language: 'cn',
      timeout: 5000,
      onError: expect.any(Function),
      onClose: expect.any(Function),
      delayBeforeSuccess: false,
    });
    /* eslint-enable @typescript-eslint/no-unsafe-assignment */

    const scripts = document.querySelectorAll(`script#${scriptId}`);
    expect(scripts).toHaveLength(1);
    expect(scripts[0]?.getAttribute('src')).toBe(aliyunCaptchaScriptUrl);
    expect(container.querySelector(`#${aliyunCaptchaElementId}`)).not.toBeNull();
    expect(container.querySelector(`#${aliyunCaptchaButtonId}`)?.hasAttribute('hidden')).toBe(true);
    expect(container.textContent).not.toContain('captcha');
  });

  it('initializes first and passes one successful phone token only to the send POST', async () => {
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const token = 'captcha-verify-param';
    const { submission } = submitPhone();

    await waitFor(() => {
      expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    });

    await act(async () => {
      getLatestOptions(initAliyunCaptcha).success(token);
      getLatestOptions(initAliyunCaptcha).success('ignored-second-token');
      await submission;
    });

    expect(mockedInitInteraction).toHaveBeenCalledTimes(1);
    expect(mockedInitInteraction).toHaveBeenCalledWith(InteractionEvent.SignIn);
    expect(mockedSendVerificationCode).toHaveBeenCalledTimes(1);
    expect(mockedSendVerificationCode).toHaveBeenCalledWith(
      InteractionEvent.SignIn,
      {
        type: SignInIdentifier.Phone,
        value: '+8613800138000',
      },
      token
    );
    const [instance] = instances;
    if (!instance) {
      throw new TypeError('Expected Alibaba CAPTCHA to create an instance');
    }
    const startVerification = jest.mocked(instance.startTracelessVerification);
    expect(mockedInitInteraction.mock.invocationCallOrder[0]).toBeLessThan(
      startVerification.mock.invocationCallOrder[0] ?? 0
    );
    expect(startVerification.mock.invocationCallOrder[0]).toBeLessThan(
      mockedSendVerificationCode.mock.invocationCallOrder[0] ?? 0
    );
    expect(instances[0]?.destroyCaptcha).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toContain(token);
    expect(document.body.textContent).not.toContain('ignored-second-token');
  });

  it('skips CAPTCHA for email under phone verification scope and still sends email', async () => {
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const rendered = renderHook(() => useSendVerificationCode(UserFlow.SignIn), {
      wrapper: ({ children }) => (
        <ProviderWrapper settings={createSettings()}>{children}</ProviderWrapper>
      ),
    });

    await act(async () =>
      rendered.result.current.onSubmit({
        identifier: SignInIdentifier.Email,
        value: 'person@example.com',
      })
    );

    expect(initAliyunCaptcha).toHaveBeenCalledTimes(1);
    expect(instances[0]?.startTracelessVerification).not.toHaveBeenCalled();
    expect(mockedInitInteraction).toHaveBeenCalledWith(InteractionEvent.SignIn);
    expect(mockedSendVerificationCode).toHaveBeenCalledWith(InteractionEvent.SignIn, {
      type: SignInIdentifier.Email,
      value: 'person@example.com',
    });
  });

  it('sends a verified social Continue request once without executing CAPTCHA', async () => {
    const { instances } = installAliyunSdk();
    const rendered = renderSendHook(UserFlow.Continue);

    await act(async () =>
      rendered.result.current.onSubmit(
        { identifier: SignInIdentifier.Phone, value: '+8613800138000' },
        InteractionEvent.Register
      )
    );

    expect(mockedInitInteraction).not.toHaveBeenCalled();
    expect(mockedSendVerificationCode).toHaveBeenCalledTimes(1);
    expect(mockedSendVerificationCode).toHaveBeenCalledWith(
      InteractionEvent.Register,
      { type: SignInIdentifier.Phone, value: '+8613800138000' },
      undefined
    );
    expect(instances[0]?.startTracelessVerification).not.toHaveBeenCalled();
  });

  it('challenges a password Continue phone once and retries the same send with its token', async () => {
    mockedSendVerificationCode
      .mockRejectedValueOnce(createRequestError('session.captcha_required'))
      .mockResolvedValueOnce({ verificationId: 'continued-verification-id' });
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const rendered = renderSendHook(UserFlow.Continue);
    const submission = rendered.result.current.onSubmit(
      { identifier: SignInIdentifier.Phone, value: '+8613800138000' },
      InteractionEvent.SignIn
    );

    await waitFor(() => {
      expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    });
    await act(async () => {
      getLatestOptions(initAliyunCaptcha).success('continue-captcha-token');
      await submission;
    });

    expect(mockedInitInteraction).not.toHaveBeenCalled();
    expect(mockedSendVerificationCode).toHaveBeenCalledTimes(2);
    expect(mockedSendVerificationCode).toHaveBeenNthCalledWith(
      1,
      InteractionEvent.SignIn,
      { type: SignInIdentifier.Phone, value: '+8613800138000' },
      undefined
    );
    expect(mockedSendVerificationCode).toHaveBeenNthCalledWith(
      2,
      InteractionEvent.SignIn,
      { type: SignInIdentifier.Phone, value: '+8613800138000' },
      'continue-captcha-token'
    );
    expect(document.body.textContent).not.toContain('continue-captcha-token');
  });

  it('does not retry a Continue send when the requested challenge fails', async () => {
    mockedSendVerificationCode.mockRejectedValueOnce(
      createRequestError('session.captcha_required')
    );
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const rendered = renderSendHook(UserFlow.Continue);
    const submission = rendered.result.current.onSubmit(
      { identifier: SignInIdentifier.Phone, value: '+8613800138000' },
      InteractionEvent.SignIn
    );
    await waitFor(() => {
      expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    });
    act(() => {
      getLatestOptions(initAliyunCaptcha).fail({ code: 'FAIL' });
    });

    await expect(submission).resolves.toBeUndefined();
    expect(mockedSendVerificationCode).toHaveBeenCalledTimes(1);
    expect(mockedInitInteraction).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain('FAIL');
  });

  it('does not loop when the Continue retry token is rejected', async () => {
    mockedSendVerificationCode
      .mockRejectedValueOnce(createRequestError('session.captcha_required'))
      .mockRejectedValueOnce(createRequestError('session.captcha_failed'));
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const rendered = renderSendHook(UserFlow.Continue);
    const submission = rendered.result.current.onSubmit(
      { identifier: SignInIdentifier.Phone, value: '+8613800138000' },
      InteractionEvent.SignIn
    );

    await waitFor(() => {
      expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    });
    await act(async () => {
      getLatestOptions(initAliyunCaptcha).success('rejected-retry-token');
      await submission;
    });

    expect(mockedSendVerificationCode).toHaveBeenCalledTimes(2);
    expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toContain('rejected-retry-token');
  });

  it('can challenge and retry a global-scope Continue email send', async () => {
    mockedSendVerificationCode
      .mockRejectedValueOnce(createRequestError('session.captcha_required'))
      .mockResolvedValueOnce({ verificationId: 'continued-email-verification-id' });
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const rendered = renderSendHook(
      UserFlow.Continue,
      createSettings(CaptchaPolicyScope.Interaction)
    );
    const submission = rendered.result.current.onSubmit(
      { identifier: SignInIdentifier.Email, value: 'person@example.com' },
      InteractionEvent.Register
    );

    await waitFor(() => {
      expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    });
    await act(async () => {
      getLatestOptions(initAliyunCaptcha).success('global-email-captcha-token');
      await submission;
    });

    expect(mockedSendVerificationCode).toHaveBeenCalledTimes(2);
    expect(mockedSendVerificationCode).toHaveBeenLastCalledWith(
      InteractionEvent.Register,
      { type: SignInIdentifier.Email, value: 'person@example.com' },
      'global-email-captcha-token'
    );
  });

  it('preserves global CAPTCHA execution when scope is missing', async () => {
    const turnstileRender = jest.fn();
    window.turnstile = { render: turnstileRender };
    render(
      <ProviderWrapper
        settings={{
          ...createSettings(CaptchaPolicyScope.Interaction, {
            type: CaptchaType.Turnstile,
            siteKey: 'site-key',
          }),
          captchaPolicy: { enabled: true },
        }}
      >
        <CaptchaBox />
        <ContextProbe />
      </ProviderWrapper>
    );

    const promise = captchaApi.executeCaptcha();
    await waitFor(() => {
      expect(turnstileRender).toHaveBeenCalledTimes(1);
    });
    const callback = turnstileRender.mock.calls[0]?.[1].callback as (token: string) => void;
    callback('turnstile-token');

    await expect(promise).resolves.toBe('turnstile-token');
  });

  it('does not load or execute CAPTCHA when the policy is disabled', async () => {
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    renderProvider({
      ...createSettings(),
      captchaPolicy: { enabled: false, scope: CaptchaPolicyScope.PhoneVerificationCode },
    });

    await expect(captchaApi.executeCaptcha(SignInIdentifier.Phone)).resolves.toBeUndefined();
    expect(initAliyunCaptcha).not.toHaveBeenCalled();
    expect(instances).toHaveLength(0);
    expect(document.querySelector(`#${scriptId}`)).toBeNull();
  });

  it('destroys the prior instance and initializes a fresh instance for a second phone attempt', async () => {
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    renderProvider();

    const first = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    act(() => {
      getLatestOptions(initAliyunCaptcha).success('first-token');
    });
    await expect(first).resolves.toBe('first-token');

    const second = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    await waitFor(() => {
      expect(initAliyunCaptcha).toHaveBeenCalledTimes(2);
    });
    expect(instances[0]?.destroyCaptcha).toHaveBeenCalledTimes(1);
    expect(instances[1]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    act(() => {
      getLatestOptions(initAliyunCaptcha).success('second-token');
    });

    await expect(second).resolves.toBe('second-token');
    expect(instances[1]?.destroyCaptcha).toHaveBeenCalledTimes(1);
  });

  it.each([
    [
      'verification failure',
      (options: AliyunOptions) => {
        options.fail({ code: 'FAIL' });
      },
    ],
    [
      'SDK error',
      (options: AliyunOptions) => {
        options.onError({ code: 'LOAD_ERROR', msg: 'failed' });
      },
    ],
    [
      'user close',
      (options: AliyunOptions) => {
        options.onClose('userDismiss');
      },
    ],
    [
      'empty token',
      (options: AliyunOptions) => {
        options.success('');
      },
    ],
    [
      'oversized UTF-8 token',
      (options: AliyunOptions) => {
        options.success('界'.repeat(5462));
      },
    ],
  ])('initializes but aborts %s before calling the send API', async (_label, trigger) => {
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const { submission } = submitPhone();

    await waitFor(() => {
      expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    });
    act(() => {
      trigger(getLatestOptions(initAliyunCaptcha));
    });

    await expect(submission).resolves.toBeUndefined();
    expect(mockedInitInteraction).toHaveBeenCalledWith(InteractionEvent.SignIn);
    expect(mockedSendVerificationCode).not.toHaveBeenCalled();
    expect(instances[0]?.destroyCaptcha).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toContain('界');
  });

  it('keeps the initialized Register flow after an expected CAPTCHA failure without sending', async () => {
    const { initAliyunCaptcha, instances } = installAliyunSdk();
    const { submission } = submitPhone(createSettings(), UserFlow.Register);

    await waitFor(() => {
      expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    });
    act(() => {
      getLatestOptions(initAliyunCaptcha).onError({
        code: 'PRIVATE_CODE',
        msg: 'private provider detail',
      });
    });

    await expect(submission).resolves.toBeUndefined();
    expect(mockedInitInteraction).toHaveBeenCalledWith(InteractionEvent.Register);
    expect(mockedSendVerificationCode).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain('PRIVATE_CODE');
    expect(document.body.textContent).not.toContain('private provider detail');
  });

  it('rejects when the loaded script does not expose the SDK', async () => {
    const { submission } = submitPhone();
    await waitFor(() => {
      expect(mockedInitInteraction).toHaveBeenCalledWith(InteractionEvent.SignIn);
    });
    const script = document.querySelector<HTMLScriptElement>(`script#${scriptId}`);

    expect(script).not.toBeNull();
    await act(async () => {
      await Promise.resolve();
      script?.dispatchEvent(new Event('load'));
    });

    await expect(submission).resolves.toBeUndefined();
    expect(mockedSendVerificationCode).not.toHaveBeenCalled();
  });

  it('rejects a CAPTCHA initialization timeout after interaction init without sending', async () => {
    jest.useFakeTimers();
    installAliyunSdk(false);
    const { submission } = submitPhone();
    await act(async () => {
      await Promise.resolve();
      jest.advanceTimersByTime(5000);
    });

    await expect(submission).resolves.toBeUndefined();
    expect(mockedInitInteraction).toHaveBeenCalledWith(InteractionEvent.SignIn);
    expect(mockedSendVerificationCode).not.toHaveBeenCalled();
  });

  it('destroys an instance delivered after timeout and freshly initializes the retry', async () => {
    jest.useFakeTimers();
    const { initAliyunCaptcha } = installAliyunSdk(false);
    renderProvider();
    const first = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    const firstRejection = expect(first).rejects.toThrow('Alibaba CAPTCHA');

    await act(async () => {
      jest.advanceTimersByTime(5000);
    });
    await firstRejection;

    const staleInstance = createAliyunInstance();
    getLatestOptions(initAliyunCaptcha).getInstance(staleInstance);
    expect(staleInstance.destroyCaptcha).toHaveBeenCalledTimes(1);

    const second = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    expect(initAliyunCaptcha).toHaveBeenCalledTimes(2);
    const freshInstance = createAliyunInstance();
    getLatestOptions(initAliyunCaptcha).getInstance(freshInstance);
    expect(freshInstance.startTracelessVerification).toHaveBeenCalledTimes(1);

    act(() => {
      getLatestOptions(initAliyunCaptcha).success('retry-token');
    });
    await expect(second).resolves.toBe('retry-token');
  });

  it('does not apply the initialization timeout after an instance is ready', async () => {
    jest.useFakeTimers();
    const { initAliyunCaptcha } = installAliyunSdk(false);
    renderProvider();
    const promise = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    const settlement = jest.fn();
    // eslint-disable-next-line promise/prefer-await-to-then -- Observe that the promise remains pending while advancing fake timers.
    void promise.then(settlement, settlement);
    const instance = createAliyunInstance();

    getLatestOptions(initAliyunCaptcha).getInstance(instance);
    expect(instance.startTracelessVerification).toHaveBeenCalledTimes(1);
    await act(async () => {
      jest.advanceTimersByTime(6000);
    });

    expect(settlement).not.toHaveBeenCalled();
    expect(instance.destroyCaptcha).not.toHaveBeenCalled();
    act(() => {
      getLatestOptions(initAliyunCaptcha).success('slow-human-token');
    });
    await expect(promise).resolves.toBe('slow-human-token');
  });

  it('replaces a failed owned script once and succeeds on the next attempt', async () => {
    renderProvider();
    const failedScript = document.querySelector<HTMLScriptElement>(`script#${scriptId}`);
    const first = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    const firstRejection = expect(first).rejects.toThrow('Alibaba CAPTCHA');

    failedScript?.dispatchEvent(new Event('error'));
    await firstRejection;

    const second = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    const secondResolution = expect(second).resolves.toBe('retry-after-load-token');
    const replacementScript = document.querySelector<HTMLScriptElement>(`script#${scriptId}`);
    expect(replacementScript).not.toBe(failedScript);
    expect(document.querySelectorAll(`script#${scriptId}`)).toHaveLength(1);

    const { initAliyunCaptcha, instances } = installAliyunSdk();
    replacementScript?.dispatchEvent(new Event('load'));
    expect(initAliyunCaptcha).toHaveBeenCalledTimes(1);
    expect(instances[0]?.startTracelessVerification).toHaveBeenCalledTimes(1);
    getLatestOptions(initAliyunCaptcha).success('retry-after-load-token');

    await secondResolution;
    expect(document.querySelectorAll(`script#${scriptId}`)).toHaveLength(1);
  });

  it('never removes or replaces a CAPTCHA script it does not own', async () => {
    jest.useFakeTimers();
    const foreignScript = document.createElement('script');
    foreignScript.id = scriptId;
    foreignScript.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
    document.body.append(foreignScript);
    renderProvider();
    const first = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    const firstRejection = expect(first).rejects.toThrow('Alibaba CAPTCHA');

    await act(async () => {
      jest.advanceTimersByTime(5000);
    });
    await firstRejection;

    const second = captchaApi.executeCaptcha(SignInIdentifier.Phone);
    const secondRejection = expect(second).rejects.toThrow('Alibaba CAPTCHA');
    await act(async () => {
      jest.advanceTimersByTime(5000);
    });
    await secondRejection;

    expect(document.querySelectorAll(`script#${scriptId}`)).toHaveLength(1);
    expect(document.querySelector(`script#${scriptId}`)).toBe(foreignScript);
  });

  it('still rejects an unexpected CAPTCHA runtime failure', async () => {
    const unexpectedError = new Error('unexpected runtime detail');
    const instance = createAliyunInstance();
    jest.mocked(instance.startTracelessVerification).mockImplementationOnce(() => {
      throw unexpectedError;
    });
    window.initAliyunCaptcha = jest.fn((options: AliyunOptions) => {
      options.getInstance(instance);
    });
    const rendered = renderSendHook(UserFlow.SignIn);

    await expect(
      rendered.result.current.onSubmit({
        identifier: SignInIdentifier.Phone,
        value: '+8613800138000',
      })
    ).rejects.toBe(unexpectedError);
    expect(mockedInitInteraction).toHaveBeenCalledWith(InteractionEvent.SignIn);
    expect(mockedSendVerificationCode).not.toHaveBeenCalled();
    expect(document.body.textContent).not.toContain('unexpected runtime detail');
  });

  it('reuses and observes an SDK script that is still loading after a provider remount', () => {
    const firstRender = renderProvider();
    const script = document.querySelector<HTMLScriptElement>(`script#${scriptId}`);
    expect(script).not.toBeNull();
    firstRender.unmount();

    renderProvider();
    const { initAliyunCaptcha } = installAliyunSdk();
    act(() => {
      script?.dispatchEvent(new Event('load'));
    });

    expect(document.querySelectorAll(`script#${scriptId}`)).toHaveLength(1);
    expect(initAliyunCaptcha).toHaveBeenCalledTimes(1);
  });
});
/* eslint-enable @silverhand/fp/no-mutation */
/* eslint-enable max-lines */
