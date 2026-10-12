import { parseWechatProviderCallback } from './wechat-provider-callback-client.js';

const parse = (callbackUrl: string) =>
  parseWechatProviderCallback({
    callbackUrl,
    expectedCallbackUrl: 'https://provider-client.example/callback',
    expectedState: 'owned-state',
  });

describe('WeChat provider callback client', () => {
  it('preserves validated provider state in an exact connector payload', () => {
    const result = parse(
      'https://provider-client.example/callback?state=owned-state&code=provider-code'
    );

    expect(result).toEqual({ code: 'provider-code', state: 'owned-state' });
    expect(Reflect.ownKeys(result)).toEqual(['code', 'state']);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it.each([
    'https://provider-client.example/callback?code=provider-code',
    'https://provider-client.example/callback?code=provider-code&state=',
    'https://provider-client.example/callback?code=provider-code&state=wrong',
    'https://provider-client.example/callback?code=one&code=two&state=owned-state',
    'https://provider-client.example/callback?code=provider-code&state=owned-state&app_id=client',
    'https://provider-client.example/callback?code=provider-code&state=owned-state&redirectUri=x',
    'https://foreign.example/callback?code=provider-code&state=owned-state',
    'https://provider-client.example/other?code=provider-code&state=owned-state',
    'https://provider-client.example/callback?code=provider-code&state=owned-state#fragment',
  ])('rejects callbacks outside the strict provider contract: %s', (callbackUrl) => {
    expect(() => parse(callbackUrl)).toThrow('Invalid WeChat provider callback');
  });
});
