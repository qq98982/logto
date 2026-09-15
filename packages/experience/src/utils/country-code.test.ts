import i18next from 'i18next';

import {
  isValidCountryCode,
  getDefaultCountryCode,
  getDefaultCountryCallingCode,
  getCountryList,
  formatPhoneNumberWithCountryCallingCode,
  resolveDefaultCountryCode,
} from './country-code';

describe('country-code', () => {
  void i18next.init();

  it('isValidCountryCode', () => {
    expect(isValidCountryCode('CN')).toBeTruthy();
    expect(isValidCountryCode('xy')).toBeFalsy();
  });

  it('getDefaultCountryCode', async () => {
    await i18next.changeLanguage('zh');

    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('CN');

    await i18next.changeLanguage('en');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('US');

    await i18next.changeLanguage('zh-CN');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('CN');

    await i18next.changeLanguage('zh-TW');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('TW');

    await i18next.changeLanguage('en-US');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('US');

    await i18next.changeLanguage('en-CA');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('CA');

    await i18next.changeLanguage('ru');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('RU');

    await i18next.changeLanguage('ja');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('JP');

    await i18next.changeLanguage('ko');
    expect(getDefaultCountryCode({ timeZone: 'Etc/UTC' })).toEqual('KR');
  });

  it('getDefaultCountryCallingCode', async () => {
    await i18next.changeLanguage('zh');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('86');

    await i18next.changeLanguage('en');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('1');

    await i18next.changeLanguage('zh-CN');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('86');

    await i18next.changeLanguage('zh-TW');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('886');

    await i18next.changeLanguage('en-US');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('1');

    await i18next.changeLanguage('en-CA');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('1');

    await i18next.changeLanguage('ru');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('7');

    await i18next.changeLanguage('ja');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('81');

    await i18next.changeLanguage('ko');
    expect(getDefaultCountryCallingCode({ timeZone: 'Etc/UTC' })).toEqual('82');
  });

  it('resolves deployment, timezone, language, and fallback in priority order', () => {
    expect(
      resolveDefaultCountryCode({
        deploymentCountry: 'CN',
        timeZone: 'America/Los_Angeles',
        language: 'en-US',
      })
    ).toBe('CN');
    expect(resolveDefaultCountryCode({ timeZone: 'Asia/Tokyo', language: 'en-US' })).toBe('JP');
    expect(resolveDefaultCountryCode({ timeZone: 'America/Toronto', language: 'en-US' })).toBe(
      'CA'
    );
    expect(resolveDefaultCountryCode({ timeZone: 'Etc/UTC', language: 'zh-TW' })).toBe('TW');
    expect(
      resolveDefaultCountryCode({
        deploymentCountry: 'invalid',
        timeZone: 'invalid',
        language: 'invalid',
      })
    ).toBe('US');
  });

  it('accepts an explicit country when ordering the country list', () => {
    const countryList = getCountryList('CN');

    expect(countryList[0]).toEqual({
      countryCode: 'CN',
      countryCallingCode: '86',
    });
    expect(countryList.filter(({ countryCallingCode }) => countryCallingCode === '1')).toHaveLength(
      1
    );
  });

  it('getCountryList should sort properly', async () => {
    await i18next.changeLanguage('zh');
    const countryList = getCountryList('CN');

    expect(countryList[0]).toEqual({
      countryCode: 'CN',
      countryCallingCode: '86',
    });

    expect(countryList[1]?.countryCallingCode).toEqual('1');
  });

  it('getCountryList should remove duplicate', async () => {
    await i18next.changeLanguage('zh');
    const countryList = getCountryList('CN');

    expect(countryList.filter(({ countryCallingCode }) => countryCallingCode === '1')).toHaveLength(
      1
    );
    expect(countryList[0]?.countryCallingCode).toEqual('86');
  });

  it('formatPhoneNumberWithCountryCallingCode', async () => {
    expect(formatPhoneNumberWithCountryCallingCode('18888888888')).toBe('+1 8888888888');
    expect(formatPhoneNumberWithCountryCallingCode('8618888888888')).toBe('+86 18888888888');
  });
});
