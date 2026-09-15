import { PhoneNumberParser } from '@logto/shared/universal';
import i18next from 'i18next';
import type { CountryCode, CountryCallingCode } from 'libphonenumber-js/mobile';
import { getCountries, getCountryCallingCode } from 'libphonenumber-js/mobile';
import timeZoneMetadata from 'moment-timezone/data/meta/latest.json';

export const fallbackCountryCode = 'US';
export const boxAiDefaultPhoneCountryKey = 'boxAiDefaultPhoneCountry';

export const countryCallingCodeMap: Partial<Record<string, CountryCode>> = {
  zh: 'CN',
  en: 'US',
  ja: 'JP',
  ko: 'KR',
};

export type DefaultCountrySignals = {
  readonly deploymentCountry?: string;
  readonly timeZone?: string;
  readonly language?: string;
};

const timeZoneCountriesByName: Readonly<Record<string, { readonly countries: readonly string[] }>> =
  timeZoneMetadata.zones;

export const isValidCountryCode = (countryCode: string): countryCode is CountryCode => {
  try {
    // Use getCountryCallingCode method to guard the input's value is in CountryCode union type, if type not match exceptions are expected
    // eslint-disable-next-line no-restricted-syntax
    getCountryCallingCode(countryCode as CountryCode);

    return true;
  } catch {
    return false;
  }
};

const countryFromLanguage = (language: string | undefined): CountryCode | undefined => {
  // Extract the country code from language tag suffix
  const [languageCode, countryCode] = language?.split('-') ?? [];

  if (countryCode && isValidCountryCode(countryCode)) {
    return countryCode;
  }

  const upperCaseLanguageCode = languageCode?.toUpperCase();

  if (upperCaseLanguageCode && isValidCountryCode(upperCaseLanguageCode)) {
    return upperCaseLanguageCode;
  }

  return languageCode ? countryCallingCodeMap[languageCode.toLowerCase()] : undefined;
};

const countriesForTimeZone = (timeZone: string | undefined): CountryCode[] => {
  if (!timeZone) {
    return [];
  }

  const zone = timeZoneCountriesByName[timeZone];

  return zone ? zone.countries.filter((country) => isValidCountryCode(country)) : [];
};

const browserTimeZone = () => {
  try {
    return new Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {}
};

export const resolveDefaultCountryCode = ({
  deploymentCountry,
  timeZone,
  language,
}: DefaultCountrySignals): CountryCode => {
  const normalizedDeploymentCountry = deploymentCountry?.toUpperCase();
  if (normalizedDeploymentCountry && isValidCountryCode(normalizedDeploymentCountry)) {
    return normalizedDeploymentCountry;
  }

  const languageCountry = countryFromLanguage(language);
  const timeZoneCountries = countriesForTimeZone(timeZone);
  const [primaryTimeZoneCountry] = timeZoneCountries;

  if (primaryTimeZoneCountry) {
    return primaryTimeZoneCountry;
  }

  return languageCountry ?? fallbackCountryCode;
};

export const getDefaultCountryCode = (signals: DefaultCountrySignals = {}): CountryCode =>
  resolveDefaultCountryCode({
    deploymentCountry: signals.deploymentCountry,
    timeZone: signals.timeZone ?? browserTimeZone(),
    language: signals.language ?? i18next.language,
  });

export const getDefaultCountryCallingCode = (signals?: DefaultCountrySignals) =>
  getCountryCallingCode(getDefaultCountryCode(signals));

/**
 * Provide Country Code Options
 */
export type CountryMetaData = {
  countryCode: CountryCode;
  countryCallingCode: CountryCallingCode;
};

export const getCountryList = (defaultCountryCode = getDefaultCountryCode()): CountryMetaData[] => {
  const defaultCountryCallingCode = getCountryCallingCode(defaultCountryCode);

  const countryList = getCountries()
    .map((code) => ({
      countryCode: code,
      countryCallingCode: getCountryCallingCode(code),
    }))
    // Filter the detected default countryCode & duplicates
    .filter(({ countryCallingCode }, index, self) => {
      if (countryCallingCode === defaultCountryCallingCode) {
        return false;
      }

      return (
        self.findIndex((element) => element.countryCallingCode === countryCallingCode) === index
      );
    })
    .slice()
    // Sort by countryCallingCode
    .sort((previous, next) => (next.countryCallingCode > previous.countryCallingCode ? -1 : 1));

  return [
    {
      countryCode: defaultCountryCode,
      countryCallingCode: defaultCountryCallingCode,
    },
    ...countryList,
  ];
};

export const formatPhoneNumberWithCountryCallingCode = (number: string) => {
  try {
    const phoneNumber = PhoneNumberParser.parse(number);

    return `+${phoneNumber.countryCallingCode} ${phoneNumber.nationalNumber}`;
  } catch {
    return number;
  }
};

export const parsePhoneNumber = (value: string) => {
  try {
    const phoneNumber = PhoneNumberParser.parse(value);

    return {
      countryCallingCode: phoneNumber.countryCallingCode,
      nationalNumber: phoneNumber.nationalNumber,
    };
  } catch {}
};
