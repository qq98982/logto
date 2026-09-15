import { getCountryCallingCode } from 'libphonenumber-js/mobile';
import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';

import { useSieMethods } from '@/hooks/use-sie';
import {
  boxAiDefaultPhoneCountryKey,
  getCountryList,
  getDefaultCountryCode,
} from '@/utils/country-code';

const usePhoneCountryDefaults = () => {
  const { i18n } = useTranslation();
  const { customContent } = useSieMethods();
  const deploymentCountry = customContent?.[boxAiDefaultPhoneCountryKey];

  return useMemo(() => {
    const countryCode = getDefaultCountryCode({
      deploymentCountry,
      language: i18n.language,
    });

    return {
      countryCode,
      countryCallingCode: getCountryCallingCode(countryCode),
      countryList: getCountryList(countryCode),
    };
  }, [deploymentCountry, i18n.language]);
};

export default usePhoneCountryDefaults;
