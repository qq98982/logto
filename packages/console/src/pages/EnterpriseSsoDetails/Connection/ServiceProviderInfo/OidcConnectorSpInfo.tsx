import { useContext } from 'react';
import { useTranslation } from 'react-i18next';

import { AppDataContext } from '@/contexts/AppDataProvider';
import CopyToClipboard from '@/ds-components/CopyToClipboard';
import FormField from '@/ds-components/FormField';
import useAvailableDomains from '@/hooks/use-available-domains';
import { applyDomain } from '@/utils/url';

import styles from './ConnectorSpInfo.module.scss';

type Props = {
  readonly ssoConnectorId: string;
};

function OidcConnectorSpInfo({ ssoConnectorId }: Props) {
  const { t } = useTranslation(undefined, { keyPrefix: 'admin_console' });
  const { tenantEndpoint } = useContext(AppDataContext);
  const availableDomains = useAvailableDomains();

  return (
    <FormField
      title="enterprise_sso.basic_info.oidc.redirect_uri_field_name"
      tip={() => <p>{t('enterprise_sso.basic_info.oidc.redirect_uri_field_description')}</p>}
    >
      {/* Generated and passed in by Admin console. */}
      <div className={styles.uriContent}>
        {availableDomains.map((domain) => (
          <CopyToClipboard
            key={domain}
            displayType="block"
            variant="border"
            value={applyDomain(
              new URL(`/callback/${ssoConnectorId}`, tenantEndpoint).toString(),
              domain
            )}
          />
        ))}
      </div>
    </FormField>
  );
}

export default OidcConnectorSpInfo;
