import classNames from 'classnames';
import { useTranslation } from 'react-i18next';

import AsterBrand from '@/components/AsterBrand';
import Spacer from '@/ds-components/Spacer';
import useTenantPathname from '@/hooks/use-tenant-pathname';

import UserInfo from './UserInfo';
import styles from './index.module.scss';

type Props = {
  readonly className?: string;
  /* eslint-disable react/boolean-prop-naming */
  readonly hideTitle?: boolean;
  /* eslint-enable react/boolean-prop-naming */
};

function Topbar({ className, hideTitle }: Props) {
  const { t } = useTranslation(undefined, { keyPrefix: 'admin_console' });
  const { navigate } = useTenantPathname();

  return (
    <div className={classNames(styles.topbar, className)}>
      <button
        type="button"
        className={styles.brandButton}
        aria-label="Aster home"
        onClick={() => {
          navigate('/');
        }}
      >
        <AsterBrand />
      </button>
      {!hideTitle && (
        <>
          <div className={styles.line} />
          <div className={styles.text}>{t('title')}</div>
        </>
      )}
      <Spacer />
      <UserInfo />
    </div>
  );
}

export default Topbar;
