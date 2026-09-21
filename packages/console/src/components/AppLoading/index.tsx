import AsterBrand from '@/components/AsterBrand';
import { Daisy as Spinner } from '@/ds-components/Spinner';

import styles from './index.module.scss';

function AppLoading() {
  return (
    <div className={styles.container}>
      <AsterBrand className={styles.brand} />
      <Spinner />
    </div>
  );
}

export default AppLoading;
