import AsterBrand from '@/components/AsterBrand';

import styles from './index.module.scss';

function Topbar() {
  return (
    <div className={styles.topbar}>
      <AsterBrand />
    </div>
  );
}

export default Topbar;
