import classNames from 'classnames';

import styles from './index.module.scss';

type Props = {
  readonly className?: string;
};

function AsterBrand({ className }: Props) {
  return <span className={classNames(styles.brand, className)}>Aster</span>;
}

export default AsterBrand;
