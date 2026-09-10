import { useEffect, useState } from 'react';

import styles from './App.module.scss';

export const useIsDarkMode = () => {
  const [isDarkMode, setIsDarkMode] = useState(
    window.matchMedia('(prefers-color-scheme: dark)').matches
  );

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (event: MediaQueryListEvent) => {
      setIsDarkMode(event.matches);
    };
    mediaQuery.addEventListener('change', handler);
    return () => {
      mediaQuery.removeEventListener('change', handler);
    };
  }, []);

  return isDarkMode;
};

const Footer = () => (
  <div className={styles.footerContainer}>
    <span className={styles.footer}>Aster</span>
  </div>
);

export default Footer;
