/**
 * Native SDK Utility Methods
 */
export const getAsterNativeSdk = () => {
  if (typeof asterNativeSdk !== 'undefined') {
    return asterNativeSdk;
  }
};

export const isNativeWebview = () => {
  const platform = getAsterNativeSdk()?.platform ?? '';

  return ['ios', 'android'].includes(platform);
};
