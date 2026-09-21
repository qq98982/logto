import i18next from 'i18next';
import ky from 'ky';

import { searchKeys } from '@/shared/utils/search-parameters';

export const attachAsterRequestHeaders = (request: Request) => {
  request.headers.set('Accept-Language', i18next.language);
  /**
   * Attach app ID to HTTP header in order to support client-specific interaction cookie
   * for Experience API requests. The header is used by the oidc-provider library to identify
   * the client, and hence the related interaction details.
   */
  const appId = sessionStorage.getItem(searchKeys.appId);
  if (appId) {
    request.headers.set('aster-app-id', appId);
  }
};

export default ky.extend({
  hooks: {
    beforeRequest: [attachAsterRequestHeaders],
  },
});
