import { searchKeys } from '@/shared/utils/search-parameters';

import { attachAsterRequestHeaders } from './api';

describe('Aster Experience request headers', () => {
  beforeEach(() => {
    sessionStorage.clear();
  });

  it('sends only the Aster application header for a stored client', () => {
    sessionStorage.setItem(searchKeys.appId, 'phase1-browser');
    const set = jest.fn();
    const request = { headers: { set } } as unknown as Request;

    attachAsterRequestHeaders(request);

    expect(set).toHaveBeenCalledWith('aster-app-id', 'phase1-browser');
    expect(set).not.toHaveBeenCalledWith('logto-app-id', expect.anything());
  });
});
