import { GoogleConnector } from '@logto/connector-kit';
import type { ConnectorMetadata, ExperienceSocialConnector } from '@logto/schemas';
import { ConnectorPlatform } from '@logto/schemas';
import { getCookie } from 'tiny-cookie';

import { SearchParameters } from '@/types';
import { getLogtoNativeSdk, isNativeWebview } from '@/utils/native-sdk';

import {
  filterSocialConnectors,
  filterPreviewSocialConnectors,
  buildSocialLandingUri,
  validateState,
  validateGoogleOneTapCredential,
} from './social-connectors';

const mockConnectors = [
  { platform: 'Web', target: 'facebook' },
  { platform: 'Web', target: 'google' },
  { platform: 'Universal', target: 'facebook' },
  { platform: 'Universal', target: 'wechat' },
  { platform: 'Native', target: 'wechat' },
  { platform: 'Native', target: 'alipay' },
] as ConnectorMetadata[];

const wechatWebConnector: ExperienceSocialConnector = {
  id: 'wechat-web-instance',
  target: 'wechat',
  platform: ConnectorPlatform.Web,
  name: { en: 'WeChat Web' },
  logo: '/wechat-web.svg',
  logoDark: null,
};

const wechatNativeConnector: ExperienceSocialConnector = {
  id: 'wechat-native-instance',
  target: 'wechat',
  platform: ConnectorPlatform.Native,
  name: { en: 'WeChat Native' },
  logo: '/wechat-native.svg',
  logoDark: null,
};

const wechatH5Connector: ExperienceSocialConnector = {
  id: 'wechat-h5-instance',
  target: 'wechat',
  platform: ConnectorPlatform.Universal,
  name: { en: 'WeChat Official Account' },
  logo: '/wechat-h5.svg',
  logoDark: null,
};

const wechatMiniConnector: ExperienceSocialConnector = {
  id: 'wechat-mini-instance',
  target: 'wechat',
  platform: null,
  name: { en: 'WeChat Mini Program' },
  logo: '/wechat-mini.svg',
  logoDark: null,
};

// These all-four fixtures are valid only because the Box provisioner separately enforces
// mini/native => web; these tests pin filtering only when all four coexist.
const wechatConnectorOrders = [
  {
    name: 'Mini before Web',
    connectors: [wechatMiniConnector, wechatH5Connector, wechatNativeConnector, wechatWebConnector],
  },
  {
    name: 'Web before Mini',
    connectors: [wechatWebConnector, wechatNativeConnector, wechatH5Connector, wechatMiniConnector],
  },
];

jest.mock('@/utils/native-sdk', () => ({
  isNativeWebview: jest.fn(),
  getLogtoNativeSdk: jest.fn(),
}));

// Mock tiny-cookie for new tests
jest.mock('tiny-cookie', () => ({
  getCookie: jest.fn(),
}));

const getLogtoNativeSdkMock = getLogtoNativeSdk as jest.Mock;
const isNativeWebviewMock = isNativeWebview as jest.Mock;
const getCookieMock = getCookie as jest.Mock;

describe('filterSocialConnectors', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetAllMocks();
  });

  it('undefined input should return empty list', () => {
    expect(filterSocialConnectors()).toEqual([]);
  });

  it('filter Web Connectors', () => {
    isNativeWebviewMock.mockImplementation(() => false);
    expect(filterSocialConnectors(mockConnectors)).toEqual([
      { platform: 'Web', target: 'facebook' },
      { platform: 'Web', target: 'google' },
      { platform: 'Universal', target: 'wechat' },
    ]);
  });

  it('Native Platform should return empty if not getPostMessage method is injected', () => {
    isNativeWebviewMock.mockImplementation(() => true);
    getLogtoNativeSdkMock.mockImplementation(() => ({
      supportedConnector: {
        universal: true,
        nativeTargets: ['wechat', 'alipay'],
      },
    }));

    expect(filterSocialConnectors(mockConnectors)).toEqual([]);
  });

  it('filter Native & Universal  Connectors', () => {
    isNativeWebviewMock.mockImplementation(() => true);
    getLogtoNativeSdkMock.mockImplementation(() => ({
      supportedConnector: {
        universal: true,
        nativeTargets: ['wechat'],
      },
      getPostMessage: jest.fn(),
      callbackLink: 'logto://callback',
    }));

    expect(filterSocialConnectors(mockConnectors)).toEqual([
      { platform: 'Universal', target: 'facebook' },
      { platform: 'Native', target: 'wechat' },
    ]);
  });

  it('filter Native & Universal Connectors with out callbackLink should only return native connectors', () => {
    isNativeWebviewMock.mockImplementation(() => true);
    getLogtoNativeSdkMock.mockImplementation(() => ({
      supportedConnector: {
        universal: true,
        nativeTargets: ['wechat'],
      },
      getPostMessage: jest.fn(),
    }));

    expect(filterSocialConnectors(mockConnectors)).toEqual([
      { platform: 'Native', target: 'wechat' },
    ]);
  });

  it('filter Native Connectors', () => {
    isNativeWebviewMock.mockImplementation(() => true);
    getLogtoNativeSdkMock.mockImplementation(() => ({
      platform: 'ios',
      supportedConnector: {
        universal: false,
        nativeTargets: ['wechat'],
      },
      getPostMessage: jest.fn(),
    }));

    expect(filterSocialConnectors(mockConnectors)).toEqual([
      { platform: 'Native', target: 'wechat' },
    ]);
  });
});

describe('filterPreviewSocialConnectors', () => {
  afterEach(() => {
    jest.clearAllMocks();
    jest.resetAllMocks();
  });

  it('undefined input should return empty list', () => {
    expect(filterPreviewSocialConnectors(ConnectorPlatform.Native)).toEqual([]);
    expect(filterPreviewSocialConnectors(ConnectorPlatform.Web)).toEqual([]);
  });

  it('filter Web Connectors', () => {
    expect(filterPreviewSocialConnectors(ConnectorPlatform.Web, mockConnectors)).toEqual([
      { platform: 'Web', target: 'facebook' },
      { platform: 'Web', target: 'google' },
      { platform: 'Universal', target: 'wechat' },
    ]);
  });

  it('filter Native Connectors', () => {
    expect(filterPreviewSocialConnectors(ConnectorPlatform.Native, mockConnectors)).toEqual([
      { platform: 'Universal', target: 'facebook' },
      { platform: 'Native', target: 'wechat' },
      { platform: 'Native', target: 'alipay' },
    ]);
  });
});

describe.each(wechatConnectorOrders)(
  'WeChat shared-target filtering with mini/native => web provisioner invariant: $name',
  ({ connectors }) => {
    afterEach(() => {
      jest.clearAllMocks();
      jest.resetAllMocks();
    });

    it('selects exactly Web in a browser', () => {
      isNativeWebviewMock.mockReturnValue(false);

      const result = filterSocialConnectors(connectors);

      expect(result).toEqual([wechatWebConnector]);
      expect(result).not.toContain(wechatH5Connector);
      expect(result).not.toContain(wechatMiniConnector);
      expect(result).not.toContain(wechatNativeConnector);
    });

    it('selects exactly Native with a valid native SDK bridge', () => {
      isNativeWebviewMock.mockReturnValue(true);
      getLogtoNativeSdkMock.mockReturnValue({
        platform: 'ios',
        supportedConnector: {
          universal: true,
          nativeTargets: ['wechat'],
        },
        getPostMessage: jest.fn(),
        callbackLink: 'logto://callback',
      });

      const result = filterSocialConnectors(connectors);

      expect(result).toEqual([wechatNativeConnector]);
      expect(result).not.toContain(wechatH5Connector);
      expect(result).not.toContain(wechatMiniConnector);
      expect(result).not.toContain(wechatWebConnector);
    });

    it('selects Web and Native for their respective previews, never Mini', () => {
      const webResult = filterPreviewSocialConnectors(ConnectorPlatform.Web, connectors);
      const nativeResult = filterPreviewSocialConnectors(ConnectorPlatform.Native, connectors);

      expect(webResult).toEqual([wechatWebConnector]);
      expect(webResult).not.toContain(wechatH5Connector);
      expect(webResult).not.toContain(wechatMiniConnector);
      expect(webResult).not.toContain(wechatNativeConnector);
      expect(nativeResult).toEqual([wechatNativeConnector]);
      expect(nativeResult).not.toContain(wechatH5Connector);
      expect(nativeResult).not.toContain(wechatMiniConnector);
      expect(nativeResult).not.toContain(wechatWebConnector);
    });
  }
);

describe('buildSocialLandingUri', () => {
  it('buildSocialLandingUri', () => {
    getLogtoNativeSdkMock.mockImplementation(() => ({
      platform: 'ios',
      callbackLink: 'logto://callback',
    }));

    const redirectUri = 'https://www.example.com/callback';
    const socialLandingPath = '/social/landing';
    const callbackUri = buildSocialLandingUri(socialLandingPath, redirectUri);

    expect(callbackUri.pathname).toEqual(socialLandingPath);
    expect(callbackUri.searchParams.get(SearchParameters.RedirectTo)).toEqual(redirectUri);
    expect(callbackUri.searchParams.get(SearchParameters.NativeCallbackLink)).toEqual(
      'logto://callback'
    );
  });
});

describe('validateState', () => {
  const mockConnectorId = 'test-connector-id';
  const mockState = 'test-state';

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should return match when state matches stored value', () => {
    const mockGetItem = jest.spyOn(Storage.prototype, 'getItem').mockReturnValue(mockState);
    const mockRemoveItem = jest.spyOn(Storage.prototype, 'removeItem').mockImplementation();

    expect(validateState(mockState, mockConnectorId)).toBe('match');
    expect(mockGetItem).toHaveBeenCalledWith(`social_auth_state:${mockConnectorId}`);
    expect(mockRemoveItem).toHaveBeenCalledWith(`social_auth_state:${mockConnectorId}`);

    mockGetItem.mockRestore();
    mockRemoveItem.mockRestore();
  });

  it('should return mismatch when state differs from stored value', () => {
    const mockGetItem = jest.spyOn(Storage.prototype, 'getItem').mockReturnValue('different-state');
    const mockRemoveItem = jest.spyOn(Storage.prototype, 'removeItem').mockImplementation();

    expect(validateState(mockState, mockConnectorId)).toBe('mismatch');

    mockGetItem.mockRestore();
    mockRemoveItem.mockRestore();
  });

  it('should return missing when no stored value exists', () => {
    const mockGetItem = jest.spyOn(Storage.prototype, 'getItem').mockReturnValue(null);
    const mockRemoveItem = jest.spyOn(Storage.prototype, 'removeItem').mockImplementation();

    expect(validateState(mockState, mockConnectorId)).toBe('missing');

    mockGetItem.mockRestore();
    mockRemoveItem.mockRestore();
  });
});

describe('validateGoogleOneTapCredential', () => {
  const mockParams = { [GoogleConnector.oneTapParams.csrfToken]: 'test-csrf' };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('External credentials', () => {
    it('should return valid for external credentials', () => {
      const result = validateGoogleOneTapCredential({
        isExternalCredential: true,
        params: mockParams,
      });

      expect(result).toEqual({ valid: true });
      expect(getCookieMock).not.toHaveBeenCalled();
    });
  });

  describe('Experience app (non-external)', () => {
    it('should return valid when CSRF token matches', () => {
      getCookieMock.mockReturnValue('test-csrf');

      const result = validateGoogleOneTapCredential({
        isExternalCredential: false,
        params: mockParams,
      });

      expect(result).toEqual({ valid: true });
      expect(getCookieMock).toHaveBeenCalledWith(GoogleConnector.oneTapParams.csrfToken);
    });

    it('should return invalid when CSRF token does not match', () => {
      getCookieMock.mockReturnValue('different-csrf');

      const result = validateGoogleOneTapCredential({
        isExternalCredential: false,
        params: mockParams,
      });

      expect(result).toEqual({ valid: false, error: 'invalid_connector_auth' });
    });

    it('should return invalid when CSRF token is missing from params', () => {
      const result = validateGoogleOneTapCredential({
        isExternalCredential: false,
        params: {},
      });

      expect(result).toEqual({ valid: false, error: 'invalid_connector_auth' });
    });
  });
});
