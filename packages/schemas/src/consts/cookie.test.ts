import { describe, expect, it } from 'vitest';

import { deviceFlowXsrfCookieKey, logtoCookieKey } from './cookie.js';

describe('Aster Cookie namespace', () => {
  it('uses only Aster names for shared and generated cookies', () => {
    expect(logtoCookieKey).toBe('_aster');
    expect(deviceFlowXsrfCookieKey).toBe('_aster_device_flow_xsrf');
  });
});
