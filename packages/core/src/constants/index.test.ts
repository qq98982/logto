import {
  idpInitiatedSamlSsoSessionCookieName,
  spInitiatedSamlSsoSessionCookieName,
} from './index.js';

describe('Aster generated Cookie namespace', () => {
  it('uses Aster prefixes for SAML interaction cookies', () => {
    expect(idpInitiatedSamlSsoSessionCookieName).toBe('_aster_idp_saml_sso_session_id');
    expect(spInitiatedSamlSsoSessionCookieName).toBe('_aster_sp_saml_sso_session_id');
  });
});
