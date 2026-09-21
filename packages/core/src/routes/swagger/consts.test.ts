import { managementApiAuthDescription } from './consts.js';

describe('Management API authentication documentation', () => {
  it('uses the Aster Management resource without an upstream resource alias', () => {
    expect(managementApiAuthDescription).toContain('Aster Management API');
    expect(managementApiAuthDescription).toContain(
      'The default tenant uses `urn:aster:resource:management`.'
    );
    expect(managementApiAuthDescription).toContain(
      'Non-default tenants use `urn:aster:resource:management:<encoded-tenant-id>`, where `<encoded-tenant-id>` is the tenant ID encoded with `encodeURIComponent`.'
    );
    expect(managementApiAuthDescription).toContain(
      "--data-urlencode 'resource=[management-api-resource]'"
    );
    expect(managementApiAuthDescription).not.toContain('Logto Management API');
    expect(managementApiAuthDescription).not.toContain(
      "--data-urlencode 'resource=https://[tenant-id].logto.app/api'"
    );
  });
});
