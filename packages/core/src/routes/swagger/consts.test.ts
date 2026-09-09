import { managementApiAuthDescription } from './consts.js';

describe('Management API authentication documentation', () => {
  it('uses the Aster Management resource without an upstream resource alias', () => {
    expect(managementApiAuthDescription).toContain('Aster Management API');
    expect(managementApiAuthDescription).toContain(
      "--data-urlencode 'resource=urn:aster:resource:management'"
    );
    expect(managementApiAuthDescription).not.toContain('Logto Management API');
    expect(managementApiAuthDescription).not.toContain(
      "--data-urlencode 'resource=https://[tenant-id].logto.app/api'"
    );
  });
});
