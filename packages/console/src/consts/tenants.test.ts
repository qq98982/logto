import { defaultLogtoSku, mainTitle } from './tenants';

jest.mock('@/components/Region', () => ({
  defaultRegionName: 'US',
}));
jest.mock('./env', () => ({
  adminEndpoint: undefined,
  isCloud: false,
}));

describe('Aster Console identity', () => {
  it('uses Aster for the document title and built-in development plan', () => {
    expect(mainTitle).toBe('Aster Console');
    expect(defaultLogtoSku.name).toBe('Aster Development plan');
    expect(mainTitle).not.toContain('Logto');
    expect(defaultLogtoSku.name).not.toContain('Logto');
  });
});
