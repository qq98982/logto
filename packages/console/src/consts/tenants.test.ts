import { defaultSku, mainTitle } from './tenants';

jest.mock('./env', () => ({
  adminEndpoint: undefined,
}));

describe('Aster Console identity', () => {
  it('uses Aster for the document title and built-in development plan', () => {
    expect(mainTitle).toBe('Aster Console');
    expect(defaultSku.name).toBe('Aster Development plan');
    expect(mainTitle).not.toContain('Logto');
    expect(defaultSku.name).not.toContain('Logto');
  });
});
