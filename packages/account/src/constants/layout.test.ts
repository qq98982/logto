import { layoutClassNames } from './layout';

describe('Account Center layout class names', () => {
  it('uses only the Aster stable DOM namespace', () => {
    const classNames = Object.values(layoutClassNames);

    expect(classNames.length).toBeGreaterThan(0);
    expect(classNames.every((className) => className.startsWith('aster_ac-'))).toBe(true);
    expect(classNames.some((className) => className.startsWith('logto_ac-'))).toBe(false);
  });
});
