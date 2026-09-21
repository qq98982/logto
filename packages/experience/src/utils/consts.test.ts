import { layoutClassNames } from './consts';

test('layout markers use the Aster DOM namespace', () => {
  expect(layoutClassNames).toEqual({
    pageContainer: 'aster_page-container',
    mainContent: 'aster_main-content',
    customContent: 'aster_custom-content',
    signature: 'aster_signature',
    brandingHeader: 'aster_branding-header',
  });
});
