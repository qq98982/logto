import { render, screen } from '@testing-library/react';

import AsterBrand from '.';

describe('<AsterBrand />', () => {
  it('renders the Aster fallback product name without an upstream logo asset', () => {
    const { container } = render(<AsterBrand className="test-brand" />);

    expect(screen.getByText('Aster').classList.contains('test-brand')).toBe(true);
    expect(container.querySelector('svg')).toBeNull();
  });
});
