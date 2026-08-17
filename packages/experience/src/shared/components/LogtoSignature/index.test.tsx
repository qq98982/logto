import { Theme } from '@logto/schemas';
import { render } from '@testing-library/react';

import LogtoSignature from '.';

describe('<LogtoSignature />', () => {
  it('does not render infrastructure branding in the hosted experience', () => {
    const { container } = render(<LogtoSignature theme={Theme.Light} />);

    expect(container.childElementCount).toBe(0);
  });
});
