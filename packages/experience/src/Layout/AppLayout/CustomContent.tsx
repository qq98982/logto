import { useLocation } from 'react-router-dom';

import { useSieMethods } from '@/hooks/use-sie';

type Props = {
  readonly className?: string;
};

const CustomContent = ({ className }: Props) => {
  const { customContent } = useSieMethods();
  const { pathname } = useLocation();

  const customHtml = customContent?.[pathname];

  if (!customHtml) {
    return null;
  }

  try {
    // Expected error; custom content is loaded from the Aster server.
    // eslint-disable-next-line react/no-danger
    return <div dangerouslySetInnerHTML={{ __html: customHtml }} className={className} />;
  } catch {
    return null;
  }
};

export default CustomContent;
