import { asterDocumentationUrl } from '@/consts/env';
import { resolveAsterDocumentationLink } from '@/consts/external-links';

const useDocumentationUrl = () => {
  return {
    documentationSiteUrl: asterDocumentationUrl,
    getDocumentationUrl: resolveAsterDocumentationLink,
  };
};

export default useDocumentationUrl;
