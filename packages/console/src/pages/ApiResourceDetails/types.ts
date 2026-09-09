import type { Resource } from '@logto/schemas';

export type ApiResourceDetailsOutletContext = {
  resource: Resource;
  isDeleting: boolean;
  isManagementApiResource: boolean;
  onResourceUpdated: (resource: Resource) => void;
};
