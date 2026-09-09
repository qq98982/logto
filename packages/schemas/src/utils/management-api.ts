import { isManagementApiResourceIndicator } from '@logto/core-kit';

export const isManagementApi = (indicator: string) => isManagementApiResourceIndicator(indicator);
