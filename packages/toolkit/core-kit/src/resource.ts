import { ReservedResource } from './openid.js';

export const managementApiResourceIndicator = 'urn:aster:resource:management';
export const accountApiResourceIndicator = 'urn:aster:resource:account';

type TenantManagementApiResourceIndicator = `${typeof managementApiResourceIndicator}:${string}`;
type GenericManagementApiResourceIndicator =
  `${typeof managementApiResourceIndicator}:${string}:${string}`;

export type ManagementApiResourceIndicator<
  TenantId extends string,
  Path extends string = 'api',
> = TenantId extends 'admin'
  ? Path extends 'me'
    ? typeof accountApiResourceIndicator
    : GenericManagementApiResourceIndicator
  : Path extends 'api'
    ? TenantId extends 'default'
      ? typeof managementApiResourceIndicator
      : TenantManagementApiResourceIndicator
    : GenericManagementApiResourceIndicator;

export function buildManagementApiResourceIndicator<TenantId extends string>(
  tenantId: TenantId
): ManagementApiResourceIndicator<TenantId>;
export function buildManagementApiResourceIndicator<TenantId extends string, Path extends string>(
  tenantId: TenantId,
  path: Path
): ManagementApiResourceIndicator<TenantId, Path>;
export function buildManagementApiResourceIndicator(tenantId: string, path = 'api') {
  if (tenantId.length === 0) {
    throw new TypeError('Tenant ID must not be empty.');
  }

  if (path.length === 0) {
    throw new TypeError('Path must not be empty.');
  }

  if (tenantId === 'admin' && path === 'me') {
    return accountApiResourceIndicator;
  }

  if (path === 'api' && tenantId === 'default') {
    return managementApiResourceIndicator;
  }

  const encodedTenantId = encodeURIComponent(tenantId);

  if (path === 'api') {
    return `${managementApiResourceIndicator}:${encodedTenantId}`;
  }

  return `${managementApiResourceIndicator}:${encodedTenantId}:${encodeURIComponent(path)}`;
}

const managementApiResourcePrefix = `${managementApiResourceIndicator}:`;

export const isManagementApiResourceIndicator = (indicator: string): boolean => {
  if (indicator === managementApiResourceIndicator) {
    return true;
  }

  if (!indicator.startsWith(managementApiResourcePrefix)) {
    return false;
  }

  const encodedTenantId = indicator.slice(managementApiResourcePrefix.length);

  if (encodedTenantId.length === 0 || encodedTenantId.includes(':')) {
    return false;
  }

  try {
    return encodeURIComponent(decodeURIComponent(encodedTenantId)) === encodedTenantId;
  } catch {
    return false;
  }
};

export const isAsterReservedResourceIndicator = (indicator: string): boolean =>
  indicator === managementApiResourceIndicator ||
  indicator.startsWith(managementApiResourcePrefix) ||
  indicator === accountApiResourceIndicator ||
  indicator === ReservedResource.Organization;
