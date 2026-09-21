import type { ProtocolRequestOptions, RawProtocolResponse } from './oidc.js';
import { OidcClient, ProtocolClientError, protocolHeaderPairs } from './oidc.js';

export type ManagementRequestOptions = ProtocolRequestOptions &
  Readonly<{ authenticated?: boolean }>;

export class ManagementClient extends OidcClient {
  async requestManagement(
    operation: string,
    path: string,
    options: ManagementRequestOptions = {}
  ): Promise<RawProtocolResponse> {
    const prepared = this.prepareRequest(operation, path);
    const { authenticated = true, ...requestOptions } = options;
    const suppliedHeaders = (() => {
      try {
        return protocolHeaderPairs(options.headers);
      } catch {
        throw new ProtocolClientError(operation);
      }
    })();

    if (suppliedHeaders.some(([name]) => name.toLowerCase() === 'authorization')) {
      throw new ProtocolClientError(operation);
    }
    const token = authenticated ? this.store.getToken('management') : undefined;

    if (authenticated && !token) {
      throw new ProtocolClientError(operation);
    }
    const headers = [
      ...suppliedHeaders,
      ...(token ? ([['authorization', `Bearer ${token}`]] as const) : []),
    ];

    return this.sendPreparedRequest(prepared, {
      ...requestOptions,
      headers,
      includeCookies: authenticated,
    });
  }

  protected override resolve(path: string): URL {
    return new URL(
      path,
      new URL('/api/', this.allocationRole === 'admin' ? this.target.adminUrl : this.target.coreUrl)
    );
  }
}
