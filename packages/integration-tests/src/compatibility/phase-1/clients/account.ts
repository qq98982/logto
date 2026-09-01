import type { ProtocolRequestOptions, RawProtocolResponse } from './oidc.js';
import { OidcClient, ProtocolClientError, protocolHeaderPairs } from './oidc.js';

export class AccountClient extends OidcClient {
  async requestAccount(
    operation: string,
    path: string,
    options: ProtocolRequestOptions = {}
  ): Promise<RawProtocolResponse> {
    const prepared = this.prepareRequest(operation, path);
    const suppliedHeaders = (() => {
      try {
        return protocolHeaderPairs(options.headers);
      } catch {
        throw new ProtocolClientError(operation);
      }
    })();
    const token = this.store.getToken('account');

    if (!token || suppliedHeaders.some(([name]) => name.toLowerCase() === 'authorization')) {
      throw new ProtocolClientError(operation);
    }
    const headers = [...suppliedHeaders, ['authorization', `Bearer ${token}`] as const];

    return this.sendPreparedRequest(prepared, { ...options, headers });
  }

  protected override resolve(path: string): URL {
    return new URL(
      path,
      new URL('/api/', this.allocationRole === 'admin' ? this.target.adminUrl : this.target.coreUrl)
    );
  }
}
