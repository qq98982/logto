import type { ProtocolRequestOptions, RawProtocolResponse } from './oidc.js';
import { OidcClient } from './oidc.js';

export class ConsentClient extends OidcClient {
  async requestConsent(
    operation: string,
    path: string,
    options?: ProtocolRequestOptions
  ): Promise<RawProtocolResponse> {
    return this.request(operation, path, options);
  }

  protected override resolve(path: string): URL {
    return new URL(
      path,
      new URL(
        '/api/interaction/',
        this.allocationRole === 'admin' ? this.target.adminUrl : this.target.coreUrl
      )
    );
  }
}
