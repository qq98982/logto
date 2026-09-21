import { ManagementClient } from './management.js';
import type { ManagementRequestOptions } from './management.js';
import type { RawProtocolResponse } from './oidc.js';

export class StateClient extends ManagementClient {
  async requestState(
    operation: string,
    path: string,
    options?: ManagementRequestOptions
  ): Promise<RawProtocolResponse> {
    return this.requestManagement(operation, path, options);
  }
}
