import type { CommonGoogleRegistrationFixtureRuntime } from '../scenarios/common-google-registration.js';

import { readCommonGoogleExistingOwnerFixtureRuntime } from './common-google-existing-owner-fixture-runtime.js';

export const readCommonGoogleRegistrationFixtureRuntime = async (
  filePath: string,
  controlSocket: string
): Promise<CommonGoogleRegistrationFixtureRuntime> =>
  readCommonGoogleExistingOwnerFixtureRuntime(filePath, controlSocket);
