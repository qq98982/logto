import type { TargetConfig } from '../model.js';

import {
  stopPublicNativeAtCallback,
  type NativeCallbackHandoff,
} from './clients/user-token-issuance.js';
import type { ProvisionedPhase2Fixture } from './fixtures.js';
import type { Phase2FixturePublicWithSelectedNative } from './selected-native-fixture.js';

const diagnostic = 'Invalid Phase 2 selected Native callback';
const fail = (): never => {
  throw new TypeError(diagnostic);
};

export const stopSelectedNativeAtCallback = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture & { public: Phase2FixturePublicWithSelectedNative },
  expectedIssuer: string,
  requestFetch: typeof fetch = fetch
): Promise<NativeCallbackHandoff> => {
  const selected = fixture.public.selectedNative;
  const handoff = await stopPublicNativeAtCallback(
    target,
    fixture,
    {
      identity: selected.identity,
      withSecretLease: fixture.withSecretLease,
    },
    {
      clientId: selected.clientId,
      redirectUri: selected.redirectUri,
      expectedIssuer,
      resourceIndicator: selected.resource.indicator,
      resourceScope: selected.resource.scope.name,
    },
    requestFetch
  );
  if (handoff.getExpectedSubject() !== selected.identity.id) {
    return fail();
  }
  return handoff;
};
