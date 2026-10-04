/* eslint-disable max-params -- The callback boundary keeps target, fixture, issuer, transport, and optional Native password authority explicit. */
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

export type SelectedNativeCallbackOptions = Readonly<{
  getSelectedNativePassword?: () => string;
}>;

export const stopSelectedNativeAtCallback = async (
  target: TargetConfig,
  fixture: ProvisionedPhase2Fixture & { public: Phase2FixturePublicWithSelectedNative },
  expectedIssuer: string,
  requestFetch: typeof fetch = fetch,
  options: SelectedNativeCallbackOptions = {}
): Promise<NativeCallbackHandoff> => {
  const selected = fixture.public.selectedNative;
  if (
    options.getSelectedNativePassword !== undefined &&
    typeof options.getSelectedNativePassword !== 'function'
  ) {
    return fail();
  }
  const withSecretLease = options.getSelectedNativePassword
    ? async <Result>(
        use: (
          lease: Readonly<{ getSelectedNativePassword(): string; toJSON(): never }>
        ) => Promise<Result>
      ): Promise<Result> =>
        use(
          Object.freeze({
            getSelectedNativePassword: options.getSelectedNativePassword ?? fail(),
            toJSON: (): never => fail(),
          })
        )
    : fixture.withSecretLease;
  const handoff = await stopPublicNativeAtCallback(
    target,
    fixture,
    {
      identity: selected.identity,
      withSecretLease,
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

/* eslint-enable max-params */
