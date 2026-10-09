import { types as nodeTypes } from 'node:util';

export type GoogleExistingOwnerControlError =
  | 'none'
  | 'state-mismatch'
  | 'entity-not-found'
  | 'connector-general'
  | 'invalid-input'
  | 'unknown';

export type GoogleExistingOwnerControlObservation = Readonly<{
  wrongState: Readonly<{
    callbackAccepted: boolean | 'unknown';
    status: number | 'unavailable';
    error: GoogleExistingOwnerControlError;
    ownerPreserved: true;
  }>;
  replay: Readonly<{
    firstStatus: 200;
    firstOutcome: 'verified';
    secondStatus: number | 'unavailable';
    secondError: GoogleExistingOwnerControlError;
    ownerPreserved: true;
  }>;
}>;

type RawObservation = Readonly<{
  status: number | 'unavailable';
  error: GoogleExistingOwnerControlError;
  successShape: boolean;
  ownerPreserved: boolean;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Common Google existing-owner controls');
};

const record = (value: unknown, fields: readonly string[]): Readonly<Record<string, unknown>> => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== fields.length
  ) {
    return fail();
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    fields.some((field) => {
      const descriptor = descriptors[field];
      return !descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable;
    })
  ) {
    return fail();
  }
  return Object.freeze(
    Object.fromEntries(fields.map((field) => [field, descriptors[field]?.value]))
  );
};

const status = (value: unknown): number | 'unavailable' =>
  typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599
    ? value
    : 'unavailable';

const error = (value: unknown): GoogleExistingOwnerControlError => {
  switch (value) {
    case 'none':
    case 'state-mismatch':
    case 'entity-not-found':
    case 'connector-general':
    case 'invalid-input': {
      return value;
    }
    default: {
      return 'unknown';
    }
  }
};

const observed = (value: unknown): RawObservation => {
  const source = record(value, ['status', 'error', 'successShape', 'ownerPreserved']);
  if (typeof source.successShape !== 'boolean' || source.ownerPreserved !== true) {
    return fail();
  }
  return Object.freeze({
    status: status(source.status),
    error: error(source.error),
    successShape: source.successShape,
    ownerPreserved: true,
  });
};

export const observeCommonGoogleExistingOwnerControls = async (
  runtime: Readonly<{
    runWrongStatePublicChain(): Promise<unknown>;
    runProviderCallbackReplayPublicChain(): Promise<Readonly<{ first: unknown; second: unknown }>>;
  }>
): Promise<GoogleExistingOwnerControlObservation> => {
  const wrongState = observed(await runtime.runWrongStatePublicChain());
  const replayValue = await runtime.runProviderCallbackReplayPublicChain();
  const replay = record(replayValue, ['first', 'second']);
  const first = observed(replay.first);
  const second = observed(replay.second);
  if (first.status !== 200 || first.error !== 'none' || !first.successShape) {
    return fail();
  }
  const callbackAccepted =
    wrongState.status === 'unavailable' || wrongState.error === 'unknown'
      ? ('unknown' as const)
      : wrongState.status === 200 && wrongState.error === 'none' && wrongState.successShape;
  return Object.freeze({
    wrongState: Object.freeze({
      callbackAccepted,
      status: wrongState.status,
      error: wrongState.error,
      ownerPreserved: true as const,
    }),
    replay: Object.freeze({
      firstStatus: 200 as const,
      firstOutcome: 'verified' as const,
      secondStatus: second.status,
      secondError: second.error,
      ownerPreserved: true as const,
    }),
  });
};
