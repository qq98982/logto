import { isDeepStrictEqual } from 'node:util';

import type { NormalizationContext } from '../../normalize.js';
import type { ProtocolRequestOptions, RawProtocolResponse } from '../clients/oidc.js';
import type { Phase1FixtureAllocationRole } from '../fixture-map.js';
import type { Phase1ScenarioRunContext } from '../model.js';
import { projectTokenErrorObservation, type Phase1HttpProjection } from '../projections/index.js';
import type { Phase1ScenarioStateProjectionInput } from '../scenario-runtime.js';

const invalidGrantBody = Object.freeze({
  code: 'oidc.invalid_grant',
  message: 'Grant request is invalid.',
  error_uri: 'https://openid.sh/debug/invalid_grant',
  error: 'invalid_grant',
  error_description: 'grant request is invalid',
});

export type ConcurrentTokenAttempt<Result> = Readonly<{
  operation: string;
  stepId: string;
  run: (context: Phase1ScenarioRunContext) => Promise<Result>;
}>;

type CapturedTokenRequest = Readonly<{
  path: string;
  options: ProtocolRequestOptions;
  response: RawProtocolResponse;
}>;

export type TwoTokenRequestBarrierRace<Result> = Readonly<{
  settled: readonly [PromiseSettledResult<Result>, PromiseSettledResult<Result>];
  rejections: Readonly<Record<string, Phase1HttpProjection>>;
  presentation: ReadonlyArray<
    Readonly<{ operation: string; stepId: string; kind: 'error' | 'failure' | 'success' }>
  >;
}>;

const projectConcurrentInvalidGrant = (
  response: RawProtocolResponse,
  state: Phase1ScenarioStateProjectionInput,
  normalizationContext: NormalizationContext
): Phase1HttpProjection => {
  const body: unknown = (() => {
    try {
      const parsed: unknown = JSON.parse(response.body);

      return parsed;
    } catch {
      throw new Error('Phase 1 concurrent token rejection is invalid');
    }
  })();
  const contentTypes = response.headers
    .filter(([name]) => name.toLowerCase() === 'content-type')
    .map(([, value]) => value);

  if (
    response.status !== 400 ||
    !isDeepStrictEqual(contentTypes, ['application/json; charset=utf-8']) ||
    response.headers.some(([name]) => ['location', 'set-cookie'].includes(name.toLowerCase())) ||
    !isDeepStrictEqual(body, invalidGrantBody)
  ) {
    throw new Error('Phase 1 concurrent token rejection is invalid');
  }

  return projectTokenErrorObservation(
    { ...state, status: response.status, headers: response.headers, body },
    normalizationContext
  );
};

// eslint-disable-next-line complexity -- The authority owns attempt startup, barrier release, all-settled draining, capture validation, projection, and cleanup.
export const withTwoTokenRequestBarrier = async <Result, Output>(
  context: Phase1ScenarioRunContext,
  attempts: readonly [ConcurrentTokenAttempt<Result>, ConcurrentTokenAttempt<Result>],
  input: Readonly<{
    normalizationContext: NormalizationContext;
    readState: (stepId: string) => Promise<Phase1ScenarioStateProjectionInput>;
    validateState: (state: Phase1ScenarioStateProjectionInput) => void;
    consume: (race: TwoTokenRequestBarrierRace<Result>) => Promise<Output>;
    cleanupFulfilled?: (value: Result) => void | Promise<void>;
  }>
): Promise<Output> => {
  const operations = attempts.map(({ operation }) => operation);

  if (new Set(operations).size !== 2 || operations.some((operation) => operation.length === 0)) {
    throw new Error('Phase 1 concurrent token requests are invalid');
  }
  const originalClients = context.protocol.forAllocation('data');
  const arrivals = new Map<string, Readonly<{ path: string; options: ProtocolRequestOptions }>>();
  const captures = new Map<string, CapturedTokenRequest>();
  const gate =
    // eslint-disable-next-line no-use-extend-native/no-use-extend-native -- Promise.withResolvers is the standard ES2024 deferred primitive, not a prototype extension.
    Promise.withResolvers<void>();
  const rejectGate = () => {
    gate.reject(new Error('Phase 1 concurrent token requests aborted'));
  };
  const observeGateRejection = async () => {
    try {
      await gate.promise;
    } catch {
      // The matching request observes the fixed rejection; this prevents an unhandled duplicate.
    }
  };
  // A pre-request failure in the peer attempt otherwise leaves the first arrival waiting forever.
  void observeGateRejection();
  if (context.signal.aborted) {
    rejectGate();
  } else {
    context.signal.addEventListener('abort', rejectGate, { once: true });
  }
  const racingOidc = {
    store: originalClients.oidc.store,
    request: async (
      requestOperation: string,
      path: string,
      options: ProtocolRequestOptions = {}
    ): Promise<RawProtocolResponse> => {
      if (!operations.includes(requestOperation)) {
        return originalClients.oidc.request(requestOperation, path, options);
      }
      if (arrivals.has(requestOperation) || arrivals.size >= 2) {
        throw new Error('Phase 1 concurrent token requests are invalid');
      }
      arrivals.set(requestOperation, Object.freeze({ path, options }));
      if (arrivals.size === 2) {
        gate.resolve();
      }
      await gate.promise;
      const response = await originalClients.oidc.request(requestOperation, path, options);
      captures.set(requestOperation, Object.freeze({ path, options, response }));

      return response;
    },
  };
  const raceContext: Phase1ScenarioRunContext = Object.freeze({
    ...context,
    protocol: Object.freeze({
      ...context.protocol,
      forAllocation: (role: Phase1FixtureAllocationRole) => {
        const clients = context.protocol.forAllocation(role);

        return role === 'data' ? Object.freeze({ ...clients, oidc: racingOidc }) : clients;
      },
    }),
  });
  try {
    const runAttempt = async ({ run }: ConcurrentTokenAttempt<Result>): Promise<Result> => {
      try {
        return await run(raceContext);
      } catch (error: unknown) {
        if (arrivals.size < 2) {
          rejectGate();
        }

        throw error;
      }
    };
    const settled = await Promise.allSettled([runAttempt(attempts[0]), runAttempt(attempts[1])]);

    try {
      if (context.signal.aborted) {
        throw new Error('Phase 1 concurrent token requests aborted');
      }
      const [first, second] = attempts.map(({ operation }) => arrivals.get(operation));

      if (
        arrivals.size !== 2 ||
        !first ||
        !second ||
        first.path !== second.path ||
        !isDeepStrictEqual(first.options, second.options)
      ) {
        throw new Error('Phase 1 concurrent token requests are invalid');
      }
      const presentation = attempts
        .map(({ operation }, index) => {
          const capture = captures.get(operation);
          const outcome = settled[index];

          if (!outcome) {
            throw new Error('Phase 1 concurrent token requests are invalid');
          }
          const kind = capture
            ? capture.response.status === 400
              ? ('error' as const)
              : capture.response.status === 200
                ? ('success' as const)
                : undefined
            : outcome.status === 'rejected'
              ? ('failure' as const)
              : undefined;

          if (!kind) {
            throw new Error('Phase 1 concurrent token requests are invalid');
          }

          return Object.freeze({ operation, kind });
        })
        .toSorted((left, right) => left.kind.localeCompare(right.kind))
        .map(({ operation, kind }, index) =>
          Object.freeze({ operation, kind, stepId: attempts[index]?.stepId ?? '' })
        );

      if (presentation.some(({ stepId }) => stepId.length === 0)) {
        throw new Error('Phase 1 concurrent token requests are invalid');
      }
      const rejectionEntries = await Promise.all(
        presentation.flatMap(({ operation, stepId, kind }) => {
          const capture = captures.get(operation);

          if (kind !== 'error') {
            return [];
          }
          if (!capture || capture.response.status !== 400) {
            throw new Error('Phase 1 concurrent token requests are invalid');
          }

          return [
            (async () => {
              const state = await input.readState(stepId);
              input.validateState(state);
              const projection = projectConcurrentInvalidGrant(
                capture.response,
                state,
                input.normalizationContext
              );
              originalClients.oidc.store.assertNoCredentialMaterial(projection);

              return [operation, projection] as const;
            })(),
          ];
        })
      );
      const race = Object.freeze({
        settled,
        rejections: Object.freeze(Object.fromEntries(rejectionEntries)),
        presentation: Object.freeze(presentation),
      });

      return await input.consume(race);
    } finally {
      if (input.cleanupFulfilled) {
        await Promise.all(
          settled.flatMap((outcome) =>
            outcome.status === 'fulfilled' ? [input.cleanupFulfilled?.(outcome.value)] : []
          )
        );
      }
    }
  } finally {
    if (arrivals.size === 1) {
      rejectGate();
    }
    context.signal.removeEventListener('abort', rejectGate);
  }
};
