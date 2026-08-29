import { setImmediate as waitForImmediate } from 'node:timers/promises';

import { compareJson } from '../compare.js';
import { loadCompatibilityConfig } from '../config.js';
import { runScenarioForTarget } from '../scenario.js';
import { defaultCompatibilityScenarios } from '../scenarios/index.js';

const dualTargetTest = process.env.ASTER_RUN_DUAL_TARGET === '1' ? it : it.skip;

const waitForTargetPair = async <Oracle, Candidate>(
  oraclePromise: Promise<Oracle>,
  candidatePromise: Promise<Candidate>
): Promise<readonly [Oracle, Candidate]> => {
  const [oracle, candidate] = await Promise.allSettled([oraclePromise, candidatePromise]);

  if (oracle.status === 'rejected' && candidate.status === 'rejected') {
    throw new AggregateError(
      [oracle.reason, candidate.reason],
      'Both compatibility targets failed'
    );
  }

  if (oracle.status === 'rejected') {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Preserve the target's exact rejection reason.
    throw oracle.reason;
  }

  if (candidate.status === 'rejected') {
    // eslint-disable-next-line @typescript-eslint/no-throw-literal -- Preserve the target's exact rejection reason.
    throw candidate.reason;
  }

  return [oracle.value, candidate.value];
};

const withRealmLocalResponseJson = async <Result>(run: () => Promise<Result>): Promise<Result> => {
  const jsonDescriptor = Object.getOwnPropertyDescriptor(Response.prototype, 'json');

  if (jsonDescriptor === undefined) {
    throw new Error('Response.json is unavailable');
  }

  // Node's Response creates objects outside Jest's VM. Parse in this realm so strict JSON guards
  // see the same plain-object prototypes that they see in the CLI process.
  const parseRealmLocalJson = async function (this: Response): Promise<unknown> {
    return JSON.parse(await this.text()) as unknown;
  };
  // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The override is scoped to one sequential case and restored in finally.
  Object.defineProperty(Response.prototype, 'json', {
    ...jsonDescriptor,
    value: parseRealmLocalJson,
  });

  try {
    return await run();
  } finally {
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- Restore the exact original descriptor even when a target fails.
    Object.defineProperty(Response.prototype, 'json', jsonDescriptor);
  }
};

const waitForSignal = async (signal: AbortSignal): Promise<void> => {
  if (signal.aborted) {
    return;
  }

  await new Promise<void>((resolve) => {
    signal.addEventListener(
      'abort',
      () => {
        resolve();
      },
      { once: true }
    );
  });
};

describe('reference parity', () => {
  dualTargetTest('keeps realm-local JSON active until both targets settle', async () => {
    const originalJsonDescriptor = Object.getOwnPropertyDescriptor(Response.prototype, 'json');

    expect(originalJsonDescriptor).toBeDefined();

    const immediateError = new Error('immediate target failure');
    const releasePeer = new AbortController();
    const peerFinished = new AbortController();
    const runSettled = new AbortController();
    const peerFinishedOutcome = (async () => {
      await waitForSignal(peerFinished.signal);
      return 'peer-finished' as const;
    })();
    const runSettledOutcome = (async () => {
      await waitForSignal(runSettled.signal);
      return 'run-settled' as const;
    })();
    const peerPromise = (async () => {
      await waitForSignal(releasePeer.signal);
      const parsed: unknown = await new Response('{"settled":true}').json();
      const hasRealmLocalPrototype = Object.getPrototypeOf(parsed) === Object.prototype;

      peerFinished.abort();

      return hasRealmLocalPrototype;
    })();
    const runPromise = withRealmLocalResponseJson(async () =>
      waitForTargetPair(Promise.reject(immediateError), peerPromise)
    );
    const runOutcome = (async () => {
      try {
        await runPromise;
        return 'fulfilled' as const;
      } catch (error: unknown) {
        return { error };
      } finally {
        runSettled.abort();
      }
    })();
    const firstSettlementAfterRelease = Promise.race([peerFinishedOutcome, runSettledOutcome]);

    await waitForImmediate();
    const wasPendingAfterFastFailure = !runSettled.signal.aborted;

    releasePeer.abort();
    const [peerSawRealmLocalJson, observedRunOutcome, firstSettlement] = await Promise.all([
      peerPromise,
      runOutcome,
      firstSettlementAfterRelease,
    ]);

    expect(wasPendingAfterFastFailure).toBe(true);
    expect(peerSawRealmLocalJson).toBe(true);
    expect(firstSettlement).toBe('peer-finished');
    expect(observedRunOutcome).not.toBe('fulfilled');
    if (observedRunOutcome === 'fulfilled') {
      throw new Error('Target pair unexpectedly fulfilled');
    }
    expect(observedRunOutcome.error).toBe(immediateError);
    expect(Object.getOwnPropertyDescriptor(Response.prototype, 'json')).toStrictEqual(
      originalJsonDescriptor
    );

    const oracleError = new Error('oracle target failure');
    const candidateError = new Error('candidate target failure');
    const dualFailure: unknown = await (async () => {
      try {
        await waitForTargetPair(Promise.reject(oracleError), Promise.reject(candidateError));
      } catch (error: unknown) {
        return error;
      }
    })();

    expect(dualFailure).toBeInstanceOf(AggregateError);
    if (!(dualFailure instanceof AggregateError)) {
      throw new TypeError('Expected both target failures to be aggregated');
    }
    expect(dualFailure.message).toBe('Both compatibility targets failed');
    expect(dualFailure.errors).toEqual([oracleError, candidateError]);
  });

  dualTargetTest.each(defaultCompatibilityScenarios)(
    '$id matches the reference target',
    async (scenario) => {
      await withRealmLocalResponseJson(async () => {
        const { oracle, candidate } = loadCompatibilityConfig();
        const [oracleEvidence, candidateEvidence] = await waitForTargetPair(
          runScenarioForTarget(scenario, oracle),
          runScenarioForTarget(scenario, candidate)
        );

        expect(
          compareJson(
            { observations: oracleEvidence.observations },
            { observations: candidateEvidence.observations }
          )
        ).toEqual([]);
      });
    }
  );
});
