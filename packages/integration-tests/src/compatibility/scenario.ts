import { validateTargetConfig } from './config.js';
import {
  observationGuard,
  targetEvidenceGuard,
  type Observation,
  type TargetConfig,
  type TargetEvidence,
} from './model.js';
import { normalizeJson } from './normalize.js';
import { SymbolTable } from './symbol-table.js';
import { TargetClient } from './target-client.js';

export type ScenarioContext = {
  target: TargetConfig;
  client: TargetClient;
  symbols: SymbolTable;
  observe: (observation: Observation) => void;
};

export type CompatibilityScenario = {
  id: string;
  run: (context: ScenarioContext) => Promise<void>;
};

export type ScenarioRunnerOptions = {
  client?: TargetClient;
  clientFactory?: (target: TargetConfig) => TargetClient;
};

const assertSafeScenarioId = (scenarioId: string) => {
  if (typeof scenarioId !== 'string' || scenarioId.trim().length === 0) {
    throw new TypeError('Scenario id must be a non-empty string without control characters');
  }

  const containsControlCharacter = Array.from(scenarioId).some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;

    return codePoint <= 31 || codePoint === 127;
  });

  if (containsControlCharacter) {
    throw new TypeError('Scenario id must be a non-empty string without control characters');
  }
};

const cloneObservationValue = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map((item) => cloneObservationValue(item));
  }

  if (typeof value === 'object' && value !== null) {
    const prototype = Reflect.getPrototypeOf(value);
    const isPlainObject = prototype === null || Reflect.getPrototypeOf(prototype) === null;

    if (isPlainObject) {
      return Object.fromEntries(
        Object.entries(value).map(([key, item]) => [key, cloneObservationValue(item)])
      );
    }
  }

  return value;
};

export const runScenarioForTarget = async (
  scenario: CompatibilityScenario,
  target: TargetConfig,
  options: ScenarioRunnerOptions = {}
): Promise<TargetEvidence> => {
  const parsedTarget = validateTargetConfig(target);
  assertSafeScenarioId(scenario.id);

  if (options.client && options.clientFactory) {
    throw new TypeError('Specify either client or clientFactory, not both');
  }

  const client =
    options.client ?? options.clientFactory?.(parsedTarget) ?? new TargetClient(parsedTarget);
  const symbols = new SymbolTable();
  const observations: Observation[] = [];
  const observe = (observation: Observation) => {
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods -- The callback contract accumulates validated observations in invocation order.
    observations.push(
      observationGuard.parse({ ...observation, value: cloneObservationValue(observation.value) })
    );
  };
  // The finally contract needs mutable outcome slots so cleanup errors can be combined with primary errors.
  /* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation */
  let scenarioError: unknown;
  let cleanupError: unknown;
  let scenarioFailed = false;
  let cleanupFailed = false;

  try {
    await scenario.run({ target: parsedTarget, client, symbols, observe });
  } catch (error: unknown) {
    scenarioFailed = true;
    scenarioError = error;
  } finally {
    try {
      await client.cleanup();
    } catch (error: unknown) {
      cleanupFailed = true;
      cleanupError = error;
    }
  }
  /* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation */

  if (scenarioFailed && cleanupFailed) {
    throw new AggregateError(
      [scenarioError, cleanupError],
      'Scenario execution and target cleanup both failed'
    );
  }

  if (scenarioFailed) {
    throw scenarioError;
  }

  if (cleanupFailed) {
    throw cleanupError;
  }

  return targetEvidenceGuard.parse({
    target: parsedTarget.label,
    observations: observations.map(({ stepId, kind, value }) => ({
      stepId,
      kind,
      value: normalizeJson(value, { target: parsedTarget, symbols }, []),
    })),
  });
};
