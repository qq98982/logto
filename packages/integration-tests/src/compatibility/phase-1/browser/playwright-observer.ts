/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, max-params -- Locator operations retain explicit failure context, while console observation owns bounded listener and timer state until one terminal event wins. */
import type {
  Browser,
  BrowserContext,
  BrowserType,
  ConsoleMessage,
  Locator,
  Page,
} from '@playwright/test';

import { assertEvidenceIsSanitized } from '../../evidence.js';

export const playwrightFailureClasses = Object.freeze([
  'navigation',
  'locator',
  'evaluation',
  'console-event',
  'browser-process',
] as const);

export type PlaywrightFailureClass = (typeof playwrightFailureClasses)[number];

type FailureContext = Readonly<{
  stepId: string;
  errorClass: PlaywrightFailureClass;
  projectionPointer: string;
}>;

type ObserverOptions = Readonly<{
  scenarioId: string;
  browserType: Pick<BrowserType<Browser>, 'launch'>;
  consoleTimeoutMs?: number;
  signal?: AbortSignal;
}>;

const safeIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;
const pointerPattern = /^(?:\/(?:[A-Za-z0-9._-]|~[01])+)+$/u;
const defaultConsoleTimeoutMs = 5000;
const maximumConsoleTimeoutMs = 300_000;
const launchEnvironmentKeys = Object.freeze([
  'HOME',
  'LANG',
  'PATH',
  'TMPDIR',
  'XDG_RUNTIME_DIR',
] as const);
const silentLogger = Object.freeze({
  isEnabled: () => false,
  log: () => false,
});

const requireSafeId = (value: string): string => {
  if (!safeIdPattern.test(value)) {
    throw new TypeError('Invalid Playwright observation identifier');
  }

  return value;
};

const requirePointer = (value: string): string => {
  if (!pointerPattern.test(value) || value.length > 512) {
    throw new TypeError('Invalid Playwright observation pointer');
  }
  try {
    assertEvidenceIsSanitized({ projectionPointer: value });
  } catch {
    throw new TypeError('Invalid Playwright observation pointer');
  }

  return value;
};

export class PlaywrightObservationError extends Error {
  readonly scenarioId: string;
  readonly stepId: string;
  readonly errorClass: PlaywrightFailureClass;
  readonly projectionPointer: string;

  override get name(): string {
    return 'PlaywrightObservationError';
  }

  constructor(scenarioId: string, context: FailureContext) {
    const safeScenarioId = requireSafeId(scenarioId);
    const stepId = requireSafeId(context.stepId);
    const projectionPointer = requirePointer(context.projectionPointer);

    if (!playwrightFailureClasses.includes(context.errorClass)) {
      throw new TypeError('Invalid Playwright observation error class');
    }
    super(
      `Playwright observation failed: ${safeScenarioId}/${stepId}/${context.errorClass} at ${projectionPointer}`
    );
    this.scenarioId = safeScenarioId;
    this.stepId = stepId;
    this.errorClass = context.errorClass;
    this.projectionPointer = projectionPointer;
    this.stack = this.message;
  }

  toJSON(): Readonly<{
    scenarioId: string;
    stepId: string;
    errorClass: PlaywrightFailureClass;
    projectionPointer: string;
  }> {
    return Object.freeze({
      scenarioId: this.scenarioId,
      stepId: this.stepId,
      errorClass: this.errorClass,
      projectionPointer: this.projectionPointer,
    });
  }
}

const launchEnvironment = (): Readonly<Record<string, string>> =>
  Object.freeze(
    Object.fromEntries(
      launchEnvironmentKeys.flatMap((key) =>
        process.env[key] === undefined ? [] : [[key, process.env[key]] as const]
      )
    )
  );

export const createPlaywrightObserver = (options: ObserverOptions) => {
  const scenarioId = requireSafeId(options.scenarioId);
  const consoleTimeoutMs = options.consoleTimeoutMs ?? defaultConsoleTimeoutMs;

  if (
    !Number.isSafeInteger(consoleTimeoutMs) ||
    consoleTimeoutMs <= 0 ||
    consoleTimeoutMs > maximumConsoleTimeoutMs
  ) {
    throw new TypeError('Invalid Playwright console timeout');
  }
  const execute = async <Result>(context: FailureContext, run: () => Promise<Result>) => {
    try {
      return await run();
    } catch (error: unknown) {
      if (error instanceof PlaywrightObservationError) {
        throw error;
      }
      throw new PlaywrightObservationError(scenarioId, context);
    }
  };

  return Object.freeze({
    captureFailure: async (
      context: FailureContext,
      run: () => Promise<unknown>
    ): Promise<PlaywrightObservationError> => {
      try {
        await execute(context, run);
      } catch (error: unknown) {
        return error instanceof PlaywrightObservationError
          ? error
          : new PlaywrightObservationError(scenarioId, context);
      }

      const error = new Error('Expected Playwright observation failure');
      error.stack = error.message;
      throw error;
    },

    withContext: async <Result>(
      stepId: string,
      use: (context: BrowserContext) => Promise<Result>
    ): Promise<Result> => {
      const failure = {
        stepId,
        errorClass: 'browser-process' as const,
        projectionPointer: `/steps/${stepId}/value`,
      };
      const browser = await execute(failure, async () =>
        options.browserType.launch({
          headless: true,
          env: launchEnvironment(),
          logger: silentLogger,
        })
      );

      try {
        const context = await execute(failure, async () =>
          browser.newContext({ acceptDownloads: false, serviceWorkers: 'block' })
        );
        try {
          return await execute(failure, async () => use(context));
        } finally {
          await execute(failure, async () => context.close());
        }
      } finally {
        await execute(failure, async () => browser.close());
      }
    },

    navigate: async (page: Page, stepId: string, url: string, projectionPointer: string) =>
      execute({ stepId, errorClass: 'navigation', projectionPointer }, async () =>
        page.goto(url, { waitUntil: 'load' })
      ),

    locate: async <Result>(
      page: Page,
      stepId: string,
      selector: string,
      projectionPointer: string,
      use: (locator: Locator) => Promise<Result>
    ): Promise<Result> =>
      execute({ stepId, errorClass: 'locator', projectionPointer }, async () =>
        use(page.locator(selector))
      ),

    evaluate: async <Result>(
      page: Page,
      stepId: string,
      projectionPointer: string,
      expression: () => Result | Promise<Result>
    ): Promise<Result> =>
      execute({ stepId, errorClass: 'evaluation', projectionPointer }, async () =>
        page.evaluate(expression)
      ),

    observeConsole: async (
      page: Page,
      stepId: string,
      projectionPointer: string,
      use: (projection: Readonly<{ type: string }>) => void
    ): Promise<void> => {
      const failure = { stepId, errorClass: 'console-event' as const, projectionPointer };

      await new Promise<void>((resolve, reject) => {
        let settled = false;
        let timer: NodeJS.Timeout | undefined;
        const cleanup = () => {
          if (timer) {
            clearTimeout(timer);
          }
          try {
            page.removeListener('console', onConsole);
          } catch {
            // The fixed rejection below is the only diagnostic crossing this boundary.
          }
          try {
            page.removeListener('close', onClose);
          } catch {
            // The fixed rejection below is the only diagnostic crossing this boundary.
          }
          options.signal?.removeEventListener('abort', onAbort);
        };
        const fail = () => {
          if (settled) {
            return;
          }
          settled = true;
          cleanup();
          reject(new PlaywrightObservationError(scenarioId, failure));
        };
        const succeed = () => {
          if (settled) {
            return;
          }
          settled = true;
          cleanup();
          resolve();
        };
        const onConsole = (message: ConsoleMessage) => {
          if (settled) {
            return;
          }
          try {
            use(Object.freeze({ type: message.type() }));
          } catch {
            fail();
            return;
          }
          succeed();
        };
        const onClose = () => {
          fail();
        };
        const onAbort = () => {
          fail();
        };

        try {
          page.on('console', onConsole);
          page.on('close', onClose);
          options.signal?.addEventListener('abort', onAbort, { once: true });
          if (page.isClosed() || options.signal?.aborted) {
            fail();
            return;
          }
          timer = setTimeout(fail, consoleTimeoutMs);
        } catch {
          fail();
        }
      });
    },
  });
};

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, max-params */
