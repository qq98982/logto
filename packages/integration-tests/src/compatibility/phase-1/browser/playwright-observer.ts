/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-params, max-lines, complexity, no-control-regex, no-restricted-syntax, no-await-in-loop, promise/prefer-await-to-then, @typescript-eslint/ban-types, @typescript-eslint/no-throw-literal, unicorn/no-useless-undefined -- The observer centrally owns bounded graph traversal, one-shot async listener state, sequential context/browser cleanup, fixed errors, and generic result preservation without exposing raw Playwright values. */
import type {
  Browser,
  BrowserContext,
  BrowserType,
  ConsoleMessage,
  Locator,
  Page,
} from '@playwright/test';

import { assertEvidenceIsSanitized } from '../../evidence.js';
import type { JsonObject, JsonValue } from '../../normalize.js';

export const playwrightFailureClasses = Object.freeze([
  'navigation',
  'locator',
  'evaluation',
  'console-event',
  'browser-process',
] as const);

export type PlaywrightFailureClass = (typeof playwrightFailureClasses)[number];

export type PlaywrightFailureContext = Readonly<{
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
const maximumConsoleDepth = 16;
const maximumConsoleArrayLength = 256;
const maximumConsoleObjectKeys = 256;
const maximumConsoleStringLength = 4096;
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

const snapshotConsoleValue = (
  value: unknown,
  depth: number,
  ancestors: WeakSet<object>
): JsonValue => {
  if (depth > maximumConsoleDepth) {
    throw new TypeError('Invalid Playwright console projection');
  }
  if (value === null || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('Invalid Playwright console projection');
    }
    return value;
  }
  if (typeof value === 'string') {
    if (value.length > maximumConsoleStringLength || /[\u0000-\u001F\u007F]/u.test(value)) {
      throw new TypeError('Invalid Playwright console projection');
    }
    return value;
  }
  if (typeof value !== 'object' || ancestors.has(value)) {
    throw new TypeError('Invalid Playwright console projection');
  }
  const prototype: unknown = Object.getPrototypeOf(value);

  if (Array.isArray(value)) {
    if (prototype !== Array.prototype || value.length > maximumConsoleArrayLength) {
      throw new TypeError('Invalid Playwright console projection');
    }
    ancestors.add(value);
    const result = value.map((item) => snapshotConsoleValue(item, depth + 1, ancestors));
    ancestors.delete(value);
    Object.freeze(result);
    return result;
  }
  if (prototype !== Object.prototype) {
    throw new TypeError('Invalid Playwright console projection');
  }
  const keys = Reflect.ownKeys(value);

  if (keys.length > maximumConsoleObjectKeys || keys.some((key) => typeof key !== 'string')) {
    throw new TypeError('Invalid Playwright console projection');
  }
  ancestors.add(value);
  const result = Object.fromEntries(
    (keys as string[]).map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);

      if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) {
        throw new TypeError('Invalid Playwright console projection');
      }

      return [key, snapshotConsoleValue(descriptor.value, depth + 1, ancestors)] as const;
    })
  );
  ancestors.delete(value);

  return Object.freeze(result);
};

const snapshotConsoleObject = (value: unknown): JsonObject => {
  const snapshot = snapshotConsoleValue(value, 0, new WeakSet());

  if (typeof snapshot !== 'object' || snapshot === null || Array.isArray(snapshot)) {
    throw new TypeError('Invalid Playwright console projection');
  }

  return snapshot;
};

export class PlaywrightObservationError extends Error {
  readonly scenarioId: string;
  readonly stepId: string;
  readonly errorClass: PlaywrightFailureClass;
  readonly projectionPointer: string;

  override get name(): string {
    return 'PlaywrightObservationError';
  }

  constructor(scenarioId: string, context: PlaywrightFailureContext) {
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
  const execute = async <Result>(context: PlaywrightFailureContext, run: () => Promise<Result>) => {
    try {
      return await run();
    } catch (error: unknown) {
      if (error instanceof PlaywrightObservationError) {
        throw error;
      }
      throw new PlaywrightObservationError(scenarioId, context);
    }
  };

  const observeConsoleValue = async <Result>(
    page: Page,
    stepId: string,
    projectionPointer: string,
    consume: (message: ConsoleMessage) => Promise<Result>,
    trigger?: () => Promise<void>
  ): Promise<Result> => {
    const failure = { stepId, errorClass: 'console-event' as const, projectionPointer };

    return new Promise<Result>((resolve, reject) => {
      let claimed = false;
      let settled = false;
      let timer: NodeJS.Timeout | undefined;
      const cleanup = () => {
        if (timer) {
          clearTimeout(timer);
        }
        try {
          page.removeListener('console', onConsole);
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
      const succeed = (value: Result) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        resolve(value);
      };
      const onConsole = (message: ConsoleMessage) => {
        if (settled || claimed) {
          return;
        }
        claimed = true;
        void consume(message).then(succeed, fail);
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
        if (trigger) {
          void trigger().catch(fail);
        }
      } catch {
        fail();
      }
    });
  };

  return Object.freeze({
    run: execute,

    captureFailure: async (
      context: PlaywrightFailureContext,
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

      let context: BrowserContext | undefined;
      const closeOnAbort = () => {
        void context?.close().catch(() => undefined);
      };
      let result: Result | undefined;
      let primaryError: unknown;
      const cleanupErrors: unknown[] = [];

      try {
        context = await execute(failure, async () =>
          browser.newContext({ acceptDownloads: false, locale: 'en', serviceWorkers: 'block' })
        );
        options.signal?.addEventListener('abort', closeOnAbort, { once: true });
        if (options.signal?.aborted) {
          closeOnAbort();
          throw new PlaywrightObservationError(scenarioId, failure);
        }
        const activeContext = context;
        result = await execute(failure, async () => use(activeContext));
      } catch (error: unknown) {
        primaryError = error;
      } finally {
        options.signal?.removeEventListener('abort', closeOnAbort);
        for (const close of [
          ...(context ? [async () => context?.close()] : []),
          async () => browser.close(),
        ]) {
          try {
            await execute(failure, close);
          } catch (error: unknown) {
            cleanupErrors.push(error);
          }
        }
      }
      if (primaryError !== undefined && cleanupErrors.length > 0) {
        throw new AggregateError(
          [primaryError, ...cleanupErrors],
          'Playwright observation and cleanup failed',
          { cause: primaryError }
        );
      }
      if (primaryError !== undefined) {
        throw primaryError;
      }
      if (cleanupErrors.length > 0) {
        throw new AggregateError(cleanupErrors, 'Playwright observation cleanup failed');
      }

      return result as Result;
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
      await observeConsoleValue(page, stepId, projectionPointer, async (message) => {
        use(Object.freeze({ type: message.type() }));
      });
    },

    observeConsoleProjection: async <Projection extends JsonObject>(
      page: Page,
      stepId: string,
      projectionPointer: string,
      project: (value: JsonObject) => Projection,
      trigger?: () => Promise<void>
    ): Promise<Readonly<Projection>> =>
      observeConsoleValue(
        page,
        stepId,
        projectionPointer,
        async (message) => {
          const arguments_ = message.args();

          if (message.type() !== 'log' || arguments_.length !== 1 || !arguments_[0]) {
            throw new TypeError('Invalid Playwright console projection');
          }
          const raw = snapshotConsoleObject(await arguments_[0].jsonValue());
          assertEvidenceIsSanitized({ browserConsole: raw });
          const projection = snapshotConsoleObject(project(raw)) as Readonly<Projection>;
          assertEvidenceIsSanitized({ browserProjection: projection });

          return projection;
        },
        trigger
      ),
  });
};

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, max-params, max-lines, complexity, no-control-regex, no-restricted-syntax, no-await-in-loop, promise/prefer-await-to-then, @typescript-eslint/ban-types, @typescript-eslint/no-throw-literal, unicorn/no-useless-undefined */
