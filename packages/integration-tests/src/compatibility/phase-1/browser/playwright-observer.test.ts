/* eslint-disable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function -- Browser tests record lifecycle/output state, implement narrow failure fakes, and load Playwright natively outside the tsup ESM bundle. */
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';

import type { Browser, BrowserType, Page } from '@playwright/test';

import { PlaywrightObservationError, createPlaywrightObserver } from './playwright-observer.js';

const { chromium } = createRequire(import.meta.url)('@playwright/test') as {
  chromium: BrowserType<Browser>;
};

const sentinels = [
  'Unique-password-42',
  'code=private-code',
  'private-cookie',
  'private-token',
  'private-dom-value',
];

const captureFailure = async (run: Promise<unknown>, failures: unknown[]): Promise<void> => {
  try {
    await run;
  } catch (error: unknown) {
    failures.push(error);
  }
};

const listenerCount = (page: Page, event: 'close' | 'console'): number =>
  (page as unknown as Readonly<{ listenerCount: (event: string) => number }>).listenerCount(event);

describe('phase 1 Playwright observer', () => {
  it.each(['navigation', 'locator', 'evaluation', 'console-event', 'browser-process'] as const)(
    'turns %s failures into a fixed redacted boundary',
    async (errorClass) => {
      const observer = createPlaywrightObserver({
        scenarioId: 'scenario',
        browserType: {} as never,
      });
      const error = await observer.captureFailure(
        { stepId: 'step', errorClass, projectionPointer: '/steps/step/value' },
        async () => {
          throw new Error(sentinels.join(' '));
        }
      );

      expect(error).toBeInstanceOf(PlaywrightObservationError);
      expect(error).toMatchObject({ scenarioId: 'scenario', stepId: 'step', errorClass });
      const rendered = `${String(error)} ${JSON.stringify(error)}`;
      for (const sentinel of sentinels) {
        expect(rendered).not.toContain(sentinel);
      }
    }
  );

  it('fails with a fixed diagnostic when a captured failure unexpectedly succeeds', async () => {
    const observer = createPlaywrightObserver({
      scenarioId: 'scenario',
      browserType: {} as never,
    });

    await expect(
      observer.captureFailure(
        {
          stepId: 'unexpected-success',
          errorClass: 'evaluation',
          projectionPointer: '/steps/unexpected-success/value',
        },
        async () => 'private-success-value'
      )
    ).rejects.toThrow('Expected Playwright observation failure');
  });

  it('launches with all recording and debug channels disabled', async () => {
    let closeCalls = 0;
    let launchOptions: Record<string, unknown> | undefined;
    let contextOptions: Record<string, unknown> | undefined;
    const close = async () => {
      closeCalls += 1;
    };
    const newContext = async (options: Record<string, unknown>) => {
      contextOptions = options;
      return { close };
    };
    const launch = async (options: Record<string, unknown>) => {
      launchOptions = options;
      return { newContext, close };
    };
    const observer = createPlaywrightObserver({
      scenarioId: 'scenario',
      browserType: { launch } as never,
    });

    await observer.withContext('step', async () => {});

    expect(launchOptions).toMatchObject({ headless: true });
    expect((launchOptions?.env as Record<string, unknown> | undefined)?.DEBUG).toBeUndefined();
    expect((launchOptions?.env as Record<string, unknown> | undefined)?.PWDEBUG).toBeUndefined();
    expect(contextOptions).not.toHaveProperty('recordHar');
    expect(contextOptions).not.toHaveProperty('recordVideo');
    expect(closeCalls).toBe(2);
  });

  it('rejects a URL or control text passed as a projection pointer without echoing it', () => {
    const privatePointer = '/steps/step/https://private-token.example';
    const createError = () =>
      new PlaywrightObservationError('scenario', {
        stepId: 'step',
        errorClass: 'navigation',
        projectionPointer: privatePointer,
      });
    let error: unknown;
    try {
      createError();
    } catch (error_: unknown) {
      error = error_;
    }

    expect(String(error)).toBe('TypeError: Invalid Playwright observation pointer');
    expect(String(error)).not.toContain(privatePointer);
  });

  it('rejects a runtime-injected failure class without echoing it', () => {
    const privateErrorClass = 'private-token';

    expect(
      () =>
        new PlaywrightObservationError('scenario', {
          stepId: 'step',
          errorClass: privateErrorClass as never,
          projectionPointer: '/steps/step/value',
        })
    ).toThrow('Invalid Playwright observation error class');
  });

  it('bounds console observation and removes listeners after timeout and page close', async () => {
    const observer = createPlaywrightObserver({
      scenarioId: 'console-lifecycle',
      browserType: chromium,
      consoleTimeoutMs: 20,
    });

    await observer.withContext('console-lifecycle', async (context) => {
      const timedPage = await context.newPage();
      const timedConsoleListeners = listenerCount(timedPage, 'console');
      const timedCloseListeners = listenerCount(timedPage, 'close');

      await expect(
        observer.observeConsole(timedPage, 'timeout', '/steps/timeout/value', () => {})
      ).rejects.toMatchObject({
        scenarioId: 'console-lifecycle',
        stepId: 'timeout',
        errorClass: 'console-event',
      });
      expect(listenerCount(timedPage, 'console')).toBe(timedConsoleListeners);
      expect(listenerCount(timedPage, 'close')).toBe(timedCloseListeners);

      const controlPage = await context.newPage();
      await controlPage.close();
      const closedConsoleListeners = listenerCount(controlPage, 'console');
      const closedCloseListeners = listenerCount(controlPage, 'close');
      const closedPage = await context.newPage();
      const observation = observer.observeConsole(
        closedPage,
        'closed',
        '/steps/closed/value',
        () => {}
      );
      const closedAssertion = expect(observation).rejects.toMatchObject({
        scenarioId: 'console-lifecycle',
        stepId: 'closed',
        errorClass: 'console-event',
      });

      await closedPage.close();
      await closedAssertion;
      expect(listenerCount(closedPage, 'console')).toBe(closedConsoleListeners);
      expect(listenerCount(closedPage, 'close')).toBe(closedCloseListeners);
    });
  });

  it('aborts console observation and removes listeners', async () => {
    const controller = new AbortController();
    const observer = createPlaywrightObserver({
      scenarioId: 'console-abort',
      browserType: chromium,
      signal: controller.signal,
    });

    await observer.withContext('console-abort', async (context) => {
      const page = await context.newPage();
      const consoleListeners = listenerCount(page, 'console');
      const closeListeners = listenerCount(page, 'close');
      const observation = observer.observeConsole(
        page,
        'aborted',
        '/steps/aborted/value',
        () => {}
      );
      const assertion = expect(observation).rejects.toMatchObject({
        scenarioId: 'console-abort',
        stepId: 'aborted',
        errorClass: 'console-event',
      });

      controller.abort('private-abort-reason');
      await assertion;
      expect(listenerCount(page, 'console')).toBe(consoleListeners);
      expect(listenerCount(page, 'close')).toBe(closeListeners);
    });
  });

  it('redacts real Chromium navigation locator evaluation and console failures from Jest output', async () => {
    const stdout = import.meta.jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = import.meta.jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const failures: unknown[] = [];
    let capturedOutput = '';
    const processDirectory = await mkdtemp(
      '/var/tmp/henry-build/aster-playwright-process-failure-'
    );
    const processExecutable = `${processDirectory}/browser`;
    const processMarker = `${processDirectory}/started`;
    const observer = createPlaywrightObserver({
      scenarioId: 'real-browser',
      browserType: chromium,
    });

    try {
      await observer.withContext('browser', async (context) => {
        await context.addCookies([
          { name: 'private-cookie', value: 'private-cookie', url: 'http://example.com' },
        ]);
        const page = await context.newPage();
        await page.setContent('<input value="Unique-password-42" />');
        await captureFailure(
          observer.locate(
            page,
            'locator',
            '#missing-private-dom-value',
            '/steps/locator/value',
            async (locator) => locator.click({ timeout: 20 })
          ),
          failures
        );
        await captureFailure(
          observer.evaluate(page, 'evaluation', '/steps/evaluation/value', () => {
            throw new Error('private-dom-value');
          }),
          failures
        );
        const consoleFailure = observer.observeConsole(
          page,
          'console',
          '/steps/console/value',
          () => {
            throw new Error('private-token');
          }
        );
        const capturedConsoleFailure = captureFailure(consoleFailure, failures);
        await page.evaluate((value) => {
          console.log(value);
        }, 'private-token');
        await capturedConsoleFailure;
        await captureFailure(
          observer.navigate(
            page,
            'navigation',
            'http://127.0.0.1:1/?code=private-code',
            '/steps/navigation/value'
          ),
          failures
        );
      });

      await writeFile(
        processExecutable,
        `#!/bin/sh\nprintf '%s\\n' 'private-browser-stderr' >&2\n: > '${processMarker}'\nexit 73\n`,
        { mode: 0o700 }
      );
      const failingBrowserType: Pick<BrowserType<Browser>, 'launch'> = {
        launch: async (options) =>
          chromium.launch({
            ...options,
            executablePath: processExecutable,
          }),
      };
      const processObserver = createPlaywrightObserver({
        scenarioId: 'real-browser',
        browserType: failingBrowserType,
      });
      try {
        await processObserver.withContext('process', async () => 'unused');
      } catch (error: unknown) {
        failures.push(error);
      }
      await expect(access(processMarker)).resolves.toBeUndefined();
    } finally {
      capturedOutput = [
        ...stdout.mock.calls.flat().map(String),
        ...stderr.mock.calls.flat().map(String),
      ].join('\n');
      stdout.mockRestore();
      stderr.mockRestore();
      await rm(processDirectory, { force: true, recursive: true });
    }

    expect(failures).toHaveLength(5);
    expect(
      failures.map((error) =>
        error instanceof PlaywrightObservationError ? error.errorClass : 'unexpected'
      )
    ).toEqual(['locator', 'evaluation', 'console-event', 'navigation', 'browser-process']);
    const rendered = [
      ...failures.map((error) => `${String(error)} ${JSON.stringify(error)}`),
      capturedOutput,
    ].join('\n');
    for (const sentinel of [...sentinels, 'private-browser-stderr']) {
      expect(rendered).not.toContain(sentinel);
    }
  });
});

/* eslint-enable @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/consistent-type-assertions, @typescript-eslint/no-empty-function */
