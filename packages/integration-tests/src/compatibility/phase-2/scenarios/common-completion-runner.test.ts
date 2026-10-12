import {
  CommonCompletionScenarioFailure,
  runCommonCompletionScenariosForTarget,
  type CommonCompletionFixtureRuntime,
} from './common-completion-runner.js';

test('reports the failed approved row without exposing its private fixture error', async () => {
  const fixture = {
    public: {},
    withSecretLease: async () => {
      throw new Error('synthetic-private-fixture-secret');
    },
  } as unknown as Parameters<typeof runCommonCompletionScenariosForTarget>[0]['fixture'];
  const observer = Object.freeze({}) as Parameters<
    typeof runCommonCompletionScenariosForTarget
  >[0]['observer'];
  const runtime = Object.freeze({ google: {}, web: {} }) as CommonCompletionFixtureRuntime;
  const result = runCommonCompletionScenariosForTarget({
    target: {
      label: 'oracle',
      coreUrl: 'http://localhost:3311/',
      adminUrl: 'http://localhost:3312/',
    },
    fixture,
    runtime,
    observer,
    jwks: { keys: [] },
    signal: AbortSignal.timeout(10_000),
  });
  await expect(result).rejects.toBeInstanceOf(CommonCompletionScenarioFailure);
  await expect(result).rejects.toMatchObject({
    scenarioId: 'common.password.policy',
    message: 'Common completion scenario failed: common.password.policy',
  });
});
