import { CommonCompletionScenarioFailure } from '../scenarios/common-completion-runner.js';

import {
  getCommonCompletionBoundaryFailure,
  recordCommonCompletionBoundaryFailure,
} from './common-completion-target-driver.js';

describe('Common completion boundary diagnostics', () => {
  it('records a finite phase without replacing or inspecting the original error', () => {
    const error = new Error('private detail');
    // eslint-disable-next-line @silverhand/fp/no-mutating-methods
    Object.defineProperty(error, 'message', {
      configurable: true,
      get: () => {
        throw new Error('message must not be read');
      },
    });

    expect(recordCommonCompletionBoundaryFailure(error, 'runtime-read')).toBe(error);
    expect(getCommonCompletionBoundaryFailure(error)).toEqual({ phase: 'runtime-read' });
  });

  it('retains the known row when owned cleanup masks a scenario failure', () => {
    const bodyError = new CommonCompletionScenarioFailure('common.account.google-link');
    expect(recordCommonCompletionBoundaryFailure(bodyError, 'scenarios')).toBe(bodyError);

    const cleanupError = new AggregateError(
      [bodyError, new TypeError('private cleanup')],
      'cleanup failed'
    );
    expect(
      recordCommonCompletionBoundaryFailure(cleanupError, 'owned-app-cleanup', bodyError.scenarioId)
    ).toBe(cleanupError);
    expect(getCommonCompletionBoundaryFailure(cleanupError)).toEqual({
      phase: 'owned-app-cleanup',
      scenarioId: 'common.account.google-link',
    });
    expect(cleanupError.errors[0]).toBe(bodyError);
  });

  it('retains the direct password-policy phase across the target scenario boundary', () => {
    const error = new CommonCompletionScenarioFailure(
      'common.password.policy',
      'compromise-unavailable'
    );

    expect(recordCommonCompletionBoundaryFailure(error, 'scenarios')).toBe(error);
    expect(getCommonCompletionBoundaryFailure(error)).toEqual({
      phase: 'scenarios',
      scenarioId: 'common.password.policy',
      passwordPolicyPhase: 'compromise-unavailable',
    });
  });

  it('retains the direct logout phase across the target scenario boundary', () => {
    const error = new CommonCompletionScenarioFailure(
      'common.session.logout-preservation',
      undefined,
      'wechat-native-rejected-rp-cleanup'
    );

    expect(recordCommonCompletionBoundaryFailure(error, 'scenarios')).toBe(error);
    expect(getCommonCompletionBoundaryFailure(error)).toEqual({
      phase: 'scenarios',
      scenarioId: 'common.session.logout-preservation',
      logoutPhase: 'wechat-native-rejected-rp-cleanup',
    });
  });

  it('retains fixed configured-collision and machine-cleanup attribution', () => {
    const error = new Error('private lifecycle detail');
    recordCommonCompletionBoundaryFailure(
      error,
      'machine-cleanup-result',
      'common.google.configured-collision',
      {
        googleCollisionCheckpoint: 'configured-sign-in',
        machineLifecycleOutcome: 'body-and-cleanup-rejected',
      }
    );
    expect(getCommonCompletionBoundaryFailure(error)).toEqual({
      phase: 'machine-cleanup-result',
      scenarioId: 'common.google.configured-collision',
      googleCollisionCheckpoint: 'configured-sign-in',
      machineLifecycleOutcome: 'body-and-cleanup-rejected',
    });
  });

  it('does not derive diagnostics from arbitrary aggregate members', () => {
    const error = new AggregateError(
      [new CommonCompletionScenarioFailure('common.account.wechat-link')],
      'unclassified aggregate'
    );
    expect(getCommonCompletionBoundaryFailure(error)).toBeUndefined();
  });
});
