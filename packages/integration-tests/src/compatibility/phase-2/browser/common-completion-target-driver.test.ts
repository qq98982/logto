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

  it('does not derive diagnostics from arbitrary aggregate members', () => {
    const error = new AggregateError(
      [new CommonCompletionScenarioFailure('common.account.wechat-link')],
      'unclassified aggregate'
    );
    expect(getCommonCompletionBoundaryFailure(error)).toBeUndefined();
  });
});
