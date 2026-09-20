/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/restrict-plus-operands, @silverhand/fp/no-mutation -- Hostile test cases mutate isolated JSON clones. */
import { performance } from 'node:perf_hooks';

import { jsonValueGuard } from '../../model.js';

import { requirePhase1BasicAcceptedResult } from './basic-result.js';
import { createPhase1BasicAcceptedResultFixture } from './basic-result.test-fixture.js';

const clone = <Value>(value: Value): Value => JSON.parse(JSON.stringify(value)) as Value;

describe('Phase 1 Basic accepted result', () => {
  it('validates complete module evidence repeatedly without blocking the consumer', () => {
    const value = createPhase1BasicAcceptedResultFixture();
    const started = performance.now();
    const results = Array.from({ length: 1000 }, () => jsonValueGuard.safeParse(value).success);
    const elapsedMs = performance.now() - started;

    expect(results.every(Boolean)).toBe(true);
    expect(elapsedMs).toBeLessThan(2000);
  });

  it('accepts the exact ordered 35-module result with approved screenshot reviews', () => {
    const value = createPhase1BasicAcceptedResultFixture();

    expect(requirePhase1BasicAcceptedResult(value)).toBe(value);
  });

  it('allows identical image bytes when independently bound reviews approve both captures', () => {
    const value = clone(createPhase1BasicAcceptedResultFixture()) as any;
    value.modules[17].review.imageSha256 = value.modules[14].review.imageSha256;

    expect(requirePhase1BasicAcceptedResult(value)).toBe(value);
  });

  it.each([14, 17, 27])('requires the fixed suite screenshot proof for module %s', (index) => {
    const value = clone(createPhase1BasicAcceptedResultFixture()) as any;
    value.modules[index].result = 'PASSED';
    value.modules[index].review = null;
    value.passedModuleCount += 1;
    value.reviewedModuleCount -= 1;

    expect(() => requirePhase1BasicAcceptedResult(value)).toThrow(
      /^Invalid phase 1 Basic conformance result$/u
    );
  });

  it.each([
    [
      'wrong count',
      (value: any) => {
        value.passedModuleCount += 1;
      },
    ],
    [
      'wrong order',
      (value: any) => {
        [value.modules[0], value.modules[1]] = [value.modules[1], value.modules[0]];
      },
    ],
    [
      'duplicate test ID',
      (value: any) => {
        value.modules[1].testId = value.modules[0].testId;
      },
    ],
    [
      'raw failure',
      (value: any) => {
        value.modules[0].result = 'FAILED';
      },
    ],
    [
      'missing review',
      (value: any) => {
        value.modules[14].review = null;
      },
    ],
    [
      'review on PASSED',
      (value: any) => {
        value.modules[0].review = value.modules[14].review;
      },
    ],
    [
      'wrong condition',
      (value: any) => {
        value.modules[14].review.conditionId = 'ExpectRedirectUriErrorPage';
      },
    ],
    [
      'unapproved review module',
      (value: any) => {
        value.modules[0].result = 'REVIEW';
        value.modules[0].review = value.modules[14].review;
        value.passedModuleCount -= 1;
        value.reviewedModuleCount += 1;
      },
    ],
    [
      'reused placeholder',
      (value: any) => {
        value.modules[17].review.placeholderId = value.modules[14].review.placeholderId;
      },
    ],
    [
      'reused review record',
      (value: any) => {
        value.modules[17].review.reviewRecordSha256 = value.modules[14].review.reviewRecordSha256;
      },
    ],
    [
      'rejected review',
      (value: any) => {
        value.modules[14].review.decision = 'REJECT';
      },
    ],
    [
      'unbounded reviewer',
      (value: any) => {
        value.modules[14].review.reviewer = 'x'.repeat(65);
      },
    ],
  ])('rejects %s', (_name, mutate) => {
    const value = clone(createPhase1BasicAcceptedResultFixture());
    mutate(value);

    expect(() => requirePhase1BasicAcceptedResult(value)).toThrow(
      /^Invalid phase 1 Basic conformance result$/u
    );
  });
});

/* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/restrict-plus-operands, @silverhand/fp/no-mutation */
