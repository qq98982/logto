/* eslint-disable complexity -- Four target executions and comparison form one pair boundary. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import { assertEvidenceIsSanitized } from '../../evidence.js';
import type { CommonWechatH5RegistrationTargetDriverInput } from '../browser/common-wechat-h5-target-driver.js';
import { runCommonWechatH5RegistrationForTarget } from '../browser/common-wechat-h5-target-driver.js';
import type { CommonWechatWebExistingOwnerTargetDriverInput } from '../browser/common-wechat-web-target-driver.js';
import { runCommonWechatWebExistingOwnerForTarget } from '../browser/common-wechat-web-target-driver.js';

type Side = 'oracle' | 'candidate';
type Flow = 'web' | 'h5';
type PairStage = 'admission' | 'comparison' | 'sanitizer' | `${Flow}-${Side}`;
const fail = (stage: PairStage): never => {
  throw new TypeError(`Common WeChat Web/H5 pair failed: ${stage}`);
};

const plainData = (value: unknown): boolean => {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) {
    return true;
  }
  if (
    typeof value !== 'object' ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return false;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return (
    Object.getOwnPropertySymbols(value).length === 0 &&
    Object.values(descriptors).every(
      (descriptor) => 'value' in descriptor && descriptor.enumerable && plainData(descriptor.value)
    )
  );
};

export const runCommonWechatWebH5Pair = async (
  input: Readonly<{
    web: Readonly<{
      oracle: CommonWechatWebExistingOwnerTargetDriverInput;
      candidate: CommonWechatWebExistingOwnerTargetDriverInput;
    }>;
    h5: Readonly<{
      oracle: CommonWechatH5RegistrationTargetDriverInput;
      candidate: CommonWechatH5RegistrationTargetDriverInput;
    }>;
    webDriver?: typeof runCommonWechatWebExistingOwnerForTarget;
    h5Driver?: typeof runCommonWechatH5RegistrationForTarget;
  }>
) => {
  if (
    input.web.oracle.target.label !== 'oracle' ||
    input.web.candidate.target.label !== 'candidate' ||
    input.h5.oracle.target.label !== 'oracle' ||
    input.h5.candidate.target.label !== 'candidate'
  ) {
    return fail('admission');
  }
  const webDriver = input.webDriver ?? runCommonWechatWebExistingOwnerForTarget;
  const h5Driver = input.h5Driver ?? runCommonWechatH5RegistrationForTarget;
  const webOracle = await webDriver(input.web.oracle).catch(() => fail('web-oracle'));
  const webCandidate = await webDriver(input.web.candidate).catch(() => fail('web-candidate'));
  if (!plainData(webOracle) || !isDeepStrictEqual(webOracle, webCandidate)) {
    fail('comparison');
  }
  const h5Oracle = await h5Driver(input.h5.oracle).catch(() => fail('h5-oracle'));
  const h5Candidate = await h5Driver(input.h5.candidate).catch(() => fail('h5-candidate'));
  if (!plainData(h5Oracle) || !isDeepStrictEqual(h5Oracle, h5Candidate)) {
    fail('comparison');
  }
  const evidence = Object.freeze({
    schemaVersion: 1 as const,
    id: 'common.wechat.web-h5.browser-pair' as const,
    complete: true as const,
    web: Object.freeze({ oracle: webOracle, candidate: webCandidate }),
    h5: Object.freeze({ oracle: h5Oracle, candidate: h5Candidate }),
  });
  try {
    assertEvidenceIsSanitized(evidence);
  } catch {
    return fail('sanitizer');
  }
  return evidence;
};
/* eslint-enable complexity */
