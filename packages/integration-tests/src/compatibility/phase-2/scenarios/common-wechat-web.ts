/* eslint-disable max-lines -- Exact projection validation and scenario execution share one publication boundary. */
import { isDeepStrictEqual, types as nodeTypes } from 'node:util';

import type { TargetConfig } from '../../model.js';
import type { Phase1BrowserGroupObserver } from '../../phase-1/browser/contracts.js';
import { asterNativeSurfaceContract } from '../../phase-1/native-surface.js';
import {
  runCommonWechatWebExistingOwnerForTarget,
  runCommonWechatWebProviderControlForTarget,
  runCommonWechatWebStateControlForTarget,
  runCommonWechatWebCrossInteractionForTarget,
  type CommonWechatWebExistingOwnerTargetDriverInput,
  type WechatProviderCredentialLease,
  type WechatProviderTargetConfiguration,
  type CommonWechatWebProviderControlKind,
} from '../browser/common-wechat-web-target-driver.js';
import type { SelectedWechatWebProviderLease } from '../browser/selected-wechat-web-connector-fixture.js';
import type { ProvisionedPhase2Fixture } from '../fixtures.js';

export const commonWechatWebScenarioIds = Object.freeze(['common.wechat.web'] as const);

export type CommonWechatWebProjection = Readonly<{
  channel: 'web';
  existingOwner: true;
  subjectPreserved: true;
  callback: 'state-issuer-code-bound';
  pkce: 'S256';
  refreshRotated: true;
  provider: Readonly<{
    setupRequests: 1;
    browserRequests: 1;
    providerRedirectExact: true;
    exchangeExact: true;
    userinfoExact: true;
    unionIdStable: true;
  }>;
  noUnionId: Readonly<{
    status: 400;
    error: 'connector.wechat_unionid_required';
    accepted: false;
    ownerPreserved: true;
  }>;
  invalidCode: Readonly<{
    status: 401;
    error: 'connector.social_auth_code_invalid';
    accepted: false;
    ownerPreserved: true;
  }>;
  replay: Readonly<{
    status: 401;
    error: 'connector.social_auth_code_invalid';
    accepted: false;
    ownerPreserved: true;
  }>;
  malformedProvider: Readonly<{
    status: 400;
    error: 'connector.invalid_response';
    accepted: false;
    ownerPreserved: true;
  }>;
  crossInteraction: Readonly<{
    status: 404;
    error: 'session.verification_session_not_found';
    accepted: false;
    ownerPreserved: true;
  }>;
  missingState: Readonly<{
    status: 0;
    error: 'none';
    accepted: false;
    ownerPreserved: true;
    statePreserved: true;
    proofPreserved: true;
    correctRetryAccepted: true;
  }>;
  wrongState: Readonly<{
    status: 0;
    error: 'none';
    accepted: false;
    ownerPreserved: true;
    statePreserved: true;
    proofPreserved: true;
    correctRetryAccepted: true;
  }>;
  wrongCallback: Readonly<{
    status: 0;
    error: 'none';
    accepted: false;
    ownerPreserved: true;
    statePreserved: true;
    proofPreserved: true;
    correctRetryAccepted: true;
  }>;
}>;
export type CommonWechatWebScenarioProjection = CommonWechatWebProjection;

export type CommonWechatWebScenarioResult = Readonly<{
  id: (typeof commonWechatWebScenarioIds)[number];
  projection: CommonWechatWebProjection;
}>;

export type CommonWechatWebFixtureRuntime = Readonly<{
  provider: WechatProviderTargetConfiguration;
  withProviderCredentialLease<Result>(
    use: (lease: WechatProviderCredentialLease) => Promise<Result>
  ): Promise<Result>;
  prepareProvider(
    input: Readonly<{
      connectorId: string;
      clientId: string;
      clientSecret: string;
      targetOrigin: string;
      role: 'oracle' | 'candidate';
      subject: string;
      providerCase?: 'positive' | CommonWechatWebProviderControlKind;
    }>
  ): Promise<SelectedWechatWebProviderLease & Readonly<{ takeBrowserCode(): Promise<string> }>>;
}>;

const fields = Object.freeze([
  'channel',
  'existingOwner',
  'subjectPreserved',
  'callback',
  'pkce',
  'refreshRotated',
  'provider',
  'noUnionId',
  'invalidCode',
  'replay',
  'malformedProvider',
  'crossInteraction',
  'missingState',
  'wrongState',
  'wrongCallback',
]);
const providerFields = Object.freeze([
  'setupRequests',
  'browserRequests',
  'providerRedirectExact',
  'exchangeExact',
  'userinfoExact',
  'unionIdStable',
]);
const controlFields = Object.freeze(['status', 'error', 'accepted', 'ownerPreserved']);
const stateControlFields = Object.freeze([
  'status',
  'error',
  'accepted',
  'ownerPreserved',
  'statePreserved',
  'proofPreserved',
  'correctRetryAccepted',
]);
const exactRecord = (value: unknown, expected: readonly string[]) => {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== expected.length
  ) {
    return;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  return expected.every((key) => descriptors[key]?.enumerable && 'value' in descriptors[key])
    ? Object.freeze(Object.fromEntries(expected.map((key) => [key, descriptors[key]?.value])))
    : undefined;
};
export const commonWechatWebExpectedProjection = Object.freeze({
  channel: 'web',
  existingOwner: true,
  subjectPreserved: true,
  callback: 'state-issuer-code-bound',
  pkce: 'S256',
  refreshRotated: true,
  provider: Object.freeze({
    setupRequests: 1,
    browserRequests: 1,
    providerRedirectExact: true,
    exchangeExact: true,
    userinfoExact: true,
    unionIdStable: true,
  }),
  noUnionId: Object.freeze({
    status: 400,
    error: 'connector.wechat_unionid_required',
    accepted: false,
    ownerPreserved: true,
  }),
  invalidCode: Object.freeze({
    status: 401,
    error: 'connector.social_auth_code_invalid',
    accepted: false,
    ownerPreserved: true,
  }),
  replay: Object.freeze({
    status: 401,
    error: 'connector.social_auth_code_invalid',
    accepted: false,
    ownerPreserved: true,
  }),
  malformedProvider: Object.freeze({
    status: 400,
    error: 'connector.invalid_response',
    accepted: false,
    ownerPreserved: true,
  }),
  crossInteraction: Object.freeze({
    status: 404,
    error: 'session.verification_session_not_found',
    accepted: false,
    ownerPreserved: true,
  }),
  missingState: Object.freeze({
    status: 0,
    error: 'none',
    accepted: false,
    ownerPreserved: true,
    statePreserved: true,
    proofPreserved: true,
    correctRetryAccepted: true,
  }),
  wrongState: Object.freeze({
    status: 0,
    error: 'none',
    accepted: false,
    ownerPreserved: true,
    statePreserved: true,
    proofPreserved: true,
    correctRetryAccepted: true,
  }),
  wrongCallback: Object.freeze({
    status: 0,
    error: 'none',
    accepted: false,
    ownerPreserved: true,
    statePreserved: true,
    proofPreserved: true,
    correctRetryAccepted: true,
  }),
});
const matches = (value: unknown): value is CommonWechatWebProjection => {
  const projection = exactRecord(value, fields);
  const provider = exactRecord(projection?.provider, providerFields);
  const noUnionId = exactRecord(projection?.noUnionId, controlFields);
  const invalidCode = exactRecord(projection?.invalidCode, controlFields);
  const replay = exactRecord(projection?.replay, controlFields);
  const malformedProvider = exactRecord(projection?.malformedProvider, controlFields);
  const crossInteraction = exactRecord(projection?.crossInteraction, controlFields);
  const missingState = exactRecord(projection?.missingState, stateControlFields);
  const wrongState = exactRecord(projection?.wrongState, stateControlFields);
  const wrongCallback = exactRecord(projection?.wrongCallback, stateControlFields);
  return Boolean(
    projection &&
      provider &&
      noUnionId &&
      invalidCode &&
      replay &&
      malformedProvider &&
      crossInteraction &&
      missingState &&
      wrongState &&
      wrongCallback &&
      isDeepStrictEqual(
        {
          ...projection,
          provider,
          noUnionId,
          invalidCode,
          replay,
          malformedProvider,
          crossInteraction,
          missingState,
          wrongState,
          wrongCallback,
        },
        commonWechatWebExpectedProjection
      )
  );
};

export const compareCommonWechatWebProjections = (
  oracle: unknown,
  candidate: unknown
): readonly string[] =>
  matches(oracle) && matches(candidate) && isDeepStrictEqual(oracle, candidate)
    ? []
    : ['/projection'];

export type CommonWechatWebProjectionDifference =
  | Readonly<{ field: 'contract'; oracleMatches: boolean; candidateMatches: boolean }>
  | Readonly<{
      field:
        | 'no-union-id-status'
        | 'no-union-id-error'
        | 'invalid-code-status'
        | 'invalid-code-error'
        | 'replay-status'
        | 'replay-error'
        | 'malformed-provider-status'
        | 'malformed-provider-error'
        | 'cross-interaction-status'
        | 'cross-interaction-error'
        | 'missing-state-status'
        | 'missing-state-error'
        | 'wrong-state-status'
        | 'wrong-state-error'
        | 'wrong-callback-status'
        | 'wrong-callback-error';
      oracle: number | string;
      candidate: number | string;
    }>;

// eslint-disable-next-line complexity -- The exact public control fields are checked in publication order.
export const describeCommonWechatWebProjectionDifference = (
  oracle: unknown,
  candidate: unknown
): CommonWechatWebProjectionDifference | undefined => {
  const oracleProjection = exactRecord(oracle, fields);
  const candidateProjection = exactRecord(candidate, fields);
  if (oracleProjection && candidateProjection) {
    for (const [key, field, expectedFields] of [
      ['noUnionId', 'no-union-id', controlFields],
      ['invalidCode', 'invalid-code', controlFields],
      ['replay', 'replay', controlFields],
      ['malformedProvider', 'malformed-provider', controlFields],
      ['crossInteraction', 'cross-interaction', controlFields],
      ['missingState', 'missing-state', stateControlFields],
      ['wrongState', 'wrong-state', stateControlFields],
      ['wrongCallback', 'wrong-callback', stateControlFields],
    ] as const) {
      const oracleControl = exactRecord(Reflect.get(oracleProjection, key), expectedFields);
      const candidateControl = exactRecord(Reflect.get(candidateProjection, key), expectedFields);
      if (
        oracleControl &&
        candidateControl &&
        typeof oracleControl.status === 'number' &&
        Number.isInteger(oracleControl.status) &&
        typeof candidateControl.status === 'number' &&
        Number.isInteger(candidateControl.status) &&
        typeof oracleControl.error === 'string' &&
        typeof candidateControl.error === 'string'
      ) {
        if (oracleControl.status !== candidateControl.status) {
          return Object.freeze({
            field: `${field}-status`,
            oracle: oracleControl.status,
            candidate: candidateControl.status,
          });
        }
        if (oracleControl.error !== candidateControl.error) {
          return Object.freeze({
            field: `${field}-error`,
            oracle: oracleControl.error,
            candidate: candidateControl.error,
          });
        }
      }
    }
  }
  const oracleMatches = matches(oracle);
  const candidateMatches = matches(candidate);
  if (!oracleMatches || !candidateMatches) {
    return Object.freeze({ field: 'contract', oracleMatches, candidateMatches });
  }
  if (isDeepStrictEqual(oracle, candidate)) {
    return undefined;
  }
  return Object.freeze({ field: 'contract', oracleMatches: true, candidateMatches: true });
};

const ownMessage = (error: unknown): string | undefined => {
  if (!(error instanceof Error) || nodeTypes.isProxy(error)) {
    return undefined;
  }
  const descriptor = Object.getOwnPropertyDescriptor(error, 'message');
  const value: unknown = descriptor && 'value' in descriptor ? descriptor.value : undefined;
  return typeof value === 'string' ? value : undefined;
};
const failurePatterns = Object.freeze([
  /^Common WeChat Web failed: (admission|initialization|provider-count|provider-click|consent-click|callback|profile|refresh|provider)$/u,
  /^Common WeChat Web failed: (callback-(?:callback-route|callback-facts-s(?:0|1|many)-c(?:0|1|many)-i(?:0|1|many)|cardinality|signin-(?:authority|response|client|redirect|mode|scope|resource|pkce)|callback-(?:authority|response|state|issuer|code)|exchange-(?:authority|response|correlation|client|refresh|target|scope|access)))$/u,
  /^Common Wechat existing-owner target failed: (admission|capability|cleanup|context|credentials|discovery|fixture|management)$/u,
  /^Common Wechat existing-owner target failed: (fixture-(?:read-sie|get-app|patch-app|read-app|read-resource|create-role|create-connector|prepare-connector|prepare-connector-docker-environment|prepare-connector-admission|prepare-connector-configuration-file|prepare-connector-receipt-file|prepare-connector-container-admission|prepare-connector-configuration-write|prepare-connector-start|prepare-connector-health|prepare-connector-compensation|prepare-connector-unknown|patch-sie|read-sie-updated|existing-owner-create-user|existing-owner-associate|existing-owner-read-before|existing-owner-use|existing-owner-read-after|existing-owner-cleanup-user|stop-provider|stop-provider-state|stop-provider-config-identity|stop-provider-receipt-identity|restore-app|delete-role|restore-sie|delete-connector))$/u,
  /^Common Wechat existing-owner target failed: (controls-(?:no-union-id|invalid-code|replay|malformed-provider|cross-interaction|missing-state|wrong-state|wrong-callback))$/u,
]);

export const describeCommonWechatWebFailure = (error: unknown): string | undefined => {
  const message = ownMessage(error);
  if (!message) {
    return undefined;
  }
  for (const pattern of failurePatterns) {
    const stage = pattern.exec(message)?.[1];
    if (stage) {
      return stage;
    }
  }
  return undefined;
};

const isRuntime = (value: unknown): value is CommonWechatWebFixtureRuntime =>
  typeof value === 'object' &&
  value !== null &&
  typeof Reflect.get(value, 'provider') === 'object' &&
  typeof Reflect.get(value, 'withProviderCredentialLease') === 'function' &&
  typeof Reflect.get(value, 'prepareProvider') === 'function';

type ControlStage =
  | 'no-union-id'
  | 'invalid-code'
  | 'replay'
  | 'malformed-provider'
  | 'cross-interaction'
  | 'missing-state'
  | 'wrong-state'
  | 'wrong-callback';
const runControl = async <Result>(stage: ControlStage, run: () => Promise<Result>) => {
  try {
    return await run();
  } catch {
    throw new TypeError(`Common Wechat existing-owner target failed: controls-${stage}`);
  }
};

export const runCommonWechatWebScenarioRow = async (
  input: Readonly<{
    target: TargetConfig;
    fixture: ProvisionedPhase2Fixture;
    observer: Phase1BrowserGroupObserver;
    signal: AbortSignal;
  }>
): Promise<CommonWechatWebScenarioResult> => {
  const { status } = input.fixture;
  const runtime: unknown = Reflect.get(input.fixture, 'commonWechatWeb');
  if (!status || !isRuntime(runtime)) {
    throw new TypeError('Invalid Common WeChat Web scenario fixture');
  }
  const driverInput: CommonWechatWebExistingOwnerTargetDriverInput = {
    ...input,
    browser: {
      storageKey:
        input.target.label === 'oracle'
          ? asterNativeSurfaceContract.markers.demoConfigStorageKey.reference
          : asterNativeSurfaceContract.markers.demoConfigStorageKey.candidate,
      demo: {
        appId: status.client.id,
        prompt: 'consent',
        scope: `openid offline_access profile email ${status.resource.scopeName}`,
        resource: status.resource.indicator,
      },
      redirectUri: new URL('/demo-app', input.target.coreUrl).href,
      initialResponseScope: 'openid offline_access profile email',
      resourceScope: status.resource.scopeName,
    },
    provider: runtime.provider,
    createObserver: () => input.observer,
    withProviderCredentialLease: runtime.withProviderCredentialLease,
    prepareProvider: runtime.prepareProvider,
  };
  const positive = await runCommonWechatWebExistingOwnerForTarget(driverInput);
  const noUnionId = await runControl('no-union-id', async () =>
    runCommonWechatWebProviderControlForTarget(driverInput, 'noUnionId')
  );
  const invalidCode = await runControl('invalid-code', async () =>
    runCommonWechatWebProviderControlForTarget(driverInput, 'invalidCode')
  );
  const replay = await runControl('replay', async () =>
    runCommonWechatWebProviderControlForTarget(driverInput, 'replay')
  );
  const malformedProvider = await runControl('malformed-provider', async () =>
    runCommonWechatWebProviderControlForTarget(driverInput, 'malformedProvider')
  );
  const cross = await runControl('cross-interaction', async () =>
    runCommonWechatWebCrossInteractionForTarget(driverInput)
  );
  const crossInteraction = Object.freeze({
    status: cross.secondStatus,
    error: cross.secondError,
    accepted: cross.secondAccepted,
    ownerPreserved: cross.ownerPreserved,
  });
  const missingState = await runControl('missing-state', async () =>
    runCommonWechatWebStateControlForTarget(driverInput, 'missingState')
  );
  const wrongState = await runControl('wrong-state', async () =>
    runCommonWechatWebStateControlForTarget(driverInput, 'wrongState')
  );
  const wrongCallback = await runControl('wrong-callback', async () =>
    runCommonWechatWebStateControlForTarget(driverInput, 'wrongCallback')
  );
  const projection = Object.freeze({
    ...positive,
    noUnionId,
    invalidCode,
    replay,
    malformedProvider,
    crossInteraction,
    missingState,
    wrongState,
    wrongCallback,
  });
  if (!matches(projection)) {
    throw new TypeError('Invalid Common WeChat Web scenario projection');
  }
  return Object.freeze({ id: commonWechatWebScenarioIds[0], projection });
};
/* eslint-enable max-lines */
