/* eslint-disable complexity, max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods -- Candidate-only verification controls deliberately sequence real credentials, deliveries, denials, and persistence probes. */
import type { TargetConfig } from '../../model.js';
import {
  runPhase1FixtureCommand,
  type CommandRunnerRequest,
  type CommandRunnerResult,
} from '../../phase-1/clients/command-provisioner.js';
import { issuePublicUserTokensForSubject } from '../clients/user-token-issuance.js';
import { observeVerificationCodePrivate } from '../clients/verification-code.js';
import { phase2InvariantRequestKind, phase2InvariantTerminalKind } from '../driver-protocol.js';
import type { Phase2FixtureSecretLease, ProvisionedPhase2Fixture } from '../fixtures.js';
import type { Phase2TopologyIdentity } from '../provenance.js';
import type { Phase2InvocationFence } from '../runtime.js';

import {
  verificationCodeCandidateInvariantExpectedProjection,
  type VerificationCodeCandidateInvariantExecutor,
  type VerificationCodeCandidateInvariantId,
  type VerificationCodeCandidateInvariantProjection,
} from './verification-code.js';

export type VerificationCodePersistenceProbe = (
  input: Readonly<{
    id: VerificationCodeCandidateInvariantId;
    recipient: string;
    code?: string;
    stage: 'final' | 'before-consumption' | 'after-consumption';
  }>
) => Promise<Readonly<Record<string, unknown>>>;

type LiveOptions = Readonly<{
  target: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  lease: Phase2FixtureSecretLease;
  ownerBearer: string;
  crossClientBearer: string;
  crossTenantBearer: string;
  wrongAudienceBearer: string;
  persistenceProbe: VerificationCodePersistenceProbe;
  fetch?: typeof fetch;
}>;

type ProbeOptions = Readonly<{
  target: TargetConfig;
  foreignTarget: TargetConfig;
  fixture: ProvisionedPhase2Fixture;
  driverPath: string;
  controlSocket: string;
  topology: Phase2TopologyIdentity;
  identityFence?: Phase2InvocationFence;
  runner?: (request: CommandRunnerRequest) => Promise<CommandRunnerResult>;
}>;

const fail = (): never => {
  throw new TypeError('Invalid Phase 2 live verification-code candidate invariant');
};

export const createCommandVerificationCodePersistenceProbe =
  (options: ProbeOptions): VerificationCodePersistenceProbe =>
  async (input) => {
    const descriptor = Object.freeze({
      schemaVersion: 1,
      kind: phase2InvariantRequestKind,
      invariantId: input.id,
      operation: 'probe',
      target: Object.freeze({ primary: options.target, foreign: options.foreignTarget }),
      fixture: options.fixture.public,
      private: Object.freeze({
        recipient: input.recipient,
        ...(input.code === undefined ? {} : { code: input.code }),
      }),
      observation: Object.freeze({ stage: input.stage }),
    });
    const invoke = async () =>
      (options.runner ?? runPhase1FixtureCommand)({
        command: options.driverPath,
        args: Object.freeze([]),
        stdin: JSON.stringify(descriptor),
        env: Object.freeze({
          ASTER_PHASE2_CONTROL_SOCKET: options.controlSocket,
          ASTER_CORE_URL: options.target.coreUrl,
          ASTER_ADMIN_URL: options.target.adminUrl,
          ASTER_FOREIGN_CORE_URL: options.foreignTarget.coreUrl,
          ASTER_FOREIGN_ADMIN_URL: options.foreignTarget.adminUrl,
          LC_ALL: 'C',
        }),
        timeoutMs: 120_000,
        maxStdoutBytes: 65_536,
        maxStderrBytes: 65_536,
        shell: false,
      });
    const result = options.identityFence ? await options.identityFence.run(invoke) : await invoke();
    if (
      result.exitCode !== 0 ||
      result.signal !== null ||
      result.stderr !== '' ||
      result.timedOut ||
      result.killed ||
      !result.reaped
    ) {
      return fail();
    }
    const terminal = JSON.parse(result.stdout) as Record<string, unknown>;
    if (
      terminal.schemaVersion !== 1 ||
      terminal.kind !== phase2InvariantTerminalKind ||
      terminal.invariantId !== input.id ||
      JSON.stringify(terminal.attestation) !== JSON.stringify(options.topology) ||
      typeof terminal.projection !== 'object' ||
      terminal.projection === null ||
      Array.isArray(terminal.projection)
    ) {
      return fail();
    }
    return Object.freeze({ ...(terminal.projection as Record<string, unknown>) });
  };

const error = (projection: Awaited<ReturnType<typeof observeVerificationCodePrivate>>) => {
  const { status, outcome, error: code } = projection.projection;
  if (
    outcome !== 'error' ||
    typeof code !== 'string' ||
    (status !== 400 && status !== 401 && status !== 503)
  ) {
    return fail();
  }
  return Object.freeze({ status, error: code });
};

export const createLiveVerificationCodeCandidateInvariantExecutor = async (
  options: LiveOptions
): Promise<VerificationCodeCandidateInvariantExecutor> => {
  const requestFetch = options.fetch ?? fetch;
  const peer = options.fixture.verificationPeer ?? fail();
  const peerTokens = await issuePublicUserTokensForSubject(
    options.target,
    options.fixture,
    {
      username: peer.username,
      password: options.lease.getVerificationPeerPassword?.() ?? fail(),
    },
    requestFetch
  );
  const take = async (recipient: string): Promise<string> =>
    options.lease.takeVerificationCode?.(recipient) ?? fail();
  const request = async (recipient: string) => {
    const result = await observeVerificationCodePrivate(
      {
        target: options.target,
        surface: 'account',
        operation: 'request',
        identifier: recipient,
        bearer: options.ownerBearer,
      },
      requestFetch
    );
    return Object.freeze({
      projection: result.projection,
      handle: result.handle ?? fail(),
      code: await take(recipient),
    });
  };
  const verify = async (recipient: string, handle: string, code: string, bearer: string) =>
    observeVerificationCodePrivate(
      {
        target: options.target,
        surface: 'account',
        operation: 'verify',
        identifier: recipient,
        handle,
        code,
        bearer,
      },
      requestFetch
    );
  const ownership = async (
    id: VerificationCodeCandidateInvariantId,
    bearer: string
  ): Promise<VerificationCodeCandidateInvariantProjection> => {
    const recipient = `${id.split('.')[1]}@phase2.example.invalid`;
    const challenge = await request(recipient);
    const denied = error(await verify(recipient, challenge.handle, challenge.code, bearer));
    const accepted = await verify(recipient, challenge.handle, challenge.code, options.ownerBearer);
    if (accepted.projection.status !== 200 || accepted.projection.outcome !== 'verified') {
      return fail();
    }
    return Object.freeze({
      invariant: verificationCodeCandidateInvariantExpectedProjection(id).invariant,
      denied,
      ownerAfterDenial: 'verified' as const,
      challengeConsumedByDenial: false as const,
    }) as VerificationCodeCandidateInvariantProjection;
  };
  return Object.freeze({
    execute: async (id) => {
      if (id === 'verification-code.cross-tenant-owner-rejected') {
        return ownership(id, options.crossTenantBearer);
      }
      if (id === 'verification-code.cross-account-owner-rejected') {
        return ownership(id, peerTokens.access);
      }
      if (id === 'verification-code.cross-client-owner-rejected') {
        return ownership(id, options.crossClientBearer);
      }
      if (id === 'verification-code.wrong-audience-rejected') {
        return ownership(id, options.wrongAudienceBearer);
      }
      const recipient = `${id.split('.')[1]}@phase2.example.invalid`;
      if (id === 'verification-code.retry-budget-committed') {
        const challenge = await request(recipient);
        const wrong = `${challenge.code.startsWith('0') ? '1' : '0'}${challenge.code.slice(1)}`;
        const attempts = [];
        for (let index = 0; index < 10; index += 1) {
          attempts.push(
            error(await verify(recipient, challenge.handle, wrong, options.ownerBearer))
          );
        }
        const wrongAfterCap = error(
          await verify(recipient, challenge.handle, wrong, options.ownerBearer)
        );
        const correct = error(
          await verify(recipient, challenge.handle, challenge.code, options.ownerBearer)
        );
        const persisted = await options.persistenceProbe({ id, recipient, stage: 'final' });
        if (
          attempts.some(({ error: code }) => code !== 'verification_code.code_mismatch') ||
          wrongAfterCap.error !== 'verification_code.exceed_max_try' ||
          correct.error !== 'verification_code.exceed_max_try' ||
          persisted.failedAttempts !== 10 ||
          persisted.envelopeCleared !== true
        ) {
          return fail();
        }
        return verificationCodeCandidateInvariantExpectedProjection(id);
      }
      if (id === 'verification-code.concurrent-single-consumer') {
        const challenge = await request(recipient);
        const results = await Promise.all([
          verify(recipient, challenge.handle, challenge.code, options.ownerBearer),
          verify(recipient, challenge.handle, challenge.code, options.ownerBearer),
        ]);
        const winnerCount = results.filter(({ projection }) => projection.status === 200).length;
        const loser = results.find(({ projection }) => projection.status !== 200) ?? fail();
        const persisted = await options.persistenceProbe({ id, recipient, stage: 'final' });
        if (
          winnerCount !== 1 ||
          error(loser).error !== 'verification_code.not_found' ||
          persisted.consumed !== true
        ) {
          return fail();
        }
        return verificationCodeCandidateInvariantExpectedProjection(id);
      }
      if (id === 'verification-code.failed-delivery-state-preserved') {
        const challenge = await request(recipient);
        const failedResponse = await observeVerificationCodePrivate(
          {
            target: options.target,
            surface: 'account',
            operation: 'request',
            identifier: recipient,
            bearer: options.ownerBearer,
          },
          requestFetch
        );
        const failed = error(failedResponse);
        const persisted = await options.persistenceProbe({ id, recipient, stage: 'final' });
        const accepted = await verify(
          recipient,
          challenge.handle,
          challenge.code,
          options.ownerBearer
        );
        if (
          failed.status !== 400 ||
          failed.error !== 'connector.general' ||
          failedResponse.projection.message !== 'The email service could not accept the message.' ||
          accepted.projection.status !== 200 ||
          persisted.successfulSendReceipts !== 1 ||
          persisted.replacementRows !== 0
        ) {
          return fail();
        }
        return verificationCodeCandidateInvariantExpectedProjection(id);
      }
      const challenge = await request(recipient);
      const before = await options.persistenceProbe({
        id,
        recipient,
        code: challenge.code,
        stage: 'before-consumption',
      });
      const accepted = await verify(
        recipient,
        challenge.handle,
        challenge.code,
        options.ownerBearer
      );
      const after = await options.persistenceProbe({ id, recipient, stage: 'after-consumption' });
      if (
        accepted.projection.status !== 200 ||
        before.forcedRls !== true ||
        before.clearCodeColumns !== 'absent' ||
        before.codeAbsentFromRows !== true ||
        before.ciphertextPresent !== true ||
        after.ciphertextCleared !== true
      ) {
        return fail();
      }
      return verificationCodeCandidateInvariantExpectedProjection(id);
    },
  });
};
/* eslint-enable complexity, max-lines, no-await-in-loop, no-restricted-syntax, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods */
