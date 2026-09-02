import { SymbolTable } from '../../symbol-table.js';
import { AccountClient } from '../clients/account.js';
import { ConsentClient } from '../clients/consent.js';
import { ExperienceClient } from '../clients/experience.js';
import { ManagementClient } from '../clients/management.js';
import { MemoryProtocolSecretStore, OidcClient } from '../clients/oidc.js';
import { StateClient } from '../clients/state.js';
import {
  bindPhase1FixtureSymbols,
  type Phase1FixtureAllocationRole,
  type Phase1FixtureSymbolTables,
} from '../fixture-map.js';
import type {
  Phase1AllocationProtocolClients,
  Phase1ProtocolSession,
  Phase1ProtocolSessionFactoryInput,
} from '../scenario-runtime.js';

export type Phase1ProtocolSessionBinding = Readonly<{
  session: Phase1ProtocolSession;
  symbols: Phase1FixtureSymbolTables;
}>;

const fail = (): never => {
  throw new TypeError('Invalid phase 1 protocol allocation');
};

export const createPhase1ProtocolSessionBinding = (
  input: Phase1ProtocolSessionFactoryInput
): Phase1ProtocolSessionBinding => {
  const symbols = bindPhase1FixtureSymbols(input.fixture.public);
  const publicStore = new MemoryProtocolSecretStore();
  const publicOidc = new OidcClient({
    target: input.target,
    fixture: Object.freeze({ public: Object.freeze({ allocations: Object.freeze([]) }) }),
    store: publicStore,
    signal: input.signal,
  });
  const clients = new Map<Phase1FixtureAllocationRole, Phase1AllocationProtocolClients>();

  for (const allocation of input.fixture.public.allocations) {
    if (clients.has(allocation.role)) {
      fail();
    }
    const allocationTarget =
      allocation.target === 'primary' ? input.target : (input.fixture.foreignTarget ?? fail());
    const store = new MemoryProtocolSecretStore();
    const options = Object.freeze({
      target: allocationTarget,
      fixture: input.fixture,
      allocationRole: allocation.role,
      store,
      signal: input.signal,
    });
    clients.set(
      allocation.role,
      Object.freeze({
        oidc: new OidcClient(options),
        experience: new ExperienceClient(options),
        consent: new ConsentClient(options),
        management: new ManagementClient(options),
        account: new AccountClient(options),
        state: new StateClient(options),
      })
    );
  }

  return Object.freeze({
    symbols,
    session: Object.freeze({
      publicOidc,
      publicSymbols: new SymbolTable(),
      forAllocation: (role: Phase1FixtureAllocationRole) => clients.get(role) ?? fail(),
      symbolsFor: (allocationId: string) => symbols.get(allocationId),
    }),
  });
};
