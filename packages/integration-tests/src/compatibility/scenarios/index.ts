import discoveryScenario from './discovery.js';
import { createPasswordCodeScenario, type PasswordCodeFixtureLifecycle } from './password-code.js';

export const createCompatibilityScenarios = (
  options: Readonly<{ passwordCodeLifecycle?: PasswordCodeFixtureLifecycle }> = {}
) =>
  Object.freeze([
    discoveryScenario,
    createPasswordCodeScenario(
      options.passwordCodeLifecycle
        ? { fixtureLifecycle: options.passwordCodeLifecycle }
        : undefined
    ),
  ] as const);

export const defaultCompatibilityScenarios = createCompatibilityScenarios();
