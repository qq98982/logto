import discoveryScenario from './discovery.js';
import passwordCodeScenario from './password-code.js';

export const defaultCompatibilityScenarios = Object.freeze([
  discoveryScenario,
  passwordCodeScenario,
] as const);
