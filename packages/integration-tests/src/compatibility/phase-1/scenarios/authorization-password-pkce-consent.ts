import type { Phase1ScenarioRunContext } from '../model.js';

import { withPositiveOidcFlow, type PositiveOidcFlowOptions } from './positive-oidc-flow.js';

export const runAuthorizationPasswordPkceConsent = async (
  context: Phase1ScenarioRunContext,
  options: PositiveOidcFlowOptions = {}
) => {
  const { steps } = await withPositiveOidcFlow(context, options, async () => null);

  return steps;
};
