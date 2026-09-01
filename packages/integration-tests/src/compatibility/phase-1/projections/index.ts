export * from './account.js';
export * from './authorization.js';
export * from './concurrency.js';
export * from './consent-error.js';
export * from './consent.js';
export * from './console.js';
export * from './cookie.js';
export * from './cors.js';
export * from './discovery.js';
export * from './experience-error.js';
export * from './http.js';
export * from './management.js';
export * from './organization-token.js';
export * from './redirect.js';
export * from './semantic-state.js';
export * from './token-error.js';
export * from './token.js';
export * from './userinfo.js';

export const phase1ProjectionModuleIds = Object.freeze([
  'account',
  'authorization',
  'concurrency',
  'consent',
  'consent-error',
  'console',
  'cookie',
  'cors',
  'discovery',
  'experience-error',
  'http',
  'management',
  'organization-token',
  'redirect',
  'semantic-state',
  'token',
  'token-error',
  'userinfo',
] as const);
