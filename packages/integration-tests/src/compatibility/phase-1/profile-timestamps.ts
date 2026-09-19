import type { Phase1Implementation } from './native-surface.js';

export const isValidProfileTimestamp = (
  value: unknown,
  implementation: Phase1Implementation
): value is number =>
  typeof value === 'number' &&
  Number.isSafeInteger(value) &&
  (implementation === 'oracle'
    ? value >= 100_000_000_000
    : value >= 100_000_000 && value < 100_000_000_000);

export const hasValidOptionalProfileTimestamps = (
  claims: Readonly<Record<string, unknown>>,
  implementation: Phase1Implementation
): boolean => {
  const { created_at: createdAt, updated_at: updatedAt } = claims;

  return (
    ['created_at', 'updated_at'].every(
      (key) => !Object.hasOwn(claims, key) || isValidProfileTimestamp(claims[key], implementation)
    ) &&
    (createdAt === undefined ||
      updatedAt === undefined ||
      (typeof createdAt === 'number' && typeof updatedAt === 'number' && updatedAt >= createdAt))
  );
};
