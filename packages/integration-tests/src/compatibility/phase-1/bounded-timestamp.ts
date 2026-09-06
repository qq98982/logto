const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

export type BoundedTimestampEnvelope = Readonly<{
  $timestamp: number;
  $toleranceSeconds: number;
}>;

/** Matches the immutable Phase 0 comparator's bounded-timestamp envelope contract. */
export const isBoundedTimestampEnvelope = (value: unknown): value is BoundedTimestampEnvelope => {
  if (!isRecord(value)) {
    return false;
  }
  const keys = Object.keys(value).toSorted();

  return (
    keys.length === 2 &&
    keys[0] === '$timestamp' &&
    keys[1] === '$toleranceSeconds' &&
    typeof value.$timestamp === 'number' &&
    Number.isFinite(value.$timestamp) &&
    typeof value.$toleranceSeconds === 'number' &&
    Number.isFinite(value.$toleranceSeconds) &&
    value.$toleranceSeconds >= 0
  );
};
