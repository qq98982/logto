import { type Difference, jsonValueGuard } from './model.js';

const maximumDisplayedStringLength = 500;
const truncationMarker = '...[truncated]';

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const getJsonType = (value: unknown) => {
  if (value === null) {
    return 'null';
  }

  if (Array.isArray(value)) {
    return 'array';
  }

  return typeof value;
};

const escapePointerSegment = (segment: string) =>
  segment.replaceAll('~', '~0').replaceAll('/', '~1');

const appendPointerSegment = (path: string, segment: string) =>
  `${path}/${escapePointerSegment(segment)}`;

const truncateString = (value: string) =>
  value.length <= maximumDisplayedStringLength
    ? value
    : `${value.slice(0, maximumDisplayedStringLength - truncationMarker.length)}${truncationMarker}`;

const createDisplayValue = (value: unknown): unknown => {
  if (typeof value === 'string') {
    return truncateString(value);
  }

  if (Array.isArray(value)) {
    return value.map((element) => createDisplayValue(element));
  }

  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, element]) => [key, createDisplayValue(element)])
    );
  }

  return value;
};

const isTimestampMarker = (
  value: unknown
): value is { $timestamp: number; $toleranceSeconds: number } => {
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

const createDifference = (path: string, oracle: unknown, candidate: unknown): Difference => ({
  path,
  oracle: createDisplayValue(oracle),
  candidate: createDisplayValue(candidate),
});

const compareArrays = (oracle: unknown[], candidate: unknown[], path: string): Difference[] => {
  const sharedLength = Math.min(oracle.length, candidate.length);
  const sharedDifferences = oracle
    .slice(0, sharedLength)
    .flatMap((value, index) =>
      compareValues(value, candidate[index], appendPointerSegment(path, String(index)))
    );
  const oracleOnlyDifferences = oracle.slice(sharedLength).map((value, offset) => ({
    path: appendPointerSegment(path, String(sharedLength + offset)),
    oracle: createDisplayValue(value),
  }));
  const candidateOnlyDifferences = candidate.slice(sharedLength).map((value, offset) => ({
    path: appendPointerSegment(path, String(sharedLength + offset)),
    candidate: createDisplayValue(value),
  }));

  return [...sharedDifferences, ...oracleOnlyDifferences, ...candidateOnlyDifferences];
};

const compareRecords = (
  oracle: Record<string, unknown>,
  candidate: Record<string, unknown>,
  path: string
): Difference[] => {
  const keys = Object.keys(oracle)
    .concat(Object.keys(candidate))
    .toSorted()
    .filter((key, index, sortedKeys) => index === 0 || key !== sortedKeys[index - 1]);

  return keys.flatMap((key) => {
    const childPath = appendPointerSegment(path, key);

    if (!Object.hasOwn(oracle, key)) {
      return [{ path: childPath, candidate: createDisplayValue(candidate[key]) }];
    }

    if (!Object.hasOwn(candidate, key)) {
      return [{ path: childPath, oracle: createDisplayValue(oracle[key]) }];
    }

    return compareValues(oracle[key], candidate[key], childPath);
  });
};

function compareValues(oracle: unknown, candidate: unknown, path: string): Difference[] {
  if (getJsonType(oracle) !== getJsonType(candidate)) {
    return [createDifference(path, oracle, candidate)];
  }

  if (isTimestampMarker(oracle) && isTimestampMarker(candidate)) {
    const tolerance = Math.min(oracle.$toleranceSeconds, candidate.$toleranceSeconds);

    return Math.abs(oracle.$timestamp - candidate.$timestamp) <= tolerance
      ? []
      : [createDifference(path, oracle, candidate)];
  }

  if (Array.isArray(oracle) && Array.isArray(candidate)) {
    return compareArrays(oracle, candidate, path);
  }

  if (isRecord(oracle) && isRecord(candidate)) {
    return compareRecords(oracle, candidate, path);
  }

  return oracle === candidate ? [] : [createDifference(path, oracle, candidate)];
}

const requireJsonValue = (value: unknown) => {
  if (!jsonValueGuard.safeParse(value).success) {
    throw new Error('Comparison input must be faithful JSON');
  }
};

export const compareJson = (oracle: unknown, candidate: unknown): Difference[] => {
  requireJsonValue(oracle);
  requireJsonValue(candidate);

  return compareValues(oracle, candidate, '');
};
