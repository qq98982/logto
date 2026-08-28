const assertNonEmptyString = (value: string, description: string) => {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${description} must be a non-empty string`);
  }
};

const compareRuntimeValues = (left: string, right: string) =>
  right.length - left.length || (left < right ? -1 : left > right ? 1 : 0);

export type LiteralReplacementCandidate = {
  source: string;
  replacement: string;
  isMatch?: (value: string, endIndex: number) => boolean;
};

const compareCandidates = (left: LiteralReplacementCandidate, right: LiteralReplacementCandidate) =>
  compareRuntimeValues(left.source, right.source) ||
  (left.replacement < right.replacement ? -1 : left.replacement > right.replacement ? 1 : 0);

export const replaceLiteralCandidates = (
  value: string,
  candidateClasses: ReadonlyArray<readonly LiteralReplacementCandidate[]>
): string => {
  const candidates = candidateClasses.flatMap((candidateClass) =>
    candidateClass.toSorted(compareCandidates)
  );

  return Array.from({ length: value.length }, (_, index) => index).reduce(
    (state, index) => {
      if (index < state.skipUntil) {
        return state;
      }

      const candidate = candidates.find(({ source, isMatch }) => {
        const endIndex = index + source.length;

        return value.startsWith(source, index) && (isMatch?.(value, endIndex) ?? true);
      });

      return candidate
        ? {
            result: state.result + candidate.replacement,
            skipUntil: index + candidate.source.length,
          }
        : { result: state.result + value[index], skipUntil: index + 1 };
    },
    { result: '', skipUntil: 0 }
  ).result;
};

export class SymbolTable {
  readonly #logicalToRuntime = new Map<string, string>();
  readonly #runtimeToLogical = new Map<string, string>();
  readonly #occurrenceCounters = new Map<string, number>();

  bind(logicalName: string, runtimeValue: string): string {
    assertNonEmptyString(logicalName, 'Logical name');
    assertNonEmptyString(runtimeValue, 'Runtime value');

    const existingRuntimeValue = this.#logicalToRuntime.get(logicalName);
    const existingLogicalName = this.#runtimeToLogical.get(runtimeValue);

    if (existingRuntimeValue === runtimeValue && existingLogicalName === logicalName) {
      return logicalName;
    }

    if (existingRuntimeValue !== undefined) {
      throw new Error(`Logical name "${logicalName}" is already bound to another runtime value`);
    }

    if (existingLogicalName !== undefined) {
      throw new Error(`Runtime value is already bound to logical name "${existingLogicalName}"`);
    }

    this.#logicalToRuntime.set(logicalName, runtimeValue);
    this.#runtimeToLogical.set(runtimeValue, logicalName);

    return logicalName;
  }

  getRuntimeValue(logicalName: string): string | undefined {
    return this.#logicalToRuntime.get(logicalName);
  }

  getLogicalName(runtimeValue: string): string | undefined {
    return this.#runtimeToLogical.get(runtimeValue);
  }

  bindOccurrence(namespace: string, runtimeValue: string): string {
    assertNonEmptyString(namespace, 'Occurrence namespace');
    assertNonEmptyString(runtimeValue, 'Runtime value');

    const existingLogicalName = this.#runtimeToLogical.get(runtimeValue);

    if (existingLogicalName !== undefined) {
      return existingLogicalName;
    }

    const allocate = (occurrence: number): string => {
      const logicalName = `${namespace}.${occurrence}`;

      if (this.#logicalToRuntime.has(logicalName)) {
        return allocate(occurrence + 1);
      }

      this.bind(logicalName, runtimeValue);
      this.#occurrenceCounters.set(namespace, occurrence);

      return logicalName;
    };

    return allocate((this.#occurrenceCounters.get(namespace) ?? 0) + 1);
  }

  getReplacementCandidates(): LiteralReplacementCandidate[] {
    return Array.from(this.#runtimeToLogical.entries()).map(([source, logicalName]) => ({
      source,
      replacement: `<${logicalName}>`,
    }));
  }

  replace(value: string): string {
    return replaceLiteralCandidates(value, [this.getReplacementCandidates()]);
  }
}
