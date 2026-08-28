const assertNonEmptyString = (value: string, description: string) => {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${description} must be a non-empty string`);
  }
};

const compareRuntimeValues = (left: string, right: string) =>
  right.length - left.length || (left < right ? -1 : left > right ? 1 : 0);

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

  replace(value: string): string {
    const bindings = Array.from(this.#runtimeToLogical.entries()).toSorted(([left], [right]) =>
      compareRuntimeValues(left, right)
    );

    return Array.from({ length: value.length }, (_, index) => index).reduce(
      (state, index) => {
        if (index < state.skipUntil) {
          return state;
        }

        const binding = bindings.find(([runtimeValue]) => value.startsWith(runtimeValue, index));

        return binding
          ? {
              result: `${state.result}<${binding[1]}>`,
              skipUntil: index + binding[0].length,
            }
          : { result: state.result + value[index], skipUntil: index + 1 };
      },
      { result: '', skipUntil: 0 }
    ).result;
  }
}
