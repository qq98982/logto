/* eslint-disable complexity, max-lines, no-await-in-loop, no-bitwise, no-control-regex, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/member-ordering, @typescript-eslint/prefer-nullish-coalescing -- The authority uses a runtime-loaded compiler, mutable graph traversal, Linux open flags, strict control-character paths, and bytewise sorted Git views. */
import { execFile } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { promisify } from 'node:util';

import type * as TypeScript from 'typescript';

const ts = createRequire(import.meta.url)('typescript') as typeof TypeScript;

const acceptedHarnessCommit = '83d08f0821345d1bdc01491152949cc6f044ecfb';
const diagnostic = 'Invalid Phase 2 accepted Phase 1 source closure';
const maximumSourceBytes = 4 * 1024 * 1024;
const commitPattern = /^[0-9a-f]{40}$/u;
const canonicalOrigins = new Set([
  'https://github.com/qq98982/logto.git',
  'git@github.com:qq98982/logto.git',
  'ssh://git@github.com/qq98982/logto.git',
]);
const sourceRoot = 'packages/integration-tests/src/';
const phase1SourcePrefix = 'packages/integration-tests/src/compatibility/phase-1/';

export const acceptedPhase1ExecutionRoots = Object.freeze(
  [
    'packages/integration-tests/src/compatibility/compare.ts',
    'packages/integration-tests/src/compatibility/phase-1/artifact-contract.ts',
    'packages/integration-tests/src/compatibility/phase-1/clients/command-provisioner.ts',
    'packages/integration-tests/src/compatibility/phase-1/clients/reference-provisioner.ts',
    'packages/integration-tests/src/compatibility/phase-1/differential/http-compatibility.ts',
    'packages/integration-tests/src/compatibility/phase-1/differential/reference-state.ts',
    'packages/integration-tests/src/compatibility/phase-1/differential/runtime.ts',
    'packages/integration-tests/src/compatibility/phase-1/differential/session.ts',
    'packages/integration-tests/src/compatibility/phase-1/evidence-envelope.ts',
    'packages/integration-tests/src/compatibility/phase-1/evidence.ts',
    'packages/integration-tests/src/compatibility/phase-1/fixtures.ts',
    'packages/integration-tests/src/compatibility/phase-1/native-surface-artifact.ts',
    'packages/integration-tests/src/compatibility/phase-1/native-surface-profile.ts',
    'packages/integration-tests/src/compatibility/phase-1/normalizers.ts',
    'packages/integration-tests/src/compatibility/phase-1/scenario-runtime.ts',
    'packages/integration-tests/src/compatibility/phase-1/scenarios/index.ts',
  ].sort()
);

export type Phase1SourceClosureFile = Readonly<{
  path: string;
  source: string;
  blobId: string;
  symbolicLink?: boolean;
}>;

export type Phase1SourceClosureReader = (relativePath: string) => Promise<Phase1SourceClosureFile>;

export type AcceptedPhase1SourceClosureManifest = Readonly<{
  acceptedCommit: string;
  roots: readonly string[];
  files: ReadonlyArray<Readonly<{ path: string; blobId: string }>>;
}>;

export type Phase1SourceClosureInspection = Readonly<{
  head: string;
  origin: string;
  clean: boolean;
  phase1ModifiedPaths: readonly string[];
}>;

export type Phase1SourceClosureDependencies = Readonly<{
  inspect(repositoryRoot: string): Promise<Phase1SourceClosureInspection>;
  readCurrent: Phase1SourceClosureReader;
  readAccepted: Phase1SourceClosureReader;
}>;

const executeFile = promisify(execFile);

const fail = (): never => {
  throw new TypeError(diagnostic);
};

const moduleText = (node: TypeScript.Expression | undefined): string | undefined =>
  node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
    ? node.text
    : undefined;

const importHasRuntimeBinding = (declaration: TypeScript.ImportDeclaration): boolean => {
  const clause = declaration.importClause;

  if (!clause) {
    return true;
  }
  if (clause.isTypeOnly) {
    return false;
  }
  if (clause.name || (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings))) {
    return true;
  }

  return (
    clause.namedBindings !== undefined &&
    ts.isNamedImports(clause.namedBindings) &&
    clause.namedBindings.elements.some((element) => !element.isTypeOnly)
  );
};

const exportHasRuntimeBinding = (declaration: TypeScript.ExportDeclaration): boolean => {
  if (declaration.isTypeOnly) {
    return false;
  }
  if (!declaration.exportClause || ts.isNamespaceExport(declaration.exportClause)) {
    return true;
  }

  return declaration.exportClause.elements.some((element) => !element.isTypeOnly);
};

export const runtimeValueImportSpecifiers = (source: string): readonly string[] => {
  let file: TypeScript.SourceFile;

  try {
    const { diagnostics } = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ESNext },
      reportDiagnostics: true,
    });

    if (diagnostics?.some(({ category }) => category === ts.DiagnosticCategory.Error)) {
      return fail();
    }
    file = ts.createSourceFile(
      'closure.ts',
      source,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TS
    );
  } catch {
    return fail();
  }
  const values: string[] = [];
  const add = (value: string | undefined) => {
    if (value !== undefined && value.startsWith('.') && !values.includes(value)) {
      values.push(value);
    }
  };
  const visit = (node: TypeScript.Node): void => {
    if (ts.isImportDeclaration(node) && importHasRuntimeBinding(node)) {
      add(moduleText(node.moduleSpecifier));
    } else if (
      ts.isExportDeclaration(node) &&
      exportHasRuntimeBinding(node) &&
      node.moduleSpecifier
    ) {
      add(moduleText(node.moduleSpecifier));
    } else if (
      ts.isCallExpression(node) &&
      node.expression.kind === ts.SyntaxKind.ImportKeyword &&
      node.arguments.length === 1
    ) {
      add(moduleText(node.arguments[0]));
    }
    ts.forEachChild(node, visit);
  };
  visit(file);

  return Object.freeze(values);
};

const assertRelativeSourcePath = (value: string): string => {
  if (
    path.posix.normalize(value) !== value ||
    value.startsWith('/') ||
    value.startsWith('../') ||
    !value.startsWith(sourceRoot) ||
    !value.endsWith('.ts') ||
    value.endsWith('.test.ts') ||
    /[\u0000-\u001F\u007F\\]/u.test(value)
  ) {
    return fail();
  }

  return value;
};

const resolveSpecifier = (from: string, specifier: string): string => {
  if (
    !specifier.startsWith('.') ||
    specifier.includes('?') ||
    specifier.includes('#') ||
    path.posix.extname(specifier) !== '.js'
  ) {
    return fail();
  }
  const target = path.posix.normalize(
    path.posix.join(path.posix.dirname(from), `${specifier.slice(0, -3)}.ts`)
  );

  return assertRelativeSourcePath(target);
};

const readChecked = async (
  reader: Phase1SourceClosureReader,
  filePath: string
): Promise<Phase1SourceClosureFile> => {
  let file: Phase1SourceClosureFile;

  try {
    file = await reader(filePath);
  } catch {
    return fail();
  }
  if (
    file.path !== filePath ||
    file.symbolicLink === true ||
    typeof file.source !== 'string' ||
    Buffer.byteLength(file.source) === 0 ||
    Buffer.byteLength(file.source) > maximumSourceBytes ||
    !commitPattern.test(file.blobId)
  ) {
    return fail();
  }

  return file;
};

const collectClosure = async (
  roots: readonly string[],
  reader: Phase1SourceClosureReader
): Promise<ReadonlyMap<string, Phase1SourceClosureFile>> => {
  const pending = [...roots].reverse();
  const files = new Map<string, Phase1SourceClosureFile>();

  while (pending.length > 0) {
    const current = pending.pop();

    if (!current || files.has(current)) {
      continue;
    }
    const file = await readChecked(reader, current);
    files.set(current, file);
    const imports = runtimeValueImportSpecifiers(file.source);

    for (const specifier of imports.toReversed()) {
      const resolved = resolveSpecifier(current, specifier);

      if (!files.has(resolved)) {
        pending.push(resolved);
      }
    }
  }

  return files;
};

export const buildAcceptedPhase1SourceClosureManifest = async (
  input: Readonly<{
    acceptedCommit: string;
    roots: readonly string[];
    current: Phase1SourceClosureReader;
    accepted: Phase1SourceClosureReader;
  }>
): Promise<AcceptedPhase1SourceClosureManifest> => {
  if (
    !commitPattern.test(input.acceptedCommit) ||
    input.roots.length === 0 ||
    new Set(input.roots).size !== input.roots.length
  ) {
    return fail();
  }
  const roots = Object.freeze(input.roots.map((root) => assertRelativeSourcePath(root)).toSorted());
  const [current, accepted] = await Promise.all([
    collectClosure(roots, input.current),
    collectClosure(roots, input.accepted),
  ]);
  const currentPaths = [...current.keys()].toSorted();
  const acceptedPaths = [...accepted.keys()].toSorted();

  if (
    currentPaths.length !== acceptedPaths.length ||
    currentPaths.some((value, index) => value !== acceptedPaths[index])
  ) {
    return fail();
  }
  const files = currentPaths.map((filePath) => {
    const currentFile = current.get(filePath) ?? fail();
    const acceptedFile = accepted.get(filePath) ?? fail();

    if (currentFile.blobId !== acceptedFile.blobId || currentFile.source !== acceptedFile.source) {
      return fail();
    }

    return Object.freeze({ path: filePath, blobId: acceptedFile.blobId });
  });

  return Object.freeze({
    acceptedCommit: input.acceptedCommit,
    roots,
    files: Object.freeze(files),
  });
};

const gitEnvironment = Object.freeze({
  GIT_CONFIG_COUNT: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_KEY_0: 'credential.helper',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_VALUE_0: '',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_TERMINAL_PROMPT: '0',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin',
});

const gitText = async (root: string, args: readonly string[]): Promise<string> => {
  try {
    const { stdout, stderr } = await executeFile(
      '/usr/bin/git',
      ['--no-replace-objects', ...args],
      {
        cwd: root,
        encoding: 'utf8',
        env: gitEnvironment,
        maxBuffer: 4 * 1024 * 1024,
        timeout: 30_000,
      }
    );

    return stderr === '' ? stdout.trim() : fail();
  } catch {
    return fail();
  }
};

const gitBytes = async (root: string, args: readonly string[]): Promise<Uint8Array> => {
  try {
    const { stdout, stderr } = await executeFile(
      '/usr/bin/git',
      ['--no-replace-objects', ...args],
      {
        cwd: root,
        encoding: 'buffer',
        env: gitEnvironment,
        maxBuffer: maximumSourceBytes,
        timeout: 30_000,
      }
    );

    return stderr.byteLength === 0 ? stdout : fail();
  } catch {
    return fail();
  }
};

const decodeSource = (bytes: Uint8Array): string => {
  if (bytes.byteLength === 0 || bytes.byteLength > maximumSourceBytes) {
    return fail();
  }
  try {
    return new TextDecoder('utf8', { fatal: true }).decode(bytes);
  } catch {
    return fail();
  }
};

const stableCurrentReader =
  (root: string): Phase1SourceClosureReader =>
  async (relativePath) => {
    const safePath = assertRelativeSourcePath(relativePath);
    const absolute = path.join(root, safePath);
    const before = await lstat(absolute).catch(fail);

    if (
      before.isSymbolicLink() ||
      !before.isFile() ||
      before.size === 0 ||
      before.size > maximumSourceBytes ||
      (await realpath(absolute).catch(fail)) !== absolute
    ) {
      return fail();
    }
    const handle = await open(absolute, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW).catch(fail);

    try {
      const opened = await handle.stat();
      const bytes = await handle.readFile();
      const [after, pathAfter] = await Promise.all([handle.stat(), lstat(absolute)]);

      if (
        opened.dev !== before.dev ||
        opened.ino !== before.ino ||
        opened.size !== before.size ||
        after.dev !== opened.dev ||
        after.ino !== opened.ino ||
        after.size !== opened.size ||
        after.mtimeMs !== opened.mtimeMs ||
        pathAfter.isSymbolicLink() ||
        pathAfter.dev !== opened.dev ||
        pathAfter.ino !== opened.ino ||
        pathAfter.size !== opened.size ||
        pathAfter.mtimeMs !== opened.mtimeMs
      ) {
        return fail();
      }
      const blobId = await gitText(root, ['hash-object', '--no-filters', '--', safePath]);

      return Object.freeze({ path: safePath, source: decodeSource(bytes), blobId });
    } finally {
      await handle.close();
    }
  };

const acceptedReader =
  (root: string): Phase1SourceClosureReader =>
  async (relativePath) => {
    const safePath = assertRelativeSourcePath(relativePath);
    const [bytes, blobId] = await Promise.all([
      gitBytes(root, ['show', `${acceptedHarnessCommit}:${safePath}`]),
      gitText(root, ['rev-parse', `${acceptedHarnessCommit}:${safePath}`]),
    ]);

    return Object.freeze({ path: safePath, source: decodeSource(bytes), blobId });
  };

const defaultDependencies = (root: string): Phase1SourceClosureDependencies => ({
  inspect: async (repositoryRoot) => {
    const [top, head, origin, status] = await Promise.all([
      gitText(repositoryRoot, ['rev-parse', '--show-toplevel']),
      gitText(repositoryRoot, ['rev-parse', 'HEAD']),
      gitText(repositoryRoot, ['remote', 'get-url', 'origin']),
      gitText(repositoryRoot, ['status', '--porcelain=v1', '--untracked-files=all']),
    ]);

    if (top !== repositoryRoot) {
      return fail();
    }

    return Object.freeze({
      head,
      origin,
      clean: status === '',
      phase1ModifiedPaths: Object.freeze([]),
    });
  },
  readCurrent: stableCurrentReader(root),
  readAccepted: acceptedReader(root),
});

export const createAcceptedPhase1SourceClosureManifest = async (
  repositoryRoot: string,
  dependencies: Phase1SourceClosureDependencies = defaultDependencies(repositoryRoot)
): Promise<AcceptedPhase1SourceClosureManifest> => {
  if (!path.isAbsolute(repositoryRoot) || path.resolve(repositoryRoot) !== repositoryRoot) {
    return fail();
  }
  const inspection = await dependencies.inspect(repositoryRoot).catch(fail);

  if (
    !inspection.clean ||
    !commitPattern.test(inspection.head) ||
    !canonicalOrigins.has(inspection.origin) ||
    inspection.phase1ModifiedPaths.some((file) => file.startsWith(phase1SourcePrefix))
  ) {
    return fail();
  }

  return buildAcceptedPhase1SourceClosureManifest({
    acceptedCommit: acceptedHarnessCommit,
    roots: acceptedPhase1ExecutionRoots,
    current: dependencies.readCurrent,
    accepted: dependencies.readAccepted,
  });
};

/* eslint-enable complexity, max-lines, no-await-in-loop, no-bitwise, no-control-regex, no-restricted-syntax, no-use-extend-native/no-use-extend-native, @silverhand/fp/no-let, @silverhand/fp/no-mutation, @silverhand/fp/no-mutating-methods, @typescript-eslint/member-ordering, @typescript-eslint/prefer-nullish-coalescing */
