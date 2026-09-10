import { type EditorProps } from '@monaco-editor/react';

import type { IStandaloneThemeData } from './type';

// Aster dark theme extends vs-dark.
export const asterDarkTheme: IStandaloneThemeData = {
  base: 'vs-dark',
  inherit: true,
  rules: [],
  colors: {
    'editor.background': '#090613', // :token/code/code-bg
  },
};

export const asterLightTheme: IStandaloneThemeData = {
  ...asterDarkTheme,
  colors: {
    'editor.background': '#181133', // :token/code/code-bg
  },
};

// @see {@link https://microsoft.github.io/monaco-editor/typedoc/interfaces/editor.IStandaloneEditorConstructionOptions.html}
export const defaultOptions: EditorProps['options'] = {
  minimap: {
    enabled: false,
  },
  renderLineHighlight: 'none',
  fontFamily: 'Roboto Mono, monospace',
  fontSize: 14,
  automaticLayout: true,
  tabSize: 2,
  scrollBeyondLastLine: false,
};
