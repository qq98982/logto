import { Prompt, UserScope } from '@logto/react';
import { z } from 'zod';

type ToZodObject<T> = z.ZodObject<{
  [K in keyof T]-?: z.ZodType<T[K]>;
}>;

type LocalAsterConfig = {
  signInExtraParams?: string;
  prompt?: string;
  scope?: string;
  resource?: string;
  appId?: string;
};

const localAsterConfigGuard = z
  .object({
    signInExtraParams: z.string(),
    prompt: z.string(),
    scope: z.string(),
    resource: z.string(),
    appId: z.string(),
  })
  .partial() satisfies ToZodObject<LocalAsterConfig>;

type LocalUiConfig = {
  showDevPanel?: boolean;
};

const localUiConfigGuard = z
  .object({
    showDevPanel: z.boolean(),
  })
  .partial() satisfies ToZodObject<LocalUiConfig>;

type Key = 'config' | 'ui';

const keyPrefix = 'aster:demo-app:dev:';

type KeyToType = {
  config: LocalAsterConfig;
  ui: LocalUiConfig;
};

const keyToGuard: Readonly<{
  [K in Key]: z.ZodType<KeyToType[K]>;
}> = Object.freeze({
  config: localAsterConfigGuard,
  ui: localUiConfigGuard,
});

const keyToDefault = Object.freeze({
  config: {
    prompt: [Prompt.Login, Prompt.Consent].join(' '),
    scope: [UserScope.Organizations, UserScope.OrganizationRoles].join(' '),
  },
  ui: {},
} satisfies Record<Key, unknown>);

const safeJsonParse = (value: string): unknown => {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
};

const safeZodParse = (guard: z.ZodType<unknown>, value: unknown) => {
  const result = guard.safeParse(value);
  return result.success ? result.data : {};
};

export const getLocalData = <K extends Key>(key: K): KeyToType[K] => {
  const result = keyToGuard[key].safeParse(
    safeJsonParse(localStorage.getItem(`${keyPrefix}${key}`) ?? '')
  );
  return result.success ? result.data : keyToDefault[key];
};

export const setLocalData = (key: Key, value: unknown) => {
  localStorage.setItem(`${keyPrefix}${key}`, JSON.stringify(safeZodParse(keyToGuard[key], value)));
};
