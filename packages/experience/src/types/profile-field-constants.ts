export { CustomProfileFieldType } from '@logto/schemas/lib/foundations/jsonb-types/custom-profile-fields.js';

// Public profile-field payload values used by Experience. Keeping these structural constants local
// avoids loading server-side schema initialization into the browser bundle.
export const SupportedDateFormat = {
  US: 'MM/dd/yyyy',
  UK: 'dd/MM/yyyy',
  ISO: 'yyyy-MM-dd',
  Custom: 'custom',
} as const;

export const Gender = {
  Female: 'female',
  Male: 'male',
  Other: 'prefer_not_to_say',
} as const;

export type ProfileGender = (typeof Gender)[keyof typeof Gender];
