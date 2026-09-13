import { CaptchaPolicyScope, type CaptchaPolicy } from '@logto/schemas';
import { Controller, useFormContext } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import FormField from '@/ds-components/FormField';
import RadioGroup, { Radio } from '@/ds-components/RadioGroup';
import Switch from '@/ds-components/Switch';

import styles from './index.module.scss';

type Props = {
  // eslint-disable-next-line react/boolean-prop-naming
  readonly disabled?: boolean;
};

function EnableCaptcha({ disabled }: Props) {
  const { t } = useTranslation(undefined, { keyPrefix: 'admin_console' });
  const { register, control } = useFormContext<CaptchaPolicy>();

  return (
    <div className={styles.container}>
      <FormField title="security.bot_protection.enable_captcha">
        <div className={styles.line}>
          <Switch
            label={t('security.bot_protection.enable_captcha_description')}
            {...register('enabled')}
            disabled={disabled}
          />
        </div>
      </FormField>
      <FormField title="security.bot_protection.captcha_scope">
        <Controller
          name="scope"
          control={control}
          defaultValue={CaptchaPolicyScope.Interaction}
          render={({ field: { name, onChange, value } }) => (
            <RadioGroup
              name={name}
              type="compact"
              value={value ?? CaptchaPolicyScope.Interaction}
              onChange={onChange}
            >
              <Radio
                isDisabled={disabled}
                title="security.bot_protection.captcha_scope_interaction"
                value={CaptchaPolicyScope.Interaction}
              />
              <Radio
                isDisabled={disabled}
                title="security.bot_protection.captcha_scope_phone_verification_code"
                value={CaptchaPolicyScope.PhoneVerificationCode}
              />
            </RadioGroup>
          )}
        />
      </FormField>
    </div>
  );
}

export default EnableCaptcha;
