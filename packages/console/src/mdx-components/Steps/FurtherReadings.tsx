import { type Ref, forwardRef } from 'react';

import { type GuideMetadata } from '@/assets/docs/guides/types';
import TextLink from '@/ds-components/TextLink';
import useDocumentationUrl from '@/hooks/use-documentation-url';

import Step, { type Props as StepProps } from '../Step';

type Props = Omit<StepProps, 'children'> & {
  readonly fullGuide: GuideMetadata['fullGuide'];
  readonly furtherReadings: GuideMetadata['furtherReadings'];
};

function FurtherReadings(props: Props, ref?: Ref<HTMLDivElement>) {
  const { fullGuide, furtherReadings, ...stepProps } = props;
  const { getDocumentationUrl } = useDocumentationUrl();
  const fullGuideUrl = fullGuide && getDocumentationUrl(`/quick-starts/${fullGuide}`);
  const standardReadings = [
    ['Customize sign-in experience', '/customization/sign-in-experience'],
    ['Configure connectors', '/connectors'],
    ['Configure client to use RBAC', '/authorization/role-based-access-control'],
  ] as const;

  return (
    <Step ref={ref} {...stepProps}>
      <ul>
        {fullGuideUrl && (
          <li>
            <TextLink href={fullGuideUrl} targetBlank="noopener">
              Complete guide
            </TextLink>
          </li>
        )}
        {furtherReadings?.map(({ title, url }) => (
          <li key={title}>
            <TextLink href={url.href} targetBlank="noopener">
              {title}
            </TextLink>
          </li>
        ))}
        {standardReadings.map(([title, pagePath]) => {
          const href = getDocumentationUrl(pagePath);

          return href ? (
            <li key={pagePath}>
              <TextLink href={href} targetBlank="noopener">
                {title}
              </TextLink>
            </li>
          ) : null;
        })}
      </ul>
    </Step>
  );
}

export default forwardRef<HTMLDivElement, Props>(FurtherReadings);
