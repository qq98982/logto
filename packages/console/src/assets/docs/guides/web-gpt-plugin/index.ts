import { ApplicationType } from '@logto/schemas';

import { type GuideMetadata } from '../types';

const metadata: Readonly<GuideMetadata> = Object.freeze({
  name: 'ChatGPT plugin',
  description: 'Use Aster as an OAuth identity provider for ChatGPT plugins.',
  target: ApplicationType.Traditional,
});

export default metadata;
