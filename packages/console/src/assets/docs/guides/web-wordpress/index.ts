import { ApplicationType } from '@logto/schemas';

import { type GuideMetadata } from '../types';

const metadata: Readonly<GuideMetadata> = Object.freeze({
  name: 'WordPress',
  description: 'Integrate Aster into your WordPress app.',
  target: ApplicationType.Traditional,
});

export default metadata;
