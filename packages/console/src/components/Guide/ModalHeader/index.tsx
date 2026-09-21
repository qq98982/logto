import { type AdminConsoleKey } from '@logto/phrases';

import DsModalHeader from '@/ds-components/ModalHeader';

type Props = {
  readonly title: AdminConsoleKey;
  readonly subtitle: AdminConsoleKey;
  readonly onClose: () => void;
};

function ModalHeader({ title, subtitle, onClose }: Props) {
  return <DsModalHeader title={title} subtitle={subtitle} onClose={onClose} />;
}

export default ModalHeader;
