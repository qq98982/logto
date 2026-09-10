import { type Resource } from '@logto/schemas';
import Modal from 'react-modal';

import ModalHeader from '@/components/Guide/ModalHeader';
import modalStyles from '@/scss/modal.module.scss';

import ApiGuide from '../ApiGuide';

import styles from './index.module.scss';

type Props = {
  readonly guideId: string;
  readonly apiResource?: Resource;
  readonly onClose: () => void;
};

function GuideModal({ guideId, apiResource, onClose }: Props) {
  return (
    <Modal shouldCloseOnEsc isOpen className={modalStyles.fullScreen} onRequestClose={onClose}>
      <div className={styles.modalContainer}>
        <ModalHeader
          title="guide.api.modal_title"
          subtitle="guide.api.modal_subtitle"
          onClose={onClose}
        />
        <ApiGuide
          className={styles.guide}
          guideId={guideId}
          apiResource={apiResource}
          onClose={onClose}
        />
      </div>
    </Modal>
  );
}

export default GuideModal;
