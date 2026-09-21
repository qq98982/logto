const connector_details = {
  page_title: '커넥터 세부 정보',
  back_to_connectors: '연동으로 돌아가기',
  check_readme: 'README 확인',
  settings: '일반 설정',
  settings_description: '빠른 소셜 로그인 및 소셜 계정 연결을 위해 타사 제공업체와 통합합니다',
  setting_description_with_token_storage_supported:
    '빠른 소셜 로그인, 소셜 계정 연결 및 API 액세스를 위해 타사 제공업체와 통합합니다.',
  email_connector_settings_description:
    '이메일 전송 제공업체와 통합하여 최종 사용자에게 비밀번호가 필요 없는 이메일 등록 및 로그인을 활성화합니다.',
  parameter_configuration: '매개변수 설정',
  test_connection: '테스트',
  save_error_empty_config: '설정을 입력해 주세요.',
  send: '보내기',
  send_error_invalid_format: '유효하지 않은 입력',
  edit_config_label: '여기에 JSON을 입력해 주세요.',
  test_email_sender: '이메일 연동 테스트',
  test_sms_sender: 'SMS 연동 테스트',
  test_email_placeholder: 'john.doe@example.com',
  test_sms_placeholder: '+82 10-1234-5678',
  test_message_sent: '테스트 메세지 전송 완료',
  test_sender_description:
    'Aster는 "Generic" 템플릿을 사용하여 테스트합니다. 커넥터가 올바르게 구성되면 메시지를 받게 됩니다.',
  options_change_email: '이메일 연동 수정',
  options_change_sms: 'SMS 연동 수정',
  connector_deleted: '연동이 성공적으로 제거되었어요.',
  type_email: '이메일 연동',
  type_sms: 'SMS 연동',
  type_social: '소셜 연동',
  in_used_social_deletion_description:
    '이 연동은 로그인 경험에서 사용 중이에요. 삭제하면 로그인 경험 설정에서 <name/> 로그인 경험이 삭제됩니다. 나중에 되돌리려면 다시 구성해야 해요.',
  in_used_passwordless_deletion_description:
    '{name}}은/는 로그인 경험에서 사용 중이에요. 삭제하면 충돌을 해결할 때까지 로그인 환경이 제대로 작동하지 않을 거예요. 나중에 되돌리려면 다시 구성해야 해요.',
  deletion_description:
    '이 연동을 삭제하려고 하고 있어요. 이 작업은 돌이킬 수 없으며, 나중에 되돌리려면 다시 구성해야 해요.',
  google_one_tap: {
    title: 'Google 원탭',
    description:
      'Google 원탭은 사용자들이 당신의 웹사이트에 쉽게 로그인할 수 있는 안전한 방법입니다.',
    enable_google_one_tap: 'Google 원탭 활성화',
    enable_google_one_tap_description:
      '로그인 경험에서 Google 원탭을 활성화하세요: 사용자가 이미 자신의 기기에서 Google 계정에 로그인한 경우 빠르게 가입 또는 로그인할 수 있게 합니다.',
    configure_google_one_tap: 'Google 원탭 구성',
    auto_select: '가능한 경우 자격 증명 자동 선택',
    close_on_tap_outside: '사용자가 외부 클릭/탭 시 프롬프트 취소',
    itp_support: '<a>ITP 브라우저에서 업그레이드된 원탭 UX</a> 활성화',
  },
  sign_in_experience: {
    in_use: '로그인에 사용 가능 ',
    not_in_use: '로그인에 사용 안 함 ',
  },
};

export default Object.freeze(connector_details);
