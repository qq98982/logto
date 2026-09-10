const connector_details = {
  page_title: '連結器詳情',
  back_to_connectors: '返回連結器',
  check_readme: '檢視 README',
  settings: '通用設定',
  settings_description: '整合第三方提供者以快速進行社交登入和社交帳戶連結',
  setting_description_with_token_storage_supported:
    '整合第三方提供者以快速進行社交登入、社交帳戶連結和 API 存取。',
  email_connector_settings_description:
    '與你的電子郵件傳遞服務提供者整合，以啟用終端用戶的無密碼電子郵件註冊和登錄。',
  parameter_configuration: '參數配置',
  test_connection: '測試',
  save_error_empty_config: '請輸入配置內容',
  send: '傳送',
  send_error_invalid_format: '無效輸入',
  edit_config_label: '請在此輸入您的 JSON 配置',
  test_email_sender: '測試您的郵件連結器',
  test_sms_sender: '測試您的短信連結器',
  test_email_placeholder: 'john.doe@example.com',
  test_sms_placeholder: '+86 131 1234 5678',
  test_message_sent: '測試訊息已傳送',
  test_sender_description:
    'Aster 使用「通用」模板進行測試。如果您的連結器正確配置，您將收到一條訊息。',
  options_change_email: '更換郵件連結器',
  options_change_sms: '更換短信連結器',
  connector_deleted: '成功刪除連結器',
  type_email: '郵件連結器',
  type_sms: '短信連結器',
  type_social: '社交連結器',
  in_used_social_deletion_description:
    '您的登入體驗正在使用這個連結器。刪除後，<name/> 登入體驗將在登入體驗設定中被刪除，再次添加需重新配置。',
  in_used_passwordless_deletion_description:
    '您的登入體驗正在使用 {{name}} 連結器。刪除後，您的登入體驗將無法正常工作，直到您解決衝突，再次添加需重新配置。',
  deletion_description: '您將刪除此連結器。此操作不可撤銷，再次添加需重新配置。',
  google_one_tap: {
    title: 'Google 一鍵登入',
    description: 'Google 一鍵登入 是用戶登錄您網站的一種安全且簡單的方式。',
    enable_google_one_tap: '啟用 Google 一鍵登入',
    enable_google_one_tap_description:
      '在您的登入體驗中啟用 Google 一鍵登入：讓用戶在他們的設備上已經登入 Google 帳戶時快速註冊或登入。',
    configure_google_one_tap: '配置 Google 一鍵登入',
    auto_select: '自動選擇憑證（如果可能）',
    close_on_tap_outside: '在用戶點擊/點擊外面時取消提示',
    itp_support: '啟用 <a>ITP 瀏覽器上的升級一鍵登入用戶體驗</a>',
  },
  sign_in_experience: {
    in_use: '已啟用登錄',
    not_in_use: '已停用登錄',
  },
};

export default Object.freeze(connector_details);
