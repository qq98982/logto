const connector_details = {
  page_title: 'コネクターの詳細',
  back_to_connectors: 'コネクタに戻る',
  check_readme: 'READMEを確認する',
  settings: '一般設定',
  settings_description:
    'サードパーティプロバイダーを統合して、迅速なソーシャルサインインとソーシャルアカウントのリンクを行います',
  setting_description_with_token_storage_supported:
    'サードパーティプロバイダーを統合して、迅速なソーシャルサインイン、ソーシャルアカウントのリンク、APIアクセスを行います。',
  email_connector_settings_description:
    'メール配信プロバイダーと統合して、エンドユーザー向けにパスワードレスメール登録とサインインを有効にします。',
  parameter_configuration: 'パラメーター設定',
  test_connection: 'テスト',
  save_error_empty_config: '設定を入力してください',
  send: '送信',
  send_error_invalid_format: '入力が無効です',
  edit_config_label: 'JSONを入力してください',
  test_email_sender: 'メールコネクタのテスト',
  test_sms_sender: 'SMS コネクタのテスト',
  test_email_placeholder: 'john.doe@example.com',
  test_sms_placeholder: '+1 555-123-4567',
  test_message_sent: 'テストメッセージが送信されました',
  test_sender_description:
    'Aster はテストのために「共通」テンプレートを使用しています。コネクタが正しく構成されている場合、メッセージを受信します。',
  options_change_email: 'メールコネクタの変更',
  options_change_sms: 'SMS コネクタの変更',
  connector_deleted: 'コネクタが正常に削除されました',
  type_email: 'メールコネクタ',
  type_sms: 'SMS コネクタ',
  type_social: 'ソーシャルコネクタ',
  in_used_social_deletion_description:
    'このコネクタはあなたのサインイン体験で使用されています。削除すると、サインイン体験設定のサインイン体験が削除されます。再追加する場合は再設定する必要があります。',
  in_used_passwordless_deletion_description:
    'この{{name}}はあなたのサインイン体験で使用されています。削除すると、競合が解決されるまでサインイン体験が正常に機能しません。再追加する場合は再設定する必要があります。',
  deletion_description:
    'このコネクタを削除します。元に戻すことはできず、再追加する場合は再設定する必要があります。',
  google_one_tap: {
    title: 'Google ワンタップ',
    description:
      'Google ワンタップは、ユーザーがあなたのウェブサイトにサインインするための安全で簡単な方法です。',
    enable_google_one_tap: 'Google ワンタップを有効にする',
    enable_google_one_tap_description:
      'サインインエクスペリエンスでGoogle ワンタップを有効にします。ユーザーがデバイスにサインインしている場合、Google アカウントを使用してすぐにサインアップまたはサインインできます。',
    configure_google_one_tap: 'Google ワンタップを設定する',
    auto_select: '可能であれば資格情報を自動選択',
    close_on_tap_outside: '外側をクリック／タップした場合にプロンプトをキャンセル',
    itp_support: '<a>ITP ブラウザでアップグレードされたワンタップ UX</a> を有効にする',
  },
  sign_in_experience: {
    in_use: 'サインインに有効',
    not_in_use: 'サインインに無効',
  },
};

export default Object.freeze(connector_details);
