const connector_details = {
  page_title: 'Connector details',
  back_to_connectors: 'Back to connectors',
  check_readme: 'Check README',
  settings: 'General settings',
  settings_description:
    'Integrate third-party providers for quick social sign-in and social account linking',
  setting_description_with_token_storage_supported:
    'Integrate third-party providers for quick social sign-in, social account linking, and API access.',
  email_connector_settings_description:
    'Integrate with your email delivery provider to enable passwordless email registration and sign-in for end-users.',
  parameter_configuration: 'Parameter configuration',
  test_connection: 'Test',
  save_error_empty_config: 'Please enter config',
  send: 'Send',
  send_error_invalid_format: 'Invalid input',
  edit_config_label: 'Enter your JSON here',
  test_email_sender: 'Test your email connector',
  test_sms_sender: 'Test your SMS connector',
  test_email_placeholder: 'john.doe@example.com',
  test_sms_placeholder: '+1 555-123-4567',
  test_message_sent: 'Test message sent',
  test_sender_description:
    'Aster uses the "Generic" template for testing. You will receive a message if your connector is rightly configured.',
  options_change_email: 'Change email connector',
  options_change_sms: 'Change SMS connector',
  connector_deleted: 'The connector has been successfully deleted',
  type_email: 'Email connector',
  type_sms: 'SMS connector',
  type_social: 'Social connector',
  in_used_social_deletion_description:
    'This connector is in-use in your sign in experience. By deleting, <name/> sign in experience will be deleted in sign in experience settings. You will need to reconfigure it if you decide to add it back.',
  in_used_passwordless_deletion_description:
    'This {{name}} is in-use in your sign-in experience. By deleting, your sign-in experience will not work properly until you resolve the conflict. You will need to reconfigure it if you decide to add it back.',
  deletion_description:
    'You are removing this connector. It cannot be undone, and you will need to reconfigure it if you decide to add it back.',
  google_one_tap: {
    title: 'Google One Tap',
    description: 'Google One Tap is a secure and easy way for users to sign in to your website.',
    enable_google_one_tap: 'Enable Google One Tap',
    enable_google_one_tap_description:
      "Enable Google One Tap in your sign-in experience: Let users quickly sign up or sign in with their Google account if they're already signed in on their device.",
    configure_google_one_tap: 'Configure Google One Tap',
    auto_select: 'Auto-select credential if possible',
    close_on_tap_outside: 'Cancel the prompt if user click/tap outside',
    itp_support: 'Enable <a>Upgraded One Tap UX on ITP browsers</a>',
  },
  sign_in_experience: {
    in_use: 'Enabled for sign-in ',
    not_in_use: 'Disabled for sign-in ',
  },
};

export default Object.freeze(connector_details);
