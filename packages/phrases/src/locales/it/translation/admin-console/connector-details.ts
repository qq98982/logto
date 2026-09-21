const connector_details = {
  page_title: 'Dettagli del connettore',
  back_to_connectors: 'Torna ai connettori',
  check_readme: 'Verifica README',
  settings: 'Impostazioni generali',
  settings_description:
    'Integra fornitori terzi per un rapido accesso social e collegamento di account social',
  setting_description_with_token_storage_supported:
    "Integra fornitori terzi per un rapido accesso social, collegamento di account social e accesso all'API.",
  email_connector_settings_description:
    "Integra con il tuo provider di consegna email per abilitare la registrazione e l'accesso senza password tramite email per gli utenti finali.",
  parameter_configuration: 'Configurazione dei parametri',
  test_connection: 'Test',
  save_error_empty_config: 'Inserisci la configurazione',
  send: 'Invia',
  send_error_invalid_format: 'Input non valido',
  edit_config_label: 'Inserisci il tuo JSON qui',
  test_email_sender: 'Prova il tuo connettore per email',
  test_sms_sender: 'Prova il tuo connettore per SMS',
  test_email_placeholder: 'john.doe@example.com',
  test_sms_placeholder: '+1 555-123-4567',
  test_message_sent: 'Messaggio di prova inviato',
  test_sender_description:
    'Aster utilizza il modello "Generico" per i test. Riceverai un messaggio se il tuo connettore è correttamente configurato.',
  options_change_email: 'Cambia connettore per email',
  options_change_sms: 'Cambia connettore per SMS',
  connector_deleted: 'Il connettore è stato eliminato con successo',
  type_email: 'Connettore per email',
  type_sms: 'Connettore per SMS',
  type_social: 'Connettore social',
  in_used_social_deletion_description:
    "Questo connettore è in uso nella tua esperienza di accesso. Eliminandolo, l'esperienza di accesso di <name/> verrà eliminata nelle impostazioni dell'esperienza di accesso. Dovrai riconfigurarlo se decidi di aggiungerlo di nuovo.",
  in_used_passwordless_deletion_description:
    'Questo {{name}} è in uso nella tua esperienza di accesso. Eliminandolo, la tua esperienza di accesso non funzionerà correttamente fino a quando non risolverai il conflitto. Dovrai riconfigurarlo se decidi di aggiungerlo di nuovo.',
  deletion_description:
    'Stai rimuovendo questo connettore. Non può essere annullato e dovrai riconfigurarlo se decidi di aggiungerlo di nuovo.',
  google_one_tap: {
    title: 'Google One Tap',
    description: 'Google One Tap è un modo sicuro e facile per gli utenti di accedere al tuo sito.',
    enable_google_one_tap: 'Abilita Google One Tap',
    enable_google_one_tap_description:
      'Abilita Google One Tap nella tua esperienza di accesso: consenti agli utenti di registrarsi o accedere rapidamente con il loro account Google se sono già connessi sul loro dispositivo.',
    configure_google_one_tap: 'Configura Google One Tap',
    auto_select: 'Seleziona automaticamente le credenziali, se possibile',
    close_on_tap_outside: "Annulla il prompt se l'utente clicca/tocca all'esterno",
    itp_support: 'Abilita <a>UX One Tap migliorato sui browser ITP</a>',
  },
  sign_in_experience: {
    in_use: "Abilitato per l'accesso ",
    not_in_use: "Disabilitato per l'accesso ",
  },
};

export default Object.freeze(connector_details);
