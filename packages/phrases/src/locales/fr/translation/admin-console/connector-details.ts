const connector_details = {
  page_title: 'Détails du connecteur',
  back_to_connectors: 'Retour à Connecteurs',
  check_readme: 'Vérifier le README',
  settings: 'Paramètres généraux',
  settings_description:
    'Intégrez des fournisseurs tiers pour une connexion sociale rapide et un lien de compte social',
  setting_description_with_token_storage_supported:
    "Intégrez des fournisseurs tiers pour une connexion sociale rapide, un lien de compte social, et un accès à l'API.",
  email_connector_settings_description:
    'Intégrez votre fournisseur de services de messagerie pour permettre une inscription et une connexion par e-mail sans mot de passe pour les utilisateurs finaux.',
  parameter_configuration: 'Configuration des paramètres',
  test_connection: 'Test',
  save_error_empty_config: 'Veuillez entrer la configuration',
  send: 'Envoyer',
  send_error_invalid_format: 'Entrée non valide',
  edit_config_label: 'Entrez votre json ici',
  test_email_sender: 'Testez votre connecteur Email',
  test_sms_sender: 'Testez votre connecteur SMS',
  test_email_placeholder: 'john.doe@example.com',
  test_sms_placeholder: '+33 6 12 34 56 78',
  test_message_sent: 'Message de test envoyé',
  test_sender_description:
    'Aster utilise le modèle "Generic" pour les tests. Tu recevras un message si ton connecteur est correctement configuré.',
  options_change_email: 'Modifier le connecteur Email',
  options_change_sms: 'Changer le connecteur SMS',
  connector_deleted: 'Le connecteur a été supprimé avec succès',
  type_email: 'Connecteur Email',
  type_sms: 'Connecteur SMS',
  type_social: 'Connecteur Social',
  in_used_social_deletion_description:
    'Ce connecteur est utilisé dans votre expérience de connexion. En le supprimant, l’expérience de connexion de <name/> sera supprimée dans les paramètres de l’expérience de connexion. Vous devrez le reconfigurer si vous décidez de l’ajouter à nouveau.',
  in_used_passwordless_deletion_description:
    'Cet {{name}} est utilisé dans votre expérience de connexion. En le supprimant, votre expérience de connexion ne fonctionnera pas correctement tant que vous n’aurez pas résolu le conflit. Vous devrez le reconfigurer si vous décidez de l’ajouter à nouveau.',
  deletion_description:
    "Vous supprimez ce connecteur. Il ne peut pas être annulé et vous devrez le reconfigurer si vous décidez de l'ajouter à nouveau.",
  google_one_tap: {
    title: 'Google One Tap',
    description:
      'Google One Tap est un moyen sécurisé et facile pour les utilisateurs de se connecter à votre site web.',
    enable_google_one_tap: 'Activer Google One Tap',
    enable_google_one_tap_description:
      "Activez Google One Tap dans votre expérience de connexion : Permettez aux utilisateurs de s'inscrire ou de se connecter rapidement avec leur compte Google s'ils sont déjà connectés sur leur appareil.",
    configure_google_one_tap: 'Configurer Google One Tap',
    auto_select: 'Sélection automatique des identifiants si possible',
    close_on_tap_outside: "Annuler l'invite si l'utilisateur clique/tape en dehors",
    itp_support: 'Activer <a>UX One Tap amélioré sur les navigateurs ITP</a>',
  },
  sign_in_experience: {
    in_use: 'Activé pour la connexion',
    not_in_use: 'Désactivé pour la connexion',
  },
};

export default Object.freeze(connector_details);
