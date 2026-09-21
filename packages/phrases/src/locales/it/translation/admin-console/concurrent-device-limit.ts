const concurrent_device_limit = {
  title: 'Limite dispositivo concorrente',
  enable: 'Abilita limite dispositivo concorrente',
  enable_description:
    "Quando abilitato, Aster applica il massimo di concessioni attive per utente per quest'app.",
  field: 'Limite dispositivo concorrente per app',
  field_description:
    'Limita quanti dispositivi un utente può essere connesso contemporaneamente. Aster impone questo limitando le concessioni attive e revoca automaticamente la concessione più vecchia quando il limite viene superato.',
  field_placeholder: 'Lascia vuoto per nessun limite',
  should_be_greater_than_zero: 'Dovrebbe essere maggiore di 0.',
};

export default Object.freeze(concurrent_device_limit);
