const organizations = {
  organization: 'Organizacja',
  page_title: 'Organizacje',
  title: 'Organizacje',
  subtitle:
    'Organizacje są zazwyczaj używane w aplikacjach typu SaaS lub podobnych dla wielu najemców i reprezentują Twoich klientów, którzy są zespołami, organizacjami lub całymi firmami. Organizacje są podstawowym elementem do uwierzytelniania i autoryzacji B2B.',
  organization_template: 'Szablon organizacji',
  organization_id: 'ID organizacji',
  members: 'Członkowie',
  machine_to_machine: 'Aplikacje typu machine-to-machine',
  branding: 'Marka',
  create_organization: 'Utwórz organizację',
  setup_organization: 'Skonfiguruj swoją organizację',
  organization_list_placeholder_title: 'Organizacja',
  organization_list_placeholder_text:
    'Organizacje są często wykorzystywane w aplikacjach typu SaaS lub podobnych jako praktyka najlepsza. Pozwalają one tworzyć aplikacje, które umożliwiają klientom tworzenie i zarządzanie organizacjami, zapraszanie członków oraz przypisywanie ról.',
  organization_name_placeholder: 'Moja organizacja',
  organization_description_placeholder: 'Krótki opis organizacji',
  organization_permission: 'Uprawnienie organizacji',
  organization_permission_other: 'Uprawnienia organizacji',
  create_permission_placeholder: 'Odczyt historii spotkań',
  organization_role: 'Rola organizacji',
  organization_role_other: 'Role organizacji',
  organization_role_description:
    'Rola organizacji to grupowanie uprawnień, które można przypisać użytkownikom. Uprawnienia muszą pochodzić z wcześniej zdefiniowanych uprawnień organizacji.',
  role: 'Rola',
  search_placeholder: 'Wyszukaj według nazwy lub ID organizacji',
  search_role_placeholder: 'Wpisz, aby wyszukać i wybrać role',
  empty_placeholder: '🤔 Nie masz jeszcze ustawionego żadnego {{entity}}.',
  organization_and_member: 'Organizacja i członek',
  organization_and_member_description:
    'Organizacja to grupa użytkowników i może reprezentować zespoły, klientów biznesowych i partnerów firm, z których każdy użytkownik jest "Członkiem". Mogą to być podstawowe jednostki do obsługi wymagań wielomandantowych.',
  guide: {
    title: 'Zacznij od przewodników',
    subtitle: 'Włóż kłódę pod stopy swoich ustawień organizacji za pomocą naszych przewodników',
    introduction: {
      title: 'Zrozum, jak działa organizacja w Aster',
      section_1: {
        title: 'Organizacja to grupa użytkowników (tożsamości)',
      },
      section_2: {
        title:
          'Szablon organizacji jest przeznaczony do kontroli dostępu do aplikacji wielomandantowych',
        description:
          'W wielomandantowych aplikacjach typu SaaS, wiele organizacji często dzieli ten sam szablon kontroli dostępu, który obejmuje uprawnienia i role. W Aster nazywamy to "szablonem organizacji".',
        permission_description:
          'Uprawnienie organizacji odnosi się do autoryzacji dostępu do zasobów w kontekście organizacji.',
        role_description_deprecated:
          'Rola organizacji to grupowanie uprawnień organizacji, które można przypisać członkom.',
        role_description:
          'Rola organizacyjna to grupowanie uprawnień organizacyjnych lub uprawnień API, które mogą być przypisane do członków.',
      },
      section_3: {
        title: 'Czy mogę przypisać uprawnienia API do ról organizacyjnych?',
        description:
          'Tak, możesz przypisać uprawnienia API do ról organizacyjnych. Aster oferuje elastyczność w skutecznym zarządzaniu rolami w organizacji, pozwalając na włączenie zarówno uprawnień organizacyjnych, jak i uprawnień API do tych ról.',
      },
      section_4: {
        title: 'Zaangażuj się w ilustrację, aby zobaczyć jak to wszystko się łączy',
        description:
          'Przyjmijmy przykład. John, Sarah należą do różnych organizacji z różnymi rolami w kontekście różnych organizacji. Najedź kursorem na różne moduły i zobacz co się stanie.',
      },
    },
    organization_permissions: 'Uprawnienia organizacji',
    organization_roles: 'Role organizacji',
    admin: 'Administrator',
    member: 'Członek',
    guest: 'Gość',
    role_description:
      'Rola "{{role}}" dzieli ten sam szablon organizacji między różnymi organizacjami.',
    john: 'John',
    john_tip:
      'John należy do dwóch organizacji, a jedynym identyfikatorem jest adres e-mail "john@email.com". Jest administratorem organizacji A oraz gościem organizacji B.',
    sarah: 'Sarah',
    sarah_tip:
      'Sarah należy do jednej organizacji, a jedynym identyfikatorem jest adres e-mail "sarah@email.com". Jest administratorem organizacji B.',
  },
};

export default Object.freeze(organizations);
