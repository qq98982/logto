const organizations = {
  organization: 'Organização',
  page_title: 'Organizações',
  title: 'Organizações',
  subtitle:
    'Organizações são normalmente utilizadas em aplicativos SaaS ou aplicativos semelhantes de vários inquilinos e representam seus clientes que são equipes, organizações ou empresas inteiras. Organizações funcionam como um elemento fundamental para autenticação e autorização B2B.',
  organization_template: 'Modelo de organização',
  organization_id: 'ID da organização',
  members: 'Membros',
  machine_to_machine: 'Aplicativos de máquina para máquina',
  branding: 'Marca',
  create_organization: 'Criar organização',
  setup_organization: 'Configurar sua organização',
  organization_list_placeholder_title: 'Organização',
  organization_list_placeholder_text:
    'Organizações são frequentemente usadas em aplicativos SaaS ou aplicativos semelhantes de vários inquilinos como uma prática recomendada. Elas permitem que você desenvolva aplicativos que permitem aos clientes criar e gerenciar organizações, convidar membros e atribuir funções.',
  organization_name_placeholder: 'Minha organização',
  organization_description_placeholder: 'Uma breve descrição da organização',
  organization_permission: 'Permissão da organização',
  organization_permission_other: 'Permissões da organização',
  create_permission_placeholder: 'Ler histórico de compromissos',
  organization_role: 'Papel da organização',
  organization_role_other: 'Papéis da organização',
  organization_role_description:
    'O papel da organização é um agrupamento de permissões que podem ser atribuídas aos usuários. As permissões devem vir das permissões de organização predefinidas.',
  role: 'Função',
  search_placeholder: 'Pesquisar por nome ou ID da organização',
  search_role_placeholder: 'Digite para pesquisar e selecionar funções',
  empty_placeholder: '🤔 Você ainda não configurou nenhum {{entity}}.',
  organization_and_member: 'Organização e membro',
  organization_and_member_description:
    'A organização é um grupo de usuários e pode representar as equipes, clientes comerciais e empresas parceiras, sendo que cada usuário é um "Membro". Esses podem ser entidades fundamentais para lidar com seus requisitos de multi-inquilino.',
  guide: {
    title: 'Comece com guias',
    subtitle: 'Inicie as configurações da sua organização com nossos guias',
    introduction: {
      title: 'Vamos entender como a organização funciona no Aster',
      section_1: {
        title: 'Uma organização é um grupo de usuários (identidades)',
      },
      section_2: {
        title:
          'O modelo de organização é projetado para controle de acesso de aplicativos multi-inquilino',
        description:
          'Em aplicativos SaaS multi-inquilino, várias organizações frequentemente compartilham o mesmo modelo de controle de acesso, que inclui permissões e papéis. No Aster, chamamos isso de "modelo de organização".',
        permission_description:
          'A permissão da organização refere-se à autorização para acessar um recurso no contexto da organização.',
        role_description_deprecated:
          'O papel da organização é um agrupamento de permissões da organização que podem ser atribuídas aos membros.',
        role_description:
          'A função da organização é um agrupamento de permissões da organização ou permissões de API que podem ser atribuídas aos membros.',
      },
      section_3: {
        title: 'Posso atribuir permissões de API a funções de organização?',
        description:
          'Sim, você pode atribuir permissões de API a funções de organização. A Aster oferece flexibilidade para gerenciar as funções da sua organização de forma eficaz, permitindo que você inclua tanto as permissões da organização quanto as permissões de API nessas funções.',
      },
      section_4: {
        title: 'Interaja com a ilustração para ver como tudo se conecta',
        description:
          'Vamos dar um exemplo. John, Sarah estão em diferentes organizações com diferentes papéis no contexto de organizações diferentes. Passe o mouse sobre os diferentes módulos e veja o que acontece.',
      },
    },
    organization_permissions: 'Permissões da organização',
    organization_roles: 'Papéis da organização',
    admin: 'Administrador',
    member: 'Membro',
    guest: 'Convidado',
    role_description:
      'O papel "{{role}}" compartilha o mesmo modelo de organização em diferentes organizações.',
    john: 'John',
    john_tip:
      'John pertence a duas organizações com o email "john@email.com" como único identificador. Ele é o administrador da organização A, bem como o convidado da organização B.',
    sarah: 'Sarah',
    sarah_tip:
      'Sarah pertence a uma organização com o email "sarah@email.com" como único identificador. Ela é a administradora da organização B.',
  },
};

export default Object.freeze(organizations);
