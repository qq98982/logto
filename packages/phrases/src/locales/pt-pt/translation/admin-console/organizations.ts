const organizations = {
  organization: 'Organização',
  page_title: 'Organizações',
  title: 'Organizações',
  subtitle:
    'As organizações são geralmente usadas em aplicações SaaS ou similares de múltiplos inquilinos e representam os seus clientes, que podem ser equipas, organizações ou empresas inteiras. As organizações funcionam como um elemento fundamental para a autenticação e autorização B2B.',
  organization_template: 'Modelo de organização',
  organization_id: 'ID da organização',
  members: 'Membros',
  machine_to_machine: 'Aplicações de máquina para máquina',
  branding: 'Marca',
  create_organization: 'Criar organização',
  setup_organization: 'Configurar a sua organização',
  organization_list_placeholder_title: 'Organização',
  organization_list_placeholder_text:
    'As organizações são frequentemente utilizadas em aplicações SaaS ou similares de múltiplos inquilinos como uma prática recomendada. Permitem-lhe desenvolver aplicações que permitem aos clientes criar e gerir organizações, convidar membros e atribuir funções.',
  organization_name_placeholder: 'A minha organização',
  organization_description_placeholder: 'Uma breve descrição da organização',
  organization_permission: 'Permissão da organização',
  organization_permission_other: 'Permissões da organização',
  create_permission_placeholder: 'Ler histórico de compromissos',
  organization_role: 'Papel da organização',
  organization_role_other: 'Funções da organização',
  organization_role_description:
    'O papel da organização é um agrupamento de permissões que podem ser atribuídas a utilizadores. As permissões devem provir das permissões de organização predefinidas.',
  role: 'Função',
  search_placeholder: 'Pesquisar por nome ou ID da organização',
  search_role_placeholder: 'Digite para pesquisar e selecionar funções',
  empty_placeholder: '🤔 Ainda não configurou nenhum {{entity}}.',
  organization_and_member: 'Organização e membro',
  organization_and_member_description:
    'A organização é um grupo de utilizadores e pode representar as equipas, clientes empresariais e empresas parceiras, sendo que cada utilizador é um "Membro". Estas podem ser entidades fundamentais para lidar com os requisitos de múltiplos inquilinos.',
  guide: {
    title: 'Comece com guias',
    subtitle: 'Inicie as configurações da sua organização com os nossos guias',
    introduction: {
      title: 'Vamos entender como uma organização funciona na Aster',
      section_1: {
        title: 'Uma organização é um grupo de utilizadores (identidades)',
      },
      section_2: {
        title:
          'O modelo de organização é projetado para o controlo de acesso a aplicações multi-inquilinos',
        description:
          'Nas aplicações SaaS multi-inquilinos, muitas organizações frequentemente partilham o mesmo modelo de controlo de acesso, que inclui permissões e funções. Na Aster, chamamos-lhe "modelo de organização."',
        permission_description:
          'A permissão da organização refere-se à autorização para aceder a um recurso no contexto da organização.',
        role_description_deprecated:
          'O papel da organização é um agrupamento de permissões da organização que podem ser atribuídas aos membros.',
        role_description:
          'O papel da organização é um agrupamento de permissões da organização ou permissões de API que podem ser atribuídas aos membros.',
      },
      section_3: {
        title: 'Posso atribuir permissões de API a papéis de organização?',
        description:
          'Sim, pode atribuir permissões de API a papéis de organização. O Aster oferece a flexibilidade para gerir eficazmente os papéis da sua organização, permitindo incluir tanto permissões de organização como permissões de API nesses papéis.',
      },
      section_4: {
        title: 'Interaja com a ilustração para ver como tudo está conectado',
        description:
          'Vamos ver um exemplo. John, Sarah pertencem a diferentes organizações com funções diferentes no contexto das organizações diferentes. Passe o rato sobre os diferentes módulos e veja o que acontece.',
      },
    },
    organization_permissions: 'Permissões da organização',
    organization_roles: 'Funções da organização',
    admin: 'Administrador',
    member: 'Membro',
    guest: 'Convidado',
    role_description:
      'O papel "{{role}}" partilha o mesmo modelo de organização entre diferentes organizações.',
    john: 'John',
    john_tip:
      'John pertence a duas organizações com o email "john@email.com" como único identificador. Ele é o administrador da organização A e o convidado da organização B.',
    sarah: 'Sarah',
    sarah_tip:
      'Sarah pertence a uma organização com o email "sarah@email.com" como único identificador. Ela é a administradora da organização B.',
  },
};

export default Object.freeze(organizations);
