const organizations = {
  organization: 'Organización',
  page_title: 'Organizaciones',
  title: 'Organizaciones',
  subtitle:
    'Las organizaciones suelen utilizarse en aplicaciones SaaS u aplicaciones similares de múltiples inquilinos y representan a sus clientes que son equipos, organizaciones o empresas enteras. Las organizaciones trabajan como un elemento fundamental para la autenticación y autorización de B2B.',
  organization_template: 'Plantilla de organización',
  organization_id: 'ID de la organización',
  members: 'Miembros',
  machine_to_machine: 'Aplicaciones máquina a máquina',
  branding: 'Branding',
  create_organization: 'Crear organización',
  setup_organization: 'Configurar su organización',
  organization_list_placeholder_title: 'Organización',
  organization_list_placeholder_text:
    'Las organizaciones suelen utilizarse en aplicaciones SaaS u aplicaciones similares de múltiples inquilinos como mejor práctica. Le permiten desarrollar aplicaciones que permiten a los clientes crear y gestionar organizaciones, invitar miembros y asignar roles.',
  organization_name_placeholder: 'Mi organización',
  organization_description_placeholder: 'Una breve descripción de la organización',
  organization_permission: 'Permiso de la organización',
  organization_permission_other: 'Permisos de la organización',
  create_permission_placeholder: 'Leer historial de citas',
  organization_role: 'Rol de la organización',
  organization_role_other: 'Roles de la organización',
  organization_role_description:
    'El rol de la organización es un agrupamiento de permisos que se pueden asignar a los usuarios. Los permisos deben provenir de los permisos de organización predefinidos.',
  role: 'Rol',
  search_placeholder: 'Buscar por nombre de organización o ID',
  search_role_placeholder: 'Escribe para buscar y seleccionar roles',
  empty_placeholder: '🤔 No has configurado ningún {{entity}} todavía.',
  organization_and_member: 'Organización y miembro',
  organization_and_member_description:
    'La organización es un grupo de usuarios y puede representar a los equipos, clientes comerciales y empresas asociadas, siendo cada usuario un "Miembro". Estos pueden ser entidades fundamentales para manejar sus requisitos multinivel.',
  guide: {
    title: 'Comience con guías',
    subtitle: 'Inicie la configuración de su organización con nuestras guías',
    introduction: {
      title: 'Comprenda cómo funciona la organización en Aster',
      section_1: {
        title: 'Una organización es un grupo de usuarios (identidades)',
      },
      section_2: {
        title:
          'La plantilla de organización está diseñada para el control de acceso de aplicaciones multiinquilino',
        description:
          'En aplicaciones SaaS multiinquilino, varias organizaciones a menudo comparten la misma plantilla de control de acceso, que incluye permisos y roles. En Aster, lo llamamos "plantilla de organización".',
        permission_description:
          'El permiso de la organización se refiere a la autorización para acceder a un recurso en el contexto de la organización.',
        role_description_deprecated:
          'El rol de la organización es un agrupamiento de permisos de organización que se pueden asignar a los miembros.',
        role_description:
          'El rol de la organización es un agrupamiento de permisos de la organización o permisos de API que se pueden asignar a los miembros.',
      },
      section_3: {
        title: '¿Puedo asignar permisos de API a roles de organización?',
        description:
          'Sí, puedes asignar permisos de API a roles de organización. Aster ofrece la flexibilidad para gestionar los roles de tu organización de manera efectiva, permitiéndote incluir tanto permisos de organización como permisos de API dentro de esos roles.',
      },
      section_4: {
        title: 'Interactúe con la ilustración para ver cómo se conecta todo',
        description:
          'Tomemos un ejemplo. John y Sarah están en diferentes organizaciones con diferentes roles en el contexto de diferentes organizaciones. Desplácese sobre los diferentes módulos y vea qué sucede.',
      },
    },
    organization_permissions: 'Permisos de la organización',
    organization_roles: 'Roles de la organización',
    admin: 'Admin',
    member: 'Miembro',
    guest: 'Invitado',
    role_description:
      'El rol "{{role}}" comparte la misma plantilla de organización en diferentes organizaciones.',
    john: 'John',
    john_tip:
      'John pertenece a dos organizaciones con el correo electrónico "john@email.com" como único identificador. Es el administrador de la organización A y también el invitado de la organización B.',
    sarah: 'Sarah',
    sarah_tip:
      'Sarah pertenece a una organización con el correo electrónico "sarah@email.com" como único identificador. Es la administradora de la organización B.',
  },
};

export default Object.freeze(organizations);
