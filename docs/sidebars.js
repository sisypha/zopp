/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    {
      type: 'category',
      label: 'Start Here',
      collapsed: false,
      items: ['index', 'quickstart'],
    },
    {
      type: 'category',
      label: 'Installation',
      collapsed: false,
      items: [
        'installation/index',
        'installation/cli',
        'installation/docker',
        'installation/kubernetes',
      ],
    },
    {
      type: 'category',
      label: 'Guides',
      collapsed: false,
      items: [
        'guides/index',
        'guides/joining-a-team',
        'guides/core-concepts',
        'guides/team-collaboration',
        'guides/kubernetes-operator',
        'guides/ci-cd',
        'guides/import-export',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      collapsed: false,
      items: [
        {
          type: 'category',
          label: 'CLI',
          collapsed: false,
          items: [
            'reference/cli/index',
            'reference/cli/join',
            'reference/cli/workspace',
            'reference/cli/project',
            'reference/cli/environment',
            'reference/cli/secret',
            'reference/cli/principal',
            'reference/cli/invite',
            'reference/cli/permission',
            'reference/cli/group',
            'reference/cli/sync',
            'reference/cli/diff',
            'reference/cli/audit',
            'reference/cli/run',
          ],
        },
        'reference/configuration',
        'reference/environment-variables',
      ],
    },
    {
      type: 'category',
      label: 'Self-Hosting',
      collapsed: false,
      items: [
        'self-hosting/index',
        'self-hosting/server',
        'self-hosting/docker-compose',
        'self-hosting/database',
        'self-hosting/tls',
      ],
    },
    {
      type: 'category',
      label: 'Security',
      collapsed: false,
      items: [
        'security/index',
        'security/architecture',
        'security/cryptography',
      ],
    },
  ],
};

module.exports = sidebars;
