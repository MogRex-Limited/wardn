// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';

const repo = 'https://github.com/MogRex-Limited/wardn';

export default defineConfig({
	site: 'https://wardn.oprexcloud.com',
	telemetry: false,
	integrations: [
		starlight({
			title: 'wardn',
			description: 'Simple, opinionated authorization for Go. Define your roles, permissions and tenancy; wardn handles the rest.',
			logo: { src: './src/assets/logo.svg', replacesTitle: false },
			favicon: '/favicon.svg',
			social: [{ icon: 'github', label: 'GitHub', href: repo }],
			editLink: { baseUrl: `${repo}/edit/main/website/` },
			lastUpdated: true,
			customCss: ['./src/styles/custom.css'],
			components: {
				// Adds each page's discussion thread (src/components/Discussion.astro).
				Footer: './src/components/Footer.astro',
				// Adds the Community button to the top bar (src/components/SocialIcons.astro).
				SocialIcons: './src/components/SocialIcons.astro',
			},
			plugins: [starlightLinksValidator({ errorOnLocalLinks: false })],
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ label: 'Introduction', slug: 'getting-started/introduction' },
						{ label: 'Quick start (10 minutes)', slug: 'getting-started/quick-start' },
						{ label: 'Installation', slug: 'getting-started/installation' },
					],
				},
				{
					label: 'Learn',
					items: [
						{ label: 'What is authorization?', slug: 'learn/authorization' },
						{ label: 'Role-based access control', slug: 'learn/rbac' },
						{ label: 'Roles in a hierarchy', slug: 'learn/hierarchy' },
						{ label: 'RBAC, ReBAC and ABAC', slug: 'learn/models' },
						{ label: 'Libraries, engines and servers', slug: 'learn/architectures' },
						{ label: 'Common mistakes', slug: 'learn/mistakes' },
					],
				},
				{
					label: 'Concepts',
					items: [
						{ label: 'Overview', slug: 'concepts/overview' },
						{ label: 'Permissions', slug: 'concepts/permissions' },
						{ label: 'Roles', slug: 'concepts/roles' },
						{ label: 'Scopes and hierarchy', slug: 'concepts/scopes' },
						{ label: 'Assignments', slug: 'concepts/assignments' },
						{ label: 'How a decision is made', slug: 'concepts/evaluation' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'Protect HTTP routes', slug: 'guides/http' },
						{ label: 'Check access in code', slug: 'guides/checks' },
						{ label: 'Multi-tenancy', slug: 'guides/multi-tenancy' },
						{ label: 'Custom roles and admin screens', slug: 'guides/custom-roles' },
						{ label: 'The escalation guard', slug: 'guides/escalation-guard' },
						{ label: 'Time-limited access', slug: 'guides/time-limited-access' },
						{ label: 'Audit trail', slug: 'guides/audit' },
						{ label: 'Testing', slug: 'guides/testing' },
						{ label: 'Typo-proof names (wardn gen)', slug: 'guides/code-generation' },
						{ label: 'Choosing a store', slug: 'guides/stores' },
						{ label: 'Changes in your own transaction', slug: 'guides/transactions' },
						{ label: 'Row-level security', slug: 'guides/row-level-security' },
						{ label: 'Caching across instances', slug: 'guides/caching' },
						{ label: 'Performance', slug: 'guides/performance' },
					],
				},
				{
					label: 'Recipes',
					items: [
						{ label: 'Reference applications', slug: 'recipes/reference-apps' },
						{ label: 'Multi-branch bank', slug: 'recipes/bank' },
						{ label: 'Multi-tenant SaaS', slug: 'recipes/saas' },
						{ label: 'App without tenancy', slug: 'recipes/simple' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Policy file', slug: 'reference/policy-file' },
						{ label: 'Configuration', slug: 'reference/configuration' },
						{ label: 'Go API', slug: 'reference/go-api' },
						{ label: 'Errors and HTTP statuses', slug: 'reference/errors' },
						{ label: 'CLI', slug: 'reference/cli' },
						{ label: 'Writing a store', slug: 'reference/writing-a-store' },
					],
				},
				{
					label: 'Security',
					items: [
						{ label: 'Security model', slug: 'security/overview' },
						{ label: 'Threat model', slug: 'security/threat-model' },
						{ label: 'How wardn is tested', slug: 'security/testing' },
						{ label: 'Reporting a vulnerability', slug: 'security/reporting' },
					],
				},
				{
					label: 'Community',
					items: [
						{ label: 'Ask, suggest, discuss', link: '/community/', badge: { text: 'New', variant: 'tip' } },
						{ label: 'All discussions on GitHub', link: `${repo}/discussions`, attrs: { target: '_blank', rel: 'noopener' } },
					],
				},
				{
					label: 'Project',
					items: [
						{ label: 'Design decisions', slug: 'project/decisions' },
						{ label: 'Roadmap', slug: 'project/roadmap' },
						{ label: 'Stability promise', slug: 'project/stability' },
						{ label: 'Contributing', slug: 'project/contributing' },
					],
				},
			],
		}),
	],
});
