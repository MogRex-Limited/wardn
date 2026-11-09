// Where page discussions live: GitHub Discussions on the wardn repository,
// shown on each page through giscus (https://giscus.app).
//
// To move page threads to another category, create it in the repository's
// Discussions settings and put its name and ID here. Get the ID with:
//   gh api graphql -f query='{repository(owner:"MogRex-Limited",name:"wardn"){discussionCategories(first:20){nodes{id name}}}}'
export const discussion = {
	repo: 'MogRex-Limited/wardn',
	repoId: 'R_kgDOVmga8g',
	category: 'Docs comments',
	categoryId: 'DIC_kwDOVmga8s4DKsfD',
	script: 'https://giscus.app/client.js',
} as const;

// Links to the Discussions categories, for the Community page.
const base = `https://github.com/${discussion.repo}/discussions`;
export const discussionLinks = {
	all: base,
	questions: `${base}/categories/q-a`,
	ideas: `${base}/categories/ideas`,
	general: `${base}/categories/general`,
	newQuestion: `${base}/new?category=q-a`,
	newIdea: `${base}/new?category=ideas`,
	newGeneral: `${base}/new?category=general`,
} as const;
