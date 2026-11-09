# wardn documentation site

The landing page and documentation for wardn, built with [Astro Starlight](https://starlight.astro.build).

```bash
npm ci
npm run dev      # http://localhost:4321, reloads as you edit
npm run build    # writes dist/ and fails on any broken internal link
```

Pages are in `src/content/docs/`, one `.mdx` file per page. The sidebar is defined in `astro.config.mjs`. The landing page is `src/content/docs/index.mdx`.

## Hosting

While wardn is internal, host the site privately: for example on an internal server, or behind company sign-in. The container serves the built site with nginx, as a non-root user:

```bash
docker build -t wardn-docs .
docker run --rm -p 3002:3002 wardn-docs
```

`dist/` is also a plain static site that any web server can host. On a host whose Node.js is too old for Astro and can't be changed, use `sh website/build.sh` as the build command: it downloads a pinned, checksum-verified Node.js for the build. On a host that runs a process rather than a container, start the site with `node website/serve.mjs`: a dependency-free static server with the same security headers as `nginx.conf`, on `PORT` (default 3002).

## Discussions

Every docs page ends with a **Questions and comments** thread, and the [Community page](src/content/docs/community/index.mdx) (`/community/`, linked from the top bar on every page) explains where to post. Both use the repository's [GitHub Discussions](https://github.com/MogRex-Limited/wardn/discussions); the per-page threads are shown through [giscus](https://giscus.app) (`src/components/Discussion.astro`, added to every page by the `Footer` override in `astro.config.mjs`).

- **Setup (once):** Discussions must be enabled on the repository, and the [giscus app](https://github.com/apps/giscus) installed on it. Without the app, the page threads show an error; nothing else breaks.
- **Category and IDs** are in `src/discussion.config.ts`. Each page gets its own discussion, titled with its path, created on the first comment.
- **Hide the thread** on a page with `discussion: false` in its frontmatter. The home page never shows one.
- **Security headers:** `nginx.conf` and `serve.mjs` allow scripts, styles and frames from `https://giscus.app`. Keep them in step if you change either.

## Writing guidelines

- Lead with what the reader wants to do, then show the code.
- Every code sample must match the current API; check it against the Go code.
- Prefer a table to a long list when comparing options.
- Link concepts to their concept page the first time they appear.
