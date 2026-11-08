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

`dist/` is also a plain static site that any web server can host. It becomes public with the open-source milestone (M10).

## Writing guidelines

- Lead with what the reader wants to do, then show the code.
- Every code sample must match the current API; check it against the Go code.
- Prefer a table to a long list when comparing options.
- Link concepts to their concept page the first time they appear.
