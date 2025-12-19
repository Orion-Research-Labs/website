# Orion Labs Website (v1)

Static website (Home + Research blog) built with Astro + MDX. Deployable on Netlify.

## Run locally
```bash
npm install
npm run dev
```

## Build
```bash
npm run build
npm run preview
```

## Netlify settings
- Build command: `npm run build`
- Publish directory: `dist`

## Add a new post
Add a file in `src/content/research/<slug>.mdx` with frontmatter:
```md
---
title: "Title"
description: "One sentence description."
date: 2025-12-19
tags: ["Mobile", "AI Research"]
draft: false
---
```

RSS: `/rss.xml`
