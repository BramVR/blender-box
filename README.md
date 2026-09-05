# Blender Box website

The public documentation lives at https://bramvr.github.io/blender-box/.

This branch contains the complete static website. Edit `index.html` for the guide and FAQ, `commands.html` for the command reference, `styles.css` for presentation, `navigation.js` for the contents menu and current-section indicator, and `favicon.svg` for the tab icon. Keep the examples aligned with the current CLI and the [project README](https://github.com/BramVR/blender-box/blob/main/README.md).

The sidebar covers the introduction, setup guide, and reference. On smaller screens, use the **On this page** button to open it. The navigation remains available without JavaScript.

Preview this branch from its root:

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://localhost:8080`. Check navigation, expandable examples, keyboard focus, and narrow mobile widths before publishing.

GitHub Pages publishes the root of `gh-pages` after each push. `.nojekyll` keeps the files static. No package installation or build step is required.

## Search and agent discovery

Both HTML pages include a unique title, description, canonical URL, Open Graph and Twitter preview metadata, and JSON-LD describing the website, source repository, and page. FAQ structured answers must match the visible answers. The FAQ is useful documentation; its markup does not promise a Google rich result. Keep the shared header, sidebar, and footer aligned between pages.

`sitemap.xml` lists the two canonical HTML URLs. Update a page's `lastmod` when its content changes. `llms.txt` provides a compact documentation index for agents and links to the source Markdown contracts. It is an optional convention, not a search ranking signal. `social-preview.png` reuses the repository's banner.

The effective robots policy is at `https://bramvr.github.io/robots.txt`, outside this project site's path. It returned HTTP 404 on 2026-09-05, so it does not block crawling. A robots file inside `/blender-box/` would not control crawlers. Do not add one here or change the account-wide website as part of a project-only update.

To submit the site, verify the URL-prefix property `https://bramvr.github.io/blender-box/` in Google Search Console and Bing Webmaster Tools, then submit `https://bramvr.github.io/blender-box/sitemap.xml`. If either service supplies an HTML verification file or meta tag, retain it after verification. Request indexing for the home page and command reference after submission. Search engines control whether and when they index the pages.

After changes, check both pages at desktop and mobile widths, follow every local link, open the FAQ disclosures, parse each JSON-LD block, and verify that sitemap URLs match the canonical tags. Increment the stylesheet or script URL version when changing those assets so returning visitors load the update.

## Saved version

The [website-before-sidebar-2026-09-05 tag](https://github.com/BramVR/blender-box/tree/website-before-sidebar-2026-09-05) preserves the complete published website before the sidebar redesign. Restore its files in a new commit on `gh-pages` to publish that version again while keeping the branch history.
