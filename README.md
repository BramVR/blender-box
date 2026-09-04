# Blender Box website

The public documentation lives at https://bramvr.github.io/blender-box/.

This branch contains the complete static website. Edit `index.html` for content, `styles.css` for presentation, `navigation.js` for the contents menu and current-section indicator, and `favicon.svg` for the tab icon. Keep the examples aligned with the current CLI and the [project README](https://github.com/BramVR/blender-box/blob/main/README.md).

The sidebar covers the introduction, setup guide, and reference. On smaller screens, use the **On this page** button to open it. The navigation remains available without JavaScript.

Preview this branch from its root:

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://localhost:8080`. Check navigation, expandable examples, keyboard focus, and narrow mobile widths before publishing.

GitHub Pages publishes the root of `gh-pages` after each push. `.nojekyll` keeps the files static. No package installation or build step is required.

## Saved version

The [website-before-sidebar-2026-09-05 tag](https://github.com/BramVR/blender-box/tree/website-before-sidebar-2026-09-05) preserves the complete published website before the sidebar redesign. Restore its files in a new commit on `gh-pages` to publish that version again while keeping the branch history.
