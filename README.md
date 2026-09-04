# Blender Box website

The public documentation lives at https://bramvr.github.io/blender-box/.

This branch contains the complete static website. Edit `index.html` for content, `styles.css` for presentation, and `favicon.svg` for the tab icon. Keep the examples aligned with the current CLI and the [project README](https://github.com/BramVR/blender-box/blob/main/README.md).

Preview this branch from its root:

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

Open `http://localhost:8080`. Check navigation, expandable examples, keyboard focus, and narrow mobile widths before publishing.

GitHub Pages publishes the root of `gh-pages` after each push. `.nojekyll` keeps the files static. No package installation or build step is required.
