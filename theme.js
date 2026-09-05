const themeButton = document.querySelector('.theme-toggle');
function setTheme(dark, persist = false) {
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  document.querySelector('meta[name="theme-color"]').content = dark ? '#191e1b' : '#f6f5f1';
  themeButton.setAttribute('aria-pressed', String(dark));
  themeButton.title = dark ? 'Turn off dark mode' : 'Turn on dark mode';
  if (persist) {
    try { localStorage.setItem('blenderbox-theme', dark ? 'dark' : 'light'); } catch {}
  }
  window.dispatchEvent(new CustomEvent('blenderbox-theme', { detail: { dark } }));
}
setTheme(document.documentElement.dataset.theme === 'dark');
themeButton.hidden = false;
themeButton.addEventListener('click', () => setTheme(document.documentElement.dataset.theme !== 'dark', true));
