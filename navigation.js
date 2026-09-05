const sidebar = document.querySelector('.docs-sidebar');
const toggle = document.querySelector('.contents-toggle');
const links = [...document.querySelectorAll('#docs-navigation a[href^="#"]')];
const sections = links.map(link => document.querySelector(link.hash));
const mobile = window.matchMedia('(max-width: 900px)');

sidebar.classList.add('enhanced');

function closeContents() {
  toggle.setAttribute('aria-expanded', 'false');
}

toggle.addEventListener('click', () => {
  toggle.setAttribute('aria-expanded', String(toggle.getAttribute('aria-expanded') !== 'true'));
});

sidebar.addEventListener('keydown', event => {
  if (event.key === 'Escape' && mobile.matches) {
    closeContents();
    toggle.focus();
  }
});

document.querySelectorAll('a[href^="#"]').forEach(link => {
  link.addEventListener('click', () => {
    if (mobile.matches) {
      closeContents();
      const destination = document.getElementById(link.hash.slice(1)) || document.querySelector('main');
      destination.setAttribute('tabindex', '-1');
      destination.focus({ preventScroll: true });
    }
  });
});

function updateCurrentSection() {
  const offset = mobile.matches ? 155 : 120;
  let current = 0;
  sections.forEach((section, index) => {
    if (section.getBoundingClientRect().top <= offset) current = index;
  });
  if (window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2) {
    current = sections.length - 1;
  }
  links.forEach((link, index) => {
    if (index === current) link.setAttribute('aria-current', 'location');
    else link.removeAttribute('aria-current');
  });
}

let scheduled = false;
window.addEventListener('scroll', () => {
  if (scheduled) return;
  scheduled = true;
  window.requestAnimationFrame(() => {
    updateCurrentSection();
    scheduled = false;
  });
}, { passive: true });
window.addEventListener('resize', updateCurrentSection);
window.addEventListener('load', updateCurrentSection);
mobile.addEventListener('change', closeContents);
updateCurrentSection();

// Add controls only with JavaScript; code remains selectable without it.
const copyFeedback = document.createElement('p');
copyFeedback.className = 'visually-hidden';
copyFeedback.setAttribute('role', 'status');
document.body.append(copyFeedback);

document.querySelectorAll('.steps pre').forEach((pre, index) => {
  const code = pre.querySelector('code');
  if (!code) return;
  const button = document.createElement('button');
  const label = pre.closest('details')?.querySelector('summary')?.textContent.trim()
    || pre.closest('.step')?.querySelector('h2')?.textContent.trim()
    || 'example';
  button.type = 'button';
  button.className = 'copy-button';
  button.textContent = 'Copy';
  button.setAttribute('aria-label', `Copy code ${index + 1}: ${label}`);
  let toolbar = pre.parentElement.querySelector(':scope > .code-title');
  if (!toolbar) {
    toolbar = document.createElement('div');
    toolbar.className = 'copy-toolbar';
    pre.before(toolbar);
  }
  toolbar.append(button);
  let resetTimer;
  button.addEventListener('click', async () => {
    clearTimeout(resetTimer);
    button.disabled = true;
    copyFeedback.textContent = '';
    try {
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = 'Copied';
      copyFeedback.textContent = `${label} copied.`;
    } catch {
      // Denied clipboard access still leaves a keyboard-copyable selection.
      const range = document.createRange();
      range.selectNodeContents(code);
      const selection = window.getSelection();
      pre.focus();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = 'Code selected';
      copyFeedback.textContent = 'Clipboard access is unavailable. Code selected; press Control+C or Command+C to copy.';
    } finally {
      button.disabled = false;
      resetTimer = window.setTimeout(() => { button.textContent = 'Copy'; }, 3000);
    }
  });
});
