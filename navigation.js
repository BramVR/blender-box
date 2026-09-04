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
