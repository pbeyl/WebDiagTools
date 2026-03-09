let themeToggleInitialized = false;

function getThemeIconSvg(isDark) {
  if (isDark) {
    return '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 18a1 1 0 011 1v2a1 1 0 11-2 0v-2a1 1 0 011-1zm0-16a1 1 0 011 1v2a1 1 0 11-2 0V3a1 1 0 011-1zm9 9a1 1 0 010 2h-2a1 1 0 110-2h2zM5 12a1 1 0 010 2H3a1 1 0 110-2h2zm12.364 5.95a1 1 0 011.414 1.414l-1.414 1.414a1 1 0 01-1.414-1.414l1.414-1.414zM7.636 6.636A1 1 0 019.05 8.05L7.636 9.464A1 1 0 116.222 8.05l1.414-1.414zm9.728 1.414a1 1 0 10-1.414-1.414L14.536 8.05a1 1 0 101.414 1.414l1.414-1.414zM9.464 15.95a1 1 0 00-1.414 0L6.636 17.364a1 1 0 101.414 1.414l1.414-1.414a1 1 0 000-1.414zM12 8a4 4 0 100 8 4 4 0 000-8z"/></svg>';
  }

  return '<svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.742 13.045A8.088 8.088 0 0110.955 3.258 9 9 0 1020.742 13.045z"/></svg>';
}

function initThemeToggle() {
  if (themeToggleInitialized) {
    return;
  }
  themeToggleInitialized = true;

  const themeToggle = document.getElementById('theme-toggle');
  const themeIcon = document.getElementById('theme-toggle-icon');
  const body = document.body;
  const root = document.documentElement;

  const setTheme = (isDark) => {
    root.classList.toggle('dark-mode', isDark);
    body.classList.toggle('dark-mode', isDark);
    localStorage.setItem('theme', isDark ? 'dark' : 'light');
    if (themeIcon) {
      themeIcon.innerHTML = getThemeIconSvg(isDark);
    }
  };

  setTheme(localStorage.getItem('theme') === 'dark');

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      setTheme(!body.classList.contains('dark-mode'));
    });
  }
}

window.initThemeToggle = initThemeToggle;

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initThemeToggle();
  });
} else {
  initThemeToggle();
}