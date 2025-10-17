(() => {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
      setTimeout(fn, 0);
    } else {
      document.addEventListener('DOMContentLoaded', fn, { once: true });
    }
  }

  ready(() => {
    const timePlaceholder = document.querySelector('[data-current-time]');
    if (timePlaceholder) {
      timePlaceholder.textContent = new Date().toLocaleString();
    }
  });
})();
