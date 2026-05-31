(function () {
  'use strict';

  const nativeSetInterval = window.setInterval.bind(window);
  const nativeClearInterval = window.clearInterval.bind(window);
  const trackedIntervals = new Set();

  window.setInterval = function trackedSetInterval(fn, delay, ...args) {
    const id = nativeSetInterval(fn, delay, ...args);
    trackedIntervals.add(id);
    return id;
  };

  window.clearInterval = function trackedClearInterval(id) {
    trackedIntervals.delete(id);
    return nativeClearInterval(id);
  };

  function clearRuntimeIntervals() {
    trackedIntervals.forEach(id => nativeClearInterval(id));
    trackedIntervals.clear();
  }

  const credentials = {
    evaluator: { email: 'evaluator@cbse.gov.in', pass: 'CBSE@2024' },
    admin: { email: 'admin@cbse.gov.in', pass: 'Admin@2024' },
    superadmin: { email: 'superadmin@cbse.gov.in', pass: 'SuperAdmin@2024' },
    monitor: { email: 'monitor@cbse.gov.in', pass: 'Monitor@2024' },
  };

  function selectedRoleKey() {
    const activeTab = document.querySelector('.role-tab.active');
    const key = activeTab ? activeTab.dataset.role : 'evaluator';
    return credentials[key] ? key : 'evaluator';
  }

  function patchQuickDemoLogin() {
    const demoBtn = document.getElementById('btn-demo-login');
    if (!demoBtn) return;

    demoBtn.onclick = () => {
      const roleKey = selectedRoleKey();
      const selected = credentials[roleKey] || credentials.evaluator;
      const email = document.getElementById('login-email');
      const pass = document.getElementById('login-pass');
      const loginBtn = document.getElementById('btn-login');

      if (email) email.value = selected.email;
      if (pass) pass.value = selected.pass;
      demoBtn.disabled = true;
      if (loginBtn) loginBtn.disabled = true;

      window.setTimeout(() => {
        if (typeof window.doLogin === 'function') {
          window.doLogin(selected.email, selected.pass, roleKey);
        }
        window.setTimeout(() => {
          demoBtn.disabled = false;
          if (loginBtn) loginBtn.disabled = false;
        }, 2600);
      }, 120);
    };
  }

  function patchLogoutCleanup() {
    if (typeof window.doLogout !== 'function' || window.doLogout.__evalSyncPatched) return;

    const originalLogout = window.doLogout;
    window.doLogout = function patchedLogout(...args) {
      try {
        return originalLogout.apply(this, args);
      } finally {
        clearRuntimeIntervals();
        patchQuickDemoLogin();
      }
    };
    window.doLogout.__evalSyncPatched = true;
  }

  function applyRuntimeFixes() {
    patchQuickDemoLogin();
    patchLogoutCleanup();
  }

  document.addEventListener('DOMContentLoaded', () => {
    window.setTimeout(applyRuntimeFixes, 0);
  });

  window.__evalSyncRuntime = {
    applyRuntimeFixes,
    clearRuntimeIntervals,
  };
})();
