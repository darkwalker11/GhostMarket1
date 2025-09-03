
// login.js - updated to send required fields (username, password, hcaptchaToken)

(function () {
  function $(sel) {
    return document.querySelector(sel);
  }

  const form = document.getElementById('loginForm') || $('form[action="#login"]') || $('form');
  const userInput = $('#username') || $('input[name="username"]');
  const passInput = $('#password') || $('input[name="password"]');
  const loginBtn = $('#loginBtn') || $('button[type="submit"]');

  async function doLogin(evt) {
    if (evt) evt.preventDefault();

    const username = (userInput && userInput.value || '').trim();
    const password = passInput && passInput.value || '';

    // Get hCaptcha response from the embedded widget
    let hcaptchaToken = '';
    try {
      if (window.hcaptcha && typeof window.hcaptcha.getResponse === 'function') {
        hcaptchaToken = window.hcaptcha.getResponse();
      }
    } catch (e) {
      // ignore
    }

    if (!username || !password || !hcaptchaToken) {
      alert('Please enter username, password, and complete the captcha.');
      return;
    }

    try {
      loginBtn && (loginBtn.disabled = true);

      const res = await fetch('/.netlify/functions/login-user', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, password, hcaptchaToken })
      });

      const data = await res.json().catch(() => ({}));

      if (data && data.ok) {
        // success -> go to dashboard
        window.location.href = '/dashboard.html';
      } else {
        alert((data && data.error) || 'Login failed');
      }
    } catch (err) {
      alert('Network error: ' + (err?.message || err));
    } finally {
      try { window.hcaptcha && window.hcaptcha.reset(); } catch(e) {}
      loginBtn && (loginBtn.disabled = false);
    }
  }

  if (form) form.addEventListener('submit', doLogin);
  if (loginBtn) loginBtn.addEventListener('click', doLogin);
})();
