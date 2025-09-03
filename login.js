document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("loginForm");
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("login-username").value.trim();
    const password = document.getElementById("login-password").value;

    try {
      const res = await fetch("/.netlify/functions/login-user", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        alert((data && data.error) || "Invalid credentials");
        return;
      }
      // store minimal session info
      localStorage.setItem("gm_user", JSON.stringify(data.user));
      // optional: store a session token if returned later
      if (data.token) localStorage.setItem("gm_token", data.token);

      window.location.href = "dashboard.html";
    } catch (err) {
      alert("Network error");
      console.error(err);
    }
  });
});
