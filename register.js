document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("registerForm");
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("reg-username").value.trim();
    const password = document.getElementById("reg-password").value;

    try {
      const res = await fetch("/.netlify/functions/register-user", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        alert((data && data.error) || "Registration failed");
        return;
      }
      alert("Account created. Please sign in.");
      window.location.href = "login.html";
    } catch (err) {
      alert("Network error");
      console.error(err);
    }
  });
});
