(function(){
  document.getElementById("y").textContent = new Date().getFullYear();
  const form = document.getElementById("loginForm"); const msg = document.getElementById("msg"); const btn = document.getElementById("loginBtn");
  form.addEventListener("submit", async (e)=>{
    e.preventDefault(); msg.textContent="";
    const tokenEl = document.querySelector('textarea[name="h-captcha-response"]'); const token = tokenEl ? tokenEl.value : "";
    const username = document.getElementById("username").value.trim(); const password = document.getElementById("password").value;
    if(!/^[a-zA-Z0-9._-]{3,32}$/.test(username)){ msg.textContent="Invalid username format."; return; }
    if(password.length<8){ msg.textContent="Password too short."; return; }
    btn.classList.add("loading"); btn.disabled=true;
    try{
      const res = await fetch("/.netlify/functions/login-user",{method:"POST",headers:{ "Content-Type":"application/json"}, body: JSON.stringify({ username, password, token })});
      const data = await res.json();
      if(data.ok || data.success){ window.location.href="dashboard.html"; }
      else if(data.error==="captcha_failed"){ msg.textContent="Captcha failed — try again."; if(window.hcaptcha) hcaptcha.reset(); }
      else if(data.error==="auth_failed"){ msg.textContent="Invalid username or password."; if(window.hcaptcha) hcaptcha.reset(); }
      else { msg.textContent="Login failed. Please try again."; }
    }catch(err){ msg.textContent="Network error. Please try again."; }
    finally{ btn.classList.remove("loading"); btn.disabled=false; }
  });
})();