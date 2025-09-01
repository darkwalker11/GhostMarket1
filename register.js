(function(){
  document.getElementById("y").textContent = new Date().getFullYear();
  const form = document.getElementById("regForm");
  const msg  = document.getElementById("msg");
  const btn  = document.getElementById("submitBtn");
  form.addEventListener("submit", async (e)=>{
    e.preventDefault(); msg.textContent="";
    const tokenEl = document.querySelector('textarea[name="h-captcha-response"]');
    const token = tokenEl ? tokenEl.value : "";
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    if(!token){ msg.textContent="Please complete the challenge."; return; }
    if(!/^[a-zA-Z0-9._-]{3,32}$/.test(username)){ msg.textContent="Username must be 3–32 chars (a–z, 0–9, . _ -)"; return; }
    if(password.length<8){ msg.textContent="Password must be at least 8 characters."; return; }
    btn.classList.add("loading"); btn.disabled=true;
    try{
      const res = await fetch("/.netlify/functions/register-user",{method:"POST",headers:{ "Content-Type":"application/json"}, body: JSON.stringify({ username, password, token })});
      const data = await res.json();
      if(data.ok || data.success){ msg.textContent="✅ Account created. Redirecting to login…"; if(window.hcaptcha) hcaptcha.reset(); setTimeout(()=>{ window.location.href="login.html"; }, 900); }
      else if(data.error==="username_taken"){ msg.textContent="That username is already taken."; if(window.hcaptcha) hcaptcha.reset(); }
      else if(data.error==="captcha_failed"){ msg.textContent="Captcha failed — try again."; if(window.hcaptcha) hcaptcha.reset(); }
      else { msg.textContent="Registration failed. Please try again."; }
    }catch(err){ msg.textContent="Network error. Please try again."; }
    finally{ btn.classList.remove("loading"); btn.disabled=false; }
  });
})();