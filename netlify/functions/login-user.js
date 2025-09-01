// netlify/functions/login-user.js (CommonJS)
const crypto = require("crypto");
function j(body, status=200){ return { statusCode: status, headers: { "Content-Type":"application/json","Access-Control-Allow-Origin":"*" }, body: JSON.stringify(body)};}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") return j({ ok: false, error: "method" }, 405);
    const { username, password, token } = JSON.parse(event.body || "{}");
    if (!username || !password) return j({ ok: false, error: "missing_fields" }, 400);

    if (token) {
      const secret = process.env.HCAPTCHA_SECRET;
      const form = new URLSearchParams({ secret, response: token });
      const capResp = await fetch("https://hcaptcha.com/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
      });
      const cap = await capResp.json();
      if (!cap.success) return j({ ok: false, error: "captcha_failed" }, 403);
    }

    const { SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
    const resp = await fetch(`${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=id,username,password_hash&limit=1`, {
      headers: { apikey: SUPABASE_SERVICE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_KEY}` },
    });
    if (!resp.ok) { const detail = await resp.text(); return j({ ok: false, error: "db_error", detail }, 500); }
    const rows = await resp.json();
    if (!rows.length) return j({ ok: false, error: "auth_failed" }, 401);

    const row = rows[0];
    const [saltHex, hashHex] = row.password_hash.split(":");
    const salt = Buffer.from(saltHex, "hex"); const expected = Buffer.from(hashHex, "hex");
    const derived = await new Promise((res, rej)=>
      crypto.scrypt(password, salt, expected.length, { N:16384, r:8, p:1 }, (err, buf)=> err?rej(err):res(buf))
    );
    const match = crypto.timingSafeEqual(derived, expected);
    if (!match) return j({ ok: false, error: "auth_failed" }, 401);

    return j({ ok: true, user: { id: row.id, username: row.username } });
  } catch(e) { return j({ ok:false, error:"exception", detail:String(e) }, 500); }
};
