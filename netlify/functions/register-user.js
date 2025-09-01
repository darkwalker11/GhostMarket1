// netlify/functions/register-user.js (CommonJS)
const crypto = require("crypto");

function j(body, status=200){ return { statusCode: status, headers: { "Content-Type":"application/json","Access-Control-Allow-Origin":"*" }, body: JSON.stringify(body)};}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== "POST") return j({ ok: false, error: "method" }, 405);
    const { username, password, token } = JSON.parse(event.body || "{}");
    if (!username || !password || !token) return j({ ok: false, error: "missing_fields" }, 400);

    const secret = process.env.HCAPTCHA_SECRET;
    const form = new URLSearchParams({ secret, response: token });
    const capResp = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    const cap = await capResp.json();
    if (!cap.success) return j({ ok: false, error: "captcha_failed" }, 403);

    const salt = crypto.randomBytes(16);
    const hash = await new Promise((res, rej) =>
      crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1 }, (err, buf) => err ? rej(err) : res(buf))
    );
    const password_hash = `${salt.toString("hex")}:${hash.toString("hex")}`;

    const { SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
    const resp = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
      method: "POST",
      headers: {
        apikey: SUPABASE_SERVICE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
        "Content-Type": "application/json",
        Prefer: "return=representation",
      },
      body: JSON.stringify({ username, password_hash }),
    });
    if (!resp.ok) {
      if (resp.status === 409) return j({ ok: false, error: "username_taken" }, 409);
      const detail = await resp.text();
      return j({ ok: false, error: "db_error", detail }, 500);
    }
    const [user] = await resp.json();
    return j({ ok: true, user: { id: user.id, username: user.username } }, 201);
  } catch (e) { return j({ ok: false, error: "exception", detail: String(e) }, 500); }
};
