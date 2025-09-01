import { randomBytes, pbkdf2Sync } from "node:crypto";

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, HCAPTCHA_SECRET } = process.env;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

export default async (request, context) => {
  try {
    if (request.method !== "POST") {
      return json({ ok: false, error: "Method not allowed" }, 405);
    }

    const { username, password, hcaptchaToken } = await request.json().catch(() => ({}));
    if (!username || !password || !hcaptchaToken) {
      return json({ ok: false, error: "Missing fields" }, 400);
    }

    // Verify hCaptcha
    const hres = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: HCAPTCHA_SECRET || "", response: hcaptchaToken })
    });
    const hjson = await hres.json();
    if (!hjson.success) {
      console.error("hCaptcha failed:", hjson);
      return json({ ok: false, error: "hCaptcha failed", details: hjson }, 400);
    }

    // Validate username
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      return json({ ok: false, error: "Invalid username" }, 400);
    }

    // Check if username exists
    const existsRes = await fetch(`${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=id&limit=1`, {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      }
    });
    const exists = await existsRes.json();
    if (Array.isArray(exists) && exists.length > 0) {
      return json({ ok: false, error: "Username already taken" }, 409);
    }

    // Hash password
    const salt = randomBytes(16).toString("hex");
    const hash = pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");

    // Insert new user
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        Prefer: "return=representation"
      },
      body: JSON.stringify({ username, password_hash: hash, password_salt: salt })
    });

    if (!insertRes.ok) {
      const txt = await insertRes.text();
      console.error("Supabase insert failed:", insertRes.status, txt);
      return json({ ok: false, error: "Supabase insert failed", status: insertRes.status, details: txt }, 500);
    }

    const [user] = await insertRes.json();
    return json({ ok: true, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error("register-user exception:", err);
    return json({ ok: false, error: err?.message || String(err) }, 500);
  }
};
