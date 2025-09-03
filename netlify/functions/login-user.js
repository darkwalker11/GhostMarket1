import { pbkdf2Sync } from "node:crypto";

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, HCAPTCHA_SECRET } = process.env;

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}

export default async (request, context) => {
  try {
    if (request.method !== "POST") {
      return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
    }

    const { username, password, hcaptchaToken } = await request.json().catch(() => ({}));
    if (!username || !password || !hcaptchaToken) {
      return json({ ok: false, error: "MISSING_FIELDS" }, 400);
    }

    // Verify hCaptcha (same as register)
    const hres = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: HCAPTCHA_SECRET || "", response: hcaptchaToken })
    });
    const hjson = await hres.json();
    if (!hjson.success) {
      console.error("hCaptcha failed:", hjson);
      return json({ ok: false, error: "HCAPTCHA_FAILED", details: hjson }, 400);
    }

    // Fetch user row
    const ures = await fetch(
      `${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=id,username,password_hash,password_salt`,
      {
        headers: {
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        },
      }
    );

    if (!ures.ok) {
      const txt = await ures.text();
      console.error("Supabase read failed:", ures.status, txt);
      return json({ ok: false, error: "SUPABASE_READ_FAILED", status: ures.status, details: txt }, 500);
    }

    const rows = await ures.json();
    if (!Array.isArray(rows) || rows.length === 0) {
      return json({ ok: false, error: "USER_NOT_FOUND" }, 401);
    }

    const user = rows[0];
    if (!user.password_hash || !user.password_salt) {
      // This happens if the user was created before we added hashing/salt.
      return json({ ok: false, error: "MISSING_HASH_SALT" }, 401);
    }

    // Recompute hash using same parameters as register-user
    const computed = pbkdf2Sync(password, user.password_salt, 100000, 64, "sha512").toString("hex");

    if (computed !== user.password_hash) {
      return json({ ok: false, error: "BAD_PASSWORD" }, 401);
    }

    // Create a very basic session cookie (demo purposes; consider JWT in production)
    const token = `${user.id}.${Date.now()}`; // lightweight opaque token
    const cookie = [
      `gm_session=${encodeURIComponent(token)}`,
      "Path=/",
      "HttpOnly",
      "SameSite=Strict",
      "Max-Age=86400"
    ].join("; ");

    return json(
      { ok: true, user: { id: user.id, username: user.username } },
      200,
      { "Set-Cookie": cookie }
    );
  } catch (err) {
    console.error("login-user exception:", err);
    return json({ ok: false, error: err?.message || String(err) }, 500);
  }
};
