import { randomBytes, pbkdf2Sync } from "node:crypto";

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;

function respond(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type"
    }
  });
}

export default async (request) => {
  if (request.method === "OPTIONS") return respond({}, 204);
  if (request.method !== "POST") return respond({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);

  try {
    const { username, password } = await request.json().catch(() => ({}));
    if (!username || !password) return respond({ ok: false, error: "MISSING_FIELDS" }, 400);

    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      return respond({ ok: false, error: "INVALID_USERNAME" }, 400);
    }

    // Check existing
    const existsRes = await fetch(`${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=id&limit=1`, {
      headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` }
    });
    const exists = await existsRes.json();
    if (Array.isArray(exists) && exists.length) {
      return respond({ ok: false, error: "USERNAME_TAKEN" }, 409);
    }

    // Hash
    const salt = randomBytes(16).toString("hex");
    const hash = pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");

    // Insert
    const ins = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        Prefer: "return=representation"
      },
      body: JSON.stringify({ username, password_hash: hash, password_salt: salt })
    });

    if (!ins.ok) {
      const details = await ins.text();
      return respond({ ok: false, error: "SUPABASE_INSERT_FAILED", details }, 500);
    }

    const [user] = await ins.json();
    return respond({ ok: true, user: { id: user.id, username: user.username } });
  } catch (err) {
    return respond({ ok: false, error: "EXCEPTION", details: String(err) }, 500);
  }
};
