import { pbkdf2Sync } from "node:crypto";

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

    const res = await fetch(`${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=id,username,password_hash,password_salt&limit=1`, {
      headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` }
    });
    const rows = await res.json();
    const user = Array.isArray(rows) && rows[0];
    if (!user) return respond({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    const calc = pbkdf2Sync(password, user.password_salt, 100000, 64, "sha512").toString("hex");
    if (calc !== user.password_hash) return respond({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

    // (Optional) generate a session token or JWT here.
    return respond({ ok: true, user: { id: user.id, username: user.username } });
  } catch (err) {
    return respond({ ok: false, error: "EXCEPTION", details: String(err) }, 500);
  }
};
