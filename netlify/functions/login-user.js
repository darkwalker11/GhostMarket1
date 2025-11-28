import { pbkdf2Sync } from "node:crypto";
import jwt from "jsonwebtoken";
import cookie from "cookie";

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET } = process.env;

function respond(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      ...headers
    }
  });
}

export default async (request) => {
  if (request.method === "OPTIONS") return respond({}, 204);

  // 1. CHECK LOGIN (Dashboard calls this)
  if (request.method === "GET") {
    const cookieHeader = request.headers.get("cookie") || "";
    const cookies = cookie.parse(cookieHeader);
    const token = cookies.session;

    if (!token) return respond({ user: null });

    try {
      // If no secret is set, it uses a default so it won't crash, but you should set one!
      const secret = JWT_SECRET || "default_dev_secret_CHANGE_ME";
      const verifiedUser = jwt.verify(token, secret);
      return respond({ user: verifiedUser });
    } catch (err) {
      return respond({ user: null });
    }
  }

  // 2. PERFORM LOGIN (Login page calls this)
  if (request.method === "POST") {
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

      // Create the token
      const secret = JWT_SECRET || "default_dev_secret_CHANGE_ME";
      const token = jwt.sign({ id: user.id, username: user.username }, secret, { expiresIn: "7d" });

      // Create the cookie string
      const cookieString = cookie.serialize("session", token, {
        httpOnly: true,
        secure: true, 
        sameSite: "strict",
        path: "/",
        maxAge: 60 * 60 * 24 * 7 // 7 days
      });

      return respond({ ok: true, user: { id: user.id, username: user.username } }, 200, {
        "Set-Cookie": cookieString
      });

    } catch (err) {
      return respond({ ok: false, error: "EXCEPTION", details: String(err) }, 500);
    }
  }

  return respond({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
};
