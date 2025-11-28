// netlify/functions/login-user.js
const { pbkdf2Sync } = require("node:crypto");
const jwt = require("jsonwebtoken");
const cookie = require("cookie");

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET } = process.env;

// Helper for sending responses
function respond(body, status = 200, headers = {}) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      ...headers
    },
    body: JSON.stringify(body)
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return respond({}, 204);

  // 1. DASHBOARD CHECK (GET Request)
  if (event.httpMethod === "GET") {
    const cookieHeader = event.headers.cookie || event.headers.Cookie || "";
    const cookies = cookie.parse(cookieHeader);
    const token = cookies.session;

    if (!token) return respond({ user: null });

    try {
      const secret = JWT_SECRET || "default_secret";
      const verifiedUser = jwt.verify(token, secret);
      return respond({ user: verifiedUser });
    } catch (err) {
      return respond({ user: null });
    }
  }

  // 2. LOGGING IN (POST Request)
  if (event.httpMethod === "POST") {
    try {
      const { username, password } = JSON.parse(event.body || "{}");
      if (!username || !password) return respond({ ok: false, error: "MISSING_FIELDS" }, 400);

      // Check User in Supabase
      const res = await fetch(`${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=id,username,password_hash,password_salt&limit=1`, {
        headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` }
      });
      const rows = await res.json();
      const user = Array.isArray(rows) && rows[0];
      
      if (!user) return respond({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

      // Verify Password
      const calc = pbkdf2Sync(password, user.password_salt, 100000, 64, "sha512").toString("hex");
      if (calc !== user.password_hash) return respond({ ok: false, error: "INVALID_CREDENTIALS" }, 401);

      // Create Token
      const secret = JWT_SECRET || "default_secret";
      const token = jwt.sign({ id: user.id, username: user.username }, secret, { expiresIn: "7d" });

      // Create Cookie
      const cookieString = cookie.serialize("session", token, {
        httpOnly: true,
        secure: true, 
        sameSite: "strict",
        path: "/",
        maxAge: 60 * 60 * 24 * 7 // 7 days
      });

      return {
        statusCode: 200,
        headers: {
            "Content-Type": "application/json",
            "Set-Cookie": cookieString
        },
        body: JSON.stringify({ ok: true, user: { id: user.id, username: user.username } })
      };

    } catch (err) {
      return respond({ ok: false, error: "EXCEPTION", details: String(err) }, 500);
    }
  }

  return respond({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
};
