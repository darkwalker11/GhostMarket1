// netlify/functions/register-user.js
const { randomBytes, pbkdf2Sync } = require("node:crypto");
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = process.env;

function respond(body, status = 200) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    },
    body: JSON.stringify(body),
  };
}

exports.handler = async (event) => {
  // 1. TRACKING START
  console.log("STARTING REGISTER FUNCTION...");
  
  if (event.httpMethod === "OPTIONS") return respond({}, 204);

  try {
    // 2. CHECK INPUTS
    const { username, password } = JSON.parse(event.body || "{}");
    console.log("Input received for user:", username);

    // 3. CHECK DATABASE KEYS
    if (!SUPABASE_URL) throw new Error("Missing SUPABASE_URL");
    if (!SUPABASE_SERVICE_ROLE_KEY) throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY");

    // 4. TALK TO SUPABASE
    console.log("Checking if user exists...");
    const existsRes = await fetch(`${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=id&limit=1`, {
      headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` }
    });

    if (!existsRes.ok) {
       const errText = await existsRes.text();
       throw new Error(`Supabase Connection Failed: ${existsRes.status} - ${errText}`);
    }

    const exists = await existsRes.json();
    if (Array.isArray(exists) && exists.length) {
      console.log("Username taken");
      return respond({ ok: false, error: "USERNAME_TAKEN" }, 409);
    }

    // 5. CREATE USER
    console.log("Hashing password and creating user...");
    const salt = randomBytes(16).toString("hex");
    const hash = pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");

    const ins = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        Prefer: "return=representation"
      },
      body: JSON.stringify({ username, password_hash: hash, password_salt: salt })
    });

    if (!ins.ok) {
      const details = await ins.text();
      throw new Error(`Insert Failed: ${details}`);
    }

    const [user] = await ins.json();
    console.log("SUCCESS! User created.");
    return respond({ ok: true, user: { id: user.id, username: user.username } });
    
  } catch (err) {
    // 6. FORCE ERROR TO LOGS
    console.error("CRITICAL CRASH ERROR:", err.message); // This is what we need to see!
    return respond({ ok: false, error: "EXCEPTION", details: err.message }, 500);
  }
};
