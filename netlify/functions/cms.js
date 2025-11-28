// netlify/functions/cms.js
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET } = process.env;
const jwt = require("jsonwebtoken");
const cookie = require("cookie");

function respond(body, status = 200) {
  return { statusCode: status, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

// Security Check: Ensures a logged-in user is attempting the action
function getUser(event) {
  try {
    const cookies = cookie.parse(event.headers.cookie || "");
    if (!cookies.session) return null;
    return jwt.verify(cookies.session, JWT_SECRET || "default_secret");
  } catch (err) { return null; }
}

exports.handler = async (event) => {
  const user = getUser(event);
  
  // RLS (Row Level Security) is on, but we still check login for client-side security
  if (!user) return respond({ error: "Unauthorized access" }, 401);

  const supabaseHeaders = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json'
  };
  const configId = 1; // We always target the main configuration row (ID 1)

  // 1. GET: Fetch the single CMS row (site_config)
  if (event.httpMethod === "GET") {
    try {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/site_config?id=eq.${configId}&select=*`, { headers: supabaseHeaders });
      const data = await res.json();
      return respond({ config: data[0] || {} }); // Return the single config row
    } catch (err) { return respond({ error: err.message }, 500); }
  }

  // 2. POST: Save/Update the single CMS row (site_config)
  if (event.httpMethod === "POST") {
    try {
      const payload = JSON.parse(event.body);
      
      // Ensure we are updating ID 1
      payload.id = configId; 

      const res = await fetch(`${SUPABASE_URL}/rest/v1/site_config`, {
        method: "POST",
        headers: { 
            ...supabaseHeaders,
            "Prefer": "return=representation,resolution=merge-duplicates" // UPSERT
        },
        body: JSON.stringify(payload)
      });
      
      return respond({ msg: "Page configuration saved", data: await res.json() });
    } catch (err) { return respond({ error: err.message }, 500); }
  }

  return respond({ error: "Method not allowed" }, 405);
};
