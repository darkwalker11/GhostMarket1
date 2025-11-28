// netlify/functions/cms.js
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET } = process.env;
const jwt = require("jsonwebtoken");
const cookie = require("cookie");

function respond(body, status = 200) {
  return { statusCode: status, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

function getUser(event) {
  try {
    const cookies = cookie.parse(event.headers.cookie || "");
    if (!cookies.session) return null;
    return jwt.verify(cookies.session, JWT_SECRET || "default_secret");
  } catch (err) { return null; }
}

exports.handler = async (event) => {
  const user = getUser(event);
  
  const supabaseHeaders = {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json'
  };
  const configId = 1; 

  // 1. GET: Fetch content (PUBLIC READ ACCESS)
  // We removed the security check here so the dashboard can always load.
  if (event.httpMethod === "GET") {
    try {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/site_config?id=eq.${configId}&select=*`, { headers: supabaseHeaders });
      const data = await res.json();
      return respond({ config: data[0] || {} }); 
    } catch (err) { return respond({ error: err.message }, 500); }
  }

  // 2. POST: Save content (ADMIN ONLY)
  // We keep the security check here. Only logged-in users can save.
  if (event.httpMethod === "POST") {
    if (!user) return respond({ error: "Unauthorized access" }, 401);

    try {
      const payload = JSON.parse(event.body);
      payload.id = configId; 

      const res = await fetch(`${SUPABASE_URL}/rest/v1/site_config`, {
        method: "POST",
        headers: { 
            ...supabaseHeaders,
            "Prefer": "return=representation,resolution=merge-duplicates" 
        },
        body: JSON.stringify(payload)
      });
      
      return respond({ msg: "Page configuration saved", data: await res.json() });
    } catch (err) { return respond({ error: err.message }, 500); }
  }

  return respond({ error: "Method not allowed" }, 405);
};
