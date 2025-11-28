// netlify/functions/reports.js (Updated to handle UPSERT/Updates)
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, JWT_SECRET } = process.env;
const jwt = require("jsonwebtoken");
const cookie = require("cookie");

function respond(body, status = 200) {
  return {
    statusCode: status,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  };
}

function getUser(event) {
  try {
    const cookies = cookie.parse(event.headers.cookie || "");
    if (!cookies.session) return null;
    return jwt.verify(cookies.session, JWT_SECRET || "default_secret");
  } catch (err) {
    return null;
  }
}

exports.handler = async (event) => {
  const user = getUser(event);
  if (!user) return respond({ error: "Unauthorized" }, 401);

  // 1. GET: Fetch all reports
  if (event.httpMethod === "GET") {
    try {
      const res = await fetch(`${SUPABASE_URL}/rest/v1/reports?select=*&order=id.desc`, {
        headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` }
      });
      const data = await res.json();
      return respond({ reports: data });
    } catch (err) {
      return respond({ error: err.message }, 500);
    }
  }

  // 2. POST: Create, Update, or Delete a Report
  if (event.httpMethod === "POST") {
    try {
      const payload = JSON.parse(event.body);

      // A. DELETE Action
      if (payload.action === 'delete') {
         await fetch(`${SUPABASE_URL}/rest/v1/reports?id=eq.${payload.id}`, {
            method: "DELETE",
            headers: { apikey: SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}` }
         });
         return respond({ msg: "Deleted" });
      }

      // B. INSERT/UPDATE (UPSERT) Action - Use Supabase built-in upsert logic
      const isUpdate = payload.data.id !== undefined; // Check if an ID is present

      const res = await fetch(`${SUPABASE_URL}/rest/v1/reports`, {
        method: isUpdate ? "POST" : "POST", // POST is used for both with the 'Prefer' header
        headers: { 
            "Content-Type": "application/json",
            apikey: SUPABASE_SERVICE_ROLE_KEY, 
            Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
            "Prefer": isUpdate ? "return=representation,resolution=merge-duplicates" : "return=representation"
        },
        body: JSON.stringify(payload.data)
      });
      
      return respond({ msg: isUpdate ? "Updated" : "Created", data: await res.json() });

    } catch (err) {
      return respond({ error: err.message }, 500);
    }
  }

  return respond({ error: "Method not allowed" }, 405);
};
