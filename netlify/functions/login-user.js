export default async (request, context) => {
  const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SESSION_SECRET } = process.env;
  try {
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ ok: false, error: "Method not allowed" }), { status: 405 });
    }
    const { username, password } = await request.json().catch(() => ({}));
    if (!username || !password) {
      return new Response(JSON.stringify({ ok: false, error: "Missing fields" }), { status: 400 });
    }
    // Fetch user from Supabase
    const res = await fetch(`${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(username)}&select=*`, {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`
      }
    });
    const users = await res.json();
    if (!Array.isArray(users) || users.length === 0) {
      return new Response(JSON.stringify({ ok: false, error: "Invalid credentials" }), { status: 401 });
    }
    const user = users[0];
    // Insecure demo: compare password_hash directly
    // TODO: Replace with proper password hash verification
    if (user.password_hash !== password) {
      return new Response(JSON.stringify({ ok: false, error: "Invalid credentials" }), { status: 401 });
    }
    return new Response(JSON.stringify({ ok: true, user: { id: user.id, username: user.username } }), {
      headers: { "Set-Cookie": `session=${user.id}; Path=/; HttpOnly; Secure` }
    });
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: err.message }), { status: 500 });
  }
};