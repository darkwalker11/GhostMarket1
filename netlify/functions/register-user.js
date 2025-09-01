import { randomBytes, pbkdf2Sync } from "node:crypto";

// Required environment variables
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, HCAPTCHA_SECRET } = process.env;

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

async function readBody(request) {
  const ct = request.headers.get("content-type") || "";
  try {
    if (ct.includes("application/json")) {
      return await request.json();
    }
    if (ct.includes("application/x-www-form-urlencoded")) {
      const params = new URLSearchParams(await request.text());
      return Object.fromEntries(params.entries());
    }
    if (ct.includes("multipart/form-data")) {
      const fd = await request.formData();
      const obj = {};
      for (const [k, v] of fd.entries()) obj[k] = typeof v === "string" ? v : String(v);
      return obj;
    }
  } catch (e) {
    console.error("Body parse error:", e);
  }
  // Fallback best-effort
  try {
    return await request.json();
  } catch {
    return {};
  }
}

export default async (request, context) => {
  const reqId = context?.requestId || crypto.randomUUID?.() || String(Date.now());
  const start = Date.now();
  try {
    if (request.method !== "POST") {
      return json({ ok: false, error: "Method not allowed" }, 405, { Allow: "POST" });
    }

    // Ensure envs exist (don't log secrets)
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !HCAPTCHA_SECRET) {
      console.error(`[${reqId}] Missing env`, {
        hasUrl: !!SUPABASE_URL,
        hasServiceRole: !!SUPABASE_SERVICE_ROLE_KEY,
        hasCaptcha: !!HCAPTCHA_SECRET,
      });
      return json({ ok: false, error: "Server not configured (env)" }, 500);
    }

    const body = await readBody(request);
    const username = (body.username || "").trim();
    const password = body.password || "";
    const hcaptchaToken =
      body.hcaptchaToken ||
      body["h-captcha-response"] ||
      body["hcaptcha-response"] ||
      body.token ||
      "";

    console.log(`[${reqId}] Incoming`, {
      hasToken: !!hcaptchaToken,
      userLen: username.length,
      bodyKeys: Object.keys(body || {}),
    });

    if (!username || !password || !hcaptchaToken) {
      return json({ ok: false, error: "Missing fields" }, 400);
    }

    // Verify hCaptcha
    const hres = await fetch("https://hcaptcha.com/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ secret: HCAPTCHA_SECRET, response: hcaptchaToken }),
    });
    const hjson = await hres.json().catch(() => ({}));
    if (!hjson?.success) {
      console.error(`[${reqId}] hCaptcha failed`, hjson);
      return json({ ok: false, error: "hCaptcha failed", details: hjson }, 400);
    }

    // Validate username
    if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
      return json({ ok: false, error: "Invalid username" }, 400);
    }

    // Check if username exists
    const existsUrl = `${SUPABASE_URL}/rest/v1/users?username=eq.${encodeURIComponent(
      username
    )}&select=id&limit=1`;
    const existsRes = await fetch(existsUrl, {
      headers: {
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      },
    });
    const exists = await existsRes.json().catch(() => []);
    console.log(`[${reqId}] Exists check`, existsRes.status, Array.isArray(exists) ? exists.length : "n/a");
    if (Array.isArray(exists) && exists.length > 0) {
      return json({ ok: false, error: "Username already taken" }, 409);
    }

    // Hash password
    const salt = randomBytes(16).toString("hex");
    const hash = pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");

    // Insert new user (public.users)
    const insertRes = await fetch(`${SUPABASE_URL}/rest/v1/users`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        apikey: SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        Prefer: "return=representation",
      },
      body: JSON.stringify({ username, password_hash: hash, password_salt: salt }),
    });

    const txt = await insertRes.text();
    console.log(`[${reqId}] Insert status`, insertRes.status, txt);
    if (!insertRes.ok) {
      let details;
      try { details = JSON.parse(txt); } catch { details = txt; }
      return json(
        { ok: false, error: "Supabase insert failed", status: insertRes.status, details },
        500
      );
    }

    const arr = (() => { try { return JSON.parse(txt); } catch { return []; } })();
    const user = Array.isArray(arr) ? arr[0] : arr;
    return json({ ok: true, user: { id: user?.id, username: user?.username } });
  } catch (err) {
    console.error(`[${reqId}] register-user exception:`, err);
    return json({ ok: false, error: err?.message || String(err) }, 500);
  } finally {
    console.log(`[${reqId}] Done in ${Date.now() - start}ms`);
  }
};
