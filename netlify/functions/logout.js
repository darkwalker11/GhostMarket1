export default async () => {
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; Secure" }
  });
};