/**
 * /api/event — authenticated POST { type }.
 *
 * Logs export_pdf / export_img for the analytics, and toggles publishing:
 * publish / unpublish also flip users.published. Returns { ok, published? }.
 */

import { json, readBody, authenticate, logEvent } from "./_shared.js";

const TYPES = new Set(["export_pdf", "export_img", "publish", "unpublish"]);

export async function onRequestPost({ request, env }) {
  const a = await authenticate(request, env);
  if (a.res) return a.res;

  const body = await readBody(request);
  if (body.res) return body.res;
  const type = body.data && body.data.type;
  if (!TYPES.has(type)) return json({ error: "unknown_type" }, 400);

  if (type === "publish" || type === "unpublish") {
    const val = type === "publish" ? 1 : 0;
    await env.DB.prepare("UPDATE users SET published = ? WHERE id = ?").bind(val, a.user.id).run();
    await logEvent(env, a.user.id, type);
    return json({ ok: true, published: !!val });
  }

  await logEvent(env, a.user.id, type);
  return json({ ok: true });
}

export async function onRequest() {
  return json({ error: "Method not allowed" }, 405);
}
