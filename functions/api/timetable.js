/**
 * Cloudflare Pages Function  ->  /api/timetable
 *
 * Needs, in your Pages project (Settings > Bindings / Variables and Secrets):
 *   - KV namespace binding, variable name:  TIMETABLE
 *   - Secret (optional but recommended):    API_TOKEN
 *
 * The page and this function are served from the same origin, so no CORS is needed.
 */

const KEY = "timetable";
const HEX = /^#[0-9a-fA-F]{6}$/;
const MAX_BODY = 300_000;
const MAX_TASKS = 300;
const MAX_SESSIONS = 21;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function authorized(request, env) {
  if (!env.API_TOKEN) return true;
  return (request.headers.get("Authorization") || "") === `Bearer ${env.API_TOKEN}`;
}

function cleanSession(s) {
  if (!s || typeof s !== "object") return null;
  const { day, start, end } = s;
  if (![day, start, end].every(Number.isInteger)) return null;
  if (day < 0 || day > 6 || start < 0 || end > 1440 || end <= start) return null;
  return { day, start, end };
}

function cleanTask(t) {
  if (!t || typeof t !== "object") return null;
  const str = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
  if (typeof t.id !== "string" || !t.id || t.id.length > 64) return null;
  const name = str(t.name, 120).trim();
  if (!name) return null;
  if (!Array.isArray(t.sessions) || t.sessions.length < 1 || t.sessions.length > MAX_SESSIONS) return null;
  const sessions = t.sessions.map(cleanSession);
  if (sessions.some((s) => s === null)) return null;
  return {
    id: t.id,
    name,
    venue: str(t.venue, 120),
    details: str(t.details, 500),
    color: HEX.test(t.color) ? t.color : "#1e9af0",
    sessions,
  };
}

export async function onRequestGet({ request, env }) {
  if (!authorized(request, env)) return json({ error: "Unauthorized" }, 401);
  if (!env.TIMETABLE) return json({ error: "KV binding TIMETABLE is missing" }, 500);
  const raw = await env.TIMETABLE.get(KEY);
  return json(raw ? JSON.parse(raw) : { tasks: [], updatedAt: null });
}

export async function onRequestPut({ request, env }) {
  if (!authorized(request, env)) return json({ error: "Unauthorized" }, 401);
  if (!env.TIMETABLE) return json({ error: "KV binding TIMETABLE is missing" }, 500);

  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: "Payload too large" }, 413);

  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }
  if (!body || !Array.isArray(body.tasks) || body.tasks.length > MAX_TASKS) {
    return json({ error: `Expected { tasks: [...] } with at most ${MAX_TASKS} tasks` }, 400);
  }

  const tasks = body.tasks.map(cleanTask);
  if (tasks.some((t) => t === null)) return json({ error: "One or more tasks are invalid" }, 400);

  const data = { tasks, updatedAt: new Date().toISOString() };
  await env.TIMETABLE.put(KEY, JSON.stringify(data));
  return json({ ok: true, count: tasks.length, updatedAt: data.updatedAt });
}

// Any other method
export async function onRequest() {
  return json({ error: "Method not allowed" }, 405);
}