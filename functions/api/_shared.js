/* Shared helpers for the /api/* Pages Functions. Files starting with _ get no route. */

export const PIN_RE = /^[\x21-\x7E]{4,20}$/; // 4 to 20 printable characters, no spaces
export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const HEX = /^#[0-9a-fA-F]{6}$/;
const MAX_BODY = 300_000;
const MAX_TASKS = 300;
const MAX_SESSIONS = 21;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const PBKDF2_ITERATIONS = 10_000; // kept modest so it fits the free plan's CPU limit

const enc = new TextEncoder();

export const now = () => new Date().toISOString();
export const clientIp = (request) => request.headers.get("CF-Connecting-IP") || "";

export function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

/* Parse a JSON request body; returns { data } or { res } with the error response. */
export async function readBody(request) {
  const text = await request.text();
  if (text.length > MAX_BODY) return { res: json({ error: "Payload too large" }, 413) };
  try {
    return { data: JSON.parse(text) };
  } catch {
    return { res: json({ error: "Invalid JSON" }, 400) };
  }
}

export function slugify(s) {
  return String(s ?? "")
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32)
    .replace(/-+$/, "");
}

export function toB64(buf) {
  let s = "";
  new Uint8Array(buf).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}
function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

export async function hashPin(pin, saltB64) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: fromB64(saltB64), iterations: PBKDF2_ITERATIONS },
    key,
    256
  );
  return toB64(bits);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ---------- task validation ---------- */
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

export function cleanTasks(list) {
  if (!Array.isArray(list) || list.length > MAX_TASKS) return null;
  const tasks = list.map(cleanTask);
  return tasks.some((t) => t === null) ? null : tasks;
}

/* ---------- events ---------- */
export async function logEvent(env, userId, type, meta = null) {
  try {
    await env.DB.prepare("INSERT INTO events (user_id, type, meta, created_at) VALUES (?, ?, ?, ?)")
      .bind(userId, type, meta ? JSON.stringify(meta) : null, now())
      .run();
  } catch { /* analytics must never break the request */ }
}

/* ---------- auth ---------- */
/* Checks X-Email / X-Pin and returns { user } (a users row) or { res } with the error. */
export async function authenticate(request, env) {
  if (!env.DB) return { res: json({ error: "D1 binding DB is missing" }, 500) };

  const email = (request.headers.get("X-Email") || "").trim().toLowerCase();
  const pin = request.headers.get("X-Pin") || "";
  if (!EMAIL_RE.test(email) || !PIN_RE.test(pin)) return { res: json({ error: "invalid_credentials" }, 400) };

  const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  if (!user) {
    await logEvent(env, null, "failed_signin", { ip: clientIp(request), email });
    return { res: json({ error: "no_account" }, 404) };
  }

  if (user.lock_until && user.lock_until > Date.now()) {
    return { res: json({ error: "locked", retryAfter: Math.ceil((user.lock_until - Date.now()) / 1000) }, 429) };
  }

  const hash = await hashPin(pin, user.salt);
  if (!safeEqual(hash, user.pin_hash)) {
    const fails = (user.fails || 0) + 1;
    const lock = fails >= MAX_FAILS;
    await env.DB.prepare("UPDATE users SET fails = ?, lock_until = ? WHERE id = ?")
      .bind(lock ? 0 : fails, lock ? Date.now() + LOCK_MS : null, user.id)
      .run();
    await logEvent(env, user.id, "failed_signin", { ip: clientIp(request), locked: lock });
    return { res: json({ error: "wrong_pin" }, 401) };
  }

  if (user.fails || user.lock_until) {
    await env.DB.prepare("UPDATE users SET fails = 0, lock_until = NULL WHERE id = ?").bind(user.id).run();
  }
  return { user };
}
