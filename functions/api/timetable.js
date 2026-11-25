/**
 * Cloudflare Pages Function  ->  /api/timetable
 *
 * Every person has their own timetable, stored under their name and protected by a PIN.
 *
 *   POST  create  { displayName, pin, tasks? }          -> 201 | 409 name taken
 *   GET   read    headers X-Name, X-Pin                  -> { displayName, tasks, updatedAt }
 *   PUT   save    headers X-Name, X-Pin, { tasks }       -> { ok: true }
 *
 * Needs one binding in your Pages project (Settings > Bindings):
 *   KV namespace, variable name:  TIMETABLE
 * (The old API_TOKEN secret is no longer used.)
 *
 * Storage: one KV entry per person, key "u:<name>", holding a salted PBKDF2 hash of the PIN
 * (never the PIN itself) and their tasks. Five wrong PINs lock that name for 15 minutes.
 */

const NAME_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const PIN_RE = /^[\x21-\x7E]{4,20}$/; // 4 to 20 printable characters, no spaces
const HEX = /^#[0-9a-fA-F]{6}$/;
const MAX_BODY = 300_000;
const MAX_TASKS = 300;
const MAX_SESSIONS = 21;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const PBKDF2_ITERATIONS = 10_000; // kept modest so it fits the free plan's CPU limit

const enc = new TextEncoder();

/* ---------- small helpers ---------- */
function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

function slugify(s) {
  return String(s ?? "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32)
    .replace(/-+$/, "");
}

const validName = (n) => typeof n === "string" && n.length >= 2 && n.length <= 32 && NAME_RE.test(n);

function toB64(buf) {
  let s = "";
  new Uint8Array(buf).forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s);
}
function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function hashPin(pin, saltB64) {
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

function cleanTasks(list) {
  if (!Array.isArray(list) || list.length > MAX_TASKS) return null;
  const tasks = list.map(cleanTask);
  return tasks.some((t) => t === null) ? null : tasks;
}

/* ---------- auth ---------- */
async function authenticate(request, env) {
  if (!env.TIMETABLE) return { res: json({ error: "KV binding TIMETABLE is missing" }, 500) };

  const name = request.headers.get("X-Name") || "";
  const pin = request.headers.get("X-Pin") || "";
  if (!validName(name) || !PIN_RE.test(pin)) return { res: json({ error: "invalid_credentials" }, 400) };

  const key = "u:" + name;
  const raw = await env.TIMETABLE.get(key);
  if (!raw) return { res: json({ error: "no_account" }, 404) };
  const rec = JSON.parse(raw);

  if (rec.lockUntil && rec.lockUntil > Date.now()) {
    return { res: json({ error: "locked", retryAfter: Math.ceil((rec.lockUntil - Date.now()) / 1000) }, 429) };
  }

  const hash = await hashPin(pin, rec.salt);
  if (!safeEqual(hash, rec.hash)) {
    rec.fails = (rec.fails || 0) + 1;
    if (rec.fails >= MAX_FAILS) {
      rec.lockUntil = Date.now() + LOCK_MS;
      rec.fails = 0;
    }
    await env.TIMETABLE.put(key, JSON.stringify(rec));
    return { res: json({ error: "wrong_pin" }, 401) };
  }

  if (rec.fails || rec.lockUntil) {
    rec.fails = 0;
    delete rec.lockUntil;
    await env.TIMETABLE.put(key, JSON.stringify(rec));
  }
  return { key, rec };
}

/* ---------- handlers ---------- */
export async function onRequestGet({ request, env }) {
  const a = await authenticate(request, env);
  if (a.res) return a.res;
  return json({ displayName: a.rec.displayName, tasks: a.rec.tasks || [], updatedAt: a.rec.updatedAt || null });
}

export async function onRequestPut({ request, env }) {
  const a = await authenticate(request, env);
  if (a.res) return a.res;

  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: "Payload too large" }, 413);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }
  const tasks = cleanTasks(body && body.tasks);
  if (!tasks) return json({ error: "Expected { tasks: [...] } with valid tasks" }, 400);

  a.rec.tasks = tasks;
  a.rec.updatedAt = new Date().toISOString();
  await env.TIMETABLE.put(a.key, JSON.stringify(a.rec));
  return json({ ok: true, count: tasks.length, updatedAt: a.rec.updatedAt });
}

export async function onRequestPost({ request, env }) {
  if (!env.TIMETABLE) return json({ error: "KV binding TIMETABLE is missing" }, 500);

  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: "Payload too large" }, 413);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: "Invalid JSON" }, 400);
  }

  const displayName = String((body && body.displayName) ?? "").trim().slice(0, 40);
  const name = slugify(displayName);
  const pin = String((body && body.pin) ?? "");
  if (!validName(name)) return json({ error: "invalid_name" }, 400);
  if (!PIN_RE.test(pin)) return json({ error: "invalid_pin" }, 400);

  let tasks = [];
  if (body.tasks !== undefined) {
    tasks = cleanTasks(body.tasks);
    if (!tasks) return json({ error: "Invalid tasks" }, 400);
  }

  const key = "u:" + name;
  if (await env.TIMETABLE.get(key)) return json({ error: "name_taken" }, 409);

  const salt = toB64(crypto.getRandomValues(new Uint8Array(16)));
  const now = new Date().toISOString();
  const rec = {
    displayName,
    salt,
    hash: await hashPin(pin, salt),
    tasks,
    fails: 0,
    createdAt: now,
    updatedAt: now,
  };
  await env.TIMETABLE.put(key, JSON.stringify(rec));
  return json({ ok: true, name, displayName }, 201);
}

// Any other method
export async function onRequest() {
  return json({ error: "Method not allowed" }, 405);
}