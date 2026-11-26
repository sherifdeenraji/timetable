/**
 * Cloudflare Pages Function  ->  /api/timetable
 *
 * Accounts are stored in D1 (binding: DB, see schema.sql). Each person signs up with
 * their name and email and protects edits with a PIN (hashed with salted PBKDF2,
 * never stored as-is). Five wrong PINs lock the account for 15 minutes.
 *
 *   POST  create  { firstName, lastName, email, pin, tasks?, source? } -> 201 | 409 email taken
 *   GET   read    headers X-Email, X-Pin (+ X-Signin: 1 on the gate)   -> { displayName, slug, published, tasks, updatedAt }
 *   PUT   save    headers X-Email, X-Pin, body { tasks }               -> { ok: true }
 *
 * Every signup, sign-in, failed sign-in and save is logged to the events table,
 * and each real save stores a snapshot, so usage can be analysed later.
 */

import {
  json, readBody, authenticate, cleanTasks, logEvent,
  PIN_RE, EMAIL_RE, hashPin, toB64, slugify, now, clientIp,
} from "./_shared.js";

export async function onRequestGet({ request, env }) {
  const a = await authenticate(request, env);
  if (a.res) return a.res;
  if (request.headers.get("X-Signin") === "1") {
    await logEvent(env, a.user.id, "signin", { ip: clientIp(request) });
  }
  return json({
    displayName: a.user.first_name,
    slug: a.user.slug,
    published: !!a.user.published,
    tasks: JSON.parse(a.user.tasks || "[]"),
    updatedAt: a.user.updated_at,
  });
}

export async function onRequestPut({ request, env }) {
  const a = await authenticate(request, env);
  if (a.res) return a.res;

  const body = await readBody(request);
  if (body.res) return body.res;
  const tasks = cleanTasks(body.data && body.data.tasks);
  if (!tasks) return json({ error: "Expected { tasks: [...] } with valid tasks" }, 400);

  const text = JSON.stringify(tasks);
  if (text === a.user.tasks) return json({ ok: true, unchanged: true, updatedAt: a.user.updated_at });

  const at = now();
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET tasks = ?, updated_at = ? WHERE id = ?").bind(text, at, a.user.id),
    env.DB.prepare("INSERT INTO snapshots (user_id, tasks, created_at) VALUES (?, ?, ?)").bind(a.user.id, text, at),
    env.DB.prepare("INSERT INTO events (user_id, type, meta, created_at) VALUES (?, 'save', ?, ?)")
      .bind(a.user.id, JSON.stringify({ taskCount: tasks.length }), at),
  ]);
  return json({ ok: true, count: tasks.length, updatedAt: at });
}

export async function onRequestPost({ request, env }) {
  if (!env.DB) return json({ error: "D1 binding DB is missing" }, 500);

  const body = await readBody(request);
  if (body.res) return body.res;
  const b = body.data || {};

  const firstName = String(b.firstName ?? "").trim().slice(0, 40);
  const lastName = String(b.lastName ?? "").trim().slice(0, 40);
  const email = String(b.email ?? "").trim().toLowerCase().slice(0, 120);
  const pin = String(b.pin ?? "");

  if (!firstName || !lastName) return json({ error: "invalid_name" }, 400);
  if (!EMAIL_RE.test(email)) return json({ error: "invalid_email" }, 400);
  if (!PIN_RE.test(pin)) return json({ error: "invalid_pin" }, 400);

  let tasks = [];
  if (b.tasks !== undefined) {
    tasks = cleanTasks(b.tasks);
    if (!tasks) return json({ error: "Invalid tasks" }, 400);
  }

  const taken = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (taken) return json({ error: "email_taken" }, 409);

  // slug from the name; add a number if someone else has it already
  const base = slugify(`${firstName} ${lastName}`) || "student";
  let slug = base;
  for (let i = 2; await env.DB.prepare("SELECT id FROM users WHERE slug = ?").bind(slug).first(); i++) {
    slug = `${base}-${i}`.slice(0, 40);
  }

  const salt = toB64(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await hashPin(pin, salt);
  const at = now();
  const row = await env.DB.prepare(
    `INSERT INTO users (email, first_name, last_name, slug, salt, pin_hash, tasks, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
  ).bind(email, firstName, lastName, slug, salt, hash, JSON.stringify(tasks), at, at).first();

  await logEvent(env, row.id, "signup", { ip: clientIp(request) });
  if (b.source) await logEvent(env, row.id, "copy_template", { source: String(b.source).slice(0, 40) });

  return json({ ok: true, slug, displayName: firstName }, 201);
}

export async function onRequest() {
  return json({ error: "Method not allowed" }, 405);
}
