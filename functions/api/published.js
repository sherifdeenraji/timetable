/**
 * /api/published — public, no auth (publishing means anyone can view and copy).
 *
 *   GET            -> { timetables: [{ slug, displayName, taskCount, updatedAt }] }
 *   GET ?slug=x    -> { slug, displayName, tasks }
 */

import { json } from "./_shared.js";

export async function onRequestGet({ request, env }) {
  if (!env.DB) return json({ error: "D1 binding DB is missing" }, 500);

  const slug = new URL(request.url).searchParams.get("slug");
  if (slug) {
    const row = await env.DB.prepare(
      "SELECT slug, first_name, last_name, tasks FROM users WHERE slug = ? AND published = 1"
    ).bind(slug).first();
    if (!row) return json({ error: "not_found" }, 404);
    return json({
      slug: row.slug,
      displayName: `${row.first_name} ${row.last_name}`.trim(),
      tasks: JSON.parse(row.tasks || "[]"),
    });
  }

  const { results } = await env.DB.prepare(
    "SELECT slug, first_name, last_name, tasks, updated_at FROM users WHERE published = 1 ORDER BY updated_at DESC LIMIT 100"
  ).all();
  return json({
    timetables: (results || []).map((r) => ({
      slug: r.slug,
      displayName: `${r.first_name} ${r.last_name}`.trim(),
      taskCount: JSON.parse(r.tasks || "[]").length,
      updatedAt: r.updated_at,
    })),
  });
}

export async function onRequest() {
  return json({ error: "Method not allowed" }, 405);
}
