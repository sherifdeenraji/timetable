-- Timetable D1 schema. Apply with:
--   npx wrangler d1 execute timetable --remote --file schema.sql

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,            -- lowercased; the sign-in key
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,             -- slugified "first-last"; export filename + publish id
  salt TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  fails INTEGER NOT NULL DEFAULT 0,
  lock_until INTEGER,                    -- ms epoch; sign-in locked until then
  published INTEGER NOT NULL DEFAULT 0,
  tasks TEXT NOT NULL DEFAULT '[]',      -- current timetable JSON
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- One row per real save: how often people change their schedule.
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  tasks TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_user ON snapshots (user_id, created_at);

-- Everything worth counting.
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,                       -- null for failed sign-ins to unknown emails
  type TEXT NOT NULL,                    -- signup | signin | failed_signin | save | export_pdf | export_img | publish | unpublish | copy_template
  meta TEXT,                             -- JSON: { ip }, { source }, { taskCount }, ...
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (type, created_at);
CREATE INDEX IF NOT EXISTS idx_events_user ON events (user_id, created_at);
