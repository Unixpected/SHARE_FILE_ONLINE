-- FRESH INSTALL: run this file once.
--   npx wrangler d1 execute share-comments --remote --file=schema.sql
--
-- If you ALREADY have a database from the earlier version, do NOT run this.
-- Run migrate.sql instead.

CREATE TABLE IF NOT EXISTS comments (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL DEFAULT 'Anonymous',
  text       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  likes      INTEGER NOT NULL DEFAULT 0,
  stars      INTEGER NOT NULL DEFAULT 0,
  parent_id  TEXT,
  ip         TEXT
);
CREATE INDEX IF NOT EXISTS idx_comments_created ON comments (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_parent  ON comments (parent_id);

-- Admin-adjustable settings (max file size, log retention)
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Activity log shown on the admin page
CREATE TABLE IF NOT EXISTS logs (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  event   TEXT NOT NULL,
  ip      TEXT,
  country TEXT,
  city    TEXT,
  ua      TEXT,
  detail  TEXT
);
CREATE INDEX IF NOT EXISTS idx_logs_ts    ON logs (ts DESC);
CREATE INDEX IF NOT EXISTS idx_logs_event ON logs (event, id DESC);
CREATE INDEX IF NOT EXISTS idx_logs_ip    ON logs (ip);
