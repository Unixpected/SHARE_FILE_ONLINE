-- UPGRADE an existing database (the one that already has the comments table).
-- Run ONCE:
--   npx wrangler d1 execute share-comments --remote --file=migrate.sql
-- (If it says "duplicate column name: ip", you already ran it. That is fine.)

ALTER TABLE comments ADD COLUMN ip TEXT;

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

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
