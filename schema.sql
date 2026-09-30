-- FRESH INSTALL: run this file once.
-- If you ALREADY created the comments table earlier, do NOT run this;
-- run these two lines instead:
--   ALTER TABLE comments ADD COLUMN parent_id TEXT;
--   CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments (parent_id);
CREATE TABLE IF NOT EXISTS comments (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL DEFAULT 'Anonymous',
  text       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  likes      INTEGER NOT NULL DEFAULT 0,
  stars      INTEGER NOT NULL DEFAULT 0,
  parent_id  TEXT
);
CREATE INDEX IF NOT EXISTS idx_comments_created ON comments (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments (parent_id);
