-- Per-guild settings (currently just "who can view the member list").
-- One row per guild, separate from role_links so multiple role links for the
-- same guild can't drift apart.
CREATE TABLE IF NOT EXISTS guild_settings (
    guild_id        TEXT PRIMARY KEY,
    view_permission TEXT NOT NULL DEFAULT 'managers'
                    CHECK (view_permission IN ('members', 'managers')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backfill a row for every guild that already has a role link, so reads
-- always find one. Default 'managers' since member data is sensitive.
INSERT INTO guild_settings (guild_id)
SELECT DISTINCT guild_id FROM role_links
ON CONFLICT (guild_id) DO NOTHING;
