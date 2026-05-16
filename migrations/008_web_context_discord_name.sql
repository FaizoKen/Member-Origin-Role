-- Cache the Discord display name from the session at collect time, so the
-- admin-facing member list can show names without an extra round trip to
-- the Auth Gateway. Pure UI data — auth still flows through rl_session.
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'web_contexts' AND column_name = 'discord_name'
    ) THEN
        ALTER TABLE web_contexts ADD COLUMN discord_name TEXT;
    END IF;
END $$;
