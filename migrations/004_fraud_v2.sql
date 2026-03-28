-- Anti-Fraud v2: smarter spoofing detection + impossible travel

-- Add new fraud columns
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'spoofing_detected') THEN
        ALTER TABLE web_contexts ADD COLUMN spoofing_detected BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'impossible_travel') THEN
        ALTER TABLE web_contexts ADD COLUMN impossible_travel BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'prev_country') THEN
        ALTER TABLE web_contexts ADD COLUMN prev_country TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'prev_visit_at') THEN
        ALTER TABLE web_contexts ADD COLUMN prev_visit_at TIMESTAMPTZ;
    END IF;
END $$;

-- Migrate existing conditions JSON: rename block_timezone_mismatch -> block_spoofing
UPDATE role_links
SET conditions = jsonb_set(
    conditions - 'block_timezone_mismatch',
    '{block_spoofing}',
    COALESCE(conditions->'block_timezone_mismatch', 'false'::jsonb)
)
WHERE conditions ? 'block_timezone_mismatch';

-- Seed spoofing_detected from old timezone_mismatch where it exists
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'timezone_mismatch') THEN
        UPDATE web_contexts SET spoofing_detected = timezone_mismatch WHERE timezone_mismatch = true;
        ALTER TABLE web_contexts DROP COLUMN timezone_mismatch;
    END IF;
END $$;
