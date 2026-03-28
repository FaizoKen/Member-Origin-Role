-- Add columns that may be missing from earlier versions of the schema.
-- All use IF NOT EXISTS or are idempotent so this is safe to re-run.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'country') THEN
        ALTER TABLE web_contexts ADD COLUMN country TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'vpn_detected') THEN
        ALTER TABLE web_contexts ADD COLUMN vpn_detected BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'timezone_mismatch') THEN
        ALTER TABLE web_contexts ADD COLUMN timezone_mismatch BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'ip_address') THEN
        ALTER TABLE web_contexts ADD COLUMN ip_address TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'accept_language') THEN
        ALTER TABLE web_contexts ADD COLUMN accept_language TEXT;
    END IF;
END $$;

-- Drop columns that are no longer used (from the original 17-field design).
-- Wrapped in DO block so it doesn't fail if columns were never created.
DO $$ BEGIN
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS screen_width;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS screen_height;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS touch_capable;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS cpu_cores;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS device_memory;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS connection_type;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS pixel_ratio;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS color_depth;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS cookies_enabled;
    ALTER TABLE web_contexts DROP COLUMN IF EXISTS do_not_track;
END $$;
