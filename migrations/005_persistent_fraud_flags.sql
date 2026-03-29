-- Persistent fraud flags: prevent flag reset by tracking historical detections.
-- Current flags (vpn_detected, etc.) reflect the LATEST visit.
-- "Ever" flags are sticky — set to true on first detection, only cleared after a cooldown.

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'vpn_ever_detected') THEN
        ALTER TABLE web_contexts ADD COLUMN vpn_ever_detected BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'spoofing_ever_detected') THEN
        ALTER TABLE web_contexts ADD COLUMN spoofing_ever_detected BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'impossible_travel_ever_detected') THEN
        ALTER TABLE web_contexts ADD COLUMN impossible_travel_ever_detected BOOLEAN NOT NULL DEFAULT false;
    END IF;
    -- Tracks when all current flags became clean. "Ever" flags clear after cooldown from this timestamp.
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'web_contexts' AND column_name = 'fraud_clean_since') THEN
        ALTER TABLE web_contexts ADD COLUMN fraud_clean_since TIMESTAMPTZ;
    END IF;
END $$;

-- Seed "ever" flags from current state
UPDATE web_contexts SET vpn_ever_detected = true WHERE vpn_detected = true;
UPDATE web_contexts SET spoofing_ever_detected = true WHERE spoofing_detected = true;
UPDATE web_contexts SET impossible_travel_ever_detected = true WHERE impossible_travel = true;
