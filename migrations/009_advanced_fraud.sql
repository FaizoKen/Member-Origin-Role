-- Advanced anti-fraud signals:
--   1. ASN/proxy reputation lookup (catches same-country commercial VPNs)
--   2. Discord account age (catches alt farms with freshly-minted accounts)
--   3. Turnstile passive bot check (catches headless / scripted clients)
--
-- Storage:
--   web_contexts.vpn_asn_detected       — true if external ASN lookup flagged the IP
--   web_contexts.asn_org                — provider/org name from the lookup (audit)
--   web_contexts.account_created_at     — Discord snowflake decoded to creation time
--   ip_reputation_cache                 — per /24 (v4) or /48 (v6) prefix cache

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'web_contexts' AND column_name = 'vpn_asn_detected'
    ) THEN
        ALTER TABLE web_contexts ADD COLUMN vpn_asn_detected BOOLEAN NOT NULL DEFAULT false;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'web_contexts' AND column_name = 'asn_org'
    ) THEN
        ALTER TABLE web_contexts ADD COLUMN asn_org TEXT;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_name = 'web_contexts' AND column_name = 'account_created_at'
    ) THEN
        ALTER TABLE web_contexts ADD COLUMN account_created_at TIMESTAMPTZ;
    END IF;
END $$;

-- Backfill account_created_at from the Discord snowflake.
-- Discord epoch = 2015-01-01T00:00:00.000Z = 1420070400000 ms.
-- creation_ms = (snowflake >> 22) + 1420070400000
UPDATE web_contexts
   SET account_created_at = to_timestamp(
           (((discord_id::bigint) >> 22) + 1420070400000)::double precision / 1000.0
       )
 WHERE account_created_at IS NULL
   AND discord_id ~ '^[0-9]+$';

-- IP reputation cache. Keyed by network prefix (/24 for v4, /48 for v6) to
-- amortize lookups across users sharing a residential CGN range or VPN POP.
CREATE TABLE IF NOT EXISTS ip_reputation_cache (
    ip_prefix    TEXT PRIMARY KEY,
    is_proxy     BOOLEAN NOT NULL,
    asn_org      TEXT,
    checked_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ip_reputation_cache_checked_at_idx
    ON ip_reputation_cache (checked_at);
