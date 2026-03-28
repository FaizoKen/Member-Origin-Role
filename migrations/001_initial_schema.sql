-- Role links: one per guild+role pair registered via POST /register
CREATE TABLE IF NOT EXISTS role_links (
    id              BIGSERIAL PRIMARY KEY,
    guild_id        TEXT NOT NULL,
    role_id         TEXT NOT NULL,
    api_token       TEXT NOT NULL,
    conditions      JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (guild_id, role_id)
);

-- Web contexts: visitor identity collected from JS + HTTP headers
-- One row per Discord user, updated on each page visit
CREATE TABLE IF NOT EXISTS web_contexts (
    discord_id      TEXT PRIMARY KEY,
    raw_data        JSONB NOT NULL,
    -- Extracted columns for SQL-side filtering
    timezone        TEXT,                           -- JS: Intl.DateTimeFormat timezone
    utc_offset      INTEGER,                        -- JS: Date.getTimezoneOffset (minutes)
    country         TEXT,                           -- HTTP: CF-IPCountry / X-Country header
    platform        TEXT,                           -- UA parsed: Windows, macOS, Linux, Android, iOS
    browser         TEXT,                           -- UA parsed: Chrome, Firefox, Safari, Edge, Opera
    language        TEXT,                           -- HTTP: Accept-Language primary tag
    device_type     TEXT,                           -- UA parsed: Desktop, Mobile, Tablet
    visit_count     INTEGER NOT NULL DEFAULT 1,     -- incremented on each visit
    -- Fraud detection flags (computed server-side)
    vpn_detected    BOOLEAN NOT NULL DEFAULT false, -- Tor, WARP, proxy headers
    timezone_mismatch BOOLEAN NOT NULL DEFAULT false, -- JS timezone vs IP country continent
    -- Raw tracking data (stored for reference, not filterable)
    user_agent      TEXT,                           -- raw UA string
    ip_address      TEXT,                           -- client IP from X-Forwarded-For / CF-Connecting-IP
    accept_language TEXT,                           -- raw Accept-Language header
    first_visit     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_visit      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Role assignments: tracks which users currently have which roles (local mirror)
CREATE TABLE IF NOT EXISTS role_assignments (
    guild_id        TEXT NOT NULL,
    role_id         TEXT NOT NULL,
    discord_id      TEXT NOT NULL,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (guild_id, role_id, discord_id),
    FOREIGN KEY (guild_id, role_id) REFERENCES role_links (guild_id, role_id) ON DELETE CASCADE
);

-- OAuth states: CSRF protection for Discord OAuth flow
CREATE TABLE IF NOT EXISTS oauth_states (
    state           TEXT PRIMARY KEY,
    redirect_data   JSONB,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User guilds: guild membership for scoping sync
CREATE TABLE IF NOT EXISTS user_guilds (
    discord_id      TEXT NOT NULL,
    guild_id        TEXT NOT NULL,
    guild_name      TEXT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (discord_id, guild_id)
);

-- Discord tokens: stored refresh tokens for guild list refresh
CREATE TABLE IF NOT EXISTS discord_tokens (
    discord_id          TEXT PRIMARY KEY,
    refresh_token       TEXT NOT NULL,
    guilds_refreshed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
