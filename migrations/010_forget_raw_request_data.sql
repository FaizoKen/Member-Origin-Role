-- Stop keeping raw request data. Verification only ever needed what is parsed
-- out of a visit (country, timezone, offset, language, platform, browser,
-- device, the fraud flags); the raw IP, user agent, Accept-Language header and
-- request body were written on every visit and read by nothing. The IP is now
-- only looked at during the visit (the reputation lookup and Turnstile), as
-- the plugin's directory page says. Empties what earlier versions stored.
-- Idempotent: after the first run it matches no rows.
UPDATE web_contexts
   SET ip_address = NULL,
       user_agent = NULL,
       accept_language = NULL,
       raw_data = '{}'::jsonb
 WHERE ip_address IS NOT NULL
    OR user_agent IS NOT NULL
    OR accept_language IS NOT NULL
    OR raw_data <> '{}'::jsonb;
