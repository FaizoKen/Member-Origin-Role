-- Discord-related tables now live exclusively in the Auth Gateway database.
-- Run `cargo run --bin migrate_to_gateway` BEFORE this migration ships in production.
DROP TABLE IF EXISTS user_guilds;
DROP TABLE IF EXISTS discord_tokens;
DROP TABLE IF EXISTS oauth_states;
