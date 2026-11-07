# Member Origin Role

A [RoleLogic](https://rolelogic.faizo.net) plugin that assigns Discord roles based on member origin — country, timezone, and language detected from HTTP headers and browser APIs.

> **Requires [Auth Gateway](https://github.com/FaizoKen/Auth-Gateway)** — Discord login is handled by the centralized Auth Gateway. This plugin reads the shared `rl_session` cookie set by the gateway.

## How It Works

1. Members visit the verification page and sign in with Discord (via Auth Gateway)
2. Their origin is automatically detected from HTTP identity signals (IP country, Accept-Language) and browser APIs (timezone)
3. Admins configure conditions (e.g. Country = US, Timezone = Asia/Tokyo, Language = ja)
4. Members matching the condition get the role automatically
5. Built-in anti-fraud blocks VPN users, spoofed identities, and impossible travel

## Features

### Identity Detection

| Signal      | Source                                  | Example                       |
| ----------- | --------------------------------------- | ----------------------------- |
| Country     | HTTP `CF-IPCountry` header (Cloudflare) | US, JP, MY, DE                |
| Timezone    | Browser `Intl.DateTimeFormat` API       | America/New_York, Asia/Tokyo  |
| UTC Offset  | Browser `Date.getTimezoneOffset()`      | -300 (EST), +540 (JST)        |
| Language    | HTTP `Accept-Language` header           | en-US, ja, fr-FR              |
| Platform    | User-Agent parsing                      | Windows, macOS, Android, iOS  |
| Browser     | User-Agent parsing                      | Chrome, Firefox, Safari, Edge |
| Device Type | User-Agent + touch detection            | Desktop, Mobile, Tablet       |

Each role link checks one of these — or **Anyone who verifies**, which checks
none and relies on the anti-fraud checks below (a Verified role). Matching
never cares about case. A language without a region matches every region
(`en` takes `en-US` and `en-GB`; `en-US` only US English), and a timezone
matches under its older names too (`Asia/Kolkata` and the `Asia/Calcutta`
Chrome on Windows reports). A timezone is checked against the tz database
when saved. An iPad asking for desktop sites (a Mac user agent with a
touchscreen) counts as iOS / Tablet; Chrome and Firefox on iOS keep their
names.

**Flip the rule** gives the role to the verified members the rule turns away
instead: Anyone who verifies + the checks below, flipped, is a Needs Review
role for flagged members.

### Anti-Fraud (AND'd with identity condition)

- **Block VPN / Proxy** — Detects Tor exit nodes, IP-timezone country mismatch (the classic VPN fingerprint: IP says Japan but browser timezone says America/New_York), **and** — when an ASN reputation key is configured — any IP flagged as a known VPN / datacenter / proxy. The ASN check is what catches *same-country* commercial VPNs (NordVPN, ExpressVPN, etc.) that the timezone heuristic can't see.
- **Block Spoofed Identity** — Cross-validates UTC offset vs timezone (DST-aware), offset vs country, platform/browser consistency, platform/device consistency
- **Block Impossible Travel** — Flags users whose IP country changed faster than physically possible between visits
- **Minimum account age** — Rejects Discord accounts younger than N days. Creation time is decoded from the Discord snowflake (no API call). Effective against alt farms. An hourly sweep re-checks members the moment their account reaches a configured minimum, so a member who was too new gets the role without verifying again.
- **Turnstile bot check** *(host-wide, optional)* — Cloudflare Turnstile gate on the verify page. Blocks headless browsers and scripted clients before any data is stored. Fails closed when enabled.

ASN reputation and Turnstile are **opt-in via environment variables** — the plugin runs fine without them; those checks simply stay off. IP reputation results are cached per /24 (IPv4) or /48 (IPv6) for 7 days to keep external API usage low.

The checks run against the location and timezone patterns Windows produces:
a PC whose region was never set reports its zone's default city (a
Malaysian PC says `Asia/Singapore`, a Canadian one `America/New_York`), so
those countries count as consistent with it.

### Silent verification

On by default: the verify page signs the member in and says "You're all set"
without showing what was detected. It is decided per server — a per-server
link (`/verify?guild=<id>`) shows the details only if one of *that* server's
role links turned silent mode off. (A bare `/verify` keeps the old rule:
silent unless any role link turned it off.)

### What is stored

Per member: the parsed signals above, the UTC offset, the fraud flags, the
Discord name and account creation time, visit count and times. The IP is only
looked at during the visit (the reputation lookup and Turnstile) and never
stored; nor are the raw user agent, `Accept-Language` header or request body
(migration 010 emptied what earlier versions kept).

## Tech Stack

- **Rust** + **Axum 0.8** + **PostgreSQL 16** + **SQLx** + **Tokio**
- **chrono-tz** for DST-aware timezone validation
- Single binary, ~15MB RAM at idle, runs on a $4/month VPS

## Quick Start

```bash
# Copy .env.example and fill in your values
cp .env.example .env

# Run with Docker Compose
docker compose up -d
```

### Environment Variables

| Variable         | Required | Description                                                             |
| ---------------- | -------- | ----------------------------------------------------------------------- |
| `DATABASE_URL`   | Yes      | PostgreSQL connection string                                            |
| `SESSION_SECRET` | Yes      | HMAC key for `rl_session` cookie (must match Auth Gateway)              |
| `BASE_URL`       | Yes      | Full URL with prefix, e.g. `https://your-domain.com/member-origin-role` |
| `LISTEN_ADDR`    | No       | Bind address (default `0.0.0.0:8080`)                                   |
| `PROXYCHECK_API_KEY`  | No  | proxycheck.io key — enables ASN/proxy reputation in "Block VPN / Proxy" |
| `TURNSTILE_SITE_KEY`  | No  | Cloudflare Turnstile site key (widget). Both keys required to enable    |
| `TURNSTILE_SECRET_KEY`| No  | Cloudflare Turnstile secret key (server-side siteverify)                |

### Endpoints

All routes are nested under `/member-origin-role`:

| Method   | Path            | Purpose                                     |
| -------- | --------------- | ------------------------------------------- |
| `POST`   | `/register`     | RoleLogic registers a role link             |
| `GET`    | `/config`       | Return config schema to dashboard           |
| `POST`   | `/config`       | Save admin configuration                    |
| `DELETE` | `/config`       | Delete role link                            |
| `GET`    | `/verify`       | Verification page (user-facing)             |
| `GET`    | `/verify/login` | Redirects to Auth Gateway for Discord login |
| `GET`    | `/health`       | Health check                                |

## License

MIT
