# Member Origin Role

A [RoleLogic](https://rolelogic.faizo.net) plugin that assigns Discord roles based on member origin — country, timezone, and language detected from HTTP headers and browser APIs.

> **Requires [Auth Gateway](../Auth-Gateway/)** — Discord login is handled by the centralized Auth Gateway. This plugin reads the shared `rl_session` cookie set by the gateway.

## How It Works

1. Members visit the verification page and sign in with Discord (via Auth Gateway)
2. Their origin is automatically detected from HTTP identity signals (IP country, Accept-Language) and browser APIs (timezone)
3. Admins configure conditions (e.g. Country = US, Timezone = Asia/Tokyo, Language = ja)
4. Members matching the condition get the role automatically
5. Built-in anti-fraud blocks VPN users, spoofed identities, and impossible travel

## Features

### Identity Detection
| Signal | Source | Example |
|--------|--------|---------|
| Country | HTTP `CF-IPCountry` header (Cloudflare) | US, JP, MY, DE |
| Timezone | Browser `Intl.DateTimeFormat` API | America/New_York, Asia/Tokyo |
| UTC Offset | Browser `Date.getTimezoneOffset()` | -300 (EST), +540 (JST) |
| Language | HTTP `Accept-Language` header | en-US, ja, fr-FR |
| Platform | User-Agent parsing | Windows, macOS, Android, iOS |
| Browser | User-Agent parsing | Chrome, Firefox, Safari, Edge |
| Device Type | User-Agent + touch detection | Desktop, Mobile, Tablet |

### Anti-Fraud (3 toggles, AND'd with identity condition)

- **Block VPN / Proxy** — Detects Tor exit nodes and IP-timezone country mismatch (the classic VPN fingerprint: IP says Japan but browser timezone says America/New_York)
- **Block Spoofed Identity** — Cross-validates UTC offset vs timezone (DST-aware), offset vs country, platform/browser consistency, platform/device consistency
- **Block Impossible Travel** — Flags users whose IP country changed faster than physically possible between visits

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

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SESSION_SECRET` | Yes | HMAC key for `rl_session` cookie (must match Auth Gateway) |
| `BASE_URL` | Yes | Full URL with prefix, e.g. `https://your-domain.com/member-origin-role` |
| `LISTEN_ADDR` | No | Bind address (default `0.0.0.0:8080`) |

### Endpoints

All routes are nested under `/member-origin-role`:

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/register` | RoleLogic registers a role link |
| `GET` | `/config` | Return config schema to dashboard |
| `POST` | `/config` | Save admin configuration |
| `DELETE` | `/config` | Delete role link |
| `GET` | `/verify` | Verification page (user-facing) |
| `GET` | `/verify/login` | Redirects to Auth Gateway for Discord login |
| `GET` | `/health` | Health check |

## License

MIT
