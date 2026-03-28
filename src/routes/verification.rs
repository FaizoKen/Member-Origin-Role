use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::discord_oauth::{sign_session, verify_session, DiscordOAuth};
use crate::services::fraud;
use crate::services::sync::PlayerSyncEvent;
use crate::services::ua_parser::parse_user_agent;
use crate::AppState;

const SESSION_COOKIE: &str = "wur_session";

fn get_session(jar: &CookieJar, secret: &str) -> Result<(String, String), AppError> {
    let cookie = jar.get(SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    verify_session(cookie.value(), secret).ok_or(AppError::Unauthorized)
}

/// Extract country code from HTTP headers (reverse proxy / CDN).
/// Checks CF-IPCountry (Cloudflare), X-Country, X-Vercel-IP-Country in order.
fn extract_country(headers: &HeaderMap) -> Option<String> {
    for header_name in ["cf-ipcountry", "x-country", "x-vercel-ip-country"] {
        if let Some(val) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            let code = val.trim().to_uppercase();
            if code.len() == 2 && code != "XX" && code != "T1" {
                return Some(code);
            }
        }
    }
    None
}

/// Extract client IP from HTTP headers.
fn extract_ip(headers: &HeaderMap) -> Option<String> {
    // CF-Connecting-IP (Cloudflare), X-Real-IP (nginx), X-Forwarded-For (generic)
    for header_name in ["cf-connecting-ip", "x-real-ip"] {
        if let Some(val) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
            let ip = val.trim().to_string();
            if !ip.is_empty() {
                return Some(ip);
            }
        }
    }
    // X-Forwarded-For: take the first (leftmost = original client) IP
    if let Some(val) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first_ip) = val.split(',').next() {
            let ip = first_ip.trim().to_string();
            if !ip.is_empty() {
                return Some(ip);
            }
        }
    }
    None
}

/// Extract primary language from Accept-Language header.
/// Returns the first language tag, e.g. "en-US" from "en-US,en;q=0.9,ja;q=0.8".
fn extract_language_from_header(headers: &HeaderMap) -> Option<String> {
    let val = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())?;
    let first = val.split(',').next()?.trim();
    // Strip quality value: "en-US;q=0.9" -> "en-US"
    let lang = first.split(';').next()?.trim();
    if lang.is_empty() {
        return None;
    }
    Some(lang.to_string())
}

/// Serve the verification SPA page.
pub async fn verify_page(State(state): State<Arc<AppState>>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        state.verify_html.clone(),
    )
        .into_response()
}

/// Render the full HTML page for the verification flow.
pub fn render_verify_page(base_url: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Member Origin Role — Verify</title>
<meta property="og:title" content="Member Origin Role — Verify">
<meta property="og:description" content="Sign in with Discord to verify your identity for automatic role assignment.">
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0e1525;color:#c9d1d9;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.container{{max-width:480px;width:100%;padding:2rem;margin:1rem}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:2rem;margin-bottom:1.5rem}}
h1{{font-size:1.5rem;color:#e6edf3;margin-bottom:.5rem}}
.subtitle{{color:#8b949e;font-size:.9rem;margin-bottom:1.5rem}}
.btn{{display:inline-flex;align-items:center;justify-content:center;padding:.75rem 1.5rem;border-radius:8px;font-size:.95rem;font-weight:600;border:none;cursor:pointer;text-decoration:none;transition:all .2s;width:100%}}
.btn-discord{{background:#5865F2;color:#fff}}.btn-discord:hover{{background:#4752c4}}
.btn-refresh{{background:#238636;color:#fff;margin-top:.75rem}}.btn-refresh:hover{{background:#2ea043}}
.btn-logout{{background:#21262d;color:#c9d1d9;border:1px solid #30363d;margin-top:.75rem}}.btn-logout:hover{{background:#30363d}}
.hidden{{display:none}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:.5rem;margin:1rem 0}}
.meta-item{{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:.5rem .75rem}}
.meta-label{{font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}}
.meta-value{{font-size:.85rem;color:#e6edf3;margin-top:.15rem;word-break:break-all}}
.status-badge{{display:inline-block;padding:.2rem .6rem;border-radius:20px;font-size:.75rem;font-weight:600}}
.badge-ok{{background:#238636;color:#fff}}
.msg{{padding:.75rem;border-radius:6px;margin-bottom:1rem;font-size:.85rem}}
.msg-error{{background:#3d1f1f;border:1px solid #f85149;color:#f85149}}
.msg-success{{background:#1f3d1f;border:1px solid #3fb950;color:#3fb950}}
.spinner{{width:20px;height:20px;border:2px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:spin .6s linear infinite;display:inline-block;vertical-align:middle;margin-right:.5rem}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style>
</head>
<body>
<div class="container">
<div class="card">
<h1>Member Origin Role</h1>
<p class="subtitle">Sign in with Discord to verify your identity for automatic role assignment.</p>
<div id="msg" class="hidden"></div>
<div id="loading"><span class="spinner"></span> Loading...</div>
<div id="login" class="hidden">
<a class="btn btn-discord" href="{base_url}/verify/login">
<svg width="20" height="20" viewBox="0 0 71 55" fill="white" style="margin-right:8px"><path d="M60.1 4.9A58.5 58.5 0 0045.4.2a.2.2 0 00-.2.1 40.8 40.8 0 00-1.8 3.7 54 54 0 00-16.2 0A26.5 26.5 0 0025.4.3a.2.2 0 00-.2-.1A58.4 58.4 0 0010.5 4.9a.2.2 0 00-.1.1C1.5 18 -.9 30.6.3 43a.2.2 0 00.1.2 58.7 58.7 0 0017.7 9 .2.2 0 00.3-.1 42 42 0 003.6-5.9.2.2 0 00-.1-.3 38.6 38.6 0 01-5.5-2.6.2.2 0 01 0-.4l1.1-.9a.2.2 0 01.2 0 41.9 41.9 0 0035.6 0 .2.2 0 01.2 0l1.1.9a.2.2 0 010 .4c-1.8 1-3.6 1.8-5.5 2.6a.2.2 0 00-.1.3 47.2 47.2 0 003.6 5.9.2.2 0 00.3.1 58.5 58.5 0 0017.7-9 .2.2 0 00.1-.1c1.4-14.3-2.3-26.7-9.7-37.8a.2.2 0 00-.1-.1zM23.7 35.2c-3.3 0-6-3-6-6.6s2.7-6.6 6-6.6 6.1 3 6 6.6c0 3.7-2.7 6.6-6 6.6zm22.2 0c-3.3 0-6-3-6-6.6s2.6-6.6 6-6.6 6 3 6 6.6-2.6 6.6-6 6.6z"/></svg>
Sign in with Discord
</a>
</div>
<div id="collected" class="hidden">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
<span id="username" style="font-weight:600;color:#e6edf3"></span>
<span class="status-badge badge-ok">Verified</span>
</div>
<div class="meta-grid" id="meta-grid"></div>
<button class="btn btn-refresh" onclick="collectData()">Refresh Data</button>
<button class="btn btn-logout" onclick="doLogout()">Log Out</button>
</div>
</div>
</div>

<script>
const BASE = '';

function show(id) {{
  ['loading','login','collected'].forEach(s => document.getElementById(s).classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}}

function showMsg(text, type) {{
  const el = document.getElementById('msg');
  el.className = 'msg msg-' + type;
  el.textContent = text;
  el.classList.remove('hidden');
  if (type === 'success') setTimeout(() => el.classList.add('hidden'), 5000);
}}

async function api(method, path, body) {{
  const opts = {{ method, credentials: 'include', headers: {{'Content-Type': 'application/json'}} }};
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}}

function renderMeta(ctx) {{
  const grid = document.getElementById('meta-grid');
  grid.innerHTML = '';
  const items = [
    ['Country', ctx.country || '\u2014'],
    ['Timezone', ctx.timezone],
    ['Platform', ctx.platform],
    ['Browser', ctx.browser],
    ['Language', ctx.language],
    ['Device', ctx.device_type],
  ];
  for (const [label, value] of items) {{
    const div = document.createElement('div');
    div.className = 'meta-item';
    div.innerHTML = '<div class="meta-label">' + label + '</div><div class="meta-value">' + (value ?? '\u2014') + '</div>';
    grid.appendChild(div);
  }}
}}

async function collectData() {{
  try {{
    const payload = {{
      user_agent: navigator.userAgent,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezone_offset: new Date().getTimezoneOffset(),
      language: navigator.language,
      max_touch_points: navigator.maxTouchPoints || 0,
    }};
    const result = await api('POST', '/verify/collect', payload);
    if (result.context) renderMeta(result.context);
    if (result.flagged) {{
      showMsg('Your connection was flagged. Some roles may not be assigned. Try disabling any VPN or proxy and refresh.', 'error');
    }} else {{
      showMsg('Identity data collected successfully!', 'success');
    }}
  }} catch(e) {{
    showMsg(e.message, 'error');
  }}
}}

async function doLogout() {{
  try {{
    await api('POST', '/verify/logout');
    show('login');
  }} catch(e) {{
    showMsg(e.message, 'error');
  }}
}}

async function init() {{
  try {{
    const status = await api('GET', '/verify/status');
    document.getElementById('username').textContent = status.display_name;
    show('collected');
    await collectData();
  }} catch(e) {{
    show('login');
  }}
}}

init();
</script>
</body>
</html>"##
    )
}

#[derive(Deserialize)]
pub struct LoginQuery {
    redirect: Option<String>,
}

/// Start Discord OAuth flow.
pub async fn login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> Result<Redirect, AppError> {
    let state_param: String = (0..32)
        .map(|_| {
            let idx = rand::random::<usize>() % 36;
            if idx < 10 {
                (b'0' + idx as u8) as char
            } else {
                (b'a' + (idx - 10) as u8) as char
            }
        })
        .collect();

    let redirect_data = query
        .redirect
        .map(|r| serde_json::json!({"redirect": r}));

    sqlx::query(
        "INSERT INTO oauth_states (state, redirect_data, expires_at) VALUES ($1, $2, now() + interval '10 minutes')",
    )
    .bind(&state_param)
    .bind(&redirect_data)
    .execute(&state.pool)
    .await?;

    let url = DiscordOAuth::authorize_url(&state.config, &state_param);
    Ok(Redirect::temporary(&url))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: String,
}

/// Handle Discord OAuth callback.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), AppError> {
    let oauth_state = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM oauth_states WHERE state = $1 AND expires_at > now())",
    )
    .bind(&query.state)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);

    if !oauth_state {
        return Err(AppError::BadRequest("Invalid or expired OAuth state".into()));
    }

    sqlx::query("DELETE FROM oauth_states WHERE state = $1")
        .bind(&query.state)
        .execute(&state.pool)
        .await?;

    let oauth = DiscordOAuth::with_client(state.oauth_http.clone());
    let (access_token, refresh_token) = oauth.exchange_code(&state.config, &query.code).await?;
    let (discord_id, display_name) = oauth.get_user(&access_token).await?;

    if let Some(rt) = &refresh_token {
        let _ = sqlx::query(
            "INSERT INTO discord_tokens (discord_id, refresh_token) VALUES ($1, $2) \
             ON CONFLICT (discord_id) DO UPDATE SET refresh_token = $2",
        )
        .bind(&discord_id)
        .bind(rt)
        .execute(&state.pool)
        .await;
    }

    let guilds = oauth.get_user_guilds(&access_token).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM user_guilds WHERE discord_id = $1")
        .bind(&discord_id)
        .execute(&mut *tx)
        .await?;
    if !guilds.is_empty() {
        let guild_ids: Vec<&str> = guilds.iter().map(|(id, _)| id.as_str()).collect();
        let guild_names: Vec<&str> = guilds.iter().map(|(_, name)| name.as_str()).collect();
        sqlx::query(
            "INSERT INTO user_guilds (discord_id, guild_id, guild_name, updated_at) \
             SELECT $1, UNNEST($2::text[]), UNNEST($3::text[]), now()",
        )
        .bind(&discord_id)
        .bind(&guild_ids)
        .bind(&guild_names)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    let session_value = sign_session(&discord_id, &display_name, &state.config.session_secret);
    let cookie = format!(
        "{SESSION_COOKIE}={session_value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600"
    );
    let jar = jar.add(
        axum_extra::extract::cookie::Cookie::parse(cookie)
            .map_err(|e| AppError::Internal(format!("Cookie parse error: {e}")))?,
    );

    tracing::info!(discord_id, "User authenticated via OAuth");
    Ok((jar, Redirect::temporary("/verify")))
}

/// Return session status and web context summary.
pub async fn status(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<Json<Value>, AppError> {
    let (discord_id, display_name) = get_session(&jar, &state.config.session_secret)?;

    let has_context = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM web_contexts WHERE discord_id = $1)",
    )
    .bind(&discord_id)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);

    Ok(Json(json!({
        "discord_id": discord_id,
        "display_name": display_name,
        "has_context": has_context,
    })))
}

/// Client sends minimal JS data; server extracts the rest from HTTP headers.
#[derive(Deserialize, serde::Serialize)]
pub struct CollectPayload {
    pub user_agent: String,
    pub timezone: String,
    pub timezone_offset: i32,
    pub language: String,
    pub max_touch_points: Option<i32>,
}

/// Receive visitor identity from client JS + HTTP headers and store it.
pub async fn collect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<CollectPayload>,
) -> Result<Json<Value>, AppError> {
    let (discord_id, _) = get_session(&jar, &state.config.session_secret)?;

    // Parse UA for browser, platform, device type
    let touch_points = payload.max_touch_points.unwrap_or(0);
    let (browser, platform, device_type) = parse_user_agent(&payload.user_agent, touch_points);

    // Extract HTTP-level identity
    let country = extract_country(&headers);
    let ip_address = extract_ip(&headers);
    let accept_language_raw = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let language = extract_language_from_header(&headers).unwrap_or(payload.language.clone());

    // Negate JS offset to standard convention: -300 for EST, +540 for JST
    // JS getTimezoneOffset() returns +300 for EST (positive = behind UTC)
    let utc_offset = -payload.timezone_offset;

    // Fetch previous visit data for impossible travel detection
    let prev = sqlx::query_as::<_, (Option<String>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT country, last_visit FROM web_contexts WHERE discord_id = $1",
    )
    .bind(&discord_id)
    .fetch_optional(&state.pool)
    .await?;
    let (prev_country, prev_visit_at) = prev.unwrap_or((None, None));

    // Fraud detection (all server-side)
    let now = chrono::Utc::now();
    let vpn_detected = fraud::detect_vpn(&headers, &payload.timezone, country.as_deref());
    let spoofing_detected = fraud::detect_spoofing(
        &payload.timezone,
        utc_offset,
        country.as_deref(),
        &platform,
        &browser,
        &device_type,
    );
    let impossible_travel = fraud::detect_impossible_travel(
        country.as_deref(),
        prev_country.as_deref(),
        prev_visit_at,
        now,
    );

    let raw_data = serde_json::to_value(&payload).unwrap_or_else(|_| json!({}));

    // Upsert web context
    sqlx::query(
        "INSERT INTO web_contexts (discord_id, raw_data, timezone, utc_offset, country, \
         platform, browser, language, device_type, visit_count, \
         vpn_detected, spoofing_detected, impossible_travel, \
         prev_country, prev_visit_at, \
         user_agent, ip_address, accept_language, first_visit, last_visit) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, \
         $10, $11, $12, $13, $14, $15, $16, $17, now(), now()) \
         ON CONFLICT (discord_id) DO UPDATE SET \
         raw_data = $2, timezone = $3, utc_offset = $4, country = COALESCE($5, web_contexts.country), \
         platform = $6, browser = $7, language = $8, device_type = $9, \
         vpn_detected = $10, spoofing_detected = $11, impossible_travel = $12, \
         prev_country = web_contexts.country, prev_visit_at = web_contexts.last_visit, \
         user_agent = $15, ip_address = COALESCE($16, web_contexts.ip_address), \
         accept_language = COALESCE($17, web_contexts.accept_language), \
         visit_count = web_contexts.visit_count + 1, last_visit = now()",
    )
    .bind(&discord_id)              // $1
    .bind(&raw_data)                // $2
    .bind(&payload.timezone)        // $3
    .bind(utc_offset)               // $4
    .bind(&country)                 // $5
    .bind(&platform)                // $6
    .bind(&browser)                 // $7
    .bind(&language)                // $8
    .bind(&device_type)             // $9
    .bind(vpn_detected)             // $10
    .bind(spoofing_detected)        // $11
    .bind(impossible_travel)        // $12
    .bind(&prev_country)            // $13 (prev_country for INSERT)
    .bind(&prev_visit_at)           // $14 (prev_visit_at for INSERT)
    .bind(&payload.user_agent)      // $15
    .bind(&ip_address)              // $16
    .bind(&accept_language_raw)     // $17
    .execute(&state.pool)
    .await?;

    // Trigger sync
    let _ = state
        .player_sync_tx
        .send(PlayerSyncEvent::DataCollected {
            discord_id: discord_id.clone(),
        })
        .await;

    tracing::debug!(discord_id, vpn_detected, spoofing_detected, impossible_travel, "Web context collected");

    let flagged = vpn_detected || spoofing_detected || impossible_travel;

    Ok(Json(json!({
        "success": true,
        "flagged": flagged,
        "context": {
            "country": country,
            "timezone": payload.timezone,
            "platform": platform,
            "browser": browser,
            "language": language,
            "device_type": device_type,
        }
    })))
}

/// Clear session cookie.
pub async fn logout(jar: CookieJar) -> Result<(CookieJar, Json<Value>), AppError> {
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    let jar = jar.add(
        axum_extra::extract::cookie::Cookie::parse(cookie)
            .map_err(|e| AppError::Internal(format!("Cookie parse error: {e}")))?,
    );
    Ok((jar, Json(json!({"success": true}))))
}
