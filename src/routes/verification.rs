use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::session;
use crate::services::fraud;
use crate::services::sync::PlayerSyncEvent;
use crate::services::ua_parser::parse_user_agent;
use crate::AppState;

const SESSION_COOKIE: &str = "rl_session";

fn get_session(jar: &CookieJar, secret: &str) -> Result<(String, String), AppError> {
    let cookie = jar.get(SESSION_COOKIE).ok_or(AppError::Unauthorized)?;
    session::verify_session(cookie.value(), secret).ok_or(AppError::Unauthorized)
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
///
/// If any role link in this deployment has `anonymous_mode = true`, serve the
/// silent variant: no data display, auto-bounce to Discord login, generic
/// "You're all set" message. Otherwise serve the standard transparent page.
pub async fn verify_page(State(state): State<Arc<AppState>>) -> Response {
    // Default-silent: render the anonymous page unless some role_link has
    // explicitly opted out (anonymous_mode = false). Missing key = silent.
    let anonymous = sqlx::query_scalar::<_, bool>(
        "SELECT NOT EXISTS(SELECT 1 FROM role_links \
         WHERE (conditions->>'anonymous_mode') = 'false')",
    )
    .fetch_one(&state.pool)
    .await
    .unwrap_or(true);

    let body = if anonymous {
        state.verify_anonymous_html.clone()
    } else {
        state.verify_html.clone()
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Build the three Turnstile template fragments: the head `<script>`, the
/// widget `<div>`, and the JS-enabled flag. All empty/"false" when unset.
fn turnstile_fragments(site_key: Option<&str>) -> (&'static str, String, &'static str) {
    match site_key {
        Some(k) => (
            r#"<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>"#,
            format!(
                r#"<div class="cf-turnstile" data-sitekey="{k}" data-callback="onTurnstileOK" data-error-callback="onTurnstileErr" data-expired-callback="onTurnstileErr" data-theme="dark"></div>"#
            ),
            "true",
        ),
        None => ("", String::new(), "false"),
    }
}

/// Render the full HTML page for the verification flow.
pub fn render_verify_page(base_url: &str, turnstile_site_key: Option<&str>) -> String {
    let (ts_head, ts_widget, ts_enabled) = turnstile_fragments(turnstile_site_key);
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Member Origin Role — Verify</title>
<link rel="icon" type="image/x-icon" href="{base_url}/favicon.ico">
<link rel="shortcut icon" type="image/x-icon" href="{base_url}/favicon.ico">
<meta property="og:title" content="Member Origin Role — Verify">
<meta property="og:description" content="Sign in with Discord to verify your identity for automatic role assignment.">
{ts_head}
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
.guild-ctx{{display:none;align-items:center;gap:10px;background:#052e16;border:1px solid #14532d;color:#86efac;padding:8px 14px;border-radius:8px;margin:0 0 12px;font-size:13px;line-height:1.5}}
.guild-ctx.show{{display:flex}}
.guild-ctx.warn{{background:#1c1208;border-color:#422006;color:#fbbf24}}
.guild-ctx .gctx-icon{{flex-shrink:0}}
.guild-ctx .gctx-name{{color:#fff;font-weight:600}}
.manage-link{{font-size:13px;color:#8b949e;margin-top:.85rem;line-height:1.5}}
.manage-link a{{color:#74b9ff;text-decoration:none}}
.manage-link a:hover{{text-decoration:underline}}
</style>
</head>
<body>
<div class="container">
<div class="card">
<h1>Member Origin Role</h1>
<p class="subtitle">Sign in with Discord to verify your identity for automatic role assignment.</p>
<!-- Server context banner: only shown when ?guild=<id> is present in the URL.
     Lets a server admin share a per-guild link that both signs the user in
     AND auto-enables the role for that specific server in one shot. -->
<div id="guild-ctx" class="guild-ctx">
<svg class="gctx-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
<span id="guild-ctx-text"></span>
</div>
<div id="msg" class="hidden"></div>
<div id="loading"><span class="spinner"></span> Loading...</div>
<div style="display:flex;justify-content:center;margin:.5rem 0">{ts_widget}</div>
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
<p class="manage-link">
Receiving Member Origin roles in servers you didn't intend?
<a href="/auth/my_servers?from=/member-origin-role/verify">Choose which servers receive roles &rarr;</a>
</p>
<button class="btn btn-refresh" onclick="collectData()">Refresh Data</button>
<button class="btn btn-logout" onclick="doLogout()">Log Out</button>
</div>
</div>
</div>

<script>
const BASE = '{base_url}';
const PLUGIN_SLUG = 'member-origin-role';

// Optional ?guild=<id> tells us the user came from a per-guild verify
// link an admin shared in their Discord. We use it to (a) show a
// contextual banner so the user knows which server this is for and
// (b) automatically clear any existing opt-out (both per-plugin and
// the guild-wide master) once they're authenticated — so a returning
// user who'd previously disabled this server doesn't have to find
// /auth/my_servers to re-enable it.
const guildId = (() => {{
  try {{
    const v = new URLSearchParams(window.location.search).get('guild');
    return v && /^[0-9]{{5,25}}$/.test(v) ? v : '';
  }} catch (e) {{ return ''; }}
}})();

// Preserve the guild context across the Discord OAuth round-trip so
// an unauth visitor who logs in lands back on this same per-guild URL.
(function patchLoginHref() {{
  if (!guildId) return;
  const link = document.querySelector('#login a.btn-discord');
  if (!link) return;
  const returnTo = '/member-origin-role/verify?guild=' + encodeURIComponent(guildId);
  link.href = '/auth/login?return_to=' + encodeURIComponent(returnTo);
}})();

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

function showGuildCtx(text, isWarning) {{
  const el = document.getElementById('guild-ctx');
  document.getElementById('guild-ctx-text').innerHTML = text;
  el.classList.toggle('warn', !!isWarning);
  el.classList.add('show');
}}

async function api(method, path, body) {{
  const opts = {{ method, credentials: 'include', headers: {{'Content-Type': 'application/json'}} }};
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}}

// Gateway-absolute API helper for /auth/* (cookie-authed via the shared
// rl_session). Same shape as `api()` but doesn't prefix with base_url.
async function gatewayApi(method, path, body) {{
  const opts = {{ method, credentials: 'include', headers: {{}} }};
  if (body) {{
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }}
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({{}}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}}

// Resolve guildId → display name via the gateway, then clear any
// opt-out blocking this plugin from assigning roles in that server.
// Idempotent: clearing rows that don't exist is a no-op on the server.
async function applyGuildContext() {{
  if (!guildId) return;
  let prefs;
  try {{
    prefs = await gatewayApi('GET', '/auth/preferences');
  }} catch (e) {{
    // Not a fatal failure for the verify flow — just skip the banner.
    return;
  }}
  const g = (prefs.guilds || []).find(x => x.guild_id === guildId);
  if (!g) {{
    // Either the user isn't in that guild, or the gateway hasn't
    // refreshed their guild list yet. Surface it gently — the role
    // just won't apply until they're a member.
    showGuildCtx("You're not in that server yet — join it on Discord, then refresh.", true);
    return;
  }}
  const safeName = (g.guild_name || '(unnamed server)')
    .replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}})[c]);
  const wasDisabled = g.master_optout || (g.plugin_optouts || []).includes(PLUGIN_SLUG);
  // Always clear both — the master toggle wins over per-plugin
  // overrides, so we need to remove it too even if only the
  // per-plugin row was set on this server.
  try {{
    if (g.master_optout) {{
      await gatewayApi('POST', '/auth/preferences', {{
        guild_id: guildId, plugin: null, enabled: true,
      }});
    }}
    if ((g.plugin_optouts || []).includes(PLUGIN_SLUG)) {{
      await gatewayApi('POST', '/auth/preferences', {{
        guild_id: guildId, plugin: PLUGIN_SLUG, enabled: true,
      }});
    }}
  }} catch (e) {{
    // Even if the clear failed, still show the banner so the user
    // knows where they are. The role will simply not apply until
    // they fix it manually via /auth/my_servers.
  }}
  const nameHtml = '<span class="gctx-name">' + safeName + '</span>';
  if (wasDisabled) {{
    showGuildCtx('Enabled Member Origin roles for ' + nameHtml + ' — roles apply on the next sync.');
  }} else {{
    showGuildCtx('Member Origin roles are active in ' + nameHtml + '.');
  }}
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

const TS_ENABLED = {ts_enabled};
let tsToken = null;
window.onTurnstileOK = function(t) {{ tsToken = t; }};
window.onTurnstileErr = function() {{ tsToken = null; }};

function waitForToken() {{
  if (!TS_ENABLED) return Promise.resolve('');
  if (tsToken) return Promise.resolve(tsToken);
  return new Promise(function(resolve) {{
    const start = Date.now();
    const iv = setInterval(function() {{
      if (tsToken) {{ clearInterval(iv); resolve(tsToken); }}
      else if (Date.now() - start > 8000) {{ clearInterval(iv); resolve(''); }}
    }}, 150);
  }});
}}

async function collectData() {{
  try {{
    const token = await waitForToken();
    const payload = {{
      user_agent: navigator.userAgent,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezone_offset: new Date().getTimezoneOffset(),
      language: navigator.language,
      max_touch_points: navigator.maxTouchPoints || 0,
      turnstile_token: token,
    }};
    const result = await api('POST', '/verify/collect', payload);
    if (result.context) renderMeta(result.context);
    if (result.hint) {{
      showMsg(result.hint, 'error');
    }} else {{
      showMsg('Identity data collected successfully!', 'success');
    }}
  }} catch(e) {{
    showMsg(e.message, 'error');
  }} finally {{
    if (TS_ENABLED && window.turnstile) {{
      try {{ turnstile.reset(); }} catch(e) {{}}
      tsToken = null;
    }}
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
    // Session is valid — apply the per-guild side effects (if any).
    applyGuildContext();
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

/// Render the silent / anonymous-mode HTML for the verification flow.
///
/// Behaviour vs. the standard page:
///   - No collected-data grid (Country, Timezone, etc.) is rendered.
///   - No "Sign in with Discord" button — the page auto-redirects to login.
///   - On success, shows a generic "You're all set" message only.
///   - Cooldown errors on /verify/collect are swallowed (data already exists).
pub fn render_verify_anonymous_page(base_url: &str, turnstile_site_key: Option<&str>) -> String {
    let (ts_head, ts_widget, ts_enabled) = turnstile_fragments(turnstile_site_key);
    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Welcome</title>
<link rel="icon" type="image/x-icon" href="{base_url}/favicon.ico">
<link rel="shortcut icon" type="image/x-icon" href="{base_url}/favicon.ico">
<meta property="og:title" content="Welcome">
<meta property="og:description" content="Confirming access.">
{ts_head}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0e1525;color:#c9d1d9;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.box{{text-align:center;padding:2rem;max-width:420px}}
h1{{font-size:1.4rem;color:#e6edf3;margin-bottom:.6rem;font-weight:600}}
p{{color:#8b949e;font-size:.95rem;line-height:1.5}}
.spinner{{width:32px;height:32px;border:3px solid #30363d;border-top-color:#58a6ff;border-radius:50%;animation:spin .6s linear infinite;margin:0 auto 1.25rem}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
.check{{font-size:3rem;color:#3fb950;margin-bottom:1rem;line-height:1}}
.x{{font-size:3rem;color:#f85149;margin-bottom:1rem;line-height:1}}
.hidden{{display:none}}
</style>
</head>
<body>
<div class="box">
<div id="loading">
<div class="spinner"></div>
<h1>Just a moment...</h1>
<p>Confirming your access.</p>
</div>
<div id="done" class="hidden">
<div class="check">&#10003;</div>
<h1>You're all set!</h1>
<p>You can close this tab.</p>
</div>
<div id="error" class="hidden">
<div class="x">!</div>
<h1>Something went wrong</h1>
<p id="error-msg">Please try again.</p>
</div>
<div style="display:flex;justify-content:center;margin-top:1.75rem">{ts_widget}</div>
</div>

<script>
const BASE = '{base_url}';
const PLUGIN_SLUG = 'member-origin-role';

// Optional ?guild=<id> from a per-guild verify link. Even in silent
// mode we need to preserve it across the OAuth round-trip so a returning
// user lands back on the same per-guild URL after sign-in, and we use it
// post-auth to silently clear any opt-out for that server.
const guildId = (() => {{
  try {{
    const v = new URLSearchParams(window.location.search).get('guild');
    return v && /^[0-9]{{5,25}}$/.test(v) ? v : '';
  }} catch (e) {{ return ''; }}
}})();

async function gatewayApi(method, path, body) {{
  const opts = {{ method, credentials: 'include', headers: {{}} }};
  if (body) {{
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }}
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({{}}));
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}}

// Silent variant of applyGuildContext — no banner, no UI; just clears
// the opt-out rows blocking this plugin in the target guild. Best-effort:
// any failure is swallowed so the anonymous page stays silent.
async function applyGuildContextSilent() {{
  if (!guildId) return;
  let prefs;
  try {{ prefs = await gatewayApi('GET', '/auth/preferences'); }}
  catch (e) {{ return; }}
  const g = (prefs.guilds || []).find(x => x.guild_id === guildId);
  if (!g) return;
  try {{
    if (g.master_optout) {{
      await gatewayApi('POST', '/auth/preferences', {{
        guild_id: guildId, plugin: null, enabled: true,
      }});
    }}
    if ((g.plugin_optouts || []).includes(PLUGIN_SLUG)) {{
      await gatewayApi('POST', '/auth/preferences', {{
        guild_id: guildId, plugin: PLUGIN_SLUG, enabled: true,
      }});
    }}
  }} catch (e) {{}}
}}

const TS_ENABLED = {ts_enabled};
let tsToken = null;
window.onTurnstileOK = function(t) {{ tsToken = t; }};
window.onTurnstileErr = function() {{ tsToken = null; }};

function waitForToken() {{
  if (!TS_ENABLED) return Promise.resolve('');
  if (tsToken) return Promise.resolve(tsToken);
  return new Promise(function(resolve) {{
    const start = Date.now();
    const iv = setInterval(function() {{
      if (tsToken) {{ clearInterval(iv); resolve(tsToken); }}
      else if (Date.now() - start > 8000) {{ clearInterval(iv); resolve(''); }}
    }}, 150);
  }});
}}

function show(id) {{
  ['loading','done','error'].forEach(s => document.getElementById(s).classList.add('hidden'));
  document.getElementById(id).classList.remove('hidden');
}}

async function run() {{
  let signedIn = false;
  try {{
    const r = await fetch(BASE + '/verify/status', {{ credentials: 'include' }});
    signedIn = r.ok;
  }} catch(e) {{}}

  if (!signedIn) {{
    // Preserve ?guild= across the OAuth round-trip — the server-side
    // /verify/login redirect would otherwise drop it.
    let url = BASE + '/verify/login';
    if (guildId) {{
      const returnTo = '/member-origin-role/verify?guild=' + encodeURIComponent(guildId);
      url = '/auth/login?return_to=' + encodeURIComponent(returnTo);
    }}
    window.location.replace(url);
    return;
  }}

  // Signed in — clear any per-guild opt-out silently before/while we
  // collect identity. No banner in anonymous mode.
  applyGuildContextSilent();

  try {{
    const token = await waitForToken();
    const payload = {{
      user_agent: navigator.userAgent,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezone_offset: new Date().getTimezoneOffset(),
      language: navigator.language,
      max_touch_points: navigator.maxTouchPoints || 0,
      turnstile_token: token,
    }};
    const res = await fetch(BASE + '/verify/collect', {{
      method: 'POST',
      credentials: 'include',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(payload),
    }});
    // 400 from cooldown is fine — data already on file. Anything else
    // (incl. 403 bot-check failure) surfaces.
    if (!res.ok && res.status !== 400) {{
      let msg = 'Please try again.';
      try {{ const d = await res.json(); if (d && d.error) msg = d.error; }} catch(e) {{}}
      document.getElementById('error-msg').textContent = msg;
      show('error');
      return;
    }}
    show('done');
  }} catch(e) {{
    document.getElementById('error-msg').textContent = e.message || 'Network error.';
    show('error');
  }}
}}

run();
</script>
</body>
</html>"##
    )
}

/// Redirect to Auth Gateway for Discord login.
pub async fn login(
    State(state): State<Arc<AppState>>,
) -> Result<Redirect, AppError> {
    let return_to = "/member-origin-role/verify";
    let url = format!("/auth/login?return_to={}", urlencoding::encode(return_to));
    Ok(Redirect::temporary(&url))
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
    /// Cloudflare Turnstile token. Ignored unless Turnstile is configured.
    /// Skipped from the stored raw_data blob (verification-only, single-use).
    #[serde(default, skip_serializing)]
    pub turnstile_token: Option<String>,
}

/// Minimum seconds between collect calls per user (prevents spam).
const COLLECT_COOLDOWN_SECS: i64 = 10;

/// Receive visitor identity from client JS + HTTP headers and store it.
pub async fn collect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<CollectPayload>,
) -> Result<Json<Value>, AppError> {
    let (discord_id, display_name) = get_session(&jar, &state.config.session_secret)?;

    // Turnstile bot check — fail closed when configured. Runs before any work
    // so scripted clients can't even reach the cooldown / DB path.
    if let Some(secret) = state.config.turnstile_secret_key.as_deref() {
        let token = payload.turnstile_token.as_deref().unwrap_or("");
        let remote_ip = extract_ip(&headers);
        let ok = crate::services::turnstile::verify(
            &state.http,
            secret,
            token,
            remote_ip.as_deref(),
        )
        .await;
        if !ok {
            // 403 (not 400) so the anonymous page — which deliberately swallows
            // the 400 cooldown — still surfaces a real bot-check failure.
            return Err(AppError::Forbidden(
                "Bot check failed. Please refresh the page and try again.".into(),
            ));
        }
    }

    // Per-user cooldown: reject if last visit was too recent
    let last_visit = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        "SELECT last_visit FROM web_contexts WHERE discord_id = $1",
    )
    .bind(&discord_id)
    .fetch_optional(&state.pool)
    .await?;

    if let Some(last) = last_visit {
        let elapsed = (chrono::Utc::now() - last).num_seconds();
        if elapsed < COLLECT_COOLDOWN_SECS {
            return Err(AppError::BadRequest(format!(
                "Please wait {} seconds before refreshing",
                COLLECT_COOLDOWN_SECS - elapsed
            )));
        }
    }

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

    // Discord account age — decoded from the snowflake, no API call.
    let account_created_at = fraud::snowflake_to_created_at(&discord_id);

    // ASN / proxy reputation — only if a provider key is configured.
    let asn_rep = match (
        state.config.proxycheck_api_key.as_deref(),
        ip_address.as_deref(),
    ) {
        (Some(key), Some(ip)) => {
            crate::services::asn_lookup::lookup(&state.http, &state.pool, ip, Some(key)).await
        }
        _ => None,
    };
    let vpn_asn_detected = asn_rep.as_ref().map(|r| r.is_proxy).unwrap_or(false);
    let asn_org = asn_rep.and_then(|r| r.asn_org);

    let raw_data = serde_json::to_value(&payload).unwrap_or_else(|_| json!({}));

    // Upsert web context
    // "Ever" flags use OR logic: once set, they stay true until cooldown expires.
    // fraud_clean_since tracks when all current flags became clean.
    sqlx::query(
        "INSERT INTO web_contexts (discord_id, raw_data, timezone, utc_offset, country, \
         platform, browser, language, device_type, visit_count, \
         vpn_detected, spoofing_detected, impossible_travel, \
         prev_country, prev_visit_at, \
         user_agent, ip_address, accept_language, discord_name, \
         vpn_asn_detected, asn_org, account_created_at, \
         first_visit, last_visit) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, \
         $10, $11, $12, \
         $13, $14, $15, $16, $17, $18, \
         $19, $20, $21, \
         now(), now()) \
         ON CONFLICT (discord_id) DO UPDATE SET \
         raw_data = $2, timezone = $3, utc_offset = $4, country = COALESCE($5, web_contexts.country), \
         platform = $6, browser = $7, language = $8, device_type = $9, \
         vpn_detected = $10, spoofing_detected = $11, impossible_travel = $12, \
         prev_country = web_contexts.country, prev_visit_at = web_contexts.last_visit, \
         user_agent = $15, ip_address = COALESCE($16, web_contexts.ip_address), \
         accept_language = COALESCE($17, web_contexts.accept_language), \
         discord_name = $18, \
         vpn_asn_detected = $19, asn_org = COALESCE($20, web_contexts.asn_org), \
         account_created_at = COALESCE($21, web_contexts.account_created_at), \
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
    .bind(&display_name)            // $18
    .bind(vpn_asn_detected)         // $19
    .bind(&asn_org)                 // $20
    .bind(&account_created_at)      // $21
    .execute(&state.pool)
    .await?;

    // Trigger sync
    let _ = state
        .player_sync_tx
        .send(PlayerSyncEvent::DataCollected {
            discord_id: discord_id.clone(),
        })
        .await;

    tracing::debug!(
        discord_id,
        vpn_detected,
        vpn_asn_detected,
        spoofing_detected,
        impossible_travel,
        ?account_created_at,
        "Web context collected"
    );

    // Show a vague hint for VPN users (common innocent case) without revealing detection details.
    // Spoofing/impossible-travel/account-age get no hint — those are almost never accidental.
    let hint = if vpn_detected || vpn_asn_detected {
        Some("Some roles require a direct internet connection. If you're using a VPN or proxy, try disabling it and clicking Refresh Data.")
    } else {
        None
    };

    Ok(Json(json!({
        "success": true,
        "hint": hint,
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
