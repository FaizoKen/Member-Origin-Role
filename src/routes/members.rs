use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::AppError;
use crate::services::session::verify_session;
use crate::AppState;

#[derive(Deserialize)]
pub struct MembersQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    sort: Option<String>,
    order: Option<String>,
    search: Option<String>,
}

fn sort_column(key: &str) -> Option<&'static str> {
    match key {
        "discord_name"      => Some("wc.discord_name"),
        "country"           => Some("wc.country"),
        "timezone"          => Some("wc.timezone"),
        "language"          => Some("wc.language"),
        "platform"          => Some("wc.platform"),
        "browser"           => Some("wc.browser"),
        "device_type"       => Some("wc.device_type"),
        "account_created_at"=> Some("wc.account_created_at"),
        "visit_count"       => Some("wc.visit_count"),
        "last_visit"        => Some("wc.last_visit"),
        _ => None,
    }
}

pub fn render_members_page(base_url: &str) -> String {
    format!(
        r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Member Origin Role - Member List</title>
    <link rel="icon" type="image/x-icon" href="{base_url}/favicon.ico">
    <link rel="shortcut icon" type="image/x-icon" href="{base_url}/favicon.ico">
    <meta name="description" content="View collected member identity data for this Discord server.">
    <meta name="theme-color" content="#58a6ff">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: system-ui, -apple-system, sans-serif; max-width: 1180px; margin: 0 auto; padding: 32px 20px; background: #0e1525; color: #c8ccd4; min-height: 100vh; }}
        .header {{ margin-bottom: 24px; }}
        .header-top {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; justify-content: space-between; }}
        .header-title {{ display: flex; align-items: center; gap: 10px; }}
        .header-title h1 {{ color: #58a6ff; font-size: 24px; }}
        .powered {{ font-size: 11px; color: #64748b; background: #1e293b; padding: 2px 8px; border-radius: 4px; }}
        .powered a {{ color: #74b9ff; text-decoration: none; }}
        .guild-name {{ color: #e2e8f0; font-size: 18px; font-weight: 600; }}
        .guild-label {{ color: #64748b; font-size: 13px; margin-top: 2px; }}

        .card {{ background: #161d2e; padding: 22px; border-radius: 10px; border: 1px solid #1e2a3d; }}
        .msg {{ padding: 10px 14px; border-radius: 6px; margin: 12px 0; font-size: 13px; line-height: 1.5; }}
        .msg-error {{ background: #1c0a0a; color: #fca5a5; border: 1px solid #7f1d1d; }}
        .hidden {{ display: none !important; }}

        .toolbar {{ display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; }}
        .search-wrap {{ position: relative; flex: 1; max-width: 340px; }}
        .search-wrap svg {{ position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: #475569; pointer-events: none; }}
        .search-wrap input {{ width: 100%; padding: 8px 12px 8px 34px; font-size: 13px; border-radius: 6px; border: 1px solid #2a3548; background: #0e1525; color: #e0e0e0; font-family: inherit; transition: border-color .15s; }}
        .search-wrap input:focus {{ outline: none; border-color: #3b82f6; }}
        .search-hint {{ color: #475569; font-size: 11px; margin-top: 4px; }}
        .badge {{ display: inline-flex; align-items: center; gap: 5px; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 500; background: #1e293b; color: #94a3b8; border: 1px solid #334155; white-space: nowrap; }}

        .table-wrap {{ overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 9px 12px; text-align: left; white-space: nowrap; }}
        th {{ color: #64748b; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 2px solid #1e2a3d; cursor: pointer; user-select: none; transition: color .15s; }}
        th:hover {{ color: #94a3b8; }}
        th.sorted-asc::after {{ content: ' \25B2'; font-size: 9px; }}
        th.sorted-desc::after {{ content: ' \25BC'; font-size: 9px; }}
        td {{ border-bottom: 1px solid #111827; }}
        tr:hover td {{ background: #1a2236; }}
        .col-name {{ color: #e2e8f0; font-weight: 500; }}
        .col-id {{ color: #7c85f5; font-family: 'Courier New', monospace; font-size: 12px; }}
        .col-country {{ color: #e8b44a; font-family: 'Courier New', monospace; }}
        .col-mono {{ color: #94a3b8; font-family: 'Courier New', monospace; font-size: 12px; }}
        .col-num {{ color: #94a3b8; text-align: right; }}
        th.col-num {{ text-align: right; }}
        .col-date {{ color: #64748b; font-size: 12px; }}
        .flag {{ display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-right: 3px; text-transform: uppercase; letter-spacing: .03em; }}
        .flag-vpn {{ background: #3d1f1f; color: #fca5a5; border: 1px solid #7f1d1d; }}
        .flag-asn {{ background: #3d1f1f; color: #fda4af; border: 1px solid #9f1239; cursor: help; }}
        .flag-spoof {{ background: #3d2a0f; color: #fbbf24; border: 1px solid #92400e; }}
        .flag-travel {{ background: #2a1f3d; color: #c084fc; border: 1px solid #5b21b6; }}
        .flag-clean {{ color: #475569; font-size: 11px; }}

        .empty-state {{ text-align: center; padding: 40px 20px; color: #475569; }}
        .empty-state p {{ font-size: 14px; margin-bottom: 4px; }}
        .empty-state .hint {{ font-size: 12px; }}

        .pagination {{ display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 16px; font-size: 13px; }}
        .pagination button {{ padding: 6px 14px; border-radius: 6px; border: 1px solid #2a3548; background: #0e1525; color: #c8ccd4; cursor: pointer; font-family: inherit; font-size: 13px; transition: all .15s; }}
        .pagination button:hover:not(:disabled) {{ background: #1e293b; border-color: #3b82f6; }}
        .pagination button:disabled {{ opacity: 0.3; cursor: not-allowed; }}
        .pagination .page-info {{ color: #64748b; }}

        .logout-form {{ margin: 0; }}
        .logout-btn {{ padding: 6px 14px; border-radius: 6px; border: 1px solid #2a3548; background: #0e1525; color: #c8ccd4; cursor: pointer; font-family: inherit; font-size: 12px; transition: all .15s; }}
        .logout-btn:hover {{ background: #1e293b; border-color: #ef4444; color: #fca5a5; }}

        .login-btn {{ display: inline-block; padding: 10px 22px; border-radius: 6px; background: #5865f2; color: #fff; text-decoration: none; font-weight: 600; font-size: 14px; font-family: inherit; transition: background .15s; }}
        .login-btn:hover {{ background: #4752c4; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="header-top">
            <div class="header-title">
                <h1>Member Origin</h1>
                <span class="powered">Powered by <a href="https://rolelogic.faizo.net" target="_blank" rel="noopener">RoleLogic</a></span>
            </div>
            <form id="logout-form" class="logout-form" method="POST" action="/auth/logout">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
        <p class="guild-name" id="guild-name">Member Origins</p>
        <p class="guild-label" id="guild-label">Loading guild info...</p>
    </div>

    <div id="loading" class="card"><p style="color:#64748b;">Loading member data...</p></div>
    <div id="error-msg" class="hidden"></div>

    <div id="login-prompt" class="card hidden" style="text-align:center;">
        <p style="color:#e2e8f0; font-size:15px; margin-bottom:6px;">You are not signed in.</p>
        <p style="color:#64748b; font-size:13px; margin-bottom:18px;">Sign in with Discord to view this server's collected member data.</p>
        <a id="login-link" class="login-btn" href="#">Login with Discord</a>
    </div>

    <div id="content" class="hidden">
        <div class="card">
            <div class="toolbar">
                <div>
                    <div class="search-wrap">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                        <input type="text" id="search" placeholder="Search members..." />
                    </div>
                    <p class="search-hint">Search by Discord name, ID, country, timezone, or platform</p>
                </div>
                <span class="badge" id="member-count"></span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th data-key="discord_name">Discord</th>
                            <th data-key="country">Country</th>
                            <th data-key="timezone">Timezone</th>
                            <th data-key="language">Language</th>
                            <th data-key="platform">Platform</th>
                            <th data-key="browser">Browser</th>
                            <th data-key="device_type">Device</th>
                            <th data-key="account_created_at">Acct Age</th>
                            <th>Fraud</th>
                            <th data-key="visit_count" class="col-num">Visits</th>
                            <th data-key="last_visit">Last Visit</th>
                        </tr>
                    </thead>
                    <tbody id="tbody"></tbody>
                </table>
            </div>
            <div id="empty-state" class="empty-state hidden">
                <p>No members found</p>
                <p class="hint" id="empty-hint">Try a different search term</p>
            </div>
            <div class="pagination" id="pagination">
                <button id="btn-prev" onclick="goPage(state.page-1)">Prev</button>
                <span class="page-info" id="page-info"></span>
                <button id="btn-next" onclick="goPage(state.page+1)">Next</button>
            </div>
        </div>
    </div>

    <script>
    const parts = window.location.pathname.split('/').filter(Boolean);
    const guildId = parts[parts.indexOf('members') + 1] || '';
    const PER_PAGE = 20;
    const NUM_COLS = ['visit_count'];

    (function setupAuthLinks() {{
        const returnTo = window.location.pathname + window.location.search;
        const form = document.getElementById('logout-form');
        if (form) form.action = '/auth/logout?return_to=' + encodeURIComponent(returnTo);
        const loginLink = document.getElementById('login-link');
        if (loginLink) loginLink.href = '/auth/login?return_to=' + encodeURIComponent(returnTo);
    }})();

    const state = {{ page: 1, sort: 'last_visit', order: 'desc', search: '', total: 0 }};
    let debounceTimer = null;

    function timeAgo(iso) {{
        if (!iso) return '-';
        const diff = Date.now() - new Date(iso).getTime();
        const mins = Math.floor(diff / 60000);
        if (mins < 1) return 'just now';
        if (mins < 60) return mins + 'm ago';
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return hrs + 'h ago';
        const days = Math.floor(hrs / 24);
        return days + 'd ago';
    }}

    function esc(s) {{
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }}

    function acctAge(iso) {{
        if (!iso) return '-';
        const days = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
        if (days < 0) return '-';
        if (days < 31) return days + 'd';
        if (days < 365) return Math.floor(days / 30) + 'mo';
        const y = Math.floor(days / 365);
        const m = Math.floor((days % 365) / 30);
        return y + 'y' + (m ? ' ' + m + 'mo' : '');
    }}

    function renderFlags(p) {{
        const flags = [];
        if (p.vpn_detected) flags.push('<span class="flag flag-vpn">VPN</span>');
        if (p.vpn_asn_detected) flags.push('<span class="flag flag-asn" title="' + esc(p.asn_org || 'Flagged ASN/proxy') + '">VPN-ASN</span>');
        if (p.spoofing_detected) flags.push('<span class="flag flag-spoof">SPOOF</span>');
        if (p.impossible_travel) flags.push('<span class="flag flag-travel">TRAVEL</span>');
        return flags.length ? flags.join('') : '<span class="flag-clean">clean</span>';
    }}

    function render(members) {{
        const tbody = document.getElementById('tbody');
        const emptyEl = document.getElementById('empty-state');
        tbody.innerHTML = '';
        if (members.length === 0) {{
            emptyEl.classList.remove('hidden');
            document.getElementById('empty-hint').textContent = state.search
                ? 'No results for "' + state.search + '"'
                : 'No members have been collected in this server yet';
        }} else {{
            emptyEl.classList.add('hidden');
        }}
        members.forEach(p => {{
            const tr = document.createElement('tr');
            const name = p.discord_name || p.discord_id;
            tr.innerHTML =
                '<td><div class="col-name">' + esc(name) + '</div><div class="col-id">' + esc(p.discord_id) + '</div></td>' +
                '<td class="col-country">' + esc(p.country || '-') + '</td>' +
                '<td class="col-mono">' + esc(p.timezone || '-') + '</td>' +
                '<td class="col-mono">' + esc(p.language || '-') + '</td>' +
                '<td>' + esc(p.platform || '-') + '</td>' +
                '<td>' + esc(p.browser || '-') + '</td>' +
                '<td>' + esc(p.device_type || '-') + '</td>' +
                '<td class="col-date">' + acctAge(p.account_created_at) + '</td>' +
                '<td>' + renderFlags(p) + '</td>' +
                '<td class="col-num">' + (p.visit_count || 0) + '</td>' +
                '<td class="col-date">' + timeAgo(p.last_visit) + '</td>';
            tbody.appendChild(tr);
        }});
    }}

    function updatePagination() {{
        const totalPages = Math.max(1, Math.ceil(state.total / PER_PAGE));
        document.getElementById('member-count').textContent = state.total + ' member' + (state.total !== 1 ? 's' : '');
        document.getElementById('page-info').textContent = 'Page ' + state.page + ' of ' + totalPages;
        document.getElementById('btn-prev').disabled = state.page <= 1;
        document.getElementById('btn-next').disabled = state.page >= totalPages;
        document.getElementById('pagination').classList.toggle('hidden', state.total <= PER_PAGE);
    }}

    function updateSortUI() {{
        document.querySelectorAll('th[data-key]').forEach(h => {{
            h.classList.remove('sorted-asc', 'sorted-desc');
            if (h.dataset.key === state.sort) h.classList.add('sorted-' + state.order);
        }});
    }}

    async function fetchData() {{
        const params = new URLSearchParams({{
            page: state.page, per_page: PER_PAGE,
            sort: state.sort, order: state.order
        }});
        if (state.search) params.set('search', state.search);
        const res = await fetch('{base_url}/members/' + encodeURIComponent(guildId) + '/data?' + params, {{ credentials: 'same-origin' }});
        if (res.status === 401) {{
            const data = await res.json().catch(() => ({{}}));
            const err = new Error(data.error || 'You are not signed in.');
            err.authRequired = true;
            throw err;
        }}
        if (!res.ok) {{
            const data = await res.json().catch(() => ({{}}));
            throw new Error(data.error || 'Failed to load member data');
        }}
        return res.json();
    }}

    async function load() {{
        try {{
            const data = await fetchData();
            state.total = data.total;
            if (data.guild_name) {{
                document.getElementById('guild-name').textContent = data.guild_name;
                document.getElementById('guild-label').textContent = 'Collected member origins';
                document.title = data.guild_name + ' - Member Origin';
            }} else {{
                document.getElementById('guild-name').textContent = 'Member Origins';
                document.getElementById('guild-label').textContent = 'Collected member origin data';
            }}
            render(data.members);
            updatePagination();
            updateSortUI();
            document.getElementById('loading').classList.add('hidden');
            document.getElementById('content').classList.remove('hidden');
            document.getElementById('error-msg').classList.add('hidden');
        }} catch (e) {{
            document.getElementById('loading').classList.add('hidden');
            if (e && e.authRequired) {{
                document.getElementById('login-prompt').classList.remove('hidden');
                document.getElementById('error-msg').classList.add('hidden');
                document.getElementById('content').classList.add('hidden');
                const form = document.getElementById('logout-form');
                if (form) form.classList.add('hidden');
                document.getElementById('guild-name').textContent = 'Member Origins';
                document.getElementById('guild-label').textContent = 'Sign in to view this server\'s member list';
            }} else {{
                document.getElementById('guild-name').textContent = 'Member Origins';
                document.getElementById('guild-label').textContent = '';
                const el = document.getElementById('error-msg');
                el.className = 'msg msg-error';
                el.textContent = e.message;
                el.classList.remove('hidden');
            }}
        }}
    }}

    function goPage(p) {{
        const totalPages = Math.max(1, Math.ceil(state.total / PER_PAGE));
        state.page = Math.max(1, Math.min(p, totalPages));
        load();
    }}

    document.querySelectorAll('th[data-key]').forEach(th => {{
        th.addEventListener('click', () => {{
            const key = th.dataset.key;
            if (state.sort === key) {{
                state.order = state.order === 'asc' ? 'desc' : 'asc';
            }} else {{
                state.sort = key;
                state.order = NUM_COLS.includes(key) ? 'desc' : 'asc';
            }}
            state.page = 1;
            load();
        }});
    }});

    document.getElementById('search').addEventListener('input', e => {{
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {{
            state.search = e.target.value.trim();
            state.page = 1;
            load();
        }}, 300);
    }});

    load();
    </script>
</body>
</html>"##
    )
}

pub async fn members_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        state.members_html.clone(),
    )
}

/// Forward the viewer's `rl_session` cookie to the Auth Gateway. Pattern
/// matches Genshin-Player-Role/src/routes/players.rs (the gateway re-decodes
/// the cookie, so we re-encode with the same cookie machinery).
async fn auth_gateway_get(
    state: &Arc<AppState>,
    path_and_query: &str,
    session_cookie_value: &str,
) -> Result<Value, AppError> {
    let url = format!("{}{path_and_query}", state.config.auth_gateway_url);

    let outgoing = axum_extra::extract::cookie::Cookie::build((
        "rl_session",
        session_cookie_value.to_string(),
    ))
    .build();
    let cookie_header = outgoing.encoded().to_string();

    let resp = state
        .http
        .get(&url)
        .header(axum::http::header::COOKIE, cookie_header)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(error = %e, url = %url, "Auth Gateway request failed");
            AppError::Internal(format!("Auth Gateway unreachable: {e}"))
        })?;

    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(AppError::UnauthorizedWith(format!(
            "The Auth Gateway at {} rejected the session cookie. Re-login and try again.",
            state.config.auth_gateway_url
        )));
    }
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        tracing::error!(status = %status, url = %url, body = %body_text, "Auth Gateway error");
        return Err(AppError::Internal(format!(
            "Auth Gateway returned {status}"
        )));
    }

    resp.json::<Value>().await.map_err(|e| {
        AppError::Internal(format!("Auth Gateway parse error: {e}"))
    })
}

async fn fetch_guild_permission(
    state: &Arc<AppState>,
    guild_id: &str,
    session_cookie_value: &str,
) -> Result<(bool, bool), AppError> {
    let path = format!(
        "/auth/guild_permission?guild_id={}",
        urlencoding::encode(guild_id)
    );
    let body = auth_gateway_get(state, &path, session_cookie_value).await?;
    let is_member = body.get("is_member").and_then(|v| v.as_bool()).unwrap_or(false);
    let is_manager = body.get("is_manager").and_then(|v| v.as_bool()).unwrap_or(false);
    Ok((is_member, is_manager))
}

/// Call the Auth Gateway's `/auth/guild_members` endpoint.
/// Returns `(member_discord_ids, optional_guild_name)`.
///
/// Passes the plugin slug so users who opted out of this plugin (or the
/// whole guild) are stripped from the returned member set — the
/// downstream JOIN against `web_contexts` then naturally excludes them
/// from the public members list.
async fn fetch_guild_members(
    state: &Arc<AppState>,
    guild_id: &str,
    session_cookie_value: &str,
) -> Result<(Vec<String>, Option<String>), AppError> {
    let path = format!(
        "/auth/guild_members?guild_id={}&plugin=member-origin-role",
        urlencoding::encode(guild_id)
    );
    let body = auth_gateway_get(state, &path, session_cookie_value).await?;
    let discord_ids: Vec<String> = body
        .get("discord_ids")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let guild_name = body.get("guild_name").and_then(|v| v.as_str()).map(String::from);
    Ok((discord_ids, guild_name))
}

pub async fn members_data(
    State(state): State<Arc<AppState>>,
    Path(guild_id): Path<String>,
    jar: CookieJar,
    Query(query): Query<MembersQuery>,
) -> Result<Json<Value>, AppError> {
    // 1. Require a valid session cookie.
    let session_cookie = jar.get("rl_session").ok_or_else(|| {
        AppError::UnauthorizedWith(
            "No session cookie found. Please log in again.".into(),
        )
    })?;

    let (viewer_discord_id, _) =
        verify_session(session_cookie.value(), &state.config.session_secret).ok_or_else(|| {
            AppError::UnauthorizedWith(
                "Session cookie signature verification failed. Re-login and try again.".into(),
            )
        })?;

    // 2. Look up the guild's Member List Access policy.
    // 404 if no role link is configured for this guild (plugin isn't set up for the server).
    let guild_row: Option<(bool, String)> = sqlx::query_as(
        "SELECT \
           EXISTS(SELECT 1 FROM role_links WHERE guild_id = $1) AS has_link, \
           COALESCE( \
             (SELECT view_permission FROM guild_settings WHERE guild_id = $1), \
             'managers' \
           ) AS view_permission",
    )
    .bind(&guild_id)
    .fetch_optional(&state.pool)
    .await?;

    let (has_link, view_permission) =
        guild_row.unwrap_or((false, "managers".to_string()));
    if !has_link {
        return Err(AppError::NotFound(
            "No member list is configured for this server.".into(),
        ));
    }
    let members_allowed = view_permission == "members";

    // 3. Ask the Auth Gateway for guild membership + manager status.
    let (_, is_manager) =
        fetch_guild_permission(&state, &guild_id, session_cookie.value()).await?;

    let (member_ids, ag_guild_name) =
        fetch_guild_members(&state, &guild_id, session_cookie.value()).await?;

    if member_ids.is_empty() {
        return Err(AppError::Forbidden(
            "You must be a member of this server to view its member list.".into(),
        ));
    }

    if !members_allowed && !is_manager {
        tracing::debug!(
            guild_id,
            viewer = %viewer_discord_id,
            "members_data: viewer is a member but not a manager; managers-only policy"
        );
        return Err(AppError::Forbidden(
            "Only server managers can view this member list.".into(),
        ));
    }

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let order_col = query
        .sort
        .as_deref()
        .and_then(sort_column)
        .unwrap_or("wc.last_visit");
    let order_dir = match query.order.as_deref() {
        Some("asc") => "ASC",
        _ => "DESC",
    };

    let search = query.search.as_deref().unwrap_or("").trim();
    let has_search = !search.is_empty();
    let search_pattern = format!("%{search}%");

    let sql = format!(
        "SELECT wc.discord_id, \
                wc.discord_name, \
                wc.country, \
                wc.timezone, \
                wc.utc_offset, \
                wc.language, \
                wc.platform, \
                wc.browser, \
                wc.device_type, \
                wc.visit_count, \
                wc.vpn_detected, \
                wc.vpn_asn_detected, \
                wc.asn_org, \
                wc.spoofing_detected, \
                wc.impossible_travel, \
                wc.account_created_at, \
                wc.first_visit, \
                wc.last_visit, \
                COUNT(*) OVER() AS total_count \
         FROM web_contexts wc \
         WHERE wc.discord_id = ANY($1) {search_clause} \
         ORDER BY {order_col} {order_dir} NULLS LAST \
         LIMIT $2 OFFSET $3",
        search_clause = if has_search {
            "AND (wc.discord_name ILIKE $4 \
             OR wc.discord_id ILIKE $4 \
             OR wc.country ILIKE $4 \
             OR wc.timezone ILIKE $4 \
             OR wc.platform ILIKE $4 \
             OR wc.browser ILIKE $4 \
             OR wc.language ILIKE $4)"
        } else {
            ""
        },
        order_col = order_col,
        order_dir = order_dir,
    );

    use sqlx::Row;
    let rows = if has_search {
        sqlx::query(&sql)
            .bind(&member_ids)
            .bind(per_page)
            .bind(offset)
            .bind(&search_pattern)
            .fetch_all(&state.pool)
            .await?
    } else {
        sqlx::query(&sql)
            .bind(&member_ids)
            .bind(per_page)
            .bind(offset)
            .fetch_all(&state.pool)
            .await?
    };

    let total: i64 = rows.first().map(|r| r.get("total_count")).unwrap_or(0);

    let members: Vec<Value> = rows
        .iter()
        .map(|r| {
            let last_visit: chrono::DateTime<chrono::Utc> = r.get("last_visit");
            let first_visit: chrono::DateTime<chrono::Utc> = r.get("first_visit");
            let account_created_at: Option<chrono::DateTime<chrono::Utc>> =
                r.get("account_created_at");
            json!({
                "discord_id":       r.get::<String, _>("discord_id"),
                "discord_name":     r.get::<Option<String>, _>("discord_name"),
                "country":          r.get::<Option<String>, _>("country"),
                "timezone":         r.get::<Option<String>, _>("timezone"),
                "utc_offset":       r.get::<Option<i32>, _>("utc_offset"),
                "language":         r.get::<Option<String>, _>("language"),
                "platform":         r.get::<Option<String>, _>("platform"),
                "browser":          r.get::<Option<String>, _>("browser"),
                "device_type":      r.get::<Option<String>, _>("device_type"),
                "visit_count":      r.get::<i32, _>("visit_count"),
                "vpn_detected":     r.get::<bool, _>("vpn_detected"),
                "vpn_asn_detected": r.get::<bool, _>("vpn_asn_detected"),
                "asn_org":          r.get::<Option<String>, _>("asn_org"),
                "spoofing_detected":r.get::<bool, _>("spoofing_detected"),
                "impossible_travel":r.get::<bool, _>("impossible_travel"),
                "account_created_at": account_created_at,
                "first_visit":      first_visit,
                "last_visit":       last_visit,
            })
        })
        .collect();

    Ok(Json(json!({
        "members": members,
        "total": total,
        "page": page,
        "per_page": per_page,
        "guild_name": ag_guild_name,
    })))
}
