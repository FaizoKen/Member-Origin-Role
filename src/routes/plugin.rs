use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::Value;

use crate::error::AppError;
use crate::schema;
use crate::services::sync::ConfigSyncEvent;
use crate::AppState;

fn extract_token(headers: &HeaderMap) -> Result<String, AppError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let token = auth.strip_prefix("Token ").ok_or(AppError::Unauthorized)?;
    Ok(token.to_string())
}

#[derive(Deserialize)]
pub struct RegisterBody {
    pub guild_id: String,
    pub role_id: String,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> Result<Json<Value>, AppError> {
    let token = extract_token(&headers)?;

    sqlx::query(
        "INSERT INTO role_links (guild_id, role_id, api_token) VALUES ($1, $2, $3) \
         ON CONFLICT (guild_id, role_id) DO UPDATE SET api_token = $3, updated_at = now()",
    )
    .bind(&body.guild_id)
    .bind(&body.role_id)
    .bind(&token)
    .execute(&state.pool)
    .await?;

    // Ensure a guild_settings row exists so reads always find one.
    // Defaults to 'managers' since member-origin data is sensitive.
    sqlx::query(
        "INSERT INTO guild_settings (guild_id) VALUES ($1) \
         ON CONFLICT (guild_id) DO NOTHING",
    )
    .bind(&body.guild_id)
    .execute(&state.pool)
    .await?;

    tracing::info!(
        guild_id = body.guild_id,
        role_id = body.role_id,
        "Role link registered"
    );

    Ok(Json(serde_json::json!({"success": true})))
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let token = extract_token(&headers)?;

    let link = sqlx::query_as::<_, (String, sqlx::types::Json<crate::models::condition::WebConditions>)>(
        "SELECT guild_id, conditions FROM role_links WHERE api_token = $1",
    )
    .bind(&token)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::Unauthorized)?;

    // view_permission is per-guild, not per-role-link. Default 'managers'
    // when a guild_settings row doesn't yet exist.
    let view_permission: String = sqlx::query_scalar(
        "SELECT view_permission FROM guild_settings WHERE guild_id = $1",
    )
    .bind(&link.0)
    .fetch_optional(&state.pool)
    .await?
    .unwrap_or_else(|| "managers".to_string());

    // Per-guild verify URL. The `?guild=<id>` query param is what the
    // verify page reads to (a) show "Verifying for <Server>" context and
    // (b) auto-clear any existing opt-out so users who previously
    // disabled this server are re-enrolled in one click — no detour
    // through /auth/my_servers, no re-verifying.
    //
    // Guild IDs are Discord snowflakes (digits only) so they're safe to
    // splice directly into the query string without percent-encoding.
    let verify_url = format!("{}/verify?guild={}", state.config.base_url, link.0);
    let members_url = format!("{}/members/{}", state.config.base_url, link.0);
    let schema = schema::build_config_schema(&link.1, &verify_url, &members_url, &view_permission);

    Ok(Json(schema))
}

#[derive(Deserialize)]
pub struct ConfigBody {
    pub guild_id: String,
    pub role_id: String,
    pub config: HashMap<String, Value>,
}

pub async fn post_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<ConfigBody>,
) -> Result<Json<Value>, AppError> {
    let token = extract_token(&headers)?;

    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM role_links WHERE guild_id = $1 AND role_id = $2 AND api_token = $3)",
    )
    .bind(&body.guild_id)
    .bind(&body.role_id)
    .bind(&token)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(false);

    if !exists {
        return Err(AppError::Unauthorized);
    }

    let conditions = schema::parse_config(&body.config)?;

    // Parse view_permission (per-guild). Default 'managers' since member
    // data is sensitive. Validate enum.
    let view_permission = body
        .config
        .get("view_permission")
        .and_then(|v| v.as_str())
        .unwrap_or("managers")
        .to_string();
    if view_permission != "members" && view_permission != "managers" {
        return Err(AppError::BadRequest(
            "view_permission must be 'members' or 'managers'".into(),
        ));
    }

    // Write conditions (per-role) and view_permission (per-guild) together so a
    // partial failure can't leave them out of sync.
    let mut tx = state.pool.begin().await?;

    sqlx::query(
        "UPDATE role_links SET conditions = $1, updated_at = now() \
         WHERE guild_id = $2 AND role_id = $3",
    )
    .bind(sqlx::types::Json(&conditions))
    .bind(&body.guild_id)
    .bind(&body.role_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO guild_settings (guild_id, view_permission, updated_at) \
         VALUES ($1, $2, now()) \
         ON CONFLICT (guild_id) \
         DO UPDATE SET view_permission = EXCLUDED.view_permission, updated_at = now()",
    )
    .bind(&body.guild_id)
    .bind(&view_permission)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(
        guild_id = body.guild_id,
        role_id = body.role_id,
        field = conditions.field,
        view_permission,
        "Config updated"
    );

    let _ = state
        .config_sync_tx
        .send(ConfigSyncEvent {
            guild_id: body.guild_id,
            role_id: body.role_id,
        })
        .await;

    Ok(Json(serde_json::json!({"success": true})))
}

#[derive(Deserialize)]
pub struct DeleteConfigBody {
    pub guild_id: String,
    pub role_id: String,
}

pub async fn delete_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DeleteConfigBody>,
) -> Result<Json<Value>, AppError> {
    let token = extract_token(&headers)?;

    let result = sqlx::query(
        "DELETE FROM role_links WHERE guild_id = $1 AND role_id = $2 AND api_token = $3",
    )
    .bind(&body.guild_id)
    .bind(&body.role_id)
    .bind(&token)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::Unauthorized);
    }

    tracing::info!(
        guild_id = body.guild_id,
        role_id = body.role_id,
        "Role link deleted"
    );

    Ok(Json(serde_json::json!({"success": true})))
}
