use std::collections::HashSet;

use futures_util::stream::{self, StreamExt};
use sqlx::PgPool;

use crate::error::AppError;
use crate::models::condition::{ConditionField, ConditionOperator, WebConditions};
use crate::services::auth_gateway;
use crate::services::condition_eval::{evaluate, WebContextRow};
use crate::AppState;

/// Events sent to the player sync worker (lightweight, per-user).
#[derive(Debug, Clone)]
pub enum PlayerSyncEvent {
    DataCollected { discord_id: String },
}

/// Events sent to the config sync worker (heavy, per-role-link).
#[derive(Debug, Clone)]
pub struct ConfigSyncEvent {
    pub guild_id: String,
    pub role_id: String,
}

/// Sync roles for a single user across all guilds.
pub async fn sync_for_player(
    discord_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let web_ctx = sqlx::query_as::<_, WebContextRow>(
        "SELECT timezone, utc_offset, country, platform, browser, \
         language, device_type, vpn_detected, spoofing_detected, impossible_travel \
         FROM web_contexts WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_optional(pool)
    .await?;

    let Some(web_ctx) = web_ctx else {
        return Ok(());
    };

    let guild_ids = auth_gateway::fetch_user_guild_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        discord_id,
    )
    .await?;

    if guild_ids.is_empty() {
        return Ok(());
    }

    let role_links = sqlx::query_as::<_, (String, String, String, sqlx::types::Json<WebConditions>)>(
        "SELECT rl.guild_id, rl.role_id, rl.api_token, rl.conditions \
         FROM role_links rl \
         WHERE rl.guild_id = ANY($1)",
    )
    .bind(&guild_ids[..])
    .fetch_all(pool)
    .await?;

    let existing: HashSet<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT guild_id, role_id FROM role_assignments WHERE discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    enum Action {
        Add { guild_id: String, role_id: String, api_token: String },
        Remove { guild_id: String, role_id: String, api_token: String },
    }

    let mut actions: Vec<Action> = Vec::new();
    for (guild_id, role_id, api_token, conditions) in &role_links {
        let qualifies = evaluate(conditions, &web_ctx);
        let currently_assigned = existing.contains(&(guild_id.clone(), role_id.clone()));
        match (qualifies, currently_assigned) {
            (true, false) => actions.push(Action::Add {
                guild_id: guild_id.clone(),
                role_id: role_id.clone(),
                api_token: api_token.clone(),
            }),
            (false, true) => actions.push(Action::Remove {
                guild_id: guild_id.clone(),
                role_id: role_id.clone(),
                api_token: api_token.clone(),
            }),
            _ => {}
        }
    }

    if actions.is_empty() {
        return Ok(());
    }

    let discord_id_owned = discord_id.to_string();
    stream::iter(actions)
        .for_each_concurrent(10, |action| {
            let pool = pool.clone();
            let rl_client = rl_client.clone();
            let discord_id = discord_id_owned.clone();
            async move {
                match action {
                    Action::Add { guild_id, role_id, api_token } => {
                        match rl_client.add_user(&guild_id, &role_id, &discord_id, &api_token).await {
                            Err(AppError::UserLimitReached { limit }) => {
                                tracing::warn!(guild_id, role_id, discord_id, limit, "User limit reached");
                                return;
                            }
                            Err(e) => {
                                tracing::error!(guild_id, role_id, discord_id, "Failed to add user: {e}");
                                return;
                            }
                            Ok(_) => {}
                        }
                        if let Err(e) = sqlx::query(
                            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
                             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                        )
                        .bind(&guild_id).bind(&role_id).bind(&discord_id)
                        .execute(&pool).await {
                            tracing::error!(guild_id, role_id, discord_id, "Failed to insert assignment: {e}");
                        }
                    }
                    Action::Remove { guild_id, role_id, api_token } => {
                        if let Err(e) = rl_client.remove_user(&guild_id, &role_id, &discord_id, &api_token).await {
                            tracing::error!(guild_id, role_id, discord_id, "Failed to remove user: {e}");
                            return;
                        }
                        if let Err(e) = sqlx::query(
                            "DELETE FROM role_assignments WHERE guild_id = $1 AND role_id = $2 AND discord_id = $3",
                        )
                        .bind(&guild_id).bind(&role_id).bind(&discord_id)
                        .execute(&pool).await {
                            tracing::error!(guild_id, role_id, discord_id, "Failed to delete assignment: {e}");
                        }
                    }
                }
            }
        })
        .await;

    Ok(())
}

/// Build SQL WHERE clause from a WebConditions struct.
/// Fraud toggles + identity condition are AND'd together.
fn build_condition_where(conditions: &WebConditions) -> (String, Vec<ConditionBind>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut binds: Vec<ConditionBind> = Vec::new();

    // Fraud toggles — use current-visit flags so roles update immediately when cleared.
    if conditions.block_vpn {
        clauses.push("NOT wc.vpn_detected".to_string());
    }
    if conditions.block_spoofing {
        clauses.push("NOT wc.spoofing_detected".to_string());
    }
    if conditions.block_impossible_travel {
        clauses.push("NOT wc.impossible_travel".to_string());
    }

    // Identity condition
    if let Some(field) = ConditionField::from_key(&conditions.field) {
        if let Some(operator) = ConditionOperator::from_key(&conditions.operator) {
            let col = field.sql_column();

            if field.is_numeric() {
                let val = conditions.value.as_i64().unwrap_or(0);
                if matches!(operator, ConditionOperator::Between) {
                    let end = conditions.value_end.as_ref().and_then(|v| v.as_i64()).unwrap_or(val);
                    let idx_start = binds.len() + 1;
                    let idx_end = binds.len() + 2;
                    clauses.push(format!("{col} >= ${idx_start} AND {col} <= ${idx_end}"));
                    binds.push(ConditionBind::Int(val));
                    binds.push(ConditionBind::Int(end));
                } else {
                    let op = operator.sql_operator();
                    let idx = binds.len() + 1;
                    clauses.push(format!("{col} {op} ${idx}"));
                    binds.push(ConditionBind::Int(val));
                }
            } else {
                // Text/select fields
                let val = conditions.value.as_str().unwrap_or("").to_string();
                let idx = binds.len() + 1;
                match operator {
                    ConditionOperator::Eq => clauses.push(format!("LOWER({col}) = LOWER(${idx})")),
                    ConditionOperator::Neq => clauses.push(format!("LOWER({col}) != LOWER(${idx})")),
                    _ => {}
                }
                binds.push(ConditionBind::Text(val));
            }
        }
    }

    if clauses.is_empty() {
        return ("TRUE".to_string(), vec![]);
    }

    (clauses.join(" AND "), binds)
}

enum ConditionBind {
    Int(i64),
    Text(String),
}

/// Re-evaluate all users for a specific role link (after config change).
pub async fn sync_for_role_link(
    guild_id: &str,
    role_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let link = sqlx::query_as::<_, (String, sqlx::types::Json<WebConditions>)>(
        "SELECT api_token, conditions FROM role_links WHERE guild_id = $1 AND role_id = $2",
    )
    .bind(guild_id)
    .bind(role_id)
    .fetch_optional(pool)
    .await?;

    let Some((api_token, conditions)) = link else {
        return Ok(());
    };

    let member_ids = auth_gateway::fetch_guild_member_ids(
        &state.http,
        &state.config.auth_gateway_url,
        &state.config.internal_api_key,
        guild_id,
    )
    .await?;

    if member_ids.is_empty() {
        rl_client.replace_users(guild_id, role_id, &[], &api_token).await?;
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM role_assignments WHERE guild_id = $1 AND role_id = $2")
            .bind(guild_id).bind(role_id)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(());
    }

    let (_user_count, user_limit) = rl_client
        .get_user_info(guild_id, role_id, &api_token)
        .await
        .unwrap_or((0, 100));

    let (where_clause, binds) = build_condition_where(&conditions);

    let members_bind_idx = binds.len() + 1;
    let limit_bind_idx = binds.len() + 2;
    let query_str = format!(
        "SELECT wc.discord_id \
         FROM web_contexts wc \
         WHERE wc.discord_id = ANY(${members_bind_idx}::text[]) \
           AND ({where_clause}) \
         ORDER BY wc.first_visit ASC \
         LIMIT ${limit_bind_idx}",
    );

    let qualifying_ids = exec_condition_query(&query_str, &binds, &member_ids, user_limit, pool).await?;

    if !qualifying_ids.is_empty() && qualifying_ids.len() == user_limit {
        let count_query = format!(
            "SELECT COUNT(*) FROM web_contexts wc \
             WHERE wc.discord_id = ANY(${members_bind_idx}::text[]) \
               AND ({where_clause})",
        );
        let total: i64 = exec_condition_count(&count_query, &binds, &member_ids, pool)
            .await
            .unwrap_or(qualifying_ids.len() as i64);
        if total as usize > user_limit {
            tracing::warn!(
                guild_id, role_id, total, user_limit,
                "Role link user limit reached: {total} qualify but limit is {user_limit}"
            );
        }
    }

    rl_client
        .replace_users(guild_id, role_id, &qualifying_ids, &api_token)
        .await?;

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_assignments WHERE guild_id = $1 AND role_id = $2")
        .bind(guild_id).bind(role_id)
        .execute(&mut *tx).await?;

    if !qualifying_ids.is_empty() {
        sqlx::query(
            "INSERT INTO role_assignments (guild_id, role_id, discord_id) \
             SELECT $1, $2, UNNEST($3::text[])",
        )
        .bind(guild_id).bind(role_id).bind(&qualifying_ids)
        .execute(&mut *tx).await?;
    }

    tx.commit().await?;
    Ok(())
}

async fn exec_condition_query(
    query: &str,
    binds: &[ConditionBind],
    member_ids: &[String],
    limit: usize,
    pool: &PgPool,
) -> Result<Vec<String>, AppError> {
    let mut q = sqlx::query_scalar::<_, String>(query);
    for bind in binds {
        q = match bind {
            ConditionBind::Int(v) => q.bind(*v),
            ConditionBind::Text(v) => q.bind(v),
        };
    }
    q = q.bind(member_ids);
    q = q.bind(limit as i64);
    Ok(q.fetch_all(pool).await?)
}

async fn exec_condition_count(
    query: &str,
    binds: &[ConditionBind],
    member_ids: &[String],
    pool: &PgPool,
) -> Result<i64, AppError> {
    let mut q = sqlx::query_scalar::<_, i64>(query);
    for bind in binds {
        q = match bind {
            ConditionBind::Int(v) => q.bind(*v),
            ConditionBind::Text(v) => q.bind(v),
        };
    }
    q = q.bind(member_ids);
    Ok(q.fetch_one(pool).await?)
}

pub async fn remove_all_assignments(
    discord_id: &str,
    state: &AppState,
) -> Result<(), AppError> {
    let pool = &state.pool;
    let rl_client = &state.rl_client;

    let assignments = sqlx::query_as::<_, (String, String, String)>(
        "SELECT ra.guild_id, ra.role_id, rl.api_token \
         FROM role_assignments ra \
         JOIN role_links rl ON rl.guild_id = ra.guild_id AND rl.role_id = ra.role_id \
         WHERE ra.discord_id = $1",
    )
    .bind(discord_id)
    .fetch_all(pool)
    .await?;

    for (guild_id, role_id, api_token) in &assignments {
        if let Err(e) = rl_client.remove_user(guild_id, role_id, discord_id, api_token).await {
            tracing::error!(guild_id, role_id, discord_id, "Failed to remove user during cleanup: {e}");
        }
    }

    sqlx::query("DELETE FROM role_assignments WHERE discord_id = $1")
        .bind(discord_id).execute(pool).await?;

    Ok(())
}
