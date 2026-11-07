//! Re-checks members whose Discord account has just grown old enough.
//!
//! "Minimum Discord account age" is the one check that changes with time
//! alone: a member who verified at 5 days old against a 30-day minimum
//! passes on day 30 without doing anything. Nothing else would look at them
//! again — roles are worked out when a member opens the verify link and when
//! an admin saves the settings — so once an hour this finds every member
//! whose account crossed one of the configured minimums since the last
//! sweep and re-syncs just them (`sync_for_player`, which adds or removes
//! only what changed, so a flipped "Needs Review" rule drops them too).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::services::sync::PlayerSyncEvent;
use crate::AppState;

const SWEEP_EVERY: Duration = Duration::from_secs(60 * 60);
/// After a restart, catch up on crossings this far back.
const START_LOOKBACK_HOURS: i64 = 48;

pub async fn run(state: Arc<AppState>) {
    tracing::info!("Account-age re-check worker started");
    let mut since: DateTime<Utc> = Utc::now() - chrono::Duration::hours(START_LOOKBACK_HOURS);
    let mut tick = tokio::time::interval(SWEEP_EVERY);
    loop {
        tick.tick().await;
        let now = Utc::now();
        match crossed(&state, since, now).await {
            Ok(ids) => {
                if !ids.is_empty() {
                    tracing::info!(
                        members = ids.len(),
                        "Re-syncing members whose account reached a minimum age"
                    );
                }
                for discord_id in ids {
                    let _ = state
                        .player_sync_tx
                        .send(PlayerSyncEvent::DataCollected { discord_id })
                        .await;
                }
                since = now;
            }
            // Keep `since`: the next sweep covers this window too.
            Err(e) => tracing::error!("Account-age sweep failed: {e}"),
        }
    }
}

/// Members whose account age reached a configured minimum in (since, now].
async fn crossed(
    state: &AppState,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT wc.discord_id \
         FROM web_contexts wc \
         JOIN (SELECT DISTINCT \
                 CASE WHEN (conditions->>'min_account_age_days') ~ '^[0-9]+$' \
                      THEN (conditions->>'min_account_age_days')::int END AS days \
               FROM role_links) m \
           ON m.days > 0 \
          AND wc.account_created_at + make_interval(days => m.days) > $1 \
          AND wc.account_created_at + make_interval(days => m.days) <= $2",
    )
    .bind(since)
    .bind(now)
    .fetch_all(&state.pool)
    .await
}
