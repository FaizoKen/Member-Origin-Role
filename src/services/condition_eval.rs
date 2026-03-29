use crate::models::condition::{ConditionField, ConditionOperator, WebConditions};

/// Fraud flags clear after 7 days of clean visits.
const FRAUD_COOLDOWN_DAYS: i64 = 7;

/// Row data from web_contexts table for in-memory evaluation.
#[derive(Debug, sqlx::FromRow)]
pub struct WebContextRow {
    pub timezone: Option<String>,
    pub utc_offset: Option<i32>,
    pub country: Option<String>,
    pub platform: Option<String>,
    pub browser: Option<String>,
    pub language: Option<String>,
    pub device_type: Option<String>,
    pub vpn_detected: bool,
    pub spoofing_detected: bool,
    pub impossible_travel: bool,
    pub vpn_ever_detected: bool,
    pub spoofing_ever_detected: bool,
    pub impossible_travel_ever_detected: bool,
    pub fraud_clean_since: Option<chrono::DateTime<chrono::Utc>>,
}

/// Check if a persistent "ever" flag is still active (cooldown hasn't expired).
fn fraud_flag_active(ever_detected: bool, fraud_clean_since: Option<chrono::DateTime<chrono::Utc>>) -> bool {
    if !ever_detected {
        return false;
    }
    // If currently dirty (no clean_since), flag is active
    let Some(clean_since) = fraud_clean_since else {
        return true;
    };
    // Flag clears after FRAUD_COOLDOWN_DAYS of clean visits
    let cooldown = chrono::Duration::days(FRAUD_COOLDOWN_DAYS);
    chrono::Utc::now() - clean_since < cooldown
}

/// Evaluate conditions against web context. All enabled checks are AND'd.
/// Uses persistent "ever" flags so fraud detection survives clean revisits.
pub fn evaluate(conditions: &WebConditions, ctx: &WebContextRow) -> bool {
    // Fraud checks first (early exit) — use persistent flags
    if conditions.block_vpn && fraud_flag_active(ctx.vpn_ever_detected, ctx.fraud_clean_since) {
        return false;
    }
    if conditions.block_spoofing && fraud_flag_active(ctx.spoofing_ever_detected, ctx.fraud_clean_since) {
        return false;
    }
    if conditions.block_impossible_travel && fraud_flag_active(ctx.impossible_travel_ever_detected, ctx.fraud_clean_since) {
        return false;
    }

    // Identity condition
    let Some(field) = ConditionField::from_key(&conditions.field) else {
        return true; // no identity condition configured → all pass
    };
    let Some(operator) = ConditionOperator::from_key(&conditions.operator) else {
        return true;
    };

    let actual = match field {
        ConditionField::Timezone => ctx.timezone.as_deref(),
        ConditionField::Country => ctx.country.as_deref(),
        ConditionField::Language => ctx.language.as_deref(),
        ConditionField::Platform => ctx.platform.as_deref(),
        ConditionField::Browser => ctx.browser.as_deref(),
        ConditionField::DeviceType => ctx.device_type.as_deref(),
        ConditionField::UtcOffset => {
            return compare_int(ctx.utc_offset.map(|v| v as i64), &operator, &conditions.value, &conditions.value_end);
        }
    };

    compare_text(actual, &operator, &conditions.value)
}

fn compare_text(actual: Option<&str>, operator: &ConditionOperator, expected: &serde_json::Value) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let expected = expected.as_str().unwrap_or("");
    match operator {
        ConditionOperator::Eq => actual.eq_ignore_ascii_case(expected),
        ConditionOperator::Neq => !actual.eq_ignore_ascii_case(expected),
        _ => false,
    }
}

fn compare_int(actual: Option<i64>, operator: &ConditionOperator, expected: &serde_json::Value, value_end: &Option<serde_json::Value>) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    let expected = expected.as_i64().unwrap_or(0);
    match operator {
        ConditionOperator::Eq => actual == expected,
        ConditionOperator::Neq => actual != expected,
        ConditionOperator::Gt => actual > expected,
        ConditionOperator::Gte => actual >= expected,
        ConditionOperator::Lt => actual < expected,
        ConditionOperator::Lte => actual <= expected,
        ConditionOperator::Between => {
            let end = value_end.as_ref().and_then(|v| v.as_i64()).unwrap_or(expected);
            actual >= expected && actual <= end
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_context() -> WebContextRow {
        WebContextRow {
            timezone: Some("America/New_York".to_string()),
            utc_offset: Some(-300),
            country: Some("US".to_string()),
            platform: Some("Windows".to_string()),
            browser: Some("Chrome".to_string()),
            language: Some("en-US".to_string()),
            device_type: Some("Desktop".to_string()),
            vpn_detected: false,
            spoofing_detected: false,
            impossible_travel: false,
            vpn_ever_detected: false,
            spoofing_ever_detected: false,
            impossible_travel_ever_detected: false,
            fraud_clean_since: None,
        }
    }

    fn cond(field: &str, op: &str, value: serde_json::Value) -> WebConditions {
        WebConditions {
            field: field.to_string(),
            operator: op.to_string(),
            value,
            value_end: None,
            block_vpn: false,
            block_spoofing: false,
            block_impossible_travel: false,
        }
    }

    #[test]
    fn test_country_eq() {
        assert!(evaluate(&cond("country", "eq", json!("US")), &sample_context()));
    }

    #[test]
    fn test_country_case_insensitive() {
        assert!(evaluate(&cond("country", "eq", json!("us")), &sample_context()));
    }

    #[test]
    fn test_country_neq() {
        assert!(evaluate(&cond("country", "neq", json!("JP")), &sample_context()));
    }

    #[test]
    fn test_platform_eq() {
        assert!(evaluate(&cond("platform", "eq", json!("Windows")), &sample_context()));
    }

    #[test]
    fn test_utc_offset_between() {
        let c = WebConditions {
            field: "utcOffset".to_string(),
            operator: "between".to_string(),
            value: json!(-480),
            value_end: Some(json!(-240)),
            block_vpn: false,
            block_spoofing: false,
            block_impossible_travel: false,
        };
        assert!(evaluate(&c, &sample_context()));
    }

    #[test]
    fn test_missing_field_returns_false() {
        let mut ctx = sample_context();
        ctx.country = None;
        assert!(!evaluate(&cond("country", "eq", json!("US")), &ctx));
    }

    #[test]
    fn test_no_condition_always_true() {
        let c = WebConditions::default();
        assert!(evaluate(&c, &sample_context()));
    }

    // --- Fraud toggle tests ---

    #[test]
    fn test_block_vpn_passes_clean() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_vpn = true;
        assert!(evaluate(&c, &sample_context())); // vpn_detected = false → passes
    }

    #[test]
    fn test_block_vpn_blocks_vpn() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_vpn = true;
        let mut ctx = sample_context();
        ctx.vpn_ever_detected = true; // persistent flag, no clean_since → actively blocked
        assert!(!evaluate(&c, &ctx)); // blocked
    }

    #[test]
    fn test_block_vpn_blocks_even_after_clean_visit() {
        // Critical test: user visited with VPN, then visited clean — flag persists during cooldown
        let mut c = cond("country", "eq", json!("US"));
        c.block_vpn = true;
        let mut ctx = sample_context();
        ctx.vpn_detected = false; // current visit is clean
        ctx.vpn_ever_detected = true; // but was detected before
        ctx.fraud_clean_since = Some(chrono::Utc::now()); // just became clean
        assert!(!evaluate(&c, &ctx)); // still blocked — cooldown hasn't expired
    }

    #[test]
    fn test_block_vpn_clears_after_cooldown() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_vpn = true;
        let mut ctx = sample_context();
        ctx.vpn_detected = false;
        ctx.vpn_ever_detected = true;
        // Clean for 8 days (past 7-day cooldown)
        ctx.fraud_clean_since = Some(chrono::Utc::now() - chrono::Duration::days(8));
        assert!(evaluate(&c, &ctx)); // cooldown expired → passes
    }

    #[test]
    fn test_block_tz_mismatch_passes_clean() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_spoofing = true;
        assert!(evaluate(&c, &sample_context())); // ever_detected = false → passes
    }

    #[test]
    fn test_block_tz_mismatch_blocks() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_spoofing = true;
        let mut ctx = sample_context();
        ctx.spoofing_ever_detected = true; // persistent flag
        assert!(!evaluate(&c, &ctx)); // blocked
    }

    #[test]
    fn test_vpn_not_blocked_when_toggle_off() {
        let c = cond("country", "eq", json!("US")); // block_vpn = false
        let mut ctx = sample_context();
        ctx.vpn_ever_detected = true;
        assert!(evaluate(&c, &ctx)); // not blocked because toggle is off
    }

    #[test]
    fn test_all_and_conditions() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_vpn = true;
        c.block_spoofing = true;
        assert!(evaluate(&c, &sample_context())); // all pass
    }

    #[test]
    fn test_and_identity_fails() {
        let mut c = cond("country", "eq", json!("JP")); // wrong country
        c.block_vpn = true;
        c.block_spoofing = true;
        assert!(!evaluate(&c, &sample_context())); // identity fails
    }
}
