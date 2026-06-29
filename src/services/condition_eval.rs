use chrono::{DateTime, Utc};

use crate::models::condition::{ConditionField, ConditionOperator, WebConditions};

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
    pub vpn_asn_detected: bool,
    pub spoofing_detected: bool,
    pub impossible_travel: bool,
    pub account_created_at: Option<DateTime<Utc>>,
}

/// Evaluate conditions against web context. All enabled checks are AND'd.
/// Fraud checks use current-visit flags so roles update immediately when the issue clears.
pub fn evaluate(conditions: &WebConditions, ctx: &WebContextRow) -> bool {
    // Unconfigured (no identity, no fraud checks) → grant to nobody.
    let has_identity = ConditionField::from_key(&conditions.field).is_some();
    let has_fraud = conditions.block_vpn
        || conditions.block_spoofing
        || conditions.block_impossible_travel
        || conditions.min_account_age_days > 0;
    if !has_identity && !has_fraud {
        return false;
    }

    // Fraud checks first (early exit) — use current flags.
    // block_vpn covers both the timezone-mismatch heuristic AND the ASN lookup
    // so admins keep a single toggle for "no proxies."
    if conditions.block_vpn && (ctx.vpn_detected || ctx.vpn_asn_detected) {
        return false;
    }
    if conditions.block_spoofing && ctx.spoofing_detected {
        return false;
    }
    if conditions.block_impossible_travel && ctx.impossible_travel {
        return false;
    }
    if conditions.min_account_age_days > 0 {
        let Some(created) = ctx.account_created_at else {
            return false; // unknown age + a minimum was set → deny
        };
        let age_days = (Utc::now() - created).num_days();
        if age_days < conditions.min_account_age_days as i64 {
            return false;
        }
    }

    // Identity condition
    let Some(field) = ConditionField::from_key(&conditions.field) else {
        return true; // no identity condition, but fraud checks configured and passed
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
            return compare_int(
                ctx.utc_offset.map(|v| v as i64),
                &operator,
                &conditions.value,
                &conditions.value_end,
            );
        }
    };

    compare_text(actual, &operator, &conditions.value)
}

fn compare_text(
    actual: Option<&str>,
    operator: &ConditionOperator,
    expected: &serde_json::Value,
) -> bool {
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

fn compare_int(
    actual: Option<i64>,
    operator: &ConditionOperator,
    expected: &serde_json::Value,
    value_end: &Option<serde_json::Value>,
) -> bool {
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
            let end = value_end
                .as_ref()
                .and_then(|v| v.as_i64())
                .unwrap_or(expected);
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
            vpn_asn_detected: false,
            spoofing_detected: false,
            impossible_travel: false,
            // Anything older than ~2 years so age-gate tests with reasonable
            // thresholds pass without being flaky.
            account_created_at: Some(Utc::now() - chrono::Duration::days(1000)),
        }
    }

    fn cond(field: &str, op: &str, value: serde_json::Value) -> WebConditions {
        WebConditions {
            field: field.to_string(),
            operator: op.to_string(),
            value,
            value_end: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_country_eq() {
        assert!(evaluate(
            &cond("country", "eq", json!("US")),
            &sample_context()
        ));
    }

    #[test]
    fn test_country_case_insensitive() {
        assert!(evaluate(
            &cond("country", "eq", json!("us")),
            &sample_context()
        ));
    }

    #[test]
    fn test_country_neq() {
        assert!(evaluate(
            &cond("country", "neq", json!("JP")),
            &sample_context()
        ));
    }

    #[test]
    fn test_platform_eq() {
        assert!(evaluate(
            &cond("platform", "eq", json!("Windows")),
            &sample_context()
        ));
    }

    #[test]
    fn test_utc_offset_between() {
        let c = WebConditions {
            field: "utcOffset".to_string(),
            operator: "between".to_string(),
            value: json!(-480),
            value_end: Some(json!(-240)),
            ..Default::default()
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
    fn test_unconfigured_grants_to_nobody() {
        // No identity field and no fraud checks → deny (documented behavior:
        // "Unconfigured → grant to nobody"). The old name/assertion was stale.
        let c = WebConditions::default();
        assert!(!evaluate(&c, &sample_context()));
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
        ctx.vpn_detected = true;
        assert!(!evaluate(&c, &ctx)); // blocked
    }

    #[test]
    fn test_block_vpn_passes_when_vpn_off() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_vpn = true;
        let mut ctx = sample_context();
        ctx.vpn_detected = false; // VPN off → passes immediately
        assert!(evaluate(&c, &ctx));
    }

    #[test]
    fn test_block_spoofing_passes_clean() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_spoofing = true;
        assert!(evaluate(&c, &sample_context())); // spoofing_detected = false → passes
    }

    #[test]
    fn test_block_spoofing_blocks() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_spoofing = true;
        let mut ctx = sample_context();
        ctx.spoofing_detected = true;
        assert!(!evaluate(&c, &ctx)); // blocked
    }

    #[test]
    fn test_vpn_not_blocked_when_toggle_off() {
        let c = cond("country", "eq", json!("US")); // block_vpn = false
        let mut ctx = sample_context();
        ctx.vpn_detected = true;
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

    // --- Advanced fraud tests ---

    #[test]
    fn test_block_vpn_catches_asn_only() {
        // VPN heuristic clean but ASN flagged → still blocked when block_vpn=true.
        let mut c = cond("country", "eq", json!("US"));
        c.block_vpn = true;
        let mut ctx = sample_context();
        ctx.vpn_detected = false;
        ctx.vpn_asn_detected = true;
        assert!(!evaluate(&c, &ctx));
    }

    #[test]
    fn test_asn_flag_ignored_when_toggle_off() {
        let c = cond("country", "eq", json!("US")); // block_vpn = false
        let mut ctx = sample_context();
        ctx.vpn_asn_detected = true;
        assert!(evaluate(&c, &ctx));
    }

    #[test]
    fn test_account_age_passes_when_old_enough() {
        let mut c = cond("country", "eq", json!("US"));
        c.min_account_age_days = 30;
        assert!(evaluate(&c, &sample_context())); // sample is 1000 days old
    }

    #[test]
    fn test_account_age_blocks_when_too_new() {
        let mut c = cond("country", "eq", json!("US"));
        c.min_account_age_days = 30;
        let mut ctx = sample_context();
        ctx.account_created_at = Some(Utc::now() - chrono::Duration::days(5));
        assert!(!evaluate(&c, &ctx));
    }

    #[test]
    fn test_account_age_unknown_blocks_when_required() {
        let mut c = cond("country", "eq", json!("US"));
        c.min_account_age_days = 30;
        let mut ctx = sample_context();
        ctx.account_created_at = None;
        assert!(!evaluate(&c, &ctx));
    }

    #[test]
    fn test_account_age_unknown_passes_when_disabled() {
        let c = cond("country", "eq", json!("US")); // min = 0
        let mut ctx = sample_context();
        ctx.account_created_at = None;
        assert!(evaluate(&c, &ctx));
    }
}
