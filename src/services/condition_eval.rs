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
    pub spoofing_detected: bool,
    pub impossible_travel: bool,
}

/// Evaluate conditions against web context. All enabled checks are AND'd.
pub fn evaluate(conditions: &WebConditions, ctx: &WebContextRow) -> bool {
    // Fraud checks first (early exit)
    if conditions.block_vpn && ctx.vpn_detected {
        return false;
    }
    if conditions.block_spoofing && ctx.spoofing_detected {
        return false;
    }
    if conditions.block_impossible_travel && ctx.impossible_travel {
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
        ctx.vpn_detected = true;
        assert!(!evaluate(&c, &ctx)); // blocked
    }

    #[test]
    fn test_block_tz_mismatch_passes_clean() {
        let mut c = cond("country", "eq", json!("US"));
        c.block_spoofing = true;
        assert!(evaluate(&c, &sample_context())); // mismatch = false → passes
    }

    #[test]
    fn test_block_tz_mismatch_blocks() {
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
}
