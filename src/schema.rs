use serde_json::{json, Value};
use std::collections::HashMap;

use crate::error::AppError;
use crate::models::condition::{
    canonical_timezone, valid_language_tag, ConditionField, ConditionOperator, WebConditions,
};

pub fn build_config_schema(
    conditions: &WebConditions,
    verify_url: &str,
    members_url: &str,
    view_permission: &str,
) -> Value {
    // Populate current values for the form
    let mut values: HashMap<String, Value> = HashMap::new();
    values.insert("field".into(), json!(conditions.field));
    // Only the operator key the saved field uses gets the saved operator. The
    // other keeps its schema default: the dashboard lets a value override a
    // default, so an empty or foreign operator here (a fresh link has "") would
    // show "Select…" and fail validation the moment the admin picks a field.
    let field = ConditionField::from_key(&conditions.field);
    let op = ConditionOperator::from_key(&conditions.operator);
    match (&field, &op) {
        (Some(f), Some(_)) if f.is_numeric() => {
            values.insert("operator".into(), json!(conditions.operator));
        }
        (Some(f), Some(ConditionOperator::Eq | ConditionOperator::Neq))
            if *f != ConditionField::Any =>
        {
            values.insert("operator_text".into(), json!(conditions.operator));
        }
        _ => {}
    }
    values.insert("block_vpn".into(), json!(conditions.block_vpn));
    values.insert("block_spoofing".into(), json!(conditions.block_spoofing));
    values.insert(
        "block_impossible_travel".into(),
        json!(conditions.block_impossible_travel),
    );
    values.insert(
        "min_account_age_days".into(),
        json!(conditions.min_account_age_days),
    );
    values.insert("anonymous_mode".into(), json!(conditions.anonymous_mode));
    values.insert("invert".into(), json!(conditions.invert));
    values.insert("view_permission".into(), json!(view_permission));

    // Populate value for the specific field type
    if field.as_ref().is_some_and(|f| *f != ConditionField::Any) {
        let value_key = format!("value_{}", conditions.field);
        values.insert(value_key, conditions.value.clone());

        if conditions.operator == "between" {
            if let Some(end) = &conditions.value_end {
                let end_key = format!("value_end_{}", conditions.field);
                values.insert(end_key, end.clone());
            }
        }
    }

    json!({
        "version": 1,
        "name": "Member Origin Role",
        "description": "Assign Discord roles based on visitor identity and location.",
        "sections": [
            {
                "title": "Getting Started",
                "fields": [
                    {
                        "type": "display",
                        "key": "info",
                        "label": "How it works",
                        "value": format!(
                            "Share this link with members:\n\
                             {verify_url}\n\
                             \n\
                             They sign in \u{2192} their origin is detected \u{2192} matching members get the role.\n\
                             \n\
                             View collected data:\n\
                             {members_url}"
                        )
                    }
                ]
            },
            {
                "title": "Identity Condition",
                "description": "Set the requirement a visitor must meet to earn this role.",
                "fields": [
                    {
                        "type": "select",
                        "key": "field",
                        "label": "Identity field",
                        "description": "Which visitor attribute to check. \"Anyone who verifies\" checks none: everyone who opens the link gets the role, as long as they pass the Anti-Fraud checks you turn on below.",
                        "validation": { "required": true },
                        "options": [
                            {"label": "Anyone who verifies", "value": "any"},
                            {"label": "Country (from IP)", "value": "country"},
                            {"label": "Timezone (IANA)", "value": "timezone"},
                            {"label": "UTC Offset (minutes)", "value": "utcOffset"},
                            {"label": "Platform (OS)", "value": "platform"},
                            {"label": "Browser", "value": "browser"},
                            {"label": "Language", "value": "language"},
                            {"label": "Device Type", "value": "deviceType"}
                        ]
                    },
                    // Operator for numeric fields (utcOffset) — full comparison set
                    {
                        "type": "select",
                        "key": "operator",
                        "label": "Comparison",
                        "default_value": "gte",
                        "condition": { "field": "field", "equals": "utcOffset" },
                        "options": [
                            {"label": "= equals", "value": "eq"},
                            {"label": "\u{2265} at least", "value": "gte"},
                            {"label": "\u{2264} at most", "value": "lte"},
                            {"label": "\u{2194} between (range)", "value": "between"}
                        ]
                    },
                    // Operator for text/select fields — equals or not equals only
                    {
                        "type": "select",
                        "key": "operator_text",
                        "label": "Comparison",
                        "default_value": "eq",
                        "condition": { "field": "field", "equals_any": [
                            "country", "timezone", "platform", "browser", "language", "deviceType"
                        ]},
                        "options": [
                            {"label": "= equals", "value": "eq"},
                            {"label": "\u{2260} not equals", "value": "neq"}
                        ]
                    },
                    // Country
                    {
                        "type": "text",
                        "key": "value_country",
                        "label": "Country Code",
                        "description": "ISO 3166-1 alpha-2 code, e.g. US, GB, MY, JP, DE, BR",
                        "validation": { "required": true, "min": 2, "max": 2, "pattern": "^[A-Za-z]{2}$", "pattern_message": "Enter a 2-letter country code (e.g. US, GB, JP)" },
                        "condition": { "field": "field", "equals": "country" }
                    },
                    // Timezone
                    {
                        "type": "text",
                        "key": "value_timezone",
                        "label": "Timezone",
                        "description": "IANA timezone name, e.g. America/New_York, Europe/London, Asia/Tokyo. Older names that browsers still report (Asia/Calcutta for Asia/Kolkata, Europe/Kiev for Europe/Kyiv) match too.",
                        "validation": { "required": true },
                        "condition": { "field": "field", "equals": "timezone" }
                    },
                    // Platform
                    {
                        "type": "select",
                        "key": "value_platform",
                        "label": "Platform",
                        "condition": { "field": "field", "equals": "platform" },
                        "options": [
                            {"label": "Windows", "value": "Windows"},
                            {"label": "macOS", "value": "macOS"},
                            {"label": "Linux", "value": "Linux"},
                            {"label": "Android", "value": "Android"},
                            {"label": "iOS", "value": "iOS"},
                            {"label": "ChromeOS", "value": "ChromeOS"}
                        ]
                    },
                    // Browser
                    {
                        "type": "select",
                        "key": "value_browser",
                        "label": "Browser",
                        "condition": { "field": "field", "equals": "browser" },
                        "options": [
                            {"label": "Chrome", "value": "Chrome"},
                            {"label": "Firefox", "value": "Firefox"},
                            {"label": "Safari", "value": "Safari"},
                            {"label": "Edge", "value": "Edge"},
                            {"label": "Opera", "value": "Opera"}
                        ]
                    },
                    // Device Type
                    {
                        "type": "select",
                        "key": "value_deviceType",
                        "label": "Device Type",
                        "condition": { "field": "field", "equals": "deviceType" },
                        "options": [
                            {"label": "Desktop", "value": "Desktop"},
                            {"label": "Mobile", "value": "Mobile"},
                            {"label": "Tablet", "value": "Tablet"}
                        ]
                    },
                    // Language
                    {
                        "type": "text",
                        "key": "value_language",
                        "label": "Language",
                        "description": "The browser's first language, as a BCP 47 tag. A tag without a region matches every region: en matches en-US and en-GB, while en-US matches only US English. e.g. en, en-US, ja, fr, zh-CN",
                        "validation": { "required": true, "pattern": "^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$", "pattern_message": "Enter a language tag such as en, en-US or ja (a hyphen, not an underscore)" },
                        "condition": { "field": "field", "equals": "language" }
                    },
                    // UTC Offset
                    {
                        "type": "number",
                        "key": "value_utcOffset",
                        "label": "UTC Offset (minutes)",
                        "description": "e.g. -300 for EST (UTC-5), 0 for UTC, 540 for JST (UTC+9)",
                        "validation": { "required": true, "min": -720, "max": 840 },
                        "condition": { "field": "field", "equals": "utcOffset" }
                    },
                    {
                        "type": "number",
                        "key": "value_end_utcOffset",
                        "label": "UTC Offset (end)",
                        "validation": { "required": true, "min": -720, "max": 840 },
                        "pair_with": "value_utcOffset",
                        "conditions": [
                            { "field": "field", "equals": "utcOffset" },
                            { "field": "operator", "equals": "between" }
                        ]
                    }
                ]
            },
            {
                "title": "Silent Verification",
                "description": "Quick verify mode for admins who want to confirm a member's identity without showing them what was collected. Default: ON.",
                "fields": [
                    {
                        "type": "toggle",
                        "key": "anonymous_mode",
                        "label": "Anonymous mode",
                        "default_value": true,
                        "description": "When ON (default), the verify page shows only a generic 'You're all set' message — no country, timezone, browser, or other detected data is shown back to the user. The page also auto-redirects to Discord login immediately (no 'Sign in' button to click), so the flow is one click: member opens the link, signs in, done. Detection and role assignment work exactly the same; only the UI changes. Turn OFF to show members what was detected. It applies to this server's link: if any of its role links turns it off, members see what was detected."
                    }
                ]
            },
            {
                "title": "Anti-Fraud",
                "description": "Block suspicious visitors. These checks are AND'd with the identity condition above.",
                "fields": [
                    {
                        "type": "toggle",
                        "key": "block_vpn",
                        "label": "Block VPN / Proxy",
                        "description": "Reject users whose IP country doesn't match their browser timezone (the classic VPN fingerprint), Tor exit nodes, AND any IP flagged as a known VPN / datacenter / proxy by the ASN reputation lookup. The ASN check catches same-country commercial VPNs (NordVPN, ExpressVPN, etc.) that the timezone heuristic misses."
                    },
                    {
                        "type": "toggle",
                        "key": "block_spoofing",
                        "label": "Block Spoofed Identity",
                        "description": "Reject users with inconsistent data: timezone offset doesn't match timezone name (DST-aware), offset doesn't match IP country, impossible browser/platform combos (e.g. Safari on Linux), or timezone doesn't match country."
                    },
                    {
                        "type": "toggle",
                        "key": "block_impossible_travel",
                        "label": "Block Impossible Travel",
                        "description": "Reject users whose IP country changed faster than physically possible between visits (e.g. US to Japan in 1 hour). Requires at least 2 visits to detect."
                    },
                    {
                        "type": "number",
                        "key": "min_account_age_days",
                        "label": "Minimum Discord account age (days)",
                        "description": "Reject Discord accounts younger than this many days. Account creation time is decoded from the Discord user ID (no API call). Useful against alt farms and freshly-minted accounts. A member who is too new gets the role automatically once their account is old enough. 0 = no minimum.",
                        "default_value": 0,
                        "validation": { "min": 0, "max": 3650 }
                    }
                ]
            },
            {
                "title": "Flip the Rule",
                "description": "Give the role to the members this rule turns away, instead of the ones it lets through.",
                "fields": [
                    {
                        "type": "toggle",
                        "key": "invert",
                        "label": "Give the role to members who don't match",
                        "default_value": false,
                        "description": "For a Needs Review role: choose \"Anyone who verifies\", turn on the Anti-Fraud checks above, then flip it. Members a check flags (a VPN, spoofed details, impossible travel, an account too new) get the role; everyone else doesn't. Only members who opened the link are checked."
                    }
                ]
            },
            {
                "title": "Member List Access",
                "description": "Control who can view the collected member data for this server. This setting is shared across the entire server \u{2014} changing it from any role link's config updates it for every role link in this server.",
                "fields": [
                    {
                        "type": "radio",
                        "key": "view_permission",
                        "label": "Who can view the member list",
                        "description": "Applies server-wide. Default: Server managers only (recommended, since member origin data is sensitive).",
                        "default_value": "managers",
                        "options": [
                            {"label": "Server managers only (requires Manage Server permission)", "value": "managers"},
                            {"label": "Server members (anyone in this server)", "value": "members"}
                        ]
                    }
                ]
            },
            {
                "title": "Examples",
                "collapsible": true,
                "default_collapsed": true,
                "fields": [
                    {
                        "type": "display",
                        "key": "examples",
                        "label": "Common setups",
                        "value": "**Region roles**\nCountry = JP \u{2192} members connecting from Japan\nTimezone = Europe/London \u{2192} UK time\nUTC Offset between -600 to -180 \u{2192} the Americas\nUTC Offset between -60 to 240 \u{2192} Europe, Africa & the Middle East\nUTC Offset between 300 to 780 \u{2192} Asia-Pacific\n\n**Language roles**\nLanguage = ja \u{2192} Japanese browsers\nLanguage = es \u{2192} every Spanish (es-ES, es-MX, es-419)\n\n**Platform & device roles**\nDevice Type = Mobile \u{2192} phones\nPlatform = iOS \u{2192} iPhones and iPads\n\n**Verification & safety**\nAnyone who verifies + Block VPN + 30-day minimum \u{2192} a Verified role\nCountry = US + Block VPN \u{2192} real US connections only\nThe Verified setup, flipped \u{2192} a Needs Review role for flagged members"
                    }
                ]
            }
        ],
        "values": values
    })
}

pub fn parse_config(config: &HashMap<String, Value>) -> Result<WebConditions, AppError> {
    let field_key = config.get("field").and_then(|v| v.as_str()).unwrap_or("");

    if field_key.is_empty() {
        return Err(AppError::BadRequest("Field is required".into()));
    }

    let field = ConditionField::from_key(field_key)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid field '{field_key}'")))?;

    // "Anyone who verifies" has no comparison and no value.
    let (operator, value, value_end) = if field == ConditionField::Any {
        (String::new(), Value::Null, None)
    } else {
        parse_identity(&field, field_key, config)?
    };

    toggles(config, field_key, operator, value, value_end)
}

/// The comparison and value(s) of an identity condition.
fn parse_identity(
    field: &ConditionField,
    field_key: &str,
    config: &HashMap<String, Value>,
) -> Result<(String, Value, Option<Value>), AppError> {
    // Numeric fields use "operator" key, text/select fields use "operator_text" key
    let op_key = if field.is_numeric() {
        config
            .get("operator")
            .and_then(|v| v.as_str())
            .unwrap_or("gte")
    } else {
        config
            .get("operator_text")
            .and_then(|v| v.as_str())
            .unwrap_or("eq")
    };

    let operator = ConditionOperator::from_key(op_key)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid operator '{op_key}'")))?;

    // Non-numeric fields only support eq/neq
    if !field.is_numeric() && !matches!(operator, ConditionOperator::Eq | ConditionOperator::Neq) {
        return Err(AppError::BadRequest(
            "Only '= equals' and '\u{2260} not equals' are supported for this field".into(),
        ));
    }

    // Parse value
    let specific_key = format!("value_{field_key}");
    let raw_value = config.get(&specific_key).or_else(|| config.get("value"));

    let value = if field.is_numeric() {
        let n = raw_value
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
            })
            .ok_or_else(|| {
                AppError::BadRequest(format!("Value must be a number for '{field_key}'"))
            })?;
        json!(n)
    } else if field.is_select() {
        let s = raw_value.and_then(|v| v.as_str()).unwrap_or("");
        if s.is_empty() {
            return Err(AppError::BadRequest("Value is required".into()));
        }
        validate_select_value(field, s)?;
        json!(s)
    } else {
        let s = raw_value.and_then(|v| v.as_str()).unwrap_or("").trim();
        if s.is_empty() {
            return Err(AppError::BadRequest("Value is required".into()));
        }
        match field {
            ConditionField::Country => json!(s.to_uppercase()),
            // A typo would match nobody: only names the timezone database
            // knows, spelled its way ("asia/tokyo" → "Asia/Tokyo").
            ConditionField::Timezone => json!(canonical_timezone(s).ok_or_else(|| {
                AppError::BadRequest(format!(
                    "Unknown timezone '{s}'. Use an IANA name such as America/New_York or Asia/Tokyo"
                ))
            })?),
            ConditionField::Language => {
                if !valid_language_tag(s) {
                    return Err(AppError::BadRequest(format!(
                        "'{s}' is not a language tag. Use one such as en, en-US or ja"
                    )));
                }
                json!(s)
            }
            _ => json!(s),
        }
    };

    // Parse between end value
    let value_end = if matches!(operator, ConditionOperator::Between) {
        let end_key = format!("value_end_{field_key}");
        let raw_end = config.get(&end_key).or_else(|| config.get("value_end"));
        let n = raw_end
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
            })
            .ok_or_else(|| {
                AppError::BadRequest("End value is required for between operator".into())
            })?;
        let end_val = json!(n);
        if let (Some(start), Some(end)) = (value.as_i64(), end_val.as_i64()) {
            if start > end {
                return Err(AppError::BadRequest(
                    "Start value must be less than or equal to end value".into(),
                ));
            }
        }
        Some(end_val)
    } else {
        None
    };

    Ok((op_key.to_string(), value, value_end))
}

/// The fraud checks, silent mode and the flip, around a parsed condition.
fn toggles(
    config: &HashMap<String, Value>,
    field_key: &str,
    operator: String,
    value: Value,
    value_end: Option<Value>,
) -> Result<WebConditions, AppError> {
    // Parse fraud toggles
    let block_vpn = config
        .get("block_vpn")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let block_spoofing = config
        .get("block_spoofing")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let block_impossible_travel = config
        .get("block_impossible_travel")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let min_account_age_days = config
        .get("min_account_age_days")
        .and_then(|v| {
            v.as_i64()
                .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
        })
        .unwrap_or(0)
        .clamp(0, 3650) as i32;
    let anonymous_mode = config
        .get("anonymous_mode")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let invert = config
        .get("invert")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Ok(WebConditions {
        field: field_key.to_string(),
        operator,
        value,
        value_end,
        block_vpn,
        block_spoofing,
        block_impossible_travel,
        min_account_age_days,
        anonymous_mode,
        invert,
    })
}

fn validate_select_value(field: &ConditionField, value: &str) -> Result<(), AppError> {
    let valid = match field {
        ConditionField::Platform => {
            ["Windows", "macOS", "Linux", "Android", "iOS", "ChromeOS"].contains(&value)
        }
        ConditionField::Browser => {
            ["Chrome", "Firefox", "Safari", "Edge", "Opera"].contains(&value)
        }
        ConditionField::DeviceType => ["Desktop", "Mobile", "Tablet"].contains(&value),
        _ => true,
    };
    if !valid {
        return Err(AppError::BadRequest(format!("Invalid value '{value}'")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn a_fresh_link_keeps_the_comparison_defaults() {
        // A new link's conditions are empty: neither operator key may carry
        // its "" over the schema's default, or the dashboard shows "Select…"
        // and rejects the first save.
        let schema = build_config_schema(&WebConditions::default(), "v", "m", "managers");
        let values = schema["values"].as_object().unwrap();
        assert!(!values.contains_key("operator"));
        assert!(!values.contains_key("operator_text"));
    }

    #[test]
    fn a_saved_operator_lands_on_its_own_key() {
        let mut c = WebConditions {
            field: "country".into(),
            operator: "neq".into(),
            value: json!("JP"),
            ..Default::default()
        };
        let v = build_config_schema(&c, "v", "m", "managers")["values"].clone();
        assert_eq!(v["operator_text"], json!("neq"));
        assert!(v.get("operator").is_none());
        assert_eq!(v["value_country"], json!("JP"));

        c.field = "utcOffset".into();
        c.operator = "between".into();
        c.value = json!(-600);
        c.value_end = Some(json!(-180));
        let v = build_config_schema(&c, "v", "m", "managers")["values"].clone();
        assert_eq!(v["operator"], json!("between"));
        assert!(v.get("operator_text").is_none());
        assert_eq!(v["value_end_utcOffset"], json!(-180));
    }

    #[test]
    fn the_first_save_needs_no_comparison_pick() {
        // What the dashboard submits for a fresh link after picking Country
        // and typing a code: operator_text holds its schema default "eq".
        let c = parse_config(&cfg(&[
            ("field", json!("country")),
            ("operator_text", json!("eq")),
            ("value_country", json!("jp")),
        ]))
        .unwrap();
        assert_eq!((c.operator.as_str(), c.value.clone()), ("eq", json!("JP")));
    }

    #[test]
    fn anyone_needs_no_value() {
        let c = parse_config(&cfg(&[
            ("field", json!("any")),
            ("block_vpn", json!(true)),
            ("min_account_age_days", json!(30)),
            ("invert", json!(true)),
        ]))
        .unwrap();
        assert_eq!(c.field, "any");
        assert_eq!(c.operator, "");
        assert!(c.value.is_null() && c.block_vpn && c.invert);
        assert_eq!(c.min_account_age_days, 30);
    }

    #[test]
    fn timezones_are_checked_and_spelled_like_the_database() {
        let c = parse_config(&cfg(&[
            ("field", json!("timezone")),
            ("operator_text", json!("eq")),
            ("value_timezone", json!(" asia/tokyo ")),
        ]))
        .unwrap();
        assert_eq!(c.value, json!("Asia/Tokyo"));
        assert!(parse_config(&cfg(&[
            ("field", json!("timezone")),
            ("operator_text", json!("eq")),
            ("value_timezone", json!("Asia/Tokio")),
        ]))
        .is_err());
    }

    #[test]
    fn language_tags_are_checked() {
        let ok = cfg(&[("field", json!("language")), ("operator_text", json!("eq")), ("value_language", json!("en"))]);
        assert_eq!(parse_config(&ok).unwrap().value, json!("en"));
        let bad = cfg(&[("field", json!("language")), ("operator_text", json!("eq")), ("value_language", json!("en_US"))]);
        assert!(parse_config(&bad).is_err());
    }
}
