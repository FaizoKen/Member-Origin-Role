use serde_json::{json, Value};
use std::collections::HashMap;

use crate::error::AppError;
use crate::models::condition::{ConditionField, ConditionOperator, WebConditions};

pub fn build_config_schema(conditions: &WebConditions, verify_url: &str) -> Value {
    // Populate current values for the form
    let mut values: HashMap<String, Value> = HashMap::new();
    values.insert("field".into(), json!(conditions.field));
    // Populate both operator keys so the correct one shows the saved value
    values.insert("operator".into(), json!(conditions.operator));
    values.insert("operator_text".into(), json!(conditions.operator));
    values.insert("block_vpn".into(), json!(conditions.block_vpn));
    values.insert("block_spoofing".into(), json!(conditions.block_spoofing));
    values.insert("block_impossible_travel".into(), json!(conditions.block_impossible_travel));

    // Populate value for the specific field type
    if !conditions.field.is_empty() {
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
                            "This plugin assigns a Discord role based on visitor identity \
                             detected when members visit your verification page.\n\
                             \n\
                             Step 1 \u{2192} Members visit and sign in with Discord at:\n\
                             {verify_url}\n\
                             \n\
                             Step 2 \u{2192} Their identity is automatically detected from both \
                             browser APIs and HTTP headers (timezone, country, platform, \
                             language, device type, etc.).\n\
                             \n\
                             Step 3 \u{2192} Configure a condition and anti-fraud settings below.\n\
                             \n\
                             Step 4 \u{2192} Any member whose identity matches gets this role \
                             automatically. Data updates each time they revisit."
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
                        "description": "Which visitor attribute to check.",
                        "validation": { "required": true },
                        "options": [
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
                        "description": "IANA timezone, e.g. America/New_York, Europe/London, Asia/Tokyo",
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
                        "description": "BCP 47 language tag, e.g. en, en-US, ja, fr-FR, zh-CN",
                        "condition": { "field": "field", "equals": "language" }
                    },
                    // UTC Offset
                    {
                        "type": "number",
                        "key": "value_utcOffset",
                        "label": "UTC Offset (minutes)",
                        "description": "e.g. -300 for EST (UTC-5), 0 for UTC, 540 for JST (UTC+9)",
                        "validation": { "min": -720, "max": 840 },
                        "condition": { "field": "field", "equals": "utcOffset" }
                    },
                    {
                        "type": "number",
                        "key": "value_end_utcOffset",
                        "label": "UTC Offset (end)",
                        "validation": { "min": -720, "max": 840 },
                        "pair_with": "value_utcOffset",
                        "conditions": [
                            { "field": "field", "equals": "utcOffset" },
                            { "field": "operator", "equals": "between" }
                        ]
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
                        "description": "Reject users whose IP country doesn't match their browser timezone (the classic VPN fingerprint), and Tor exit nodes. Catches NordVPN, ExpressVPN, etc. when connecting to a different country."
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
                        "value": "**Region-based roles**\nCountry = US  \u{2192}  US visitors only\nCountry = JP  \u{2192}  Japan visitors\nTimezone = Europe/London  \u{2192}  UK timezone members\nUTC Offset between -300 to -240  \u{2192}  US Eastern / Atlantic\n\n**Platform & device roles**\nPlatform = Android  \u{2192}  Android users\nDevice Type = Mobile  \u{2192}  Mobile visitors\nBrowser = Firefox  \u{2192}  Firefox users\n\n**Language-based roles**\nLanguage = ja  \u{2192}  Japanese speakers\nLanguage = en-US  \u{2192}  US English speakers\n\n**Anti-fraud (toggle ON above to enforce)**\nCountry = US + Block VPN  \u{2192}  Real US IPs only\nCountry = JP + Block Timezone Mismatch  \u{2192}  Japan IP with matching timezone\nBoth toggles ON  \u{2192}  Maximum fraud protection"
                    }
                ]
            }
        ],
        "values": values
    })
}

pub fn parse_config(config: &HashMap<String, Value>) -> Result<WebConditions, AppError> {
    let field_key = config
        .get("field")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if field_key.is_empty() {
        return Err(AppError::BadRequest("Field is required".into()));
    }

    let field = ConditionField::from_key(field_key)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid field '{field_key}'")))?;

    // Numeric fields use "operator" key, text/select fields use "operator_text" key
    let op_key = if field.is_numeric() {
        config.get("operator").and_then(|v| v.as_str()).unwrap_or("gte")
    } else {
        config.get("operator_text").and_then(|v| v.as_str()).unwrap_or("eq")
    };

    let operator = ConditionOperator::from_key(op_key)
        .ok_or_else(|| AppError::BadRequest(format!("Invalid operator '{op_key}'")))?;

    // Non-numeric fields only support eq/neq
    if !field.is_numeric()
        && !matches!(operator, ConditionOperator::Eq | ConditionOperator::Neq)
    {
        return Err(AppError::BadRequest(
            "Only '= equals' and '\u{2260} not equals' are supported for this field".into(),
        ));
    }

    // Parse value
    let specific_key = format!("value_{field_key}");
    let raw_value = config.get(&specific_key).or_else(|| config.get("value"));

    let value = if field.is_numeric() {
        let n = raw_value
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok())))
            .ok_or_else(|| AppError::BadRequest(format!("Value must be a number for '{field_key}'")))?;
        json!(n)
    } else if field.is_select() {
        let s = raw_value.and_then(|v| v.as_str()).unwrap_or("");
        if s.is_empty() {
            return Err(AppError::BadRequest("Value is required".into()));
        }
        validate_select_value(&field, s)?;
        json!(s)
    } else {
        let s = raw_value.and_then(|v| v.as_str()).unwrap_or("");
        if s.is_empty() {
            return Err(AppError::BadRequest("Value is required".into()));
        }
        if field == ConditionField::Country {
            json!(s.to_uppercase())
        } else {
            json!(s)
        }
    };

    // Parse between end value
    let value_end = if matches!(operator, ConditionOperator::Between) {
        let end_key = format!("value_end_{field_key}");
        let raw_end = config.get(&end_key).or_else(|| config.get("value_end"));
        let n = raw_end
            .and_then(|v| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok())))
            .ok_or_else(|| AppError::BadRequest("End value is required for between operator".into()))?;
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

    Ok(WebConditions {
        field: field_key.to_string(),
        operator: op_key.to_string(),
        value,
        value_end,
        block_vpn,
        block_spoofing,
        block_impossible_travel,
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
