use serde::{Deserialize, Serialize};

/// Flat conditions struct stored as JSON in role_links.conditions.
/// The identity condition (field + operator + value) is AND'd with the fraud toggles.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WebConditions {
    /// Which identity field to check (timezone, country, platform, etc.)
    #[serde(default)]
    pub field: String,
    /// Comparison operator (eq, neq, gt, gte, lt, lte, between)
    #[serde(default)]
    pub operator: String,
    /// Expected value
    #[serde(default)]
    pub value: serde_json::Value,
    /// End value for between operator
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_end: Option<serde_json::Value>,

    /// Block users detected as using VPN/proxy/Tor
    #[serde(default)]
    pub block_vpn: bool,
    /// Block users with spoofed identity (offset/tz/country/platform/browser cross-validation)
    #[serde(default, alias = "block_timezone_mismatch")]
    pub block_spoofing: bool,
    /// Block users whose IP country changed too fast between visits
    #[serde(default)]
    pub block_impossible_travel: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConditionField {
    Timezone,
    UtcOffset,
    Country,
    Platform,
    Browser,
    Language,
    DeviceType,
}

impl ConditionField {
    pub fn is_numeric(&self) -> bool {
        matches!(self, Self::UtcOffset)
    }

    pub fn is_select(&self) -> bool {
        matches!(self, Self::Platform | Self::Browser | Self::DeviceType)
    }

    pub fn sql_column(&self) -> &'static str {
        match self {
            Self::Timezone => "wc.timezone",
            Self::UtcOffset => "wc.utc_offset",
            Self::Country => "wc.country",
            Self::Platform => "wc.platform",
            Self::Browser => "wc.browser",
            Self::Language => "wc.language",
            Self::DeviceType => "wc.device_type",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "timezone" => Some(Self::Timezone),
            "utcOffset" => Some(Self::UtcOffset),
            "country" => Some(Self::Country),
            "platform" => Some(Self::Platform),
            "browser" => Some(Self::Browser),
            "language" => Some(Self::Language),
            "deviceType" => Some(Self::DeviceType),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConditionOperator {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
    Between,
}

impl ConditionOperator {
    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "eq" => Some(Self::Eq),
            "neq" => Some(Self::Neq),
            "gt" => Some(Self::Gt),
            "gte" => Some(Self::Gte),
            "lt" => Some(Self::Lt),
            "lte" => Some(Self::Lte),
            "between" => Some(Self::Between),
            _ => None,
        }
    }

    pub fn sql_operator(&self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Neq => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Between => "BETWEEN",
        }
    }
}
