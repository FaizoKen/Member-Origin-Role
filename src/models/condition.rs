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

    /// Reject Discord accounts younger than this many days. 0 disables the check.
    /// Account age comes from the Discord snowflake — no API call needed.
    #[serde(default)]
    pub min_account_age_days: i32,

    /// Silent verify mode: hide collected data from the user and skip the
    /// "Sign in with Discord" button (auto-bounce to login). Same /verify URL.
    /// Defaults to true — admins must opt out to show users what was detected.
    #[serde(default = "default_true")]
    pub anonymous_mode: bool,

    /// Flip the rule: the role goes to verified members who do NOT pass it
    /// (condition and checks together). With `field = "any"` and the fraud
    /// checks on, that is a "Needs Review" role for flagged members.
    #[serde(default)]
    pub invert: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConditionField {
    /// No identity condition: anyone who verified (and passes the enabled
    /// checks). Distinct from an unconfigured link (empty field), which
    /// grants nobody.
    Any,
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

    /// The `web_contexts` column a condition on this field reads; `None` for
    /// `Any`, which reads none.
    pub fn sql_column(&self) -> Option<&'static str> {
        match self {
            Self::Any => None,
            Self::Timezone => Some("wc.timezone"),
            Self::UtcOffset => Some("wc.utc_offset"),
            Self::Country => Some("wc.country"),
            Self::Platform => Some("wc.platform"),
            Self::Browser => Some("wc.browser"),
            Self::Language => Some("wc.language"),
            Self::DeviceType => Some("wc.device_type"),
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "any" => Some(Self::Any),
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

// ─── Text matching shared by the in-memory and SQL paths ────────────────────

/// Does a member's browser language match the configured one?
///
/// BCP 47 basic filtering (RFC 4647 §3.3.1): a tag without a region matches
/// every regional form of that language, so "en" matches "en", "en-US" and
/// "en-GB", while "en-US" matches only "en-US". Case never matters. Browsers
/// almost always send a regional tag first, so an exact match on "en" alone
/// would leave out nearly every English speaker.
pub fn language_matches(actual: &str, expected: &str) -> bool {
    let a = actual.trim().to_ascii_lowercase();
    let e = expected.trim().to_ascii_lowercase();
    !e.is_empty()
        && (a == e || (a.len() > e.len() && a.starts_with(&e) && a.as_bytes()[e.len()] == b'-'))
}

/// IANA zones that browsers still report under an older name, and the name
/// they have now. Chrome on Windows says "Asia/Calcutta" for India and
/// "Europe/Kiev" for Ukraine (ICU's names), Firefox and phones say
/// "Asia/Kolkata" and "Europe/Kyiv": an admin who types either must match
/// both. Pairs are (old, current), compared without case.
const TIMEZONE_ALIASES: &[(&str, &str)] = &[
    ("Asia/Calcutta", "Asia/Kolkata"),
    ("Asia/Saigon", "Asia/Ho_Chi_Minh"),
    ("Asia/Katmandu", "Asia/Kathmandu"),
    ("Asia/Rangoon", "Asia/Yangon"),
    ("Asia/Dacca", "Asia/Dhaka"),
    ("Asia/Thimbu", "Asia/Thimphu"),
    ("Asia/Ulan_Bator", "Asia/Ulaanbaatar"),
    ("Asia/Macao", "Asia/Macau"),
    ("Asia/Ujung_Pandang", "Asia/Makassar"),
    ("Asia/Chongqing", "Asia/Shanghai"),
    ("Asia/Chungking", "Asia/Shanghai"),
    ("Asia/Harbin", "Asia/Shanghai"),
    ("Asia/Istanbul", "Europe/Istanbul"),
    ("Asia/Tel_Aviv", "Asia/Jerusalem"),
    ("Europe/Kiev", "Europe/Kyiv"),
    ("Europe/Uzhgorod", "Europe/Kyiv"),
    ("Europe/Zaporozhye", "Europe/Kyiv"),
    ("Europe/Belfast", "Europe/London"),
    ("Europe/Nicosia", "Asia/Nicosia"),
    ("America/Buenos_Aires", "America/Argentina/Buenos_Aires"),
    ("America/Catamarca", "America/Argentina/Catamarca"),
    ("America/Cordoba", "America/Argentina/Cordoba"),
    ("America/Jujuy", "America/Argentina/Jujuy"),
    ("America/Mendoza", "America/Argentina/Mendoza"),
    ("America/Indianapolis", "America/Indiana/Indianapolis"),
    ("America/Louisville", "America/Kentucky/Louisville"),
    ("America/Godthab", "America/Nuuk"),
    ("America/Montreal", "America/Toronto"),
    ("America/Shiprock", "America/Denver"),
    ("Atlantic/Faeroe", "Atlantic/Faroe"),
    ("Pacific/Enderbury", "Pacific/Kanton"),
    ("Pacific/Truk", "Pacific/Chuuk"),
    ("Pacific/Ponape", "Pacific/Pohnpei"),
    ("Australia/Canberra", "Australia/Sydney"),
    ("Australia/ACT", "Australia/Sydney"),
    ("Australia/NSW", "Australia/Sydney"),
    ("Australia/Currie", "Australia/Hobart"),
];

/// Every spelling of the zone `name` names — its current name and every
/// older one — lower-cased.
pub fn timezone_names(name: &str) -> Vec<String> {
    let lower = name.trim().to_ascii_lowercase();
    let current = TIMEZONE_ALIASES
        .iter()
        .find(|(old, _)| old.eq_ignore_ascii_case(&lower))
        .map(|(_, cur)| cur.to_ascii_lowercase())
        .unwrap_or_else(|| lower.clone());
    let mut names = vec![current.clone()];
    for (old, cur) in TIMEZONE_ALIASES {
        if cur.eq_ignore_ascii_case(&current) {
            names.push(old.to_ascii_lowercase());
        }
    }
    if !names.contains(&lower) {
        names.push(lower);
    }
    names
}

/// Does a member's browser timezone name the configured zone (under any of
/// its names)?
pub fn timezone_matches(actual: &str, expected: &str) -> bool {
    let a = actual.trim().to_ascii_lowercase();
    timezone_names(expected).iter().any(|n| *n == a)
}

/// A configured timezone, checked against the timezone database and spelled
/// as the database spells it ("asia/tokyo" → "Asia/Tokyo"). `None` for a
/// name the database doesn't know (a typo would match nobody).
pub fn canonical_timezone(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    chrono_tz::TZ_VARIANTS
        .iter()
        .map(|tz| tz.name())
        .find(|name| name.eq_ignore_ascii_case(s))
        .map(str::to_string)
}

/// A configured language tag: letters, then hyphen-separated letter/digit
/// subtags ("en", "en-US", "zh-Hant-TW", "es-419").
pub fn valid_language_tag(input: &str) -> bool {
    let mut parts = input.trim().split('-');
    let Some(primary) = parts.next() else {
        return false;
    };
    (2..=8).contains(&primary.len())
        && primary.bytes().all(|b| b.is_ascii_alphabetic())
        && parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_without_region_matches_every_region() {
        assert!(language_matches("en-US", "en"));
        assert!(language_matches("en-GB", "EN"));
        assert!(language_matches("en", "en"));
        assert!(!language_matches("en-US", "en-GB"));
        assert!(language_matches("en-us", "en-US"));
        // "e" is not a prefix match for "en", nor "en" for "eng".
        assert!(!language_matches("en-US", "e"));
        assert!(!language_matches("eng", "en"));
        assert!(!language_matches("en", "en-US"));
        assert!(!language_matches("en", ""));
    }

    #[test]
    fn timezone_aliases_match_both_ways() {
        assert!(timezone_matches("Asia/Calcutta", "Asia/Kolkata"));
        assert!(timezone_matches("Asia/Kolkata", "Asia/Calcutta"));
        assert!(timezone_matches("Europe/Kiev", "europe/kyiv"));
        assert!(timezone_matches("Asia/Tokyo", "asia/tokyo"));
        assert!(!timezone_matches("Asia/Seoul", "Asia/Tokyo"));
        // Two old names of one zone match each other through the current one.
        assert!(timezone_matches("Europe/Uzhgorod", "Europe/Kiev"));
    }

    #[test]
    fn canonical_timezone_fixes_case_and_rejects_typos() {
        assert_eq!(canonical_timezone("asia/tokyo").as_deref(), Some("Asia/Tokyo"));
        assert_eq!(
            canonical_timezone(" America/New_York ").as_deref(),
            Some("America/New_York")
        );
        assert_eq!(canonical_timezone("Asia/Calcutta").as_deref(), Some("Asia/Calcutta"));
        assert_eq!(canonical_timezone("Asia/Tokio"), None);
        assert_eq!(canonical_timezone(""), None);
    }

    #[test]
    fn language_tags() {
        for ok in ["en", "en-US", "zh-Hant-TW", "es-419", "FIL"] {
            assert!(valid_language_tag(ok), "{ok}");
        }
        for bad in ["", "e", "en_US", "en-", "-US", "en US", "1a"] {
            assert!(!valid_language_tag(bad), "{bad}");
        }
    }
}
