use axum::http::HeaderMap;
use chrono::{DateTime, Offset, Utc};

// ─── VPN / Proxy Detection ───────────────────────────────────────────────────

/// Detect VPN/proxy usage.
///
/// Two detection methods:
/// 1. **Tor** — Cloudflare reports CF-IPCountry "T1" for Tor exit nodes
/// 2. **IP-timezone mismatch** — VPNs change your IP country but your browser
///    timezone stays the same. If IP says Japan but timezone says America/New_York,
///    the user is on a VPN. This is the primary detection method for commercial VPNs
///    (NordVPN, ExpressVPN, etc.) that don't set any detectable headers.
///
/// Does NOT flag:
/// - Cloudflare WARP (1.1.1.1 app) — doesn't change your country
/// - `Via` / X-Forwarded-For — infrastructure headers, not VPN indicators
/// - Same-country VPNs — undetectable (IP country matches real country)
pub fn detect_vpn(headers: &HeaderMap, timezone: &str, country: Option<&str>) -> bool {
    // Tor exit node
    if let Some(cf_country) = headers.get("cf-ipcountry").and_then(|v| v.to_str().ok()) {
        if cf_country.trim() == "T1" {
            return true;
        }
    }

    // IP-timezone mismatch: the classic VPN fingerprint.
    // VPN changes IP country but browser timezone stays real.
    if let Some(cc) = country {
        if !timezone_country_consistent(timezone, cc) {
            return true;
        }
    }

    false
}

// ─── Spoofing Detection (5 cross-validation checks) ─────────────────────────

/// Detect spoofed/tampered identity by cross-validating data points.
/// Returns true if ANY check fails (spoofing detected).
///
/// This catches data tampering (faked timezone offset, impossible browser/platform
/// combos). VPN detection (timezone-country mismatch) is handled by `detect_vpn`.
pub fn detect_spoofing(
    timezone: &str,
    utc_offset_minutes: i32, // stored convention: -300 for EST, +540 for JST
    country: Option<&str>,
    platform: &str,
    browser: &str,
    device_type: &str,
) -> bool {
    // Check 1: UTC offset vs timezone name (DST-aware)
    // Catches: user spoofed timezone string but forgot to match the offset
    if !validate_offset_for_timezone(timezone, utc_offset_minutes) {
        return true;
    }
    // Check 2: UTC offset vs country
    // Catches: user on VPN spoofed timezone to match VPN country but offset still reveals real location
    if let Some(cc) = country {
        if !country_offset_plausible(cc, utc_offset_minutes) {
            return true;
        }
    }
    // Check 3: Platform/browser consistency
    // Catches: faked User-Agent (Safari on Linux, etc.)
    if !platform_browser_consistent(platform, browser) {
        return true;
    }
    // Check 4: Platform/device-type consistency
    // Catches: faked device type (Android as Desktop, etc.)
    if !platform_device_consistent(platform, device_type) {
        return true;
    }
    false
}

/// Check 1: Is the reported UTC offset correct for this IANA timezone right now?
fn validate_offset_for_timezone(timezone: &str, offset_minutes: i32) -> bool {
    use chrono::TimeZone;
    let tz: chrono_tz::Tz = match timezone.parse() {
        Ok(tz) => tz,
        Err(_) => return true, // unknown tz, can't validate
    };
    let now = Utc::now();
    let local = tz.from_utc_datetime(&now.naive_utc());
    let expected_seconds = local.offset().fix().local_minus_utc();
    // offset_minutes is negated JS convention: -300 for EST (UTC-5)
    // expected_seconds for EST = -18000
    let actual_seconds = offset_minutes as i64 * 60;
    expected_seconds as i64 == actual_seconds
}

/// Check 2: Is the UTC offset plausible for this country?
/// Covers major countries with all their valid offsets including DST.
fn country_offset_plausible(country: &str, offset_minutes: i32) -> bool {
    let valid_offsets: &[i32] = match country.to_uppercase().as_str() {
        // Americas
        "US" => &[-300, -240, -360, -300, -420, -360, -480, -420, -540, -480, -600], // EST..HST + DST
        "CA" => &[-210, -150, -240, -180, -300, -240, -360, -300, -420, -360, -480, -420], // NST..PST + DST
        "MX" => &[-300, -360, -300, -420, -360],
        "BR" => &[-120, -180, -240, -300],
        "AR" => &[-180],
        "CL" => &[-180, -240],
        "CO" | "PE" | "EC" => &[-300],
        // Europe
        "GB" | "IE" | "PT" => &[0, 60],          // GMT/BST
        "DE" | "FR" | "IT" | "ES" | "NL" | "BE" | "AT" | "CH" | "SE" | "NO" | "DK"
        | "PL" | "CZ" | "HU" | "HR" | "SK" | "SI" => &[60, 120], // CET/CEST
        "FI" | "EE" | "LV" | "LT" | "RO" | "BG" | "GR" | "UA" => &[120, 180], // EET/EEST
        "RU" => &[120, 180, 240, 300, 360, 420, 480, 540, 600, 660, 720], // Russia spans many zones
        "TR" => &[180],
        // Asia
        "JP" => &[540],
        "KR" => &[540],
        "CN" | "HK" | "MO" | "TW" | "SG" | "MY" | "PH" => &[480],
        "IN" => &[330],
        "TH" | "VN" | "KH" | "LA" => &[420],
        "ID" => &[420, 480, 540],
        "BD" => &[360],
        "PK" => &[300],
        "AE" | "OM" => &[240],
        "SA" | "QA" | "KW" | "BH" | "IQ" => &[180],
        "IL" => &[120, 180],
        "IR" => &[210, 270],
        // Oceania
        "AU" => &[480, 525, 570, 600, 630, 660],  // AWST..AEDT
        "NZ" => &[720, 780],                       // NZST/NZDT
        // Africa
        "ZA" => &[120],
        "EG" => &[120, 180],
        "NG" | "GH" => &[60, 0],
        "KE" | "ET" | "TZ" => &[180],
        "MA" => &[0, 60],
        _ => return true, // unknown country, don't flag
    };
    valid_offsets.contains(&offset_minutes)
}

/// Check 3: Impossible browser/platform combinations.
fn platform_browser_consistent(platform: &str, browser: &str) -> bool {
    !matches!(
        (platform, browser),
        ("Linux", "Safari")
            | ("Windows", "Safari")
            | ("Android", "Safari")
            | ("ChromeOS", "Safari")
    )
}

/// Check 4: Impossible platform/device-type combinations.
fn platform_device_consistent(platform: &str, device_type: &str) -> bool {
    !matches!(
        (platform, device_type),
        ("Android", "Desktop")
            | ("iOS", "Desktop")
            | ("Windows", "Mobile")
            | ("macOS", "Mobile")
            | ("Linux", "Mobile")
            | ("ChromeOS", "Mobile")
    )
}

/// Check 5: Country-level timezone validation.
/// Maps common IANA timezones to expected country codes.
/// Falls back to continent-level check for unmapped timezones.
fn timezone_country_consistent(timezone: &str, country: &str) -> bool {
    let expected: Option<&[&str]> = match timezone {
        // United States
        "America/New_York" | "America/Detroit" | "America/Indiana/Indianapolis"
        | "America/Indiana/Knox" | "America/Indiana/Marengo" | "America/Indiana/Petersburg"
        | "America/Indiana/Tell_City" | "America/Indiana/Vevay" | "America/Indiana/Vincennes"
        | "America/Indiana/Winamac" | "America/Kentucky/Louisville"
        | "America/Kentucky/Monticello" | "America/Chicago" | "America/Menominee"
        | "America/North_Dakota/Beulah" | "America/North_Dakota/Center"
        | "America/North_Dakota/New_Salem" | "America/Denver" | "America/Boise"
        | "America/Phoenix" | "America/Los_Angeles" | "America/Anchorage" | "America/Juneau"
        | "America/Sitka" | "America/Metlakatla" | "America/Yakutat" | "America/Nome"
        | "America/Adak" | "Pacific/Honolulu" => Some(&["US"]),
        // Canada
        "America/Toronto" | "America/Iqaluit" | "America/Winnipeg" | "America/Resolute"
        | "America/Rankin_Inlet" | "America/Regina" | "America/Swift_Current"
        | "America/Edmonton" | "America/Cambridge_Bay" | "America/Inuvik"
        | "America/Dawson_Creek" | "America/Fort_Nelson" | "America/Creston"
        | "America/Vancouver" | "America/Whitehorse" | "America/Dawson"
        | "America/St_Johns" | "America/Halifax" | "America/Glace_Bay"
        | "America/Moncton" | "America/Goose_Bay" | "America/Blanc-Sablon"
        | "America/Nipigon" | "America/Thunder_Bay" | "America/Rainy_River"
        | "America/Atikokan" | "America/Yellowknife" => Some(&["CA"]),
        // UK / Ireland
        "Europe/London" => Some(&["GB", "IE"]),
        // Central Europe
        "Europe/Berlin" => Some(&["DE"]),
        "Europe/Paris" => Some(&["FR"]),
        "Europe/Rome" => Some(&["IT"]),
        "Europe/Madrid" => Some(&["ES"]),
        "Europe/Amsterdam" => Some(&["NL"]),
        "Europe/Brussels" => Some(&["BE"]),
        "Europe/Zurich" => Some(&["CH", "LI"]),
        "Europe/Vienna" => Some(&["AT"]),
        "Europe/Stockholm" => Some(&["SE"]),
        "Europe/Oslo" => Some(&["NO"]),
        "Europe/Copenhagen" => Some(&["DK"]),
        "Europe/Helsinki" => Some(&["FI"]),
        "Europe/Warsaw" => Some(&["PL"]),
        "Europe/Prague" => Some(&["CZ", "SK"]),
        "Europe/Budapest" => Some(&["HU"]),
        "Europe/Bucharest" => Some(&["RO"]),
        "Europe/Sofia" => Some(&["BG"]),
        "Europe/Athens" => Some(&["GR"]),
        "Europe/Dublin" => Some(&["IE"]),
        "Europe/Lisbon" => Some(&["PT"]),
        "Europe/Kyiv" => Some(&["UA"]),
        "Europe/Moscow" | "Europe/Kaliningrad" | "Europe/Samara" | "Europe/Volgograd"
        | "Asia/Yekaterinburg" | "Asia/Omsk" | "Asia/Novosibirsk" | "Asia/Krasnoyarsk"
        | "Asia/Irkutsk" | "Asia/Yakutsk" | "Asia/Vladivostok" | "Asia/Magadan"
        | "Asia/Kamchatka" => Some(&["RU"]),
        "Europe/Istanbul" => Some(&["TR"]),
        // East Asia
        "Asia/Tokyo" => Some(&["JP"]),
        "Asia/Seoul" => Some(&["KR"]),
        "Asia/Shanghai" | "Asia/Urumqi" => Some(&["CN"]),
        "Asia/Hong_Kong" => Some(&["HK", "CN"]),
        "Asia/Taipei" => Some(&["TW"]),
        "Asia/Singapore" => Some(&["SG"]),
        "Asia/Kuala_Lumpur" | "Asia/Kuching" => Some(&["MY"]),
        "Asia/Manila" => Some(&["PH"]),
        "Asia/Jakarta" | "Asia/Pontianak" | "Asia/Makassar" | "Asia/Jayapura" => Some(&["ID"]),
        "Asia/Bangkok" => Some(&["TH"]),
        "Asia/Ho_Chi_Minh" => Some(&["VN"]),
        // South Asia
        "Asia/Kolkata" | "Asia/Calcutta" => Some(&["IN"]),
        "Asia/Dhaka" => Some(&["BD"]),
        "Asia/Karachi" => Some(&["PK"]),
        "Asia/Colombo" => Some(&["LK"]),
        // Middle East
        "Asia/Dubai" => Some(&["AE"]),
        "Asia/Riyadh" => Some(&["SA"]),
        "Asia/Qatar" => Some(&["QA"]),
        "Asia/Jerusalem" | "Asia/Tel_Aviv" => Some(&["IL", "PS"]),
        "Asia/Tehran" => Some(&["IR"]),
        "Asia/Baghdad" => Some(&["IQ"]),
        // Oceania
        "Australia/Sydney" | "Australia/Melbourne" | "Australia/Brisbane"
        | "Australia/Hobart" | "Australia/Adelaide" | "Australia/Darwin"
        | "Australia/Perth" | "Australia/Lord_Howe" => Some(&["AU"]),
        "Pacific/Auckland" | "Pacific/Chatham" => Some(&["NZ"]),
        // Latin America
        "America/Sao_Paulo" | "America/Noronha" | "America/Bahia" | "America/Fortaleza"
        | "America/Recife" | "America/Manaus" | "America/Belem" | "America/Cuiaba"
        | "America/Porto_Velho" | "America/Boa_Vista" | "America/Campo_Grande"
        | "America/Rio_Branco" => Some(&["BR"]),
        "America/Mexico_City" | "America/Cancun" | "America/Merida" | "America/Monterrey"
        | "America/Chihuahua" | "America/Mazatlan" | "America/Hermosillo"
        | "America/Tijuana" => Some(&["MX"]),
        "America/Argentina/Buenos_Aires" | "America/Argentina/Cordoba"
        | "America/Argentina/Mendoza" => Some(&["AR"]),
        "America/Santiago" => Some(&["CL"]),
        "America/Bogota" => Some(&["CO"]),
        "America/Lima" => Some(&["PE"]),
        // Africa
        "Africa/Cairo" => Some(&["EG"]),
        "Africa/Johannesburg" => Some(&["ZA"]),
        "Africa/Lagos" => Some(&["NG"]),
        "Africa/Nairobi" => Some(&["KE"]),
        "Africa/Casablanca" => Some(&["MA"]),
        _ => None,
    };

    let country_upper = country.to_uppercase();

    if let Some(expected_countries) = expected {
        return expected_countries.contains(&country_upper.as_str());
    }

    // Fallback: continent-level check for unmapped timezones
    !continent_mismatch(timezone, country)
}

/// Continent-level fallback: timezone continent vs country continent.
fn continent_mismatch(timezone: &str, country: &str) -> bool {
    let tz_continent = timezone_to_continent(timezone);
    let country_continent = country_to_continent(country);
    let (Some(tz_c), Some(cc_c)) = (tz_continent, country_continent) else {
        return false;
    };
    tz_c != cc_c
}

fn timezone_to_continent(tz: &str) -> Option<&'static str> {
    let prefix = tz.split('/').next()?;
    match prefix {
        "America" | "US" | "Canada" | "Brazil" => Some("americas"),
        "Europe" => Some("europe"),
        "Asia" | "Indian" => Some("asia"),
        "Africa" => Some("africa"),
        "Australia" | "Pacific" => Some("oceania"),
        _ => None,
    }
}

fn country_to_continent(code: &str) -> Option<&'static str> {
    match code.to_uppercase().as_str() {
        "US" | "CA" | "MX" | "BR" | "AR" | "CL" | "CO" | "PE" | "VE" | "EC" | "BO" | "PY"
        | "UY" | "PA" | "CR" | "GT" | "HN" | "SV" | "NI" | "CU" | "DO" | "HT" | "JM"
        | "TT" | "BB" | "BS" | "BZ" | "PR" => Some("americas"),
        "GB" | "DE" | "FR" | "IT" | "ES" | "NL" | "BE" | "PT" | "AT" | "CH" | "SE" | "NO"
        | "DK" | "FI" | "PL" | "CZ" | "RO" | "HU" | "IE" | "GR" | "BG" | "HR" | "SK"
        | "SI" | "LT" | "LV" | "EE" | "RS" | "BA" | "AL" | "MK" | "ME" | "IS" | "LU"
        | "MT" | "CY" | "MD" | "UA" | "BY" | "RU" => Some("europe"),
        "JP" | "CN" | "KR" | "IN" | "SG" | "MY" | "TH" | "VN" | "PH" | "ID" | "TW" | "HK"
        | "MO" | "BD" | "PK" | "LK" | "NP" | "MM" | "KH" | "LA" | "BN" | "MN" | "KZ"
        | "UZ" | "AF" | "IQ" | "IR" | "SA" | "AE" | "QA" | "KW" | "BH" | "OM" | "YE"
        | "JO" | "LB" | "SY" | "IL" | "PS" | "TR" | "GE" | "AM" | "AZ" => Some("asia"),
        "AU" | "NZ" | "FJ" | "PG" => Some("oceania"),
        "ZA" | "NG" | "EG" | "KE" | "GH" | "TZ" | "ET" | "MA" | "TN" | "DZ" | "SD"
        | "UG" | "CM" | "CI" | "SN" | "MG" | "MZ" | "ZM" | "ZW" | "BW" | "NA" | "RW"
        | "CD" | "AO" => Some("africa"),
        _ => None,
    }
}

// ─── Impossible Travel Detection ─────────────────────────────────────────────

/// Detect if country changed too fast between visits to be physically possible.
pub fn detect_impossible_travel(
    current_country: Option<&str>,
    prev_country: Option<&str>,
    prev_visit_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    let (Some(curr), Some(prev), Some(prev_time)) = (current_country, prev_country, prev_visit_at)
    else {
        return false;
    };

    if curr.eq_ignore_ascii_case(prev) {
        return false; // same country
    }

    let curr_continent = country_to_continent(curr);
    let prev_continent = country_to_continent(prev);
    let (Some(cc), Some(pc)) = (curr_continent, prev_continent) else {
        return false; // unknown countries
    };

    let min_hours = min_travel_hours(cc, pc);
    let elapsed_hours = (now - prev_time).num_hours();

    elapsed_hours < min_hours
}

/// Minimum realistic travel time in hours between two continents.
fn min_travel_hours(a: &str, b: &str) -> i64 {
    if a == b {
        return 2; // same continent
    }
    let mut pair = [a, b];
    pair.sort();
    match pair {
        ["africa", "europe"] => 3,
        ["asia", "europe"] => 5,
        ["americas", "europe"] => 6,
        ["africa", "asia"] => 6,
        ["asia", "oceania"] => 5,
        ["americas", "asia"] => 10,
        ["americas", "africa"] => 10,
        ["europe", "oceania"] => 12,
        ["africa", "oceania"] => 12,
        ["americas", "oceania"] => 14,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ── VPN tests ──

    #[test]
    fn test_vpn_tor() {
        let mut h = HeaderMap::new();
        h.insert("cf-ipcountry", "T1".parse().unwrap());
        assert!(detect_vpn(&h, "Asia/Kuala_Lumpur", Some("MY")));
    }

    #[test]
    fn test_vpn_timezone_country_mismatch() {
        // User in MY connects to US VPN: IP says US but timezone says Asia/Kuala_Lumpur
        let h = HeaderMap::new();
        assert!(detect_vpn(&h, "Asia/Kuala_Lumpur", Some("US")));
    }

    #[test]
    fn test_vpn_cross_continent() {
        // User in JP connects to EU VPN: IP says DE but timezone says Asia/Tokyo
        let h = HeaderMap::new();
        assert!(detect_vpn(&h, "Asia/Tokyo", Some("DE")));
    }

    #[test]
    fn test_no_vpn_matching_country() {
        // User in MY, no VPN, timezone matches country
        let h = HeaderMap::new();
        assert!(!detect_vpn(&h, "Asia/Kuala_Lumpur", Some("MY")));
    }

    #[test]
    fn test_no_vpn_same_country_vpn() {
        // User in US, VPN also in US — undetectable and that's OK
        let h = HeaderMap::new();
        assert!(!detect_vpn(&h, "America/New_York", Some("US")));
    }

    #[test]
    fn test_no_vpn_no_country() {
        // No country header available — can't detect, don't flag
        let h = HeaderMap::new();
        assert!(!detect_vpn(&h, "Asia/Tokyo", None));
    }

    #[test]
    fn test_no_vpn_warp() {
        let mut h = HeaderMap::new();
        h.insert("cf-warp-tag-id", "abc".parse().unwrap());
        assert!(!detect_vpn(&h, "Asia/Kuala_Lumpur", Some("MY")));
    }

    #[test]
    fn test_no_vpn_infra_headers() {
        // Via + XFF are infrastructure, not VPN
        let mut h = HeaderMap::new();
        h.insert("via", "1.1 cloudflare".parse().unwrap());
        h.insert("x-forwarded-for", "1.2.3.4, 5.6.7.8, 9.10.11.12".parse().unwrap());
        assert!(!detect_vpn(&h, "Asia/Kuala_Lumpur", Some("MY")));
    }

    // ── Spoofing: offset vs timezone ──

    #[test]
    fn test_offset_matches_timezone() {
        // EST is UTC-5 = -300 minutes. This should pass if we're currently in EST.
        // Use a timezone that doesn't observe DST for a stable test.
        assert!(!detect_spoofing("Asia/Tokyo", 540, Some("JP"), "Windows", "Chrome", "Desktop"));
    }

    #[test]
    fn test_offset_mismatch_timezone() {
        // Claiming Asia/Tokyo (UTC+9 = +540) but sending EST offset (-300)
        assert!(detect_spoofing("Asia/Tokyo", -300, Some("JP"), "Windows", "Chrome", "Desktop"));
    }

    // ── Spoofing: offset vs country ──

    #[test]
    fn test_offset_plausible_for_country() {
        assert!(!detect_spoofing("Asia/Tokyo", 540, Some("JP"), "Windows", "Chrome", "Desktop"));
    }

    #[test]
    fn test_offset_implausible_for_country() {
        // Claiming JP country with correct JP timezone but wrong offset (US Eastern)
        let us_offset = current_offset("America/New_York");
        // This fails check 1 (offset vs timezone) since Asia/Tokyo offset != US offset
        assert!(detect_spoofing("Asia/Tokyo", us_offset, Some("JP"), "Windows", "Chrome", "Desktop"));
    }

    // ── Spoofing: platform/browser ──

    #[test]
    fn test_safari_on_linux_impossible() {
        assert!(detect_spoofing("Etc/UTC", 0, None, "Linux", "Safari", "Desktop"));
    }

    #[test]
    fn test_chrome_on_linux_ok() {
        assert!(!detect_spoofing("Etc/UTC", 0, None, "Linux", "Chrome", "Desktop"));
    }

    // ── Spoofing: platform/device ──

    #[test]
    fn test_android_desktop_impossible() {
        assert!(detect_spoofing("Etc/UTC", 0, None, "Android", "Chrome", "Desktop"));
    }

    #[test]
    fn test_windows_desktop_ok() {
        assert!(!detect_spoofing("Etc/UTC", 0, None, "Windows", "Chrome", "Desktop"));
    }

    // ── Spoofing: timezone vs country (country-level) ──

    /// Helper: get the current correct UTC offset for a timezone.
    fn current_offset(tz_name: &str) -> i32 {
        use chrono::TimeZone;
        let tz: chrono_tz::Tz = tz_name.parse().unwrap();
        let now = Utc::now();
        let local = tz.from_utc_datetime(&now.naive_utc());
        local.offset().fix().local_minus_utc() / 60 // seconds to minutes
    }

    #[test]
    fn test_us_timezone_us_country() {
        let offset = current_offset("America/New_York");
        assert!(!detect_spoofing("America/New_York", offset, Some("US"), "Windows", "Chrome", "Desktop"));
    }

    #[test]
    fn test_spoof_offset_doesnt_match_country() {
        // User on VPN to JP, spoofed timezone to Asia/Tokyo, but offset still reveals US location
        let us_offset = current_offset("America/New_York");
        // offset is US value but country is JP → check 2 (offset vs country) catches this
        assert!(detect_spoofing("America/New_York", us_offset, Some("JP"), "Windows", "Chrome", "Desktop"));
    }

    #[test]
    fn test_clean_data_no_spoofing() {
        let offset = current_offset("America/Guayaquil");
        assert!(!detect_spoofing("America/Guayaquil", offset, Some("EC"), "Windows", "Chrome", "Desktop"));
    }

    // ── Impossible travel ──

    #[test]
    fn test_same_country_no_travel() {
        let now = Utc::now();
        assert!(!detect_impossible_travel(Some("US"), Some("US"), Some(now - Duration::minutes(5)), now));
    }

    #[test]
    fn test_us_to_jp_1hr_impossible() {
        let now = Utc::now();
        assert!(detect_impossible_travel(Some("JP"), Some("US"), Some(now - Duration::hours(1)), now));
    }

    #[test]
    fn test_us_to_jp_24hr_ok() {
        let now = Utc::now();
        assert!(!detect_impossible_travel(Some("JP"), Some("US"), Some(now - Duration::hours(24)), now));
    }

    #[test]
    fn test_us_to_gb_3hr_impossible() {
        let now = Utc::now();
        assert!(detect_impossible_travel(Some("GB"), Some("US"), Some(now - Duration::hours(3)), now));
    }

    #[test]
    fn test_us_to_gb_8hr_ok() {
        let now = Utc::now();
        assert!(!detect_impossible_travel(Some("GB"), Some("US"), Some(now - Duration::hours(8)), now));
    }

    #[test]
    fn test_no_prev_country() {
        assert!(!detect_impossible_travel(Some("US"), None, None, Utc::now()));
    }
}
