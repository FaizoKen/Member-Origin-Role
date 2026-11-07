/// Parse a User-Agent string into (browser, platform, device_type).
/// Uses lightweight substring matching — no external crate needed.
///
/// `max_touch_points` is the page's `navigator.maxTouchPoints`: it is what
/// tells an iPad apart from a Mac, because since iPadOS 13 Safari on an iPad
/// asks for desktop sites with a Mac's user agent — and no Mac has a
/// touchscreen.
pub fn parse_user_agent(ua: &str, max_touch_points: i32) -> (String, String, String) {
    let ipad_as_mac = is_ipad_as_mac(ua, max_touch_points);
    let browser = detect_browser(ua);
    let platform = if ipad_as_mac {
        "iOS".to_string()
    } else {
        detect_platform(ua)
    };
    let device_type = if ipad_as_mac {
        "Tablet".to_string()
    } else {
        detect_device_type(ua)
    };
    (browser, platform, device_type)
}

fn is_ipad_as_mac(ua: &str, max_touch_points: i32) -> bool {
    ua.contains("Macintosh") && max_touch_points > 1
}

fn detect_browser(ua: &str) -> String {
    // Order matters: Edge and Opera contain "Chrome"; every iOS browser is
    // WebKit and contains "Safari", so Chrome (CriOS) and Firefox (FxiOS) on
    // an iPhone are named by their own tokens before Safari is assumed.
    if ua.contains("Edg/") || ua.contains("EdgA/") || ua.contains("EdgiOS/") {
        "Edge".to_string()
    } else if ua.contains("OPR/") || ua.contains("OPT/") || ua.contains("Opera") {
        "Opera".to_string()
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        "Firefox".to_string()
    } else if ua.contains("CriOS/") {
        "Chrome".to_string()
    } else if ua.contains("Safari/") && !ua.contains("Chrome/") && !ua.contains("Chromium/") {
        "Safari".to_string()
    } else if ua.contains("Chrome/") || ua.contains("Chromium/") {
        "Chrome".to_string()
    } else {
        "Other".to_string()
    }
}

fn detect_platform(ua: &str) -> String {
    if ua.contains("iPhone") || ua.contains("iPad") || ua.contains("iPod") {
        "iOS".to_string()
    } else if ua.contains("Windows") {
        "Windows".to_string()
    } else if ua.contains("Macintosh") || ua.contains("Mac OS") {
        "macOS".to_string()
    } else if ua.contains("Android") {
        "Android".to_string()
    } else if ua.contains("CrOS") {
        "ChromeOS".to_string()
    } else if ua.contains("Linux") {
        "Linux".to_string()
    } else {
        "Other".to_string()
    }
}

fn detect_device_type(ua: &str) -> String {
    // Android's own convention: phones put "Mobile" in the user agent,
    // tablets leave it out (Firefox says "Tablet" outright).
    if ua.contains("iPad") || ua.contains("Tablet") {
        "Tablet".to_string()
    } else if ua.contains("Mobile") {
        "Mobile".to_string()
    } else if ua.contains("Android") {
        "Tablet".to_string()
    } else {
        "Desktop".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        let (browser, platform, device_type) = parse_user_agent(ua, 0);
        assert_eq!(browser, "Chrome");
        assert_eq!(platform, "Windows");
        assert_eq!(device_type, "Desktop");
    }

    #[test]
    fn test_safari_mac() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        let (browser, platform, device_type) = parse_user_agent(ua, 0);
        assert_eq!(browser, "Safari");
        assert_eq!(platform, "macOS");
        assert_eq!(device_type, "Desktop");
    }

    #[test]
    fn test_firefox_linux() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0";
        let (browser, platform, device_type) = parse_user_agent(ua, 0);
        assert_eq!(browser, "Firefox");
        assert_eq!(platform, "Linux");
        assert_eq!(device_type, "Desktop");
    }

    #[test]
    fn test_edge_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        let (browser, platform, _) = parse_user_agent(ua, 0);
        assert_eq!(browser, "Edge");
        assert_eq!(platform, "Windows");
    }

    #[test]
    fn test_chrome_android_mobile() {
        let ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36";
        let (browser, platform, device_type) = parse_user_agent(ua, 5);
        assert_eq!(browser, "Chrome");
        assert_eq!(platform, "Android");
        assert_eq!(device_type, "Mobile");
    }

    #[test]
    fn test_safari_ipad() {
        let ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        let (browser, platform, device_type) = parse_user_agent(ua, 5);
        assert_eq!(browser, "Safari");
        assert_eq!(platform, "iOS");
        assert_eq!(device_type, "Tablet");
    }

    #[test]
    fn test_chrome_iphone() {
        let ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.50 Mobile/15E148 Safari/604.1";
        let (_, platform, device_type) = parse_user_agent(ua, 5);
        assert_eq!(platform, "iOS");
        assert_eq!(device_type, "Mobile");
    }

    #[test]
    fn test_ipad_asking_for_the_desktop_site() {
        // iPadOS 13+ Safari: a Mac's user agent, but a touchscreen.
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        assert_eq!(parse_user_agent(ua, 5), ("Safari".into(), "iOS".into(), "Tablet".into()));
        // The same user agent without touch is a Mac.
        assert_eq!(parse_user_agent(ua, 0), ("Safari".into(), "macOS".into(), "Desktop".into()));
    }

    #[test]
    fn test_chrome_and_firefox_on_iphone_keep_their_names() {
        let chrome = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.50 Mobile/15E148 Safari/604.1";
        assert_eq!(parse_user_agent(chrome, 5).0, "Chrome");
        let firefox = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/605.1.15";
        assert_eq!(parse_user_agent(firefox, 5).0, "Firefox");
        let safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
        assert_eq!(parse_user_agent(safari, 5), ("Safari".into(), "iOS".into(), "Mobile".into()));
    }

    #[test]
    fn test_android_tablets_are_tablets() {
        let tab = "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(parse_user_agent(tab, 5), ("Chrome".into(), "Android".into(), "Tablet".into()));
        let ff_tab = "Mozilla/5.0 (Android 13; Tablet; rv:120.0) Gecko/120.0 Firefox/120.0";
        assert_eq!(parse_user_agent(ff_tab, 5).2, "Tablet");
        let ff_phone = "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0";
        assert_eq!(parse_user_agent(ff_phone, 5).2, "Mobile");
    }

    #[test]
    fn test_touchscreen_windows_is_still_a_desktop() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(parse_user_agent(ua, 10).2, "Desktop");
    }
}
