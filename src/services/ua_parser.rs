/// Parse a User-Agent string into (browser, platform, device_type).
/// Uses lightweight substring matching — no external crate needed.
pub fn parse_user_agent(ua: &str, max_touch_points: i32) -> (String, String, String) {
    let browser = detect_browser(ua);
    let platform = detect_platform(ua);
    let device_type = detect_device_type(ua, max_touch_points);
    (browser, platform, device_type)
}

fn detect_browser(ua: &str) -> String {
    // Order matters: Edge contains "Chrome", Opera contains "Chrome"
    if ua.contains("Edg/") || ua.contains("EdgA/") || ua.contains("EdgiOS/") {
        "Edge".to_string()
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        "Opera".to_string()
    } else if ua.contains("Firefox/") {
        "Firefox".to_string()
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

fn detect_device_type(ua: &str, max_touch_points: i32) -> String {
    if ua.contains("iPad") || ua.contains("Tablet") {
        "Tablet".to_string()
    } else if ua.contains("Mobile") || (ua.contains("Android") && !ua.contains("Tablet")) {
        "Mobile".to_string()
    } else if max_touch_points > 0
        && (ua.contains("Macintosh") || ua.contains("Windows"))
        && !ua.contains("Mobile")
    {
        // Touch-capable desktop (e.g., Surface, touchscreen Mac)
        "Desktop".to_string()
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
}
