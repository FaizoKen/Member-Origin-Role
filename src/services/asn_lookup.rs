use std::net::IpAddr;

use serde_json::Value;
use sqlx::PgPool;

const PROVIDER_URL: &str = "https://proxycheck.io/v2/";
const CACHE_TTL_DAYS: i64 = 7;

/// Result of an ASN/proxy lookup for a single IP.
#[derive(Debug, Clone)]
pub struct Reputation {
    pub is_proxy: bool,
    pub asn_org: Option<String>,
}

/// Network-prefix key used for caching. Multiple users sharing a residential
/// CGN range or VPN POP collapse to one cache row.
///   IPv4 → /24 (first three octets)
///   IPv6 → /48 (first three hextets)
fn ip_to_prefix(ip: &str) -> Option<String> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}", o[0], o[1], o[2]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            Some(format!("{:x}:{:x}:{:x}", s[0], s[1], s[2]))
        }
    }
}

/// Check an IP's reputation. Returns `None` when no signal is available
/// (lookup disabled, network error, malformed IP, etc.) — callers must treat
/// that as "no signal," never as "clean."
///
/// Hits the Postgres cache first; only queries the upstream provider on miss
/// or stale entry. Cache writes are best-effort.
pub async fn lookup(
    http: &reqwest::Client,
    pool: &PgPool,
    ip: &str,
    api_key: Option<&str>,
) -> Option<Reputation> {
    let prefix = ip_to_prefix(ip)?;

    // 1. Cache lookup
    let cached = sqlx::query_as::<_, (bool, Option<String>, chrono::DateTime<chrono::Utc>)>(
        "SELECT is_proxy, asn_org, checked_at FROM ip_reputation_cache WHERE ip_prefix = $1",
    )
    .bind(&prefix)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if let Some((is_proxy, asn_org, checked_at)) = cached {
        let age_days = (chrono::Utc::now() - checked_at).num_days();
        if age_days < CACHE_TTL_DAYS {
            return Some(Reputation { is_proxy, asn_org });
        }
    }

    // 2. Upstream lookup
    let rep = fetch_proxycheck(http, ip, api_key).await?;

    // 3. Cache write (best-effort)
    let _ = sqlx::query(
        "INSERT INTO ip_reputation_cache (ip_prefix, is_proxy, asn_org, checked_at) \
         VALUES ($1, $2, $3, now()) \
         ON CONFLICT (ip_prefix) DO UPDATE \
            SET is_proxy = EXCLUDED.is_proxy, \
                asn_org  = EXCLUDED.asn_org, \
                checked_at = now()",
    )
    .bind(&prefix)
    .bind(rep.is_proxy)
    .bind(&rep.asn_org)
    .execute(pool)
    .await;

    Some(rep)
}

/// Call proxycheck.io. `vpn=3` enables strict VPN/proxy/hosting detection.
/// Without an API key the service still answers but is rate-limited (~100/day).
async fn fetch_proxycheck(
    http: &reqwest::Client,
    ip: &str,
    api_key: Option<&str>,
) -> Option<Reputation> {
    let mut url = format!("{PROVIDER_URL}{ip}?vpn=3&asn=1");
    if let Some(k) = api_key {
        if !k.is_empty() {
            url.push_str("&key=");
            url.push_str(k);
        }
    }

    let resp = match http.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "proxycheck request failed");
            return None;
        }
    };

    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "proxycheck non-2xx");
        return None;
    }

    let body: Value = resp.json().await.ok()?;
    let ip_entry = body.get(ip)?;
    let proxy_str = ip_entry.get("proxy").and_then(|v| v.as_str()).unwrap_or("no");
    let asn_org = ip_entry
        .get("provider")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| {
            ip_entry
                .get("asn")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        });

    Some(Reputation {
        is_proxy: proxy_str.eq_ignore_ascii_case("yes"),
        asn_org,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_prefix() {
        assert_eq!(ip_to_prefix("1.2.3.4").as_deref(), Some("1.2.3"));
        assert_eq!(ip_to_prefix("192.168.1.255").as_deref(), Some("192.168.1"));
    }

    #[test]
    fn test_ipv6_prefix() {
        assert_eq!(
            ip_to_prefix("2001:db8:abcd:1234::1").as_deref(),
            Some("2001:db8:abcd")
        );
    }

    #[test]
    fn test_invalid_ip_returns_none() {
        assert_eq!(ip_to_prefix("not-an-ip"), None);
        assert_eq!(ip_to_prefix(""), None);
    }
}
