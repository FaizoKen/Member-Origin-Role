use serde_json::Value;

const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Verify a Turnstile token against Cloudflare's siteverify endpoint.
/// Returns true only on a confirmed success; any error, network failure, or
/// malformed response returns false so callers can fail closed.
///
/// `remote_ip` is optional but recommended — Cloudflare uses it as an extra
/// signal and warns in the dashboard if it's missing.
pub async fn verify(
    http: &reqwest::Client,
    secret_key: &str,
    token: &str,
    remote_ip: Option<&str>,
) -> bool {
    if token.is_empty() {
        return false;
    }

    let mut form: Vec<(&str, &str)> = vec![("secret", secret_key), ("response", token)];
    if let Some(ip) = remote_ip {
        form.push(("remoteip", ip));
    }

    let resp = match http.post(SITEVERIFY_URL).form(&form).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "turnstile siteverify request failed");
            return false;
        }
    };

    let body: Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "turnstile siteverify parse failed");
            return false;
        }
    };

    let ok = body.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !ok {
        let codes = body
            .get("error-codes")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        tracing::info!(error_codes = %codes, "turnstile verification failed");
    }
    ok
}
