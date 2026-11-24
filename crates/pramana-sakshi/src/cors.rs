//! CORS for browser wallets on other origins.
//!
//! The layer wraps the whole router, so headers are added to *every* response —
//! including error responses and panics caught by `CatchPanicLayer` (which must be
//! installed *inside* this layer). Origins are matched against comma-separated
//! patterns with `*` wildcards, e.g.
//! `https://pramana.example,https://*.pages.dev,http://localhost:*`.
//!
//! No credentials (cookies) are used by the protocol, so `allow_credentials` stays off.

use axum::http::{header, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Default: local development only.
pub const DEFAULT_ORIGINS: &str = "http://localhost:*,http://127.0.0.1:*";

/// Build the CORS layer from a pattern list.
pub fn layer(spec: &str) -> CorsLayer {
    let patterns: Vec<String> = spec
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let allow = AllowOrigin::predicate(move |origin: &HeaderValue, _| {
        let Ok(o) = origin.to_str() else {
            return false;
        };
        patterns.iter().any(|p| matches(p, o))
    });
    CorsLayer::new()
        .allow_origin(allow)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(std::time::Duration::from_secs(600))
}

/// Glob match with `*` wildcards.
pub fn matches(pattern: &str, s: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == s;
    }
    let mut rest = s;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(idx) => rest = &rest[idx + part.len()..],
                None => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn wildcard_matching() {
        assert!(matches("http://localhost:*", "http://localhost:5173"));
        assert!(matches(
            "https://*.pages.dev",
            "https://abc.pramana.pages.dev"
        ));
        assert!(!matches(
            "https://*.pages.dev",
            "https://evil.com/.pages.dev.x"
        ));
        assert!(matches(
            "https://pramana.example",
            "https://pramana.example"
        ));
        assert!(!matches(
            "https://pramana.example",
            "https://pramana.example.evil"
        ));
        assert!(matches("*", "anything"));
    }
}
