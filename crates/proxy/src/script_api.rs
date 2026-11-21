//! `/api/v1/script` (the loaded scripts) and `/api/v1/script/log` (their `log()` output and
//! errors). File names only, never directories.

use http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::script::Scripts;

/// Answers the script paths; `None` for any other path.
pub(crate) fn route(
    scripts: Option<&Scripts>,
    method: &Method,
    segments: &[&str],
    query: &str,
) -> Option<(StatusCode, Value)> {
    let log = match segments {
        ["script"] => false,
        ["script", "log"] => true,
        _ => return None,
    };
    if method != Method::GET {
        return Some((
            StatusCode::METHOD_NOT_ALLOWED,
            json!({ "error": "only GET is allowed" }),
        ));
    }
    let Some(scripts) = scripts else {
        return Some((
            StatusCode::OK,
            if log {
                json!({ "entries": [] })
            } else {
                json!({ "scripts": [] })
            },
        ));
    };
    Some(if log {
        let after = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("after="))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        (
            StatusCode::OK,
            json!({ "entries": scripts.log_after(after) }),
        )
    } else {
        (StatusCode::OK, json!({ "scripts": scripts.report() }))
    })
}
