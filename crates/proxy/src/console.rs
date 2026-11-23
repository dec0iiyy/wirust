//! Makes traffic-derived text safe to print to a terminal.
//!
//! Host names, URLs, header values, error text and device names come from the network, and
//! a terminal acts on control characters in them: `ESC]0;` sets the window title, `ESC]52;`
//! writes the clipboard in some terminals, `ESC[2K` with a carriage return erases and forges
//! a log line. Every line printed from traffic goes through [`escape`] (text) or
//! [`escape_json`] (JSON Lines) first.

use std::borrow::Cow;

/// `text` with every control character (C0, DEL, C1) shown as a `\u{1b}`-style escape;
/// other Unicode is kept. Borrows when there is nothing to escape.
#[must_use]
pub fn escape(text: &str) -> Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| {
                if c.is_control() {
                    c.escape_unicode().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

/// A serialised JSON document with DEL and C1 characters written as `\u007f`-style escapes.
///
/// `serde_json` escapes C0 controls but writes DEL and C1 (U+0080 to U+009F, which some
/// terminals read as CSI and friends) raw. Raw control characters can only occur inside
/// JSON strings, where the `\uXXXX` form means the same character, so the result is the same
/// JSON value.
#[must_use]
pub fn escape_json(json: &str) -> Cow<'_, str> {
    if !json.chars().any(char::is_control) {
        return Cow::Borrowed(json);
    }
    Cow::Owned(
        json.chars()
            .map(|c| {
                if c.is_control() {
                    format!("\\u{:04x}", u32::from(c))
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Escape sequences a hostile peer might send, with what the console must show instead.
    pub(crate) const HOSTILE: &[(&str, &str)] = &[
        ("\u{1b}]0;title\u{7}", "\\u{1b}]0;title\\u{7}"),
        ("\u{1b}]52;c;cHduZWQ=\u{7}", "\\u{1b}]52;c;cHduZWQ=\\u{7}"),
        ("\u{1b}[2K\rforged", "\\u{1b}[2K\\u{d}forged"),
        ("nul\0", "nul\\u{0}"),
        ("del\u{7f}", "del\\u{7f}"),
        ("csi\u{9b}31m", "csi\\u{9b}31m"),
    ];

    #[test]
    fn control_characters_are_escaped_and_text_is_kept() {
        for (raw, shown) in HOSTILE {
            assert_eq!(escape(raw), *shown, "input {raw:?}");
        }
        assert!(matches!(
            escape("héllo мир ✓"),
            Cow::Borrowed("héllo мир ✓")
        ));
    }

    #[test]
    fn json_keeps_its_value_without_raw_controls() -> serde_json::Result<()> {
        let value = serde_json::json!({ "url": "a\u{1b}[2K\r\u{7f}\u{9b}b" });
        let text = serde_json::to_string(&value)?;
        let escaped = escape_json(&text);
        assert!(!escaped.chars().any(char::is_control), "{escaped}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&escaped)?, value);
        Ok(())
    }
}
