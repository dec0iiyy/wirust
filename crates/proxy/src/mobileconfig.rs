//! An unsigned iOS configuration profile (`.mobileconfig`) that installs the CA as a root.
//!
//! The profile holds one `com.apple.security.root` payload with the CA's DER bytes inside a
//! top-level `Configuration` payload. Installing it does not make iOS trust the CA for TLS;
//! the user still turns on full trust under Settings > General > About > Certificate Trust
//! Settings.

use std::fmt::Write as _;

use base64::Engine as _;

/// The media type iOS opens as a profile.
pub const CONTENT_TYPE: &str = "application/x-apple-aspen-config";

/// Builds the profile XML for the CA certificate `der`, with fresh payload UUIDs.
///
/// # Errors
///
/// Fails when the system random generator fails.
pub fn profile(der: &[u8]) -> anyhow::Result<String> {
    Ok(render(der, &uuid_v4()?, &uuid_v4()?))
}

/// The profile XML with the given payload UUIDs (`outer` for the profile, `inner` for the
/// certificate payload).
fn render(der: &[u8], outer: &str, inner: &str) -> String {
    let name = crate::NAME;
    let id = format!(
        "local.{}",
        name.replace(|c: char| !c.is_ascii_alphanumeric(), "-")
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    // Plist <data> is base64; wrap it the way Apple's tools do.
    let mut data = String::with_capacity(encoded.len() + encoded.len() / 13);
    for line in encoded.as_bytes().chunks(52) {
        let _ = writeln!(data, "\t\t\t{}", String::from_utf8_lossy(line));
    }
    let name = escape(name);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>{name}-ca.cer</string>
			<key>PayloadContent</key>
			<data>
{data}			</data>
			<key>PayloadDescription</key>
			<string>Adds the {name} certificate authority</string>
			<key>PayloadDisplayName</key>
			<string>{name} CA</string>
			<key>PayloadIdentifier</key>
			<string>{id}.ca.{inner}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{inner}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Lets {name} decrypt HTTPS traffic from this device for debugging. Remove it when you stop using the proxy.</string>
	<key>PayloadDisplayName</key>
	<string>{name} CA</string>
	<key>PayloadIdentifier</key>
	<string>{id}.profile.{outer}</string>
	<key>PayloadOrganization</key>
	<string>{name}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{outer}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#
    )
}

/// A random (version 4) UUID in upper case, as Apple's tools write them.
fn uuid_v4() -> anyhow::Result<String> {
    let mut bytes = [0_u8; 16];
    rustls::crypto::aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system random generator failed"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut text = String::with_capacity(36);
    for (i, byte) in bytes.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            text.push('-');
        }
        let _ = write!(text, "{byte:02X}");
    }
    Ok(text)
}

/// Escapes text for XML character data.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_random_version_4() -> anyhow::Result<()> {
        let (a, b) = (uuid_v4()?, uuid_v4()?);
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4", "{a}");
        assert!(matches!(&a[19..20], "8" | "9" | "A" | "B"), "{a}");
        assert!(a.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        Ok(())
    }

    #[test]
    fn the_profile_carries_the_ca_as_a_root_payload() -> anyhow::Result<()> {
        let der = b"\x30\x82\x01\x0a not a real certificate, just bytes";
        let xml = render(der, "OUTER-UUID", "INNER-UUID");
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<string>com.apple.security.root</string>"));
        assert!(xml.contains("<key>PayloadType</key>\n\t<string>Configuration</string>"));
        assert!(xml.contains("<key>PayloadUUID</key>\n\t<string>OUTER-UUID</string>"));
        assert!(xml.contains("<key>PayloadUUID</key>\n\t\t\t<string>INNER-UUID</string>"));
        assert!(xml.contains(&format!("<string>{}</string>", crate::NAME)));
        assert_eq!(xml.matches("<integer>1</integer>").count(), 2);
        // The <data> element decodes back to the certificate bytes.
        let start = xml.find("<data>").expect("data element") + "<data>".len();
        let end = xml.find("</data>").expect("data end");
        let compact: String = xml[start..end].split_whitespace().collect();
        let decoded = base64::engine::general_purpose::STANDARD.decode(compact)?;
        assert_eq!(decoded, der);
        // Balanced tags: every <dict> and <array> is closed.
        assert_eq!(
            xml.matches("<dict>").count(),
            xml.matches("</dict>").count()
        );
        assert_eq!(
            xml.matches("<array>").count(),
            xml.matches("</array>").count()
        );
        let fresh = profile(der)?;
        assert_ne!(fresh, profile(der)?, "fresh UUIDs per download");
        Ok(())
    }
}
