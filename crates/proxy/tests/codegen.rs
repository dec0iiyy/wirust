//! Golden files for the "Copy as" code generators: every case of `codegen_cases` in every
//! language. Run with `UPDATE_GOLDEN=1` to rewrite them after a deliberate change, then read
//! the diff.

mod codegen_cases;

use std::path::{Path, PathBuf};

use codegen_cases::cases;
use wirust::codegen::{Lang, generate};

fn golden_path(lang: Lang, case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/codegen")
        .join(lang.id())
        .join(format!("{case}.txt"))
}

#[test]
fn every_language_matches_its_golden_files() -> anyhow::Result<()> {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    let cases = cases("https://api.test");
    assert!(cases.len() >= 6, "each language needs at least 6 cases");
    for lang in Lang::ALL {
        for case in &cases {
            let got = generate(lang, &case.exchange);
            let path = golden_path(lang, case.name);
            if update {
                std::fs::create_dir_all(path.parent().expect("a directory"))?;
                std::fs::write(&path, &got)?;
            }
            // A checkout with CRLF line endings (Windows) must not fail the comparison.
            let want = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("{}: {e}; run with UPDATE_GOLDEN=1", path.display()))?
                .replace("\r\n", "\n");
            assert_eq!(got, want, "{} / {}", lang.id(), case.name);
        }
    }
    Ok(())
}

#[test]
fn no_snippet_holds_a_hop_by_hop_header_the_length_or_a_pseudo_header() {
    for lang in Lang::ALL {
        for case in cases("https://api.test") {
            let code = generate(lang, &case.exchange).to_ascii_lowercase();
            for banned in [
                "content-length",
                ":authority",
                "connection",
                "keep-alive",
                "accept-encoding",
                "content-encoding",
            ] {
                assert!(
                    !code.contains(banned),
                    "{} / {} mentions {banned}:\n{code}",
                    lang.id(),
                    case.name
                );
            }
        }
    }
}

#[test]
fn language_names_round_trip() {
    for lang in Lang::ALL {
        assert_eq!(Lang::parse(lang.id()), Some(lang));
    }
    assert_eq!(Lang::parse("cobol"), None);
    assert_eq!(Lang::parse(""), None);
}

#[test]
fn the_ui_menu_offers_every_language_the_api_serves() -> anyhow::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("ui/codegen.js");
    let menu = std::fs::read_to_string(path)?;
    for lang in Lang::ALL {
        assert!(
            menu.contains(&format!("[\"{}\", \"", lang.id())),
            "ui/codegen.js lacks {}",
            lang.id()
        );
    }
    Ok(())
}
