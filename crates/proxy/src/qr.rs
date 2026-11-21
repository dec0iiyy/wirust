//! QR codes for the terminal, drawn with Unicode half blocks (two modules per character).

use qrcode::{Color, EcLevel, QrCode};

/// Modules of light border around the code. The standard asks for four; two is what
/// phone cameras need in practice and keeps the code small in a terminal.
const QUIET_ZONE: usize = 2;

/// Draws `text` as a QR code for a terminal with a dark background: light modules are
/// printed as blocks, dark modules as spaces, so the code reads dark-on-light.
///
/// # Errors
///
/// Fails when `text` is too long for a QR code.
pub fn terminal(text: &str) -> anyhow::Result<String> {
    let code = QrCode::with_error_correction_level(text, EcLevel::L)?;
    let width = code.width();
    let colors = code.to_colors();
    Ok(draw(width, |x, y| colors[y * width + x] == Color::Dark))
}

/// Draws a `width` x `width` matrix where `dark(x, y)` says which modules are dark.
fn draw(width: usize, dark: impl Fn(usize, usize) -> bool) -> String {
    let size = width + 2 * QUIET_ZONE;
    let light = |x: usize, y: usize| {
        let inside = (QUIET_ZONE..QUIET_ZONE + width).contains(&x)
            && (QUIET_ZONE..QUIET_ZONE + width).contains(&y);
        !(inside && dark(x - QUIET_ZONE, y - QUIET_ZONE))
    };
    let mut out = String::with_capacity(size * size * 2);
    for y in (0..size).step_by(2) {
        for x in 0..size {
            let top = light(x, y);
            let bottom = y + 1 < size && light(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '\u{2588}',
                (true, false) => '\u{2580}',
                (false, true) => '\u{2584}',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draws_two_rows_per_line_with_a_light_border() {
        // A 1x1 dark matrix: the border is light, the centre module dark.
        let drawn = draw(1, |_, _| true);
        let lines: Vec<&str> = drawn.lines().collect();
        assert_eq!(lines.len(), 3, "5 rows -> 3 lines: {drawn}");
        assert!(lines.iter().all(|line| line.chars().count() == 5));
        assert_eq!(lines[0], "\u{2588}".repeat(5));
        // Row 2 (the dark module) is the top half of line 1.
        assert_eq!(lines[1].chars().nth(2), Some('\u{2584}'));
    }

    #[test]
    fn encodes_a_setup_url() -> anyhow::Result<()> {
        let url = "http://192.168.1.10:8080/";
        let drawn = terminal(url)?;
        let code = QrCode::with_error_correction_level(url, EcLevel::L)?;
        let size = code.width() + 2 * QUIET_ZONE;
        assert_eq!(drawn.lines().count(), size.div_ceil(2));
        assert!(drawn.lines().all(|line| line.chars().count() == size));
        // The top-left finder pattern starts with a dark row of seven modules.
        let first_code_line: Vec<char> = drawn
            .lines()
            .nth(QUIET_ZONE / 2)
            .into_iter()
            .flat_map(str::chars)
            .collect();
        assert!(
            first_code_line[QUIET_ZONE..QUIET_ZONE + 7]
                .iter()
                .all(|c| *c == ' ' || *c == '\u{2584}')
        );
        assert!(terminal(&"x".repeat(5000)).is_err());
        Ok(())
    }
}
