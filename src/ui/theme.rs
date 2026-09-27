//! One palette for the whole interface: a dark theme with a single blue
//! accent. Status colours carry meaning and are used for nothing else.

use ratatui::style::{Color, Modifier, Style};

pub const FG: Color = Color::Rgb(0xc0, 0xca, 0xf5);
pub const MUTED: Color = Color::Rgb(0x73, 0x7a, 0xa2);
pub const FAINT: Color = Color::Rgb(0x3b, 0x42, 0x61);
pub const BORDER: Color = Color::Rgb(0x2f, 0x35, 0x4f);
pub const SURFACE: Color = Color::Rgb(0x1f, 0x23, 0x35);
pub const SELECTED: Color = Color::Rgb(0x28, 0x34, 0x57);

pub const ACCENT: Color = Color::Rgb(0x7a, 0xa2, 0xf7);
pub const VIOLET: Color = Color::Rgb(0xbb, 0x9a, 0xf7);
pub const CYAN: Color = Color::Rgb(0x7d, 0xcf, 0xff);
pub const GREEN: Color = Color::Rgb(0x9e, 0xce, 0x6a);
pub const YELLOW: Color = Color::Rgb(0xe0, 0xaf, 0x68);
pub const RED: Color = Color::Rgb(0xf7, 0x76, 0x8e);
pub const ORANGE: Color = Color::Rgb(0xff, 0x9e, 0x64);
pub const TEAL: Color = Color::Rgb(0x73, 0xda, 0xca);

/// Device families share a colour in the list and on the map.
pub fn family(kind: crate::classify::Kind) -> (Color, &'static str) {
    use crate::classify::Kind::*;
    match kind {
        Router => (YELLOW, "network"),
        Computer | Server => (ACCENT, "computers"),
        Phone => (CYAN, "phones"),
        Tv | Streamer | Speaker => (VIOLET, "media"),
        Hub | SmartDevice | Camera => (TEAL, "smart home"),
        Printer => (ORANGE, "printers"),
        Unknown => (MUTED, "unknown"),
    }
}

pub fn text() -> Style {
    Style::new().fg(FG)
}

pub fn muted() -> Style {
    Style::new().fg(MUTED)
}

pub fn faint() -> Style {
    Style::new().fg(FAINT)
}

pub fn bold(color: Color) -> Style {
    Style::new().fg(color).add_modifier(Modifier::BOLD)
}

pub fn border(focused: bool) -> Style {
    Style::new().fg(if focused { ACCENT } else { BORDER })
}

/// A key cap in the footer and help: `␣q␣`.
pub fn key() -> Style {
    Style::new().fg(FG).bg(SURFACE).add_modifier(Modifier::BOLD)
}

/// A chip for ports and services.
pub fn chip(color: Color) -> Style {
    Style::new().fg(color).bg(SURFACE)
}

/// Geometric shapes rather than Braille, which many terminal fonts lack.
pub const SPINNER: [&str; 4] = ["◐", "◓", "◑", "◒"];
