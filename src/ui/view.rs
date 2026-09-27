//! Rendering. Pure functions of the app state and a snapshot, so they can be
//! tested against ratatui's in-memory backend.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Flex, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Cell, Clear, HighlightSpacing, Padding, Paragraph, Row, Table, TableState,
    Wrap,
};

use super::theme::{self, *};
use super::{App, Entry, Focus, PeerRow, Phase, Row as DeviceRow, Snapshot, Sort, labels};
use crate::classify::{Classification, Confidence, Kind};
use crate::inventory::{Device, SourceState};
use crate::oui::Vendor;

/// Below this width the detail panel and map give way to the list.
const SIDE_PANEL_MIN_WIDTH: u16 = 120;
const MAP_MAX_ADDRESSES: u32 = 256;
/// Lines per device in the list.
pub const ROW_HEIGHT: u16 = 2;
/// The list's columns, with the sort a click on each heading picks.
pub const COLUMNS: [(&str, Option<Sort>); 6] = [
    ("", None),
    ("NAME", Some(Sort::Name)),
    ("TYPE", Some(Sort::Type)),
    ("VENDOR", Some(Sort::Vendor)),
    ("ADDRESS", Some(Sort::Address)),
    ("PORTS", Some(Sort::Ports)),
];
const PORTS: usize = 5;

pub fn draw(f: &mut Frame, app: &mut App, snap: &Snapshot) {
    let area = f.area();
    f.render_widget(Block::new().style(theme::text()), area);
    let [header, body, stages, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(6),
        Constraint::Length(4),
        Constraint::Length(1),
    ])
    .areas(area);

    draw_header(f, app, snap, header);
    app.areas = Default::default();
    if app.zoom {
        draw_detail(f, app, snap, body);
    } else if body.width >= SIDE_PANEL_MIN_WIDTH {
        let side_width = (body.width * 32 / 100).clamp(42, 60);
        let [list, side] =
            Layout::horizontal([Constraint::Fill(1), Constraint::Length(side_width)])
                .spacing(1)
                .areas(body);
        draw_list(f, app, snap, list);
        let map_height = map_rows(app) + 5;
        if side.height >= map_height + 10 && map_rows(app) > 0 {
            let [detail, map] =
                Layout::vertical([Constraint::Min(8), Constraint::Length(map_height)]).areas(side);
            draw_detail(f, app, snap, detail);
            draw_map(f, app, snap, map);
        } else {
            draw_detail(f, app, snap, side);
        }
    } else {
        draw_list(f, app, snap, body);
    }
    draw_stages(f, app, snap, stages);
    draw_footer(f, app, footer);
    if app.help {
        draw_help(f, area);
    }
}

fn panel<'a>(title: impl Into<Line<'a>>, focused: bool) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(focused))
        .title(title)
        .padding(Padding::horizontal(1))
}

fn title(text: &str) -> Span<'_> {
    Span::styled(format!(" {text} "), theme::bold(FG))
}

// ── header ──────────────────────────────────────────────────────────────

fn draw_header(f: &mut Frame, app: &App, snap: &Snapshot, area: Rect) {
    let t = &app.target;
    let mut left = vec![
        Span::styled(" ◆ ", theme::bold(ACCENT)),
        Span::styled("eggprobe", theme::bold(FG)),
        Span::styled("   ", theme::muted()),
    ];
    let elapsed = fmt_elapsed(app.elapsed());
    let status = match app.phase() {
        Phase::Idle => vec![Span::styled("Idle", theme::muted())],
        Phase::Scanning => vec![
            Span::styled(spinner(app), theme::bold(ACCENT)),
            Span::styled(" Scanning ", theme::bold(ACCENT)),
            Span::styled(elapsed, theme::muted()),
        ],
        Phase::Stopping => vec![
            Span::styled(spinner(app), theme::bold(YELLOW)),
            Span::styled(" Stopping…", theme::bold(YELLOW)),
        ],
        Phase::Done => vec![
            Span::styled("✓ Complete ", theme::bold(GREEN)),
            Span::styled(elapsed, theme::muted()),
        ],
        Phase::Stopped => vec![
            Span::styled("■ Stopped ", theme::bold(YELLOW)),
            Span::styled(elapsed, theme::muted()),
        ],
    };
    let mut right = vec![
        Span::styled(snap.total.to_string(), theme::bold(FG)),
        Span::styled(" devices  ", theme::muted()),
        Span::styled(snap.responding.to_string(), theme::bold(GREEN)),
        Span::styled(" responding", theme::muted()),
        Span::styled("   │   ", theme::faint()),
    ];
    if snap.tailnet_total > 0 {
        right.splice(
            right.len() - 1..right.len() - 1,
            [
                Span::styled("   │   ", theme::faint()),
                Span::styled(snap.tailnet_total.to_string(), theme::bold(FG)),
                Span::styled(" on tailnet  ", theme::muted()),
                Span::styled(snap.tailnet_online.to_string(), theme::bold(GREEN)),
                Span::styled(" online", theme::muted()),
            ],
        );
    }
    right.extend(status);
    right.push(Span::raw(" "));

    // Where we are, most important first; whatever does not fit is left out
    // rather than drawn underneath the status.
    let mut place = vec![Span::styled(t.subnet.to_string(), theme::text())];
    if let Some(i) = &t.interface {
        place.insert(0, Span::styled(i.clone(), theme::text()));
    }
    if let Some(g) = t.gateway {
        place.push(Span::styled(format!("gateway {g}"), theme::muted()));
    }
    let budget = (area.width as usize).saturating_sub(Line::from(right.clone()).width() + 2);
    let by_priority = |s: &Span| {
        if s.content.starts_with("gateway") {
            2
        } else if Some(s.content.as_ref()) == t.interface.as_deref() {
            1
        } else {
            0
        }
    };
    for keep in (0..=2).rev() {
        let fits: Vec<Span> = place
            .iter()
            .filter(|s| by_priority(s) <= keep)
            .cloned()
            .collect();
        let mut candidate = left.clone();
        for (i, span) in fits.into_iter().enumerate() {
            if i > 0 {
                candidate.push(Span::styled("  ·  ", theme::faint()));
            }
            candidate.push(span);
        }
        if Line::from(candidate.clone()).width() <= budget || keep == 0 {
            left = candidate;
            break;
        }
    }

    let row = Rect { height: 1, ..area };
    f.render_widget(Paragraph::new(Line::from(left)), row);
    f.render_widget(
        Paragraph::new(Line::from(right)).alignment(Alignment::Right),
        row,
    );
}

// ── device list ─────────────────────────────────────────────────────────

fn draw_list(f: &mut Frame, app: &mut App, snap: &Snapshot, area: Rect) {
    let focused = app.focus == Focus::List && !app.filtering;
    let mut heading = vec![
        title("Devices"),
        Span::styled(format!("{} ", snap.entries.len()), theme::bold(ACCENT)),
    ];
    if app.filtering || !app.filter.is_empty() {
        heading.push(Span::raw(" "));
        heading.push(Span::styled(" / ", theme::key()));
        heading.push(Span::styled(
            format!(" {}", app.filter),
            theme::bold(if app.filtering { ACCENT } else { FG }),
        ));
        if app.filtering {
            heading.push(Span::styled("▏", theme::bold(ACCENT)));
        }
        heading.push(Span::raw(" "));
    }
    let corner = format!(
        " sorted by {}{} ",
        app.sort.label(),
        if app.reverse { ", reversed" } else { "" }
    );
    let block = panel(Line::from(heading), focused || app.filtering)
        .title_bottom(Line::from(Span::styled(corner, theme::faint())).right_aligned());
    let inner = block.inner(area);
    f.render_widget(block, area);

    if snap.entries.is_empty() {
        draw_empty(f, app, snap, inner);
        return;
    }
    let widths = [
        Constraint::Length(1),
        Constraint::Fill(3),
        Constraint::Length(13),
        Constraint::Fill(2),
        Constraint::Length(15),
        Constraint::Length(if inner.width >= 110 { 20 } else { 14 }),
    ];
    // Laid out as the table will, less the one-cell highlight column, so
    // heading and port clicks can be placed.
    let columns = Layout::horizontal(widths)
        .flex(Flex::Start)
        .spacing(COLUMN_SPACING)
        .split(Rect {
            x: inner.x + 1,
            width: inner.width.saturating_sub(1),
            ..inner
        });
    for (i, c) in columns.iter().enumerate() {
        app.areas.columns[i] = *c;
    }
    let header = Row::new(COLUMNS.iter().map(|(name, sort)| {
        if sort.is_some() && *sort == Some(app.sort) {
            let arrow = if app.reverse { "▴" } else { "▾" };
            Cell::from(Span::styled(format!("{name} {arrow}"), theme::bold(ACCENT)))
        } else {
            Cell::from(Span::styled(*name, theme::bold(MUTED)))
        }
    }));
    let ports_width = columns[PORTS].width;
    let rows = snap.entries.iter().map(|e| match e {
        Entry::Lan(r) => device_row(r, ports_width),
        Entry::Peer(r) => peer_row(r, ports_width),
    });
    let table = Table::new(rows, widths)
        .header(header)
        .flex(Flex::Start)
        .column_spacing(COLUMN_SPACING)
        .row_highlight_style(Style::new().bg(SELECTED).add_modifier(Modifier::BOLD))
        .highlight_symbol(Text::from(vec![
            Line::styled("▌", theme::bold(ACCENT)),
            Line::styled("▌", theme::bold(ACCENT)),
        ]))
        .highlight_spacing(HighlightSpacing::Always);
    let mut state = TableState::default().with_selected(app.selected_index(snap));
    f.render_stateful_widget(table, inner, &mut state);
    app.areas.list = inner;
    app.areas.list_offset = state.offset();
    app.areas.list_first_row = inner.y + 1;
}

const COLUMN_SPACING: u16 = 2;

/// The sort for a click on the list's heading row.
pub fn heading_hit(app: &App, at: Position) -> Option<Sort> {
    let i = app
        .areas
        .columns
        .iter()
        .position(|c| at.x >= c.x && at.x < c.x + c.width)?;
    COLUMNS[i].1
}

/// The port under a click on a device's row, if the click is on a number.
pub fn port_hit(app: &App, ports: &BTreeSet<u16>, at: Position) -> Option<u16> {
    let col = app.areas.columns[PORTS];
    let first = app.areas.list_first_row;
    if at.x < col.x || at.x >= col.x + col.width || at.y < first {
        return None;
    }
    let ports: Vec<u16> = ports.iter().copied().collect();
    let line = &port_lines(&ports, col.width)[((at.y - first) % ROW_HEIGHT) as usize];
    let offset = (at.x - col.x) as usize;
    let mut start = 0;
    for token in line.split(' ') {
        if (start..start + token.len()).contains(&offset) {
            return token.parse().ok();
        }
        start += token.len() + 1;
    }
    None
}

fn kind_span(c: &Classification) -> Span<'static> {
    let (color, _) = theme::family(c.kind);
    match c.confidence {
        Confidence::None => Span::styled("–", theme::faint()),
        Confidence::Guess => Span::styled(
            format!("{}?", c.kind.label()),
            Style::new().fg(color).add_modifier(Modifier::DIM),
        ),
        _ => Span::styled(c.kind.label(), Style::new().fg(color)),
    }
}

fn status_dot(up: bool) -> Span<'static> {
    if up {
        Span::styled("●", Style::new().fg(GREEN))
    } else {
        Span::styled("○", theme::faint())
    }
}

fn two_lines(top: impl Into<Line<'static>>, bottom: impl Into<Line<'static>>) -> Cell<'static> {
    Cell::from(Text::from(vec![top.into(), bottom.into()]))
}

/// Port numbers packed into the column's two lines, ending in “+N” when
/// some do not fit.
fn port_lines(ports: &[u16], width: u16) -> [String; 2] {
    let width = width as usize;
    let mut lines = [String::new(), String::new()];
    let mut line = 0;
    for (i, p) in ports.iter().enumerate() {
        let text = p.to_string();
        // The last line keeps room for the “+N” that follows it.
        let after = ports.len() - i - 1;
        let reserve = if line == 1 && after > 0 {
            format!(" +{after}").len()
        } else {
            0
        };
        let sep = usize::from(!lines[line].is_empty());
        if lines[line].len() + sep + text.len() + reserve <= width {
            if sep == 1 {
                lines[line].push(' ');
            }
            lines[line].push_str(&text);
        } else if line == 0 {
            line = 1;
            let reserve = if after > 0 {
                format!(" +{after}").len()
            } else {
                0
            };
            if text.len() + reserve <= width {
                lines[1].push_str(&text);
                continue;
            }
            lines[1] = format!("+{}", after + 1);
            break;
        } else {
            lines[1].push_str(&format!(" +{}", after + 1));
            break;
        }
    }
    lines
}

/// Port numbers underlined as links; a trailing “+N” is left plain.
fn port_links(line: String) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, token) in line.split(' ').enumerate() {
        if i > 0 {
            spans.push(Span::raw(" "));
        }
        let style = if token.starts_with('+') {
            theme::muted()
        } else {
            Style::new().fg(CYAN).add_modifier(Modifier::UNDERLINED)
        };
        spans.push(Span::styled(token.to_string(), style));
    }
    Line::from(spans)
}

fn device_row(r: &DeviceRow, ports_width: u16) -> Row<'static> {
    let d = &r.device;
    let (name, named) = labels::display_name(r);
    let mut name = vec![Span::styled(
        name,
        if named { theme::text() } else { theme::muted() },
    )];
    if d.is_gateway {
        name.push(Span::styled("  gateway", Style::new().fg(YELLOW)));
    }
    if d.is_self {
        name.push(Span::styled("  this device", Style::new().fg(CYAN)));
    }
    if r.peer.is_some() {
        name.push(Span::styled("  ◇ tailnet", Style::new().fg(VIOLET)));
    }
    let vendor = match &r.class.vendor {
        Vendor::Known(v) => Span::styled(*v, theme::text()),
        Vendor::Private => Span::styled("private MAC", theme::muted()),
        Vendor::Unknown => Span::styled("–", theme::faint()),
    };
    let mac = Span::styled(d.mac.clone().unwrap_or_default(), theme::faint());
    let services = Span::styled(labels::services(d).join(" · "), theme::faint());
    let product = match &r.class.product {
        Some(p) if r.class.confidence != Confidence::Guess => {
            Span::styled(p.clone(), theme::faint())
        }
        _ => Span::raw(""),
    };
    let tailscale_ip = r
        .peer
        .as_ref()
        .and_then(|p| p.ipv4())
        .map(|ip| Span::styled(ip.to_string(), Style::new().fg(VIOLET)))
        .unwrap_or_default();
    let ports = port_cell(&d.open_ports, ports_width);
    Row::new(vec![
        Cell::from(status_dot(d.responding)),
        two_lines(name, services),
        two_lines(kind_span(&r.class), product),
        two_lines(vendor, mac),
        two_lines(Span::styled(d.ip.to_string(), theme::text()), tailscale_ip),
        ports,
    ])
    .height(ROW_HEIGHT)
}

fn port_cell(ports: &BTreeSet<u16>, width: u16) -> Cell<'static> {
    if ports.is_empty() {
        two_lines(Span::styled("–", theme::faint()), "")
    } else {
        let [top, bottom] = port_lines(&ports.iter().copied().collect::<Vec<_>>(), width);
        two_lines(port_links(top), port_links(bottom))
    }
}

/// A tailnet peer not seen on this network.
fn peer_row(r: &PeerRow, ports_width: u16) -> Row<'static> {
    let p = &r.peer;
    let mut name = vec![Span::styled(
        p.short_name().to_string(),
        if p.online {
            theme::text()
        } else {
            theme::muted()
        },
    )];
    if p.is_self {
        name.push(Span::styled("  this device", Style::new().fg(CYAN)));
    }
    if p.exit_node {
        name.push(Span::styled("  exit node", Style::new().fg(YELLOW)));
    }
    name.push(Span::styled("  ◇ tailnet", Style::new().fg(VIOLET)));
    let about = Line::from(vec![
        Span::styled(p.os.clone(), theme::muted()),
        Span::styled(" · ", theme::faint()),
        Span::styled(
            peer_seen(p),
            if p.online {
                Style::new().fg(GREEN)
            } else {
                theme::faint()
            },
        ),
    ]);
    let ip = p
        .ipv4()
        .map(|ip| Span::styled(ip.to_string(), Style::new().fg(VIOLET)))
        .unwrap_or_else(|| Span::styled("–", theme::faint()));
    let (services, ports) = match &r.device {
        Some(d) => (
            labels::services(d).join(" · "),
            port_cell(&d.open_ports, ports_width),
        ),
        None => (
            String::new(),
            two_lines(Span::styled("–", theme::faint()), ""),
        ),
    };
    let product = match &r.class.product {
        Some(p) if r.class.confidence != Confidence::Guess => {
            Span::styled(p.clone(), theme::faint())
        }
        _ => Span::raw(""),
    };
    Row::new(vec![
        Cell::from(status_dot(p.online)),
        two_lines(name, Span::styled(services, theme::faint())),
        two_lines(kind_span(&r.class), product),
        two_lines(Span::styled("–", theme::faint()), about),
        two_lines(ip, Span::styled("not on this LAN", theme::faint())),
        ports,
    ])
    .height(ROW_HEIGHT)
}

fn peer_seen(p: &crate::inventory::Peer) -> String {
    if p.online {
        "online".into()
    } else {
        p.last_seen.map(fmt_ago).unwrap_or_else(|| "never".into())
    }
}

fn draw_empty(f: &mut Frame, app: &App, snap: &Snapshot, area: Rect) {
    let lines = if !app.filter.is_empty() && snap.total + snap.tailnet_total > 0 {
        vec![
            Line::styled(format!("Nothing matches “{}”", app.filter), theme::text()),
            Line::styled("Esc clears the filter", theme::muted()),
        ]
    } else if matches!(app.phase(), Phase::Scanning | Phase::Stopping) {
        vec![
            Line::from(vec![
                Span::styled(spinner(app), theme::bold(ACCENT)),
                Span::styled("  Looking for devices…", theme::text()),
            ]),
            Line::styled("They appear here as they answer", theme::muted()),
        ]
    } else {
        vec![
            Line::styled("No devices found", theme::text()),
            Line::styled("Press r to scan again", theme::muted()),
        ]
    };
    let top = area.y + area.height.saturating_sub(lines.len() as u16) / 2;
    let rect = Rect {
        y: top,
        height: lines.len() as u16,
        ..area
    };
    f.render_widget(Paragraph::new(lines).alignment(Alignment::Center), rect);
}

// ── detail ──────────────────────────────────────────────────────────────

fn draw_detail(f: &mut Frame, app: &mut App, snap: &Snapshot, area: Rect) {
    let focused = app.focus == Focus::Detail || app.zoom;
    let selected = app.selected_index(snap);
    let (subtitle, lines) = match selected.map(|i| &snap.entries[i]) {
        Some(Entry::Lan(r)) => (
            r.device.ip.to_string(),
            Some(detail_lines(r, area.width.saturating_sub(4))),
        ),
        Some(Entry::Peer(r)) => (
            r.peer.ipv4().map(|ip| ip.to_string()).unwrap_or_default(),
            Some(peer_lines(r, area.width.saturating_sub(4))),
        ),
        None => (String::new(), None),
    };
    let heading = Line::from(vec![
        title("Details"),
        Span::styled(format!("{subtitle} "), theme::muted()),
    ]);
    let block = panel(heading, focused);
    let inner = block.inner(area);
    f.render_widget(block, area);
    app.areas.detail = area;

    let Some(lines) = lines else {
        f.render_widget(
            Paragraph::new(Line::styled("Select a device", theme::muted()))
                .alignment(Alignment::Center),
            inner.inner(Margin::new(0, inner.height / 2)),
        );
        return;
    };
    let max_scroll = (lines.len() as u16).saturating_sub(inner.height);
    app.detail_scroll = app.detail_scroll.min(max_scroll);
    f.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0)),
        inner,
    );
}

/// What the classifier concluded and why, for both kinds of detail view.
fn classification_lines(out: &mut Vec<Line<'static>>, c: &Classification) {
    section(out, "Classification");
    if c.confidence == Confidence::None {
        out.push(Line::styled(
            "Not enough evidence to say what this is",
            theme::muted(),
        ));
        return;
    }
    let (color, _) = theme::family(c.kind);
    let mut head = vec![Span::styled(c.kind.label(), theme::bold(color))];
    if let Some(p) = &c.product {
        head.push(Span::styled(format!("  {p}"), theme::text()));
    }
    let conf_color = match c.confidence {
        Confidence::Confident => GREEN,
        Confidence::Likely => ACCENT,
        _ => YELLOW,
    };
    head.push(Span::raw("  "));
    head.push(Span::styled(
        format!(" {} ", c.confidence.label()),
        theme::chip(conf_color),
    ));
    out.push(Line::from(head));
    for reason in c.reasons.iter().take(6) {
        out.push(Line::from(vec![
            Span::styled("  · ", theme::faint()),
            Span::styled(reason.clone(), theme::muted()),
        ]));
    }
    if let Some(alt) = c.alternative {
        out.push(Line::from(vec![
            Span::styled("  could also be ", theme::faint()),
            Span::styled(alt.label().to_lowercase(), theme::muted()),
        ]));
    }
}

fn peer_lines(r: &PeerRow, width: u16) -> Vec<Line<'static>> {
    let p = &r.peer;
    let mut out = vec![Line::styled(p.short_name().to_string(), theme::bold(FG))];
    let mut badges = vec![if p.online {
        Span::styled("● online", Style::new().fg(GREEN))
    } else {
        Span::styled(
            format!("○ offline · last seen {}", peer_seen(p)),
            theme::muted(),
        )
    }];
    if p.is_self {
        badges.push(Span::styled("   ◆ this device", Style::new().fg(CYAN)));
    }
    if p.exit_node {
        badges.push(Span::styled(
            "   ◆ exit node in use",
            Style::new().fg(YELLOW),
        ));
    }
    out.push(Line::from(badges));
    out.push(Line::raw(""));
    classification_lines(&mut out, &r.class);
    out.push(Line::raw(""));

    section(&mut out, "Tailscale");
    field(&mut out, "MagicDNS", p.dns_name.clone());
    field(&mut out, "Hostname", p.hostname.clone());
    field(&mut out, "OS", p.os.clone());
    for (i, ip) in p.ips.iter().enumerate() {
        field(
            &mut out,
            if i == 0 { "Addresses" } else { "" },
            ip.to_string(),
        );
    }
    out.push(Line::raw(""));

    if let Some(d) = &r.device {
        ports_section(&mut out, &d.open_ports, width);
        reports_section(&mut out, d);
    }

    section(&mut out, "On this LAN");
    out.push(Line::styled(
        "Not seen on this network (remote, or its name differs here)",
        theme::muted(),
    ));
    out
}

/// Open ports as chips, wrapped to `width`.
fn ports_section(out: &mut Vec<Line<'static>>, ports: &BTreeSet<u16>, width: u16) {
    section(out, "Open ports");
    if ports.is_empty() {
        out.push(Line::styled(
            "None of the probed ports answered",
            theme::muted(),
        ));
    } else {
        let chips = ports.iter().map(|p| {
            let text = match labels::port(*p) {
                Some(name) => format!(" {p} {name} "),
                None => format!(" {p} "),
            };
            Span::styled(text, theme::chip(CYAN))
        });
        out.extend(wrap_chips(chips.collect(), width));
    }
    out.push(Line::raw(""));
}

/// What the device, or software on it, said about itself.
fn reports_section(out: &mut Vec<Line<'static>>, d: &Device) {
    for i in &d.info {
        section(out, "Device reports");
        for (label, value) in [
            ("Name", &i.name),
            ("Product", &i.product),
            ("Model", &i.model),
            ("Firmware", &i.firmware),
            ("MAC", &i.mac.clone().filter(|m| Some(m) != d.mac.as_ref())),
        ] {
            if let Some(v) = value {
                field(out, label, v.clone());
            }
        }
        for detail in &i.details {
            field(out, detail.label, detail.value.clone());
        }
        out.push(Line::from(vec![
            Span::styled(format!("{:<12}", ""), theme::muted()),
            Span::styled(format!("from {}", i.from), theme::faint()),
        ]));
        out.push(Line::raw(""));
    }
}

fn detail_lines(r: &DeviceRow, width: u16) -> Vec<Line<'static>> {
    let d = &r.device;
    let mut out = Vec::new();
    let name = labels::name(d);
    out.push(Line::styled(labels::display_name(r).0, theme::bold(FG)));
    let mut badges = vec![if d.responding {
        Span::styled("● responding", Style::new().fg(GREEN))
    } else {
        Span::styled("○ stale ARP entry only", theme::muted())
    }];
    if d.is_gateway {
        badges.push(Span::styled("   ◆ gateway", Style::new().fg(YELLOW)));
    }
    if d.is_self {
        badges.push(Span::styled("   ◆ this device", Style::new().fg(CYAN)));
    }
    out.push(Line::from(badges));
    out.push(Line::raw(""));

    classification_lines(&mut out, &r.class);
    out.push(Line::raw(""));

    section(&mut out, "Identity");
    field(&mut out, "Address", d.ip.to_string());
    field(
        &mut out,
        "MAC",
        d.mac.clone().unwrap_or_else(|| "unknown".into()),
    );
    field(
        &mut out,
        "Vendor",
        match &r.class.vendor {
            Vendor::Known(v) => v.to_string(),
            Vendor::Private => "none: a private (randomized) address".into(),
            Vendor::Unknown => "unknown".into(),
        },
    );
    // Every name, with how it was learned; one per line when they differ.
    for (i, (via, name)) in d.names.iter().enumerate() {
        out.push(Line::from(vec![
            Span::styled(
                format!("{:<12}", if i == 0 { "Names" } else { "" }),
                theme::muted(),
            ),
            Span::styled(name.clone(), theme::text()),
            Span::styled(format!("  {}", via.label()), theme::faint()),
        ]));
    }
    if let Some(group) = &d.workgroup {
        field(&mut out, "Workgroup", group.clone());
    }
    field(
        &mut out,
        "Seen",
        format!(
            "first {} · last {}",
            fmt_ago(d.first_seen),
            fmt_ago(d.last_seen)
        ),
    );
    out.push(Line::raw(""));

    if let Some(p) = &r.peer {
        section(&mut out, "Tailscale");
        field(&mut out, "MagicDNS", p.dns_name.clone());
        field(
            &mut out,
            "Address",
            p.ipv4().map(|ip| ip.to_string()).unwrap_or_default(),
        );
        field(&mut out, "OS", format!("{} · {}", p.os, peer_seen(p)));
        out.push(Line::raw(""));
    }

    ports_section(&mut out, &d.open_ports, width);

    reports_section(&mut out, d);

    section(&mut out, "Services");
    if d.mdns_services.is_empty() {
        out.push(Line::styled("Nothing advertised over mDNS", theme::muted()));
    }
    for s in &d.mdns_services {
        let label = labels::service(&s.service_type).unwrap_or("Service");
        let ty = s.service_type.trim_end_matches(".local.");
        out.push(Line::from(vec![
            Span::styled(format!("{label:<12}"), theme::bold(VIOLET)),
            Span::styled(format!("{ty}  :{}", s.port), theme::muted()),
        ]));
        if !s.instance.is_empty() && Some(&s.instance) != name.as_ref() {
            out.push(Line::from(vec![
                Span::raw("            "),
                Span::styled(s.instance.clone(), theme::text()),
            ]));
        }
        let txt: Vec<String> = s
            .txt
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .take(4)
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        if !txt.is_empty() {
            out.push(Line::from(vec![
                Span::raw("            "),
                Span::styled(txt.join("  "), theme::faint()),
            ]));
        }
    }
    out.push(Line::raw(""));

    section(&mut out, "Evidence");
    for (source, summary) in evidence_summary(d) {
        out.push(Line::from(vec![
            Span::styled(format!("{source:<12}"), theme::muted()),
            Span::styled(summary, theme::text()),
        ]));
    }
    out
}

/// One line per source. Open ports have their own section, so TCP findings
/// are condensed to counts; everything else is listed as found.
fn evidence_summary(d: &Device) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, Vec<String>, usize, usize)> = Vec::new();
    for e in &d.evidence {
        let i = match out.iter().position(|(s, ..)| *s == e.source) {
            Some(i) => i,
            None => {
                out.push((e.source, Vec::new(), 0, 0));
                out.len() - 1
            }
        };
        let entry = &mut out[i];
        if e.detail.starts_with("TCP ") && e.detail.ends_with(" refused") {
            entry.2 += 1;
        } else if e.detail.starts_with("TCP ") && e.detail.ends_with(" open") {
            entry.3 += 1;
        } else if !(e.detail.starts_with("TCP ") && e.detail.ends_with(" accepted")) {
            entry.1.push(e.detail.clone());
        }
    }
    out.into_iter()
        .map(|(source, mut notes, refused, open)| {
            let plural = |n: usize| if n == 1 { "port" } else { "ports" };
            if open > 0 {
                notes.push(format!("{open} open {}", plural(open)));
            }
            if refused > 0 {
                notes.push(format!("{refused} closed {} answered", plural(refused)));
            }
            (source, notes.join(" · "))
        })
        .collect()
}

fn section(out: &mut Vec<Line<'static>>, name: &str) {
    out.push(Line::styled(name.to_uppercase(), theme::bold(ACCENT)));
}

fn field(out: &mut Vec<Line<'static>>, name: &str, value: String) {
    out.push(Line::from(vec![
        Span::styled(format!("{name:<12}"), theme::muted()),
        Span::styled(value, theme::text()),
    ]));
}

/// Lays chips out left to right, one space apart, breaking between chips.
fn wrap_chips(chips: Vec<Span<'static>>, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut line: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;
    for chip in chips {
        let w = chip.width();
        if used > 0 && used + 1 + w > width as usize {
            lines.push(Line::from(std::mem::take(&mut line)));
            used = 0;
        }
        if used > 0 {
            line.push(Span::raw(" "));
            used += 1;
        }
        used += w;
        line.push(chip);
    }
    if !line.is_empty() {
        lines.push(Line::from(line));
    }
    lines
}

// ── subnet map ──────────────────────────────────────────────────────────

fn map_columns(count: u32) -> u32 {
    count.clamp(1, 32)
}

/// Grid rows for the target subnet, or 0 when it is too large to draw.
fn map_rows(app: &App) -> u16 {
    let count = address_count(app);
    if count > MAP_MAX_ADDRESSES {
        return 0;
    }
    count.div_ceil(map_columns(count)) as u16
}

fn address_count(app: &App) -> u32 {
    1u32 << (32 - app.target.subnet.prefix_len())
}

fn draw_map(f: &mut Frame, app: &mut App, snap: &Snapshot, area: Rect) {
    let heading = Line::from(vec![
        title("Subnet"),
        Span::styled(format!("{} ", app.target.subnet), theme::muted()),
    ]);
    let block = panel(heading, false);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let count = address_count(app);
    let cols = map_columns(count);
    let cell_width: u16 = if inner.width >= cols as u16 * 2 { 2 } else { 1 };
    let network = u32::from(app.target.subnet.network());
    let selected = app.highlighted(snap);

    let mut lines = Vec::new();
    for row in 0..count.div_ceil(cols) {
        let mut spans = Vec::new();
        for col in 0..cols {
            let index = row * cols + col;
            if index >= count {
                break;
            }
            let ip = Ipv4Addr::from(network + index);
            let row = snap
                .entries
                .iter()
                .filter_map(Entry::lan)
                .find(|r| r.device.ip == ip);
            let (glyph, mut style) = match row {
                None => ("·", theme::faint()),
                Some(r) => {
                    let (color, _) = theme::family(r.class.kind);
                    // Hollow when only a stale ARP entry vouches for it.
                    let glyph = if r.device.responding { "■" } else { "□" };
                    (glyph, Style::new().fg(color))
                }
            };
            if Some(ip) == selected {
                style = style.bg(SELECTED).add_modifier(Modifier::BOLD);
                spans.push(Span::styled(
                    if cell_width == 2 { "◆ " } else { "◆" },
                    style.fg(ACCENT),
                ));
                continue;
            }
            spans.push(Span::styled(glyph, style));
            if cell_width == 2 {
                spans.push(Span::raw(" "));
            }
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::raw(""));
    let legend = |color: Color, label: &'static str| {
        [
            Span::styled("■ ", Style::new().fg(color)),
            Span::styled(label, theme::muted()),
            Span::raw("   "),
        ]
    };
    let mut key = Vec::new();
    for kind in [
        Kind::Router,
        Kind::Computer,
        Kind::Phone,
        Kind::Tv,
        Kind::SmartDevice,
        Kind::Printer,
        Kind::Unknown,
    ] {
        let (color, label) = theme::family(kind);
        key.extend(legend(color, label));
    }
    lines.push(Line::from(key));
    lines.push(Line::from(vec![
        Span::styled("□ ", theme::muted()),
        Span::styled("stale ARP entry   ", theme::muted()),
        Span::styled("◆ ", theme::bold(ACCENT)),
        Span::styled("selected", theme::muted()),
    ]));

    f.render_widget(Paragraph::new(lines), inner);
    app.areas.map = Rect {
        height: count.div_ceil(cols) as u16,
        width: (cols as u16 * cell_width).min(inner.width),
        ..inner
    };
    app.areas.map_cell_width = cell_width;
}

/// The address under a map click, if any.
pub fn map_hit(app: &App, at: Position) -> Option<Ipv4Addr> {
    let a = app.areas.map;
    if !a.contains(at) || app.areas.map_cell_width == 0 {
        return None;
    }
    let count = address_count(app);
    let cols = map_columns(count);
    let col = ((at.x - a.x) / app.areas.map_cell_width) as u32;
    let index = (at.y - a.y) as u32 * cols + col;
    (index < count).then(|| Ipv4Addr::from(u32::from(app.target.subnet.network()) + index))
}

// ── scan stages ─────────────────────────────────────────────────────────

fn stage_name(source: &str) -> &'static str {
    match source {
        "tailscale" => "Tailscale",
        "tuya" => "Tuya",
        "neighbors" => "ARP table",
        "tcp-sweep" => "TCP sweep",
        "names" => "Names",
        "port-probe" => "Port probe",
        "tailnet-probe" => "Tailnet probe",
        "mdns" => "mDNS",
        "device-info" => "Device info",
        _ => "Source",
    }
}

fn draw_stages(f: &mut Frame, app: &App, snap: &Snapshot, area: Rect) {
    let block = panel(title("Scan"), false);
    let inner = block.inner(area);
    f.render_widget(block, area);
    if snap.sources.is_empty() {
        return;
    }
    let slots = Layout::horizontal(vec![Constraint::Fill(1); snap.sources.len()])
        .spacing(2)
        .split(Rect { height: 1, ..inner });
    for ((name, state), slot) in snap.sources.iter().zip(slots.iter()) {
        let progress = snap
            .progress
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, p)| *p);
        f.render_widget(
            Paragraph::new(stage_line(app, name, state, progress, slot.width)),
            *slot,
        );
    }

    // Second line: what the active stage is doing, or how the last one ended.
    let active = snap
        .sources
        .iter()
        .find(|(_, s)| matches!(s, SourceState::Running(_)))
        .or_else(|| {
            snap.sources.iter().rev().find(|(_, s)| {
                matches!(
                    s,
                    SourceState::Done(_) | SourceState::Failed(_) | SourceState::Unavailable(_)
                )
            })
        });
    if let Some((name, state)) = active
        && let SourceState::Running(detail)
        | SourceState::Done(detail)
        | SourceState::Failed(detail)
        | SourceState::Unavailable(detail) = state
    {
        let line = Line::from(vec![
            Span::styled(format!("{}  ", stage_name(name)), theme::muted()),
            Span::styled(detail.clone(), theme::faint()),
        ]);
        f.render_widget(
            Paragraph::new(line),
            Rect {
                y: inner.y + 1,
                height: 1,
                ..inner
            },
        );
    }
}

fn stage_line(
    app: &App,
    name: &str,
    state: &SourceState,
    progress: Option<(usize, usize)>,
    width: u16,
) -> Line<'static> {
    let label = stage_name(name);
    let (icon, icon_style, rest): (String, Style, Vec<Span<'static>>) = match state {
        SourceState::Pending => (
            "○".into(),
            theme::faint(),
            vec![Span::styled(" waiting", theme::faint())],
        ),
        SourceState::Running(_) => {
            let bar_width = (width as usize).saturating_sub(label.len() + 8).min(24);
            let (done, total) = progress.unwrap_or((0, 0));
            let ratio = if total == 0 {
                0.0
            } else {
                done as f64 / total as f64
            };
            let filled = (ratio * bar_width as f64).round() as usize;
            (
                spinner(app).into(),
                theme::bold(ACCENT),
                vec![
                    Span::raw(" "),
                    Span::styled("━".repeat(filled), Style::new().fg(ACCENT)),
                    Span::styled("─".repeat(bar_width - filled), theme::faint()),
                    Span::styled(format!(" {:>3}%", (ratio * 100.0) as u32), theme::muted()),
                ],
            )
        }
        SourceState::Done(_) => (
            "✓".into(),
            theme::bold(GREEN),
            vec![Span::styled(" done", theme::muted())],
        ),
        SourceState::Unavailable(_) => (
            "–".into(),
            theme::bold(YELLOW),
            vec![Span::styled(" unavailable", Style::new().fg(YELLOW))],
        ),
        SourceState::Failed(_) => (
            "✕".into(),
            theme::bold(RED),
            vec![Span::styled(" failed", Style::new().fg(RED))],
        ),
        SourceState::Skipped => (
            "–".into(),
            theme::faint(),
            vec![Span::styled(" skipped", theme::faint())],
        ),
        SourceState::Stopped => (
            "■".into(),
            theme::bold(YELLOW),
            vec![Span::styled(" stopped", Style::new().fg(YELLOW))],
        ),
    };
    let label_style = match state {
        SourceState::Running(_) => theme::bold(FG),
        SourceState::Pending | SourceState::Skipped => theme::faint(),
        _ => theme::text(),
    };
    let mut spans = vec![
        Span::styled(icon, icon_style),
        Span::styled(format!(" {label}"), label_style),
    ];
    spans.extend(rest);
    Line::from(spans)
}

// ── footer and help ─────────────────────────────────────────────────────

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let keys: &[(&str, &str)] = if app.filtering {
        &[
            ("type", "filter"),
            ("↵", "keep"),
            ("esc", "clear"),
            ("↑↓", "select"),
        ]
    } else if app.zoom || app.focus == Focus::Detail {
        &[
            ("↑↓", "scroll"),
            ("esc", "back"),
            ("⇥", "list"),
            ("?", "help"),
            ("q", "quit"),
        ]
    } else {
        &[
            ("↑↓", "select"),
            ("↵", "details"),
            ("/", "filter"),
            ("o", "sort"),
            ("s", "stop"),
            ("r", "rescan"),
            ("?", "help"),
            ("q", "quit"),
        ]
    };
    let toast = app.current_toast();
    let budget = area.width as usize - toast.map_or(0, |t| t.chars().count() + 2);
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1;
    for (k, what) in keys {
        let key = format!(" {k} ");
        let label = format!(" {what}   ");
        // Hints are in priority order; stop at the first that doesn't fit.
        let w = key.chars().count() + label.trim_end().chars().count();
        if used + w > budget {
            break;
        }
        used += w + 3;
        spans.push(Span::styled(key, theme::key()));
        spans.push(Span::styled(label, theme::muted()));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
    if let Some(toast) = toast {
        f.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                format!("{toast} "),
                theme::bold(ACCENT),
            )]))
            .alignment(Alignment::Right),
            area,
        );
    }
}

fn draw_help(f: &mut Frame, area: Rect) {
    let rows: &[(&str, &str)] = &[
        ("↑ ↓  j k", "Move through devices"),
        ("PgUp PgDn  g G", "Jump a page, or to either end"),
        ("↵  →  l", "Open details (scroll with ↑ ↓)"),
        ("esc  ←  h", "Back to the list"),
        ("⇥", "Switch between list and details"),
        ("/", "Filter by name, type, vendor, address or port"),
        ("o", "Sort by address, name, type, vendor or ports"),
        ("s", "Stop the scan and keep what was found"),
        ("r", "Scan again from scratch"),
        ("mouse", "Click a row, a heading to sort, a port to open it"),
        ("q  ctrl-c", "Quit"),
    ];
    let mut lines = vec![Line::raw("")];
    for (k, what) in rows {
        lines.push(Line::from(vec![
            Span::styled(format!("  {k:>15}  "), theme::bold(ACCENT)),
            Span::styled(*what, theme::text()),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "  ● responding / online   ○ stale ARP entry / offline   ◇ tailnet",
        theme::muted(),
    ));
    lines.push(Line::styled(
        "  Nothing here needs root, and nothing is saved.",
        theme::muted(),
    ));
    lines.push(Line::raw(""));
    lines.push(Line::styled("  Press any key to close", theme::faint()));

    let w = 66.min(area.width);
    let h = (lines.len() as u16 + 2).min(area.height);
    let rect = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border(true))
        .title(title("Keys"))
        .style(Style::new().bg(SURFACE));
    f.render_widget(Paragraph::new(lines).block(block), rect);
}

// ── formatting ──────────────────────────────────────────────────────────

fn spinner(app: &App) -> &'static str {
    SPINNER[app.tick % SPINNER.len()]
}

fn fmt_elapsed(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

fn fmt_ago(t: SystemTime) -> String {
    let s = t.elapsed().unwrap_or_default().as_secs();
    match s {
        0..=1 => "just now".into(),
        2..=59 => format!("{s}s ago"),
        60..=3599 => format!("{}m ago", s / 60),
        _ => format!("{}h ago", s / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::{Event, Finding, FindingKind, Inventory, MdnsService};
    use crate::netif::Target;
    use crate::scan::Options;
    use crate::ui::Key;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    fn app() -> App {
        let target = Target {
            interface: Some("wlan0".into()),
            address: Some("10.0.0.20".parse().unwrap()),
            gateway: Some("10.0.0.1".parse().unwrap()),
            dns: vec![],
            subnet: "10.0.0.0/24".parse().unwrap(),
        };
        let mut inv = Inventory::new(target.subnet, target.address, target.gateway);
        let now = SystemTime::now();
        let mut found = |ip: [u8; 4], kind| {
            inv.apply(
                Event::Found(Finding {
                    ip: ip.into(),
                    source: "test",
                    kind,
                }),
                now,
            )
        };
        found([10, 0, 0, 1], FindingKind::Responded("x".into()));
        found([10, 0, 0, 1], FindingKind::OpenPort(443));
        found([10, 0, 0, 80], FindingKind::Mac("00:26:AB:00:00:01".into()));
        found([10, 0, 0, 80], FindingKind::OpenPort(631));
        found(
            [10, 0, 0, 80],
            FindingKind::Mdns(MdnsService {
                service_type: "_ipp._tcp.local.".into(),
                instance: "Office Printer".into(),
                host: "printer.local".into(),
                port: 631,
                txt: BTreeMap::new(),
            }),
        );
        found([10, 0, 0, 90], FindingKind::Cached);
        found(
            [10, 0, 0, 90],
            FindingKind::Name(crate::inventory::NameSource::Netbios, "ORION".into()),
        );
        let peer = |id: &str, host: &str, os: &str, online| crate::inventory::Peer {
            id: id.into(),
            hostname: host.into(),
            dns_name: format!("{host}.tail1234.ts.net"),
            os: os.into(),
            ips: vec![format!("100.64.0.{}", id.len()).parse().unwrap()],
            online,
            is_self: false,
            exit_node: false,
            shared_in: false,
            last_seen: None,
        };
        inv.apply(
            Event::Tailnet(vec![
                peer("a", "orion", "windows", true),
                peer("bb", "far-away", "linux", false),
            ]),
            now,
        );
        inv.apply(
            Event::Status("tcp-sweep", SourceState::Running("sweep".into())),
            now,
        );
        inv.apply(Event::Progress("tcp-sweep", 50, 100), now);
        let opts = Options {
            mdns_listen: Duration::from_secs(1),
            skip: vec![],
        };
        App::new(target, opts, Arc::new(Mutex::new(inv)))
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        let snap = app.snapshot();
        term.draw(|f| draw(f, app, &snap)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| (0..w).map(|x| buf[(x, y)].symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn wide_layout_shows_list_detail_map_and_stages() {
        let mut app = app();
        app.selected = Some(Key::Lan("10.0.0.80".parse().unwrap()));
        let screen = render(&mut app, 160, 44);
        for needle in [
            "eggprobe",
            "Devices",
            "Office Printer",
            "gateway",
            "Printer",
            "631 ipp",
            "Subnet",
            "TCP sweep",
            "50%",
            "00:26:AB:00:00:01",
            "CLASSIFICATION",
            "Epson",
            "confident",
        ] {
            assert!(screen.contains(needle), "missing {needle:?} in\n{screen}");
        }
        assert!(app.areas.map.width > 0 && app.areas.detail.width > 0);
    }

    #[test]
    fn detail_shows_what_the_device_reports() {
        let mut app = app();
        {
            let mut inv = app.inv.lock().unwrap();
            let now = std::time::SystemTime::now();
            let mut found = |ip: [u8; 4], kind| {
                inv.apply(
                    Event::Found(Finding {
                        ip: ip.into(),
                        source: "device-info",
                        kind,
                    }),
                    now,
                )
            };
            found([10, 0, 0, 40], FindingKind::OpenPort(80));
            found(
                [10, 0, 0, 40],
                FindingKind::Info(crate::inventory::DeviceInfo {
                    protocol: "wled",
                    from: "http://10.0.0.40/json/info".into(),
                    name: Some("Shelf Lights".into()),
                    product: Some("WLED".into()),
                    model: Some("Example Chip".into()),
                    firmware: Some("0.1.0 (build 2400000)".into()),
                    mac: None,
                    details: vec![crate::inventory::Detail {
                        label: "Wi-Fi",
                        value: "52% · -74 dBm · channel 1".into(),
                    }],
                }),
            );
        }
        app.selected = Some(Key::Lan("10.0.0.40".parse().unwrap()));
        let screen = render(&mut app, 160, 60);
        for needle in [
            "Shelf Lights",
            "DEVICE REPORTS",
            "Example Chip",
            "0.1.0 (build 2400000)",
            "52% · -74 dBm · channel 1",
            "from http://10.0.0.40/json/info",
            "WLED lights",
        ] {
            assert!(screen.contains(needle), "missing {needle:?} in\n{screen}");
        }
    }

    #[test]
    fn probed_peers_show_ports_and_reports() {
        let mut app = app();
        {
            let mut inv = app.inv.lock().unwrap();
            let now = std::time::SystemTime::now();
            let ip: Ipv4Addr = "100.64.0.2".parse().unwrap();
            for kind in [
                FindingKind::OpenPort(32400),
                FindingKind::Info(crate::inventory::DeviceInfo {
                    protocol: "plex",
                    from: "http://100.64.0.2:32400/identity".into(),
                    name: None,
                    product: Some("Plex Media Server".into()),
                    model: None,
                    firmware: Some("1.2.3".into()),
                    mac: None,
                    details: vec![],
                }),
            ] {
                inv.apply(
                    Event::Found(Finding {
                        ip,
                        source: "tailnet-probe",
                        kind,
                    }),
                    now,
                );
            }
        }
        app.selected = Some(Key::Peer("bb".into()));
        let screen = render(&mut app, 160, 60);
        for needle in ["far-away", "32400", "Plex Media Server", "OPEN PORTS"] {
            assert!(screen.contains(needle), "missing {needle:?} in\n{screen}");
        }
    }

    #[test]
    fn narrow_layout_drops_side_panel() {
        let mut app = app();
        let screen = render(&mut app, 80, 24);
        assert!(screen.contains("Devices"));
        assert!(!screen.contains("Subnet"));
        assert_eq!(app.areas.detail.width, 0);
    }

    #[test]
    fn filter_narrows_the_list() {
        let mut app = app();
        app.filter = "printer".into();
        let snap = app.snapshot();
        assert_eq!(snap.entries.len(), 1);
        assert_eq!(snap.total, 3);
        app.filter = "631".into();
        assert_eq!(app.snapshot().entries.len(), 1);
        app.filter = "tailnet".into();
        assert_eq!(app.snapshot().entries.len(), 2);
    }

    #[test]
    fn map_click_resolves_the_address() {
        let mut app = app();
        render(&mut app, 160, 44);
        let a = app.areas.map;
        let cw = app.areas.map_cell_width;
        // Row 2, column 16 of a 32-wide grid is .80.
        let at = Position::new(a.x + 16 * cw, a.y + 2);
        assert_eq!(map_hit(&app, at), Some("10.0.0.80".parse().unwrap()));
    }

    #[test]
    fn tailnet_peers_join_the_device_list() {
        let mut app = app();
        // The LAN device matched by hostname takes Tailscale's word that it
        // runs Windows, and is listed once; the unmatched peer follows the
        // LAN devices.
        let snap = app.snapshot();
        let keys: Vec<Key> = snap.entries.iter().map(Entry::key).collect();
        assert_eq!(
            keys,
            vec![
                Key::Lan("10.0.0.1".parse().unwrap()),
                Key::Lan("10.0.0.80".parse().unwrap()),
                Key::Lan("10.0.0.90".parse().unwrap()),
                Key::Peer("bb".into()),
            ]
        );
        let linked = snap.entries[2].lan().unwrap();
        assert_eq!(linked.class.product.as_deref(), Some("Windows PC"));
        assert_eq!((snap.tailnet_total, snap.tailnet_online), (2, 1));

        app.selected = Some(Key::Peer("bb".into()));
        let screen = render(&mut app, 160, 44);
        for needle in [
            "ORION",
            "100.64.0.1",
            "far-away",
            "linux · never",
            "not on this LAN",
            "TAILSCALE",
        ] {
            assert!(screen.contains(needle), "missing {needle:?} in\n{screen}");
        }
        assert_eq!(app.highlighted(&app.snapshot()), None);
    }

    #[test]
    fn rows_show_port_numbers() {
        let mut app = app();
        for p in [22, 80, 8080, 9100] {
            app.inv.lock().unwrap().apply(
                Event::Found(Finding {
                    ip: [10, 0, 0, 80].into(),
                    source: "test",
                    kind: FindingKind::OpenPort(p),
                }),
                SystemTime::now(),
            );
        }
        let screen = render(&mut app, 80, 24);
        assert!(screen.contains("22 80 631 8080"), "{screen}");
        assert!(screen.contains("9100"), "{screen}");
    }

    #[test]
    fn clicking_headings_sorts_and_ports_resolve() {
        let mut app = app();
        render(&mut app, 160, 44);
        let heading_y = app.areas.list_first_row - 1;
        let vendor = app.areas.columns[3];
        assert_eq!(
            heading_hit(&app, Position::new(vendor.x, heading_y)),
            Some(Sort::Vendor)
        );
        assert_eq!(
            heading_hit(&app, Position::new(app.areas.columns[0].x, heading_y)),
            None
        );

        // The printer is the second row; its only port, 631, starts the column.
        let snap = app.snapshot();
        let Entry::Lan(printer) = &snap.entries[1] else {
            panic!()
        };
        let ports = app.areas.columns[PORTS];
        let y = app.areas.list_first_row + ROW_HEIGHT;
        assert_eq!(
            port_hit(
                &app,
                &printer.device.open_ports,
                Position::new(ports.x + 2, y)
            ),
            Some(631)
        );
        assert_eq!(
            port_hit(
                &app,
                &printer.device.open_ports,
                Position::new(ports.x + 3, y)
            ),
            None
        );
        assert_eq!(
            port_hit(
                &app,
                &printer.device.open_ports,
                Position::new(ports.x, y + 1)
            ),
            None
        );
    }

    #[test]
    fn ports_pack_into_two_lines() {
        assert_eq!(port_lines(&[22, 80, 443], 14), ["22 80 443", ""]);
        assert_eq!(
            port_lines(&[22, 80, 443, 8080, 8443, 9000, 9100, 10000], 14),
            ["22 80 443 8080", "8443 9000 +2"]
        );
        assert_eq!(
            port_lines(&[22, 80, 443, 8080, 8443], 9),
            ["22 80 443", "8080 8443"]
        );
    }

    #[test]
    fn chips_wrap_between_chips() {
        let chips = (0..6).map(|i| Span::raw(format!(" {i}{i}{i} "))).collect();
        let lines = wrap_chips(chips, 12);
        assert_eq!(lines.len(), 3);
    }
}
