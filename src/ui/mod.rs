//! The interactive interface. The scan runs on the async runtime; this thread
//! draws a snapshot of the inventory about ten times a second and handles
//! input between frames.

mod labels;
mod theme;
mod view;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::Result;
use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Position, Rect};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::classify::{self, Classification, Confidence};
use crate::inventory::{Device, Inventory, Peer, SourceName, SourceState, link_tailnet};
use crate::netif::Target;
use crate::oui::Vendor;
use crate::scan::{self, Shared};

const FRAME: Duration = Duration::from_millis(100);
const TOAST_FOR: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    Address,
    Name,
    Type,
    Vendor,
    Ports,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Sort::Address => Sort::Name,
            Sort::Name => Sort::Type,
            Sort::Type => Sort::Vendor,
            Sort::Vendor => Sort::Ports,
            Sort::Ports => Sort::Address,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Sort::Address => "address",
            Sort::Name => "name",
            Sort::Type => "type",
            Sort::Vendor => "vendor",
            Sort::Ports => "open ports",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Focus {
    List,
    Detail,
}

/// Where the scan stands, for the header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Idle,
    Scanning,
    Stopping,
    Done,
    Stopped,
}

struct Run {
    stop: watch::Sender<bool>,
    handle: JoinHandle<()>,
    started: Instant,
    finished: Option<Instant>,
    stopping: bool,
}

/// A LAN device with what the frame shows about it.
pub struct Row {
    pub device: Device,
    pub class: Classification,
    /// Its Tailscale identity, when it is also on the tailnet.
    pub peer: Option<Peer>,
}

/// A tailnet peer not seen on the LAN.
pub struct PeerRow {
    pub peer: Peer,
    pub class: Classification,
    /// What probing its Tailscale address found, if it was probed.
    pub device: Option<Device>,
}

/// One line of the device list: a LAN device (with its tailnet identity, if
/// matched), or a tailnet peer reachable only over Tailscale.
#[allow(clippy::large_enum_variant)] // built fresh each frame
pub enum Entry {
    Lan(Row),
    Peer(PeerRow),
}

/// What stays selected as the list grows and re-sorts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Key {
    Lan(Ipv4Addr),
    Peer(String),
}

impl Entry {
    pub fn key(&self) -> Key {
        match self {
            Entry::Lan(r) => Key::Lan(r.device.ip),
            Entry::Peer(r) => Key::Peer(r.peer.id.clone()),
        }
    }

    pub fn lan(&self) -> Option<&Row> {
        match self {
            Entry::Lan(r) => Some(r),
            Entry::Peer(_) => None,
        }
    }

    fn name(&self) -> (String, bool) {
        match self {
            Entry::Lan(r) => labels::display_name(r),
            Entry::Peer(r) => (r.peer.short_name().to_string(), true),
        }
    }

    /// Known vendors by name, then private MACs, then everything else.
    fn vendor(&self) -> (u8, String) {
        match self {
            Entry::Lan(r) => match &r.class.vendor {
                Vendor::Known(v) => (0, v.to_lowercase()),
                Vendor::Private => (1, String::new()),
                Vendor::Unknown => (2, String::new()),
            },
            Entry::Peer(_) => (3, String::new()),
        }
    }

    /// Identified kinds by label, unidentified ones last.
    fn kind(&self) -> (bool, &'static str) {
        let c = match self {
            Entry::Lan(r) => &r.class,
            Entry::Peer(r) => &r.class,
        };
        (c.confidence == Confidence::None, c.kind.label())
    }

    fn open_ports(&self) -> usize {
        match self {
            Entry::Lan(r) => r.device.open_ports.len(),
            Entry::Peer(r) => r.device.as_ref().map_or(0, |d| d.open_ports.len()),
        }
    }

    /// Address order: the LAN first, then tailnet-only peers.
    fn address(&self) -> (bool, Option<Ipv4Addr>) {
        match self {
            Entry::Lan(r) => (false, Some(r.device.ip)),
            Entry::Peer(r) => (true, r.peer.ipv4()),
        }
    }
}

/// Everything drawn in one frame, copied out of the inventory under its lock.
pub struct Snapshot {
    pub entries: Vec<Entry>,
    /// Counts over everything, whatever the filter.
    pub total: usize,
    pub responding: usize,
    pub tailnet_total: usize,
    pub tailnet_online: usize,
    pub sources: Vec<(SourceName, SourceState)>,
    pub progress: Vec<(SourceName, (usize, usize))>,
}

pub struct App {
    pub target: Target,
    opts: scan::Options,
    pub(super) inv: Shared,
    run: Option<Run>,
    pub selected: Option<Key>,
    pub sort: Sort,
    /// The sort flipped, by clicking its column heading again.
    pub reverse: bool,
    pub focus: Focus,
    pub filter: String,
    pub filtering: bool,
    pub help: bool,
    /// Full-screen detail, for terminals too narrow for the side panel.
    pub zoom: bool,
    pub detail_scroll: u16,
    pub tick: usize,
    pub toast: Option<(String, Instant)>,
    /// Screen regions from the last frame, for mouse hit-testing.
    pub areas: Areas,
    quit: bool,
}

#[derive(Default, Clone, Copy)]
pub struct Areas {
    pub list: Rect,
    /// First visible row index in the list, and the y of its first row.
    pub list_offset: usize,
    pub list_first_row: u16,
    /// Each list column's x and width, in `view::COLUMNS` order.
    pub columns: [Rect; view::COLUMNS.len()],
    pub detail: Rect,
    pub map: Rect,
    pub map_cell_width: u16,
}

pub fn run(target: Target, opts: scan::Options, runtime: &Handle) -> Result<()> {
    let inv = Shared::new(Inventory::new(target.subnet, target.address, target.gateway).into());
    let mut app = App::new(target, opts, inv);
    app.start(runtime);

    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let result = app.event_loop(&mut terminal, runtime);
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    app.stop();
    result
}

impl App {
    pub fn new(target: Target, opts: scan::Options, inv: Shared) -> Self {
        App {
            target,
            opts,
            inv,
            run: None,
            selected: None,
            sort: Sort::Address,
            reverse: false,
            focus: Focus::List,
            filter: String::new(),
            filtering: false,
            help: false,
            zoom: false,
            detail_scroll: 0,
            tick: 0,
            toast: None,
            areas: Areas::default(),
            quit: false,
        }
    }

    fn event_loop(&mut self, terminal: &mut DefaultTerminal, runtime: &Handle) -> Result<()> {
        let mut next_frame = Instant::now();
        while !self.quit {
            if Instant::now() >= next_frame {
                self.tick = self.tick.wrapping_add(1);
                self.observe_finish();
                let snap = self.snapshot();
                terminal.draw(|f| view::draw(f, self, &snap))?;
                next_frame = Instant::now() + FRAME;
            }
            let wait = next_frame.saturating_duration_since(Instant::now());
            if event::poll(wait)? {
                let snap = self.snapshot();
                match event::read()? {
                    Event::Key(k) if k.kind != KeyEventKind::Release => {
                        self.on_key(k, &snap, runtime)
                    }
                    Event::Mouse(m) => self.on_mouse(m, &snap),
                    _ => {}
                }
                // Redraw promptly after input rather than waiting a frame.
                next_frame = Instant::now();
            }
        }
        Ok(())
    }

    /// Starts a scan. A running one is stopped first and its results
    /// replaced once it has wound down.
    fn start(&mut self, runtime: &Handle) {
        let previous = self.run.take().map(|r| {
            let _ = r.stop.send(true);
            r.handle
        });
        let (stop, cancel) = watch::channel(false);
        let (inv, target) = (self.inv.clone(), self.target.clone());
        let opts = self.opts.clone();
        let handle = runtime.spawn(async move {
            if let Some(previous) = previous {
                let _ = previous.await;
            }
            *inv.lock().unwrap() = Inventory::new(target.subnet, target.address, target.gateway);
            scan::run(&target, &opts, inv, cancel).await;
        });
        self.run = Some(Run {
            stop,
            handle,
            started: Instant::now(),
            finished: None,
            stopping: false,
        });
    }

    fn stop(&mut self) {
        if let Some(run) = &mut self.run
            && run.finished.is_none()
        {
            let _ = run.stop.send(true);
            run.stopping = true;
        }
    }

    fn observe_finish(&mut self) {
        if let Some(run) = &mut self.run
            && run.finished.is_none()
            && run.handle.is_finished()
        {
            run.finished = Some(Instant::now());
        }
    }

    pub fn phase(&self) -> Phase {
        match &self.run {
            None => Phase::Idle,
            Some(r) => match (r.finished, r.stopping) {
                (None, false) => Phase::Scanning,
                (None, true) => Phase::Stopping,
                (Some(_), false) => Phase::Done,
                (Some(_), true) => Phase::Stopped,
            },
        }
    }

    pub fn elapsed(&self) -> Duration {
        match &self.run {
            None => Duration::ZERO,
            Some(r) => r.finished.unwrap_or_else(Instant::now) - r.started,
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let inv = self.inv.lock().unwrap();
        let needle = self.filter.to_lowercase();
        let links = link_tailnet(&inv.tailnet, &inv.devices);
        let peer_for = |ip: Ipv4Addr| {
            inv.tailnet
                .iter()
                .find(|p| links.get(&p.id) == Some(&ip))
                .cloned()
        };
        let devices = inv.devices.values().map(|d| {
            let peer = peer_for(d.ip);
            Entry::Lan(Row {
                class: classify::classify(d, peer.as_ref()),
                device: d.clone(),
                peer,
            })
        });
        let peers = inv
            .tailnet
            .iter()
            .filter(|p| !links.contains_key(&p.id))
            .map(|p| {
                let device = p.ipv4().and_then(|ip| inv.remote.get(&ip)).cloned();
                Entry::Peer(PeerRow {
                    class: match &device {
                        Some(d) => classify::classify(d, Some(p)),
                        None => classify::classify_peer(p),
                    },
                    device,
                    peer: p.clone(),
                })
            });
        let mut entries: Vec<Entry> = devices
            .chain(peers)
            .filter(|e| needle.is_empty() || matches(e, &needle))
            .collect();
        match self.sort {
            Sort::Address => entries.sort_by_key(|e| e.address()),
            Sort::Name => entries.sort_by_cached_key(|e| {
                let (name, named) = e.name();
                (!named, name.to_lowercase(), e.address())
            }),
            Sort::Type => entries.sort_by_key(|e| (e.kind(), e.address())),
            Sort::Vendor => entries.sort_by_cached_key(|e| (e.vendor(), e.address())),
            Sort::Ports => {
                entries.sort_by_key(|e| (std::cmp::Reverse(e.open_ports()), e.address()))
            }
        }
        if self.reverse {
            entries.reverse();
        }
        Snapshot {
            total: inv.devices.len(),
            responding: inv.devices.values().filter(|d| d.responding).count(),
            tailnet_total: inv.tailnet.len(),
            tailnet_online: inv.tailnet.iter().filter(|p| p.online).count(),
            entries,
            sources: inv.sources.clone(),
            progress: inv.progress.iter().map(|(k, v)| (*k, *v)).collect(),
        }
    }

    /// Index of the selection in the visible list, keeping it on the same
    /// device as the list grows and re-sorts.
    pub fn selected_index(&self, snap: &Snapshot) -> Option<usize> {
        if snap.entries.is_empty() {
            return None;
        }
        let found = self
            .selected
            .as_ref()
            .and_then(|k| snap.entries.iter().position(|e| &e.key() == k));
        Some(found.unwrap_or(0))
    }

    /// The LAN address to highlight on the subnet map.
    pub fn highlighted(&self, snap: &Snapshot) -> Option<Ipv4Addr> {
        let i = self.selected_index(snap)?;
        snap.entries[i].lan().map(|r| r.device.ip)
    }

    fn select_index(&mut self, snap: &Snapshot, index: usize) {
        let index = index.min(snap.entries.len().saturating_sub(1));
        if let Some(e) = snap.entries.get(index) {
            let key = e.key();
            if self.selected.as_ref() != Some(&key) {
                self.selected = Some(key);
                self.detail_scroll = 0;
            }
        }
    }

    fn move_selection(&mut self, snap: &Snapshot, delta: isize) {
        if let Some(i) = self.selected_index(snap) {
            let last = snap.entries.len() as isize - 1;
            self.select_index(snap, (i as isize + delta).clamp(0, last) as usize);
        }
    }

    fn sort_by(&mut self, sort: Sort, reverse: bool) {
        self.sort = sort;
        self.reverse = reverse;
        let order = if reverse { ", reversed" } else { "" };
        self.toast(format!("Sorted by {}{order}", sort.label()));
    }

    fn open(&mut self, url: String) {
        match open_url(&url) {
            Ok(()) => self.toast(format!("Opening {url}")),
            Err(e) => self.toast(format!("Could not open {url}: {e}")),
        }
    }

    fn toast(&mut self, text: impl Into<String>) {
        self.toast = Some((text.into(), Instant::now()));
    }

    pub fn current_toast(&self) -> Option<&str> {
        self.toast
            .as_ref()
            .filter(|(_, at)| at.elapsed() < TOAST_FOR)
            .map(|(t, _)| t.as_str())
    }

    fn on_key(&mut self, key: KeyEvent, snap: &Snapshot, runtime: &Handle) {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        if self.help {
            self.help = false;
            return;
        }
        if self.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filtering = false;
                }
                KeyCode::Enter => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char('u') if ctrl => self.filter.clear(),
                KeyCode::Char(c) => self.filter.push(c),
                KeyCode::Down => self.move_selection(snap, 1),
                KeyCode::Up => self.move_selection(snap, -1),
                _ => {}
            }
            return;
        }
        let page = (self.areas.list.height.saturating_sub(1) / view::ROW_HEIGHT).max(1) as isize;
        let detail = self.focus == Focus::Detail || self.zoom;
        match key.code {
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Char('?') => self.help = true,
            KeyCode::Char('/') => {
                self.filtering = true;
                self.focus = Focus::List;
                self.zoom = false;
            }
            KeyCode::Esc if self.zoom => self.zoom = false,
            KeyCode::Esc if self.focus == Focus::Detail => self.focus = Focus::List,
            KeyCode::Esc if !self.filter.is_empty() => self.filter.clear(),
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::List => Focus::Detail,
                    Focus::Detail => Focus::List,
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if self.areas.detail.width == 0 {
                    self.zoom = true;
                } else {
                    self.focus = Focus::Detail;
                }
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                self.zoom = false;
                self.focus = Focus::List;
            }
            KeyCode::Down | KeyCode::Char('j') if detail => {
                self.detail_scroll = self.detail_scroll.saturating_add(1)
            }
            KeyCode::Up | KeyCode::Char('k') if detail => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(snap, 1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(snap, -1),
            KeyCode::PageDown => self.move_selection(snap, page),
            KeyCode::PageUp => self.move_selection(snap, -page),
            KeyCode::Home | KeyCode::Char('g') => self.select_index(snap, 0),
            KeyCode::End | KeyCode::Char('G') => self.select_index(snap, usize::MAX),
            KeyCode::Char('o') => {
                self.sort_by(self.sort.next(), false);
            }
            KeyCode::Char('s') => match self.phase() {
                Phase::Scanning => {
                    self.stop();
                    self.toast("Stopping scan · results so far are kept");
                }
                _ => self.toast("No scan running"),
            },
            KeyCode::Char('r') => {
                self.selected = None;
                self.start(runtime);
                self.toast("Rescanning");
            }
            _ => {}
        }
    }

    fn on_mouse(&mut self, m: MouseEvent, snap: &Snapshot) {
        let at = Position::new(m.column, m.row);
        let a = self.areas;
        match m.kind {
            MouseEventKind::ScrollDown if a.detail.contains(at) => {
                self.detail_scroll = self.detail_scroll.saturating_add(2)
            }
            MouseEventKind::ScrollUp if a.detail.contains(at) => {
                self.detail_scroll = self.detail_scroll.saturating_sub(2)
            }
            MouseEventKind::ScrollDown => self.move_selection(snap, 1),
            MouseEventKind::ScrollUp => self.move_selection(snap, -1),
            MouseEventKind::Down(MouseButton::Left) => {
                if a.list.contains(at) && m.row + 1 == a.list_first_row {
                    if let Some(sort) = view::heading_hit(self, at) {
                        let reverse = sort == self.sort && !self.reverse;
                        self.sort_by(sort, reverse);
                    }
                } else if a.list.contains(at) && m.row >= a.list_first_row {
                    let row = (m.row - a.list_first_row) as usize / view::ROW_HEIGHT as usize
                        + a.list_offset;
                    if let Some(e) = snap.entries.get(row) {
                        self.select_index(snap, row);
                        self.focus = Focus::List;
                        let device = match e {
                            Entry::Lan(r) => Some(&r.device),
                            Entry::Peer(r) => r.device.as_ref(),
                        };
                        if let Some(d) = device
                            && let Some(port) = view::port_hit(self, &d.open_ports, at)
                        {
                            self.open(labels::url(d, port));
                        }
                    }
                } else if a.map.contains(at) {
                    if let Some(ip) = view::map_hit(self, at)
                        && snap.entries.iter().any(|e| e.key() == Key::Lan(ip))
                    {
                        self.selected = Some(Key::Lan(ip));
                        self.detail_scroll = 0;
                    }
                } else if a.detail.contains(at) {
                    self.focus = Focus::Detail;
                }
            }
            _ => {}
        }
    }
}

/// Hands a URL to the desktop's opener, detached from the terminal.
fn open_url(url: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let mut cmd = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    } else {
        Command::new("xdg-open")
    };
    cmd.arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|mut child| {
            // Reap it once the opener hands off to the browser.
            std::thread::spawn(move || child.wait());
        })
}

fn matches(e: &Entry, needle: &str) -> bool {
    match e {
        Entry::Lan(r) => lan_matches(r, needle),
        Entry::Peer(r) => peer_matches(r, needle),
    }
}

fn lan_matches(r: &Row, needle: &str) -> bool {
    let d = &r.device;
    let hay = [
        labels::display_name(r).0,
        d.ip.to_string(),
        d.mac.clone().unwrap_or_default(),
        d.hostname.clone().unwrap_or_default(),
        labels::services(d).join(" "),
        r.class.kind.label().to_string(),
        r.class.product.clone().unwrap_or_default(),
        r.class.vendor.name().unwrap_or_default().to_string(),
        r.peer
            .as_ref()
            .map(|p| format!("{} tailnet", p.dns_name))
            .unwrap_or_default(),
    ];
    hay.iter().any(|h| h.to_lowercase().contains(needle))
        || d.open_ports.iter().any(|p| p.to_string() == needle)
}

fn peer_matches(r: &PeerRow, needle: &str) -> bool {
    let p = &r.peer;
    let hay = [
        p.dns_name.clone(),
        p.hostname.clone(),
        p.os.clone(),
        p.ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        "tailnet".to_string(),
        r.class.kind.label().to_string(),
    ];
    hay.iter().any(|h| h.to_lowercase().contains(needle))
}
