//! Independent evidence sources. Each one reports findings and its own status
//! through a `Sink`; none of them touches the inventory directly.

pub mod device_info;
pub mod http;
pub mod mdns;
pub mod names;
pub mod neighbors;
pub mod tailscale;
pub mod tcp;
pub mod tuya;
pub mod wire;

use std::net::Ipv4Addr;

use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::watch;

use crate::inventory::{Event, Finding, FindingKind, SourceName, SourceState};

/// Set to true to stop a scan. Sources check it between steps and report
/// `Stopped`, keeping what they found.
pub type Cancel = watch::Receiver<bool>;

/// Resolves once cancellation is requested. Never resolves if the sender is
/// gone without cancelling.
pub async fn cancelled(cancel: &mut Cancel) {
    loop {
        if *cancel.borrow_and_update() {
            return;
        }
        if cancel.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

#[derive(Clone)]
pub struct Sink {
    tx: UnboundedSender<Event>,
    source: SourceName,
}

impl Sink {
    pub fn new(tx: UnboundedSender<Event>, source: SourceName) -> Self {
        Sink { tx, source }
    }

    pub fn found(&self, ip: Ipv4Addr, kind: FindingKind) {
        // A closed channel means the scan is being torn down; nothing to do.
        let _ = self.tx.send(Event::Found(Finding {
            ip,
            source: self.source,
            kind,
        }));
    }

    pub fn status(&self, state: SourceState) {
        let _ = self.tx.send(Event::Status(self.source, state));
    }

    pub fn progress(&self, done: usize, total: usize) {
        let _ = self.tx.send(Event::Progress(self.source, done, total));
    }
}
