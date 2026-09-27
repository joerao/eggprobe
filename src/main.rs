mod classify;
mod inventory;
mod netif;
mod oui;
mod report;
mod scan;
mod sources;
mod ui;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use clap::Parser;
use ipnet::Ipv4Net;

use crate::inventory::Inventory;

/// Find and identify the devices on your network.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Scan once and print a JSON report instead of opening the interactive view.
    #[arg(long)]
    scan: bool,

    /// Interface to scan from (default: the one with the default route).
    #[arg(short, long)]
    interface: Option<String>,

    /// Subnet to sweep (default: the interface's own subnet).
    #[arg(short, long)]
    subnet: Option<Ipv4Net>,

    /// Seconds to listen for mDNS answers.
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u64).range(1..=120))]
    mdns_listen: u64,

    /// Source to leave out; repeatable. One of: tailscale, tuya, neighbors, tcp-sweep, names, port-probe, tailnet-probe, mdns, device-info.
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(scan::SOURCES))]
    skip: Vec<String>,
}

// Exit codes: 0 complete, 1 a source failed, 2 bad arguments,
// 130 cancelled. A partial report is still printed for 1 and 130.
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_CANCELLED: u8 = 130;

fn main() -> ExitCode {
    let cli = Cli::parse();
    if !cli.scan && !(std::io::stdout().is_terminal() && std::io::stdin().is_terminal()) {
        eprintln!("eggprobe: the interactive view needs a terminal; use --scan for JSON");
        return ExitCode::from(EXIT_USAGE);
    }
    let target = match netif::resolve(cli.interface.as_deref(), cli.subnet) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("eggprobe: {e:#}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let opts = scan::Options {
        mdns_listen: Duration::from_secs(cli.mdns_listen),
        skip: cli.skip,
    };

    let runtime = tokio::runtime::Runtime::new().expect("start async runtime");
    if !cli.scan {
        let result = ui::run(target, opts, runtime.handle());
        runtime.shutdown_background();
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("eggprobe: {e:#}");
                ExitCode::from(EXIT_FAILED)
            }
        };
    }
    let inv = Arc::new(Mutex::new(Inventory::new(
        target.subnet,
        target.address,
        target.gateway,
    )));
    let started = SystemTime::now();
    let (stop, cancel) = tokio::sync::watch::channel(false);
    let cancelled = runtime.block_on(async {
        let scan = scan::run(&target, &opts, inv.clone(), cancel);
        tokio::pin!(scan);
        tokio::select! {
            _ = &mut scan => false,
            _ = tokio::signal::ctrl_c() => {
                // Let sources wind down and record what they found.
                let _ = stop.send(true);
                let _ = tokio::time::timeout(Duration::from_secs(3), scan).await;
                true
            }
        }
    });

    let inv = inv.lock().unwrap();
    let report = report::build(&target, &inv, started, cancelled);
    let mut out = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut out, &report).is_err() || writeln!(out).is_err() {
        return ExitCode::from(EXIT_FAILED);
    }
    // Don't wait on sockets still timing out after a cancel.
    runtime.shutdown_background();
    if cancelled {
        ExitCode::from(EXIT_CANCELLED)
    } else if report.complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILED)
    }
}
