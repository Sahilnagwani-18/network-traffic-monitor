mod capture;
mod packet;
mod proc_lookup;
mod server;

use clap::Parser;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

#[derive(Parser, Debug)]
#[command(name = "firewall-backend")]
#[command(about = "Local traffic monitor: captures packets and serves them over WebSocket")]
struct Args {
    /// Network interface to capture on, e.g. eth0, wlan0, en0
    #[arg(short, long)]
    interface: Option<String>,

    /// Port to serve the dashboard + API on
    #[arg(short, long, default_value_t = 7878)]
    port: u16,

    /// List available interfaces and exit
    #[arg(long, default_value_t = false)]
    list_interfaces: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.list_interfaces {
        for name in capture::list_interfaces() {
            println!("{name}");
        }
        return;
    }

    let iface = match args.interface {
        Some(i) => i,
        None => {
            let ifaces = capture::list_interfaces();
            match ifaces.first() {
                Some(i) => {
                    println!("No --interface given, defaulting to '{i}'. Available: {ifaces:?}");
                    i.clone()
                }
                None => {
                    eprintln!("No network interfaces found.");
                    return;
                }
            }
        }
    };

    // Broadcast channel: capture thread -> N websocket clients + stats aggregator
    let (tx, _rx) = broadcast::channel(4096);

    capture::spawn_capture(iface, tx.clone());

    let stats = Arc::new(Mutex::new(server::Stats::default()));
    tokio::spawn(server::run_stats_aggregator(tx.clone(), stats.clone()));

    let state = server::AppState { tx, stats };
    let app = server::build_router(state);

    let addr = format!("0.0.0.0:{}", args.port);
    println!("Dashboard + API listening on http://localhost:{}", args.port);
    println!("WebSocket feed at ws://localhost:{}/ws", args.port);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
