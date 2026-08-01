use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

use crate::capture::list_interfaces;
use crate::packet::PacketEvent;

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<PacketEvent>,
    pub stats: Arc<Mutex<Stats>>,
}

#[derive(Default, Serialize, Clone)]
pub struct Stats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub by_protocol: HashMap<String, u64>,
    pub by_process: HashMap<String, u64>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/interfaces", get(interfaces_handler))
        .route("/api/stats", get(stats_handler))
        .nest_service("/", ServeDir::new("frontend/dist"))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn interfaces_handler() -> Json<Vec<String>> {
    Json(list_interfaces())
}

async fn stats_handler(State(state): State<AppState>) -> Json<Stats> {
    Json(state.stats.lock().await.clone())
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.tx.subscribe();
    while let Ok(event) = rx.recv().await {
        let payload = match serde_json::to_string(&event) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if socket.send(Message::Text(payload)).await.is_err() {
            break; // client disconnected
        }
    }
}

/// Background task: consumes the same broadcast stream to keep aggregate
/// stats up to date, independent of how many dashboard clients are connected.
pub async fn run_stats_aggregator(tx: broadcast::Sender<PacketEvent>, stats: Arc<Mutex<Stats>>) {
    let mut rx = tx.subscribe();
    while let Ok(event) = rx.recv().await {
        let mut s = stats.lock().await;
        s.total_packets += 1;
        s.total_bytes += event.length as u64;
        *s.by_protocol.entry(event.protocol.clone()).or_insert(0) += 1;
        if let Some(proc_name) = &event.process {
            *s.by_process.entry(proc_name.clone()).or_insert(0) += 1;
        }
    }
}
