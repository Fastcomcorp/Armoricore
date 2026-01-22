// Copyright 2025 Francisco F. Pinochet
// Copyright 2026 Fastcomcorp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Result;
use armoricore_logging::init_logging;
use live_ingest::config::Config;
use live_ingest::server::LiveIngestServer;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging("live-ingest", "info");

    info!("Starting Live Ingest Server");

    // Load configuration
    let config = Config::from_env()?;
    info!(
        rtmp_port = config.rtmp_port,
        api_url = config.api_url,
        "Configuration loaded"
    );

    // Create server
    let server = Arc::new(LiveIngestServer::new(config).await?);

    // Start RTMP server
    let server_clone = Arc::clone(&server);
    let rtmp_handle = tokio::spawn(async move {
        if let Err(e) = server_clone.start_rtmp_server().await {
            error!(error = %e, "RTMP server error");
        }
    });

    // Start HTTP API server for stream key validation
    let server_clone = Arc::clone(&server);
    let api_handle = tokio::spawn(async move {
        if let Err(e) = server_clone.start_api_server().await {
            error!(error = %e, "API server error");
        }
    });

    // Wait for shutdown signal
    info!("Live Ingest Server started. Press Ctrl+C to shutdown.");
    signal::ctrl_c().await?;
    info!("Shutdown signal received, stopping server...");

    // Graceful shutdown
    server.shutdown().await?;
    rtmp_handle.abort();
    api_handle.abort();

    info!("Live Ingest Server stopped");
    Ok(())
}

