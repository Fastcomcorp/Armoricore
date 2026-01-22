// Copyright 2025 Francisco F. Pinochet
// Copyright 2026 Fastcomcorp, LLC
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

//! Health check endpoint for Media Processor
//!
//! Provides HTTP health check endpoint for orchestration and monitoring.
// Copyright 2025 Francisco F. Pinochet
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


use axum::{
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::info;

/// Health check server state
pub struct HealthServer {
    port: u16,
}

impl HealthServer {
    /// Create a new health check server
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Start the health check server
    pub async fn start(self) -> anyhow::Result<()> {
        let app = Router::new()
            .route("/health", get(health_check))
            .route("/api/health", get(health_check));

        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| anyhow::anyhow!("Failed to bind health check server to {}: {}", addr, e))?;

        info!(
            port = self.port,
            "Health check server started"
        );

        // Run server with graceful shutdown
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| anyhow::anyhow!("Health check server error: {}", e))?;

        info!("Health check server stopped");
        Ok(())
    }
}

/// Health check handler
async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    let response = json!({
        "status": "ok",
        "service": "media-processor",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
    });

    Ok(Json(response))
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Shutdown signal (Ctrl+C) received");
        },
        _ = terminate => {
            info!("Shutdown signal (SIGTERM) received");
        },
    }
}

