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

//! Media Processor
//!
//! Consumes `media.uploaded` events from the message bus and processes media files:
//! - Transcodes video to multiple bitrates
//! - Creates HLS segments
//! - Generates thumbnails
//! - Uploads processed files to object storage
//! - Publishes `media.ready` events
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


mod downloader;
mod encryption;
mod health;
mod processor;
mod retry;
mod storage;
mod worker;

use anyhow::Result;
use armoricore_config::AppConfig;
use armoricore_keys::{init_key_store, service_integration::*};
use armoricore_logging::init_console_logging;
use message_bus_client::nats::NatsClient;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    init_console_logging("media-processor", "info");

    info!("Starting Media Processor");

    // Load configuration
    let config = AppConfig::from_env()
        .map_err(|e| anyhow::anyhow!("Failed to load configuration: {}", e))?;

    // Try to get object storage config from key store, fallback to environment
    let object_storage_config = if let Some(ref storage_config) = config.object_storage {
        Some(storage_config.clone())
    } else {
        // Try key store
        if let Ok(key_store) = init_key_store(None).await {
            if let (Some(access_key), Some(secret_key)) = (
                get_object_storage_access_key(&key_store).await,
                get_object_storage_secret_key(&key_store).await,
            ) {
                info!("Using object storage credentials from key store");
                Some(armoricore_config::ObjectStorageConfig {
                    endpoint: std::env::var("OBJECT_STORAGE_ENDPOINT")
                        .unwrap_or_else(|_| "https://storage.akamai.com".to_string()),
                    access_key,
                    secret_key,
                    bucket: std::env::var("OBJECT_STORAGE_BUCKET")
                        .unwrap_or_else(|_| "armoricore-media".to_string()),
                    region: std::env::var("OBJECT_STORAGE_REGION").ok(),
                })
            } else {
                warn!("Object storage keys not found in key store, checking environment variables");
                None
            }
        } else {
            None
        }
    };

    let object_storage_config = match object_storage_config {
        Some(config) => config,
        None => {
            error!("Object storage configuration is required for media processing");
            return Err(anyhow::anyhow!(
                "Missing OBJECT_STORAGE_* environment variables or key store keys"
            ));
        }
    };

        info!(
            message_bus_url = config.message_bus_url(),
            "Configuration loaded"
        );

        // Start health check server in background
        let health_port = std::env::var("HEALTH_CHECK_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8080);
        
        let health_server = health::HealthServer::new(health_port);
        let health_handle = tokio::spawn(async move {
            if let Err(e) = health_server.start().await {
                error!(error = %e, "Health check server error");
            }
        });

        // Connect to message bus
        let message_bus = NatsClient::new(
            config.message_bus_url(),
            config.message_bus.stream_name.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to message bus: {}", e))?;

        info!("Connected to message bus");

    // Create worker
    let worker = worker::MediaWorker::new(
        Arc::new(message_bus),
        object_storage_config,
    );

    // Start processing events
    info!("Starting event processing");
    let worker_handle = tokio::spawn(async move {
        if let Err(e) = worker.run().await {
            error!(error = %e, "Worker error");
        }
    });

    // Wait for shutdown signal
    info!("Media Processor running. Press Ctrl+C to stop.");
    match signal::ctrl_c().await {
        Ok(()) => {
            info!("Shutdown signal received, initiating graceful shutdown");
        }
        Err(err) => {
            error!(error = %err, "Unable to listen for shutdown signal");
        }
    }

    // Graceful shutdown: wait for worker to finish current operations
    info!("Waiting for in-flight operations to complete...");
    tokio::select! {
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
            warn!("Shutdown timeout reached, forcing shutdown");
        }
        _ = worker_handle => {
            info!("Worker completed gracefully");
        }
    }

    // Cancel health check server
    health_handle.abort();
    info!("Media Processor stopped");

    Ok(())
}
