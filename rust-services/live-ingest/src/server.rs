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

use crate::config::Config;
use crate::error::{LiveIngestError, Result};
use crate::rtmp_server::RtmpServer;
use crate::stream_key_validator::StreamKeyValidator;
use crate::stream_manager::StreamManager;
use std::sync::Arc;
use tracing::{info, warn};

pub struct LiveIngestServer {
    config: Config,
    rtmp_server: Arc<RtmpServer>,
    stream_manager: Arc<StreamManager>,
    stream_key_validator: Arc<StreamKeyValidator>,
}

impl LiveIngestServer {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing Live Ingest Server");

        // Initialize stream manager
        let stream_manager = Arc::new(
            StreamManager::new(&config.message_bus_url, Some(config.recordings_base_dir.clone()))
                .await
                .map_err(|e| LiveIngestError::Config(format!("Failed to initialize stream manager: {}", e)))?,
        );

        // Initialize stream key validator
        let stream_key_validator = Arc::new(StreamKeyValidator::new(
            config.api_url.clone(),
            config.validation_timeout_secs,
        ));

        // Initialize RTMP server
        let rtmp_server = Arc::new(RtmpServer::new(
            config.rtmp_port,
            Arc::clone(&stream_key_validator),
            Arc::clone(&stream_manager),
        ));

        Ok(Self {
            config,
            rtmp_server,
            stream_manager,
            stream_key_validator,
        })
    }

    /// Start the RTMP server
    pub async fn start_rtmp_server(&self) -> Result<()> {
        info!("Starting RTMP server");
        self.rtmp_server.start().await
    }

    /// Start the HTTP API server for stream key validation
    /// This provides an internal API for validating stream keys
    pub async fn start_api_server(&self) -> Result<()> {
        info!(port = self.config.api_port, "Starting API server (placeholder)");

        // TODO: Implement HTTP API server using axum or warp
        // This would provide endpoints for:
        // - Health check
        // - Stream key validation (internal)
        // - Active streams list
        // - Stream statistics

        // For now, this is a placeholder
        warn!("API server implementation not yet complete");

        Ok(())
    }

    /// Graceful shutdown
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down Live Ingest Server");

        // TODO: Implement graceful shutdown
        // 1. Stop accepting new connections
        // 2. Wait for active streams to finish
        // 3. Close all connections
        // 4. Clean up resources

        Ok(())
    }
}

