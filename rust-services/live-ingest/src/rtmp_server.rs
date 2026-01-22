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

//! RTMP Server Implementation
//!
//! This module implements an RTMP server for live stream ingestion.
//! It uses the rml_rtmp library for RTMP protocol handling.

use crate::error::{LiveIngestError, Result};
use crate::stream_key_validator::StreamKeyValidator;
use crate::stream_manager::StreamManager;
use rml_rtmp::chunk_io::Packet;
use rml_rtmp::handshake::{Handshake, HandshakeProcessResult, PeerType};
use rml_rtmp::sessions::{
    ServerSession, ServerSessionConfig, ServerSessionEvent, ServerSessionResult,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Active stream connection info
#[derive(Debug)]
struct ActiveConnection {
    stream_id: String,
    user_id: String,
    stream_key: String,
    app_name: String,
}

/// RTMP server for live stream ingestion
pub struct RtmpServer {
    port: u16,
    stream_key_validator: Arc<StreamKeyValidator>,
    stream_manager: Arc<StreamManager>,
    active_connections: Arc<Mutex<HashMap<u32, ActiveConnection>>>,
}

impl RtmpServer {
    pub fn new(
        port: u16,
        stream_key_validator: Arc<StreamKeyValidator>,
        stream_manager: Arc<StreamManager>,
    ) -> Self {
        Self {
            port,
            stream_key_validator,
            stream_manager,
            active_connections: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start the RTMP server
    pub async fn start(&self) -> Result<()> {
        let addr = format!("0.0.0.0:{}", self.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| LiveIngestError::RtmpServer(format!("Failed to bind to {}: {}", addr, e)))?;

        info!(port = self.port, "RTMP server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!(peer = %peer_addr, "New RTMP connection");

                    let validator = Arc::clone(&self.stream_key_validator);
                    let manager = Arc::clone(&self.stream_manager);
                    let connections = Arc::clone(&self.active_connections);

                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::handle_connection(stream, validator, manager, connections).await
                        {
                            error!(error = %e, "RTMP connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept RTMP connection");
                }
            }
        }
    }

    /// Handle a single RTMP connection
    async fn handle_connection(
        mut stream: TcpStream,
        validator: Arc<StreamKeyValidator>,
        manager: Arc<StreamManager>,
        connections: Arc<Mutex<HashMap<u32, ActiveConnection>>>,
    ) -> Result<()> {
        // Perform RTMP handshake
        let mut handshake = Handshake::new(PeerType::Server);
        let mut buffer = [0u8; 4096];

        // Read C0+C1 from client
        let bytes_read = stream.read(&mut buffer).await.map_err(|e| {
            LiveIngestError::RtmpServer(format!("Failed to read handshake: {}", e))
        })?;

        let response = match handshake.process_bytes(&buffer[..bytes_read]) {
            Ok(HandshakeProcessResult::InProgress { response_bytes }) => response_bytes,
            Ok(HandshakeProcessResult::Completed {
                response_bytes,
                remaining_bytes: _,
            }) => response_bytes,
            Err(e) => {
                return Err(LiveIngestError::RtmpServer(format!(
                    "Handshake error: {:?}",
                    e
                )));
            }
        };

        // Send S0+S1+S2
        stream.write_all(&response).await.map_err(|e| {
            LiveIngestError::RtmpServer(format!("Failed to send handshake response: {}", e))
        })?;

        // Read C2
        let bytes_read = stream.read(&mut buffer).await.map_err(|e| {
            LiveIngestError::RtmpServer(format!("Failed to read C2: {}", e))
        })?;

        match handshake.process_bytes(&buffer[..bytes_read]) {
            Ok(HandshakeProcessResult::Completed { .. }) => {
                debug!("RTMP handshake completed");
            }
            Ok(HandshakeProcessResult::InProgress { .. }) => {
                // Sometimes we need more data
                debug!("Handshake still in progress after C2");
            }
            Err(e) => {
                return Err(LiveIngestError::RtmpServer(format!(
                    "Handshake completion error: {:?}",
                    e
                )));
            }
        }

        // Create RTMP session
        let config = ServerSessionConfig::new();
        let (mut session, initial_results) = ServerSession::new(config)
            .map_err(|e| LiveIngestError::RtmpServer(format!("Failed to create session: {:?}", e)))?;

        // Send initial results (usually window acknowledgement)
        for result in initial_results {
            if let ServerSessionResult::OutboundResponse(packet) = result {
                Self::send_packet(&mut stream, packet).await?;
            }
        }

        // Main message loop
        let mut current_connection_id: Option<u32> = None;
        let mut validated = false;

        loop {
            let bytes_read = match stream.read(&mut buffer).await {
                Ok(0) => {
                    info!("RTMP connection closed by client");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!(error = %e, "Failed to read from RTMP stream");
                    break;
                }
            };

            let results = session
                .handle_input(&buffer[..bytes_read])
                .map_err(|e| LiveIngestError::RtmpServer(format!("Session error: {:?}", e)))?;

            for result in results {
                match result {
                    ServerSessionResult::OutboundResponse(packet) => {
                        Self::send_packet(&mut stream, packet).await?;
                    }
                    ServerSessionResult::RaisedEvent(event) => {
                        match event {
                            ServerSessionEvent::ConnectionRequested {
                                request_id,
                                app_name,
                            } => {
                                info!(app_name = %app_name, "RTMP connection requested");
                                
                                // Accept the connection
                                let accept_results = session
                                    .accept_request(request_id)
                                    .map_err(|e| {
                                        LiveIngestError::RtmpServer(format!(
                                            "Failed to accept connection: {:?}",
                                            e
                                        ))
                                    })?;

                                for r in accept_results {
                                    if let ServerSessionResult::OutboundResponse(packet) = r {
                                        Self::send_packet(&mut stream, packet).await?;
                                    }
                                }
                            }
                            ServerSessionEvent::PublishStreamRequested {
                                request_id,
                                app_name,
                                stream_key,
                                mode: _,
                            } => {
                                info!(
                                    app_name = %app_name,
                                    stream_key = %stream_key,
                                    "RTMP publish requested"
                                );

                                // Validate stream key
                                match validator.validate(&stream_key).await {
                                    Ok(validation) if validation.valid => {
                                        let user_id = validation.user_id.unwrap_or_default();

                                        // Register stream with manager
                                        match manager
                                            .register_stream(
                                                stream_key.clone(),
                                                user_id.clone(),
                                                "rtmp".to_string(),
                                            )
                                            .await
                                        {
                                            Ok(stream_id) => {
                                                info!(
                                                    stream_id = %stream_id,
                                                    user_id = %user_id,
                                                    "Stream registered successfully"
                                                );

                                                // Store connection info
                                                let conn = ActiveConnection {
                                                    stream_id,
                                                    user_id,
                                                    stream_key,
                                                    app_name,
                                                };
                                                current_connection_id = Some(request_id);
                                                connections.lock().await.insert(request_id, conn);
                                                validated = true;

                                                // Accept publish request
                                                let accept_results = session
                                                    .accept_request(request_id)
                                                    .map_err(|e| {
                                                        LiveIngestError::RtmpServer(format!(
                                                            "Failed to accept publish: {:?}",
                                                            e
                                                        ))
                                                    })?;

                                                for r in accept_results {
                                                    if let ServerSessionResult::OutboundResponse(
                                                        packet,
                                                    ) = r
                                                    {
                                                        Self::send_packet(&mut stream, packet)
                                                            .await?;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "Failed to register stream");
                                                // Reject the publish request - stream limit reached or other error
                                            }
                                        }
                                    }
                                    Ok(_) => {
                                        warn!(stream_key = %stream_key, "Invalid stream key");
                                        // Don't accept - invalid key
                                    }
                                    Err(e) => {
                                        error!(error = %e, "Stream key validation failed");
                                        // Don't accept - validation error
                                    }
                                }
                            }
                            ServerSessionEvent::PublishStreamFinished { app_name, stream_key } => {
                                info!(
                                    app_name = %app_name,
                                    stream_key = %stream_key,
                                    "RTMP publish finished"
                                );

                                // Clean up connection
                                if let Some(conn_id) = current_connection_id {
                                    if let Some(conn) = connections.lock().await.remove(&conn_id) {
                                        if let Err(e) = manager.unregister_stream(&conn.stream_id).await {
                                            warn!(error = %e, "Failed to unregister stream");
                                        }
                                    }
                                }
                            }
                            ServerSessionEvent::VideoDataReceived { 
                                app_name: _,
                                stream_key: _,
                                data,
                                timestamp,
                            } => {
                                if validated {
                                    // Forward video data to transcoder
                                    // In a full implementation, this would send to the media processor
                                    debug!(
                                        size = data.len(),
                                        timestamp = timestamp.value,
                                        "Video data received"
                                    );
                                    
                                    // TODO: Forward to media processor via message bus
                                    // manager.forward_media_data(&stream_id, MediaType::Video, data).await?;
                                }
                            }
                            ServerSessionEvent::AudioDataReceived {
                                app_name: _,
                                stream_key: _,
                                data,
                                timestamp,
                            } => {
                                if validated {
                                    // Forward audio data to transcoder
                                    debug!(
                                        size = data.len(),
                                        timestamp = timestamp.value,
                                        "Audio data received"
                                    );
                                    
                                    // TODO: Forward to media processor via message bus
                                    // manager.forward_media_data(&stream_id, MediaType::Audio, data).await?;
                                }
                            }
                            ServerSessionEvent::StreamMetadataChanged {
                                app_name,
                                stream_key,
                                metadata,
                            } => {
                                info!(
                                    app_name = %app_name,
                                    stream_key = %stream_key,
                                    "Stream metadata: {:?}",
                                    metadata
                                );
                            }
                            _ => {
                                debug!("Unhandled RTMP event");
                            }
                        }
                    }
                    ServerSessionResult::UnhandleableMessageReceived(payload) => {
                        debug!(size = payload.data.len(), "Unhandleable message received");
                    }
                }
            }
        }

        // Clean up on disconnect
        if let Some(conn_id) = current_connection_id {
            if let Some(conn) = connections.lock().await.remove(&conn_id) {
                info!(stream_id = %conn.stream_id, "Cleaning up disconnected stream");
                if let Err(e) = manager.unregister_stream(&conn.stream_id).await {
                    warn!(error = %e, "Failed to unregister stream on disconnect");
                }
            }
        }

        Ok(())
    }

    /// Send an RTMP packet over the stream
    async fn send_packet(stream: &mut TcpStream, packet: Packet) -> Result<()> {
        stream.write_all(&packet.bytes).await.map_err(|e| {
            LiveIngestError::RtmpServer(format!("Failed to send packet: {}", e))
        })?;
        Ok(())
    }
}
