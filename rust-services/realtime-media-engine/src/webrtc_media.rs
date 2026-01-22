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

//! WebRTC Media Engine Integration
//!
//! Handles WebRTC-specific media processing including DTLS handshake,
//! ICE connection establishment, and WebRTC RTP/SRTP packet handling.
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


use crate::error::{MediaEngineError, MediaEngineResult};
use crate::rtp_handler::RtpPacket;
use crate::srtp_pipeline::{SrtpPipeline, SrtpConfig};
use crate::stream_manager::{StreamManager, StreamConfig, MediaType};
use std::collections::HashMap;
use uuid::Uuid;

/// WebRTC connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcConnectionState {
    /// New connection
    New,
    /// ICE connection checking
    Checking,
    /// ICE connection connected
    Connected,
    /// ICE connection completed
    Completed,
    /// Connection failed
    Failed,
    /// Connection disconnected
    Disconnected,
    /// Connection closed
    Closed,
}

/// WebRTC media engine
pub struct WebRtcMediaEngine {
    /// Stream manager
    stream_manager: StreamManager,
    /// Active WebRTC connections
    connections: HashMap<Uuid, WebRtcConnection>,
    /// SRTP pipelines by connection
    srtp_pipelines: HashMap<Uuid, SrtpPipeline>,
}

/// WebRTC connection
#[derive(Debug, Clone)]
pub struct WebRtcConnection {
    /// Connection ID
    pub connection_id: Uuid,
    /// Connection state
    pub state: WebRtcConnectionState,
    /// Local fingerprint (DTLS)
    pub local_fingerprint: Option<String>,
    /// Remote fingerprint (DTLS)
    pub remote_fingerprint: Option<String>,
    /// DTLS state
    pub dtls_state: DtlsState,
    /// ICE state
    pub ice_state: IceState,
    /// Audio stream ID
    pub audio_stream_id: Option<Uuid>,
    /// Video stream ID
    pub video_stream_id: Option<Uuid>,
}

/// DTLS state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtlsState {
    /// New
    New,
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Closed
    Closed,
    /// Failed
    Failed,
}

/// ICE state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// New
    New,
    /// Checking
    Checking,
    /// Connected
    Connected,
    /// Completed
    Completed,
    /// Failed
    Failed,
    /// Disconnected
    Disconnected,
    /// Closed
    Closed,
}

impl WebRtcMediaEngine {
    /// Create a new WebRTC media engine
    pub fn new() -> Self {
        WebRtcMediaEngine {
            stream_manager: StreamManager::new(),
            connections: HashMap::new(),
            srtp_pipelines: HashMap::new(),
        }
    }

    /// Create a new WebRTC connection
    pub fn create_connection(&mut self, connection_id: Uuid) -> MediaEngineResult<()> {
        let connection = WebRtcConnection {
            connection_id,
            state: WebRtcConnectionState::New,
            local_fingerprint: None,
            remote_fingerprint: None,
            dtls_state: DtlsState::New,
            ice_state: IceState::New,
            audio_stream_id: None,
            video_stream_id: None,
        };

        self.connections.insert(connection_id, connection);
        Ok(())
    }

    /// Set DTLS fingerprints
    pub fn set_dtls_fingerprints(
        &mut self,
        connection_id: &Uuid,
        local_fingerprint: String,
        remote_fingerprint: String,
    ) -> MediaEngineResult<()> {
        let connection = self.connections.get_mut(connection_id)
            .ok_or_else(|| MediaEngineError::ConfigError(
                format!("Connection {} not found", connection_id)
            ))?;

        connection.local_fingerprint = Some(local_fingerprint);
        connection.remote_fingerprint = Some(remote_fingerprint);
        connection.dtls_state = DtlsState::Connecting;

        Ok(())
    }

    /// Complete DTLS handshake
    pub fn complete_dtls_handshake(
        &mut self,
        connection_id: &Uuid,
        master_key: Vec<u8>,
        master_salt: Vec<u8>,
    ) -> MediaEngineResult<()> {
        let connection = self.connections.get_mut(connection_id)
            .ok_or_else(|| MediaEngineError::ConfigError(
                format!("Connection {} not found", connection_id)
            ))?;

        connection.dtls_state = DtlsState::Connected;

        // Create SRTP pipeline for this connection
        let srtp_config = SrtpConfig {
            master_key,
            master_salt,
            ssrc: 0, // Will be set per stream
            roc: 0, // Rollover counter
        };

        let srtp_pipeline = SrtpPipeline::new(srtp_config)?;
        self.srtp_pipelines.insert(*connection_id, srtp_pipeline);

        Ok(())
    }

    /// Update ICE state
    pub fn update_ice_state(
        &mut self,
        connection_id: &Uuid,
        state: IceState,
    ) -> MediaEngineResult<()> {
        let connection = self.connections.get_mut(connection_id)
            .ok_or_else(|| MediaEngineError::ConfigError(
                format!("Connection {} not found", connection_id)
            ))?;

        connection.ice_state = state;

        // Update connection state based on ICE state
        match state {
            IceState::Connected | IceState::Completed => {
                connection.state = WebRtcConnectionState::Connected;
            }
            IceState::Failed => {
                connection.state = WebRtcConnectionState::Failed;
            }
            IceState::Disconnected => {
                connection.state = WebRtcConnectionState::Disconnected;
            }
            IceState::Closed => {
                connection.state = WebRtcConnectionState::Closed;
            }
            _ => {}
        }

        Ok(())
    }

    /// Create media stream for WebRTC connection
    pub fn create_stream(
        &mut self,
        connection_id: &Uuid,
        media_type: MediaType,
        ssrc: u32,
        payload_type: u8,
        codec: String,
        bitrate: u32,
    ) -> MediaEngineResult<Uuid> {
        let connection = self.connections.get_mut(connection_id)
            .ok_or_else(|| MediaEngineError::ConfigError(
                format!("Connection {} not found", connection_id)
            ))?;

        // Create stream in stream manager
        // Create SRTP config for WebRTC (always encrypted)
        let srtp_config = if let Some(_srtp_pipeline) = self.srtp_pipelines.get(connection_id) {
            // Get SRTP config from existing pipeline
            // In production, would extract from pipeline
            Some(SrtpConfig {
                master_key: vec![0u8; 16], // Placeholder
                master_salt: vec![0u8; 14], // Placeholder
                ssrc,
                roc: 0,
            })
        } else {
            None
        };

        let stream_config = StreamConfig {
            user_id: connection_id.clone(), // Use connection ID as user ID
            media_type,
            ssrc,
            payload_type,
            codec,
            bitrate,
            srtp_config,
        };

        let stream_id = self.stream_manager.create_stream(stream_config)?;

        // Track stream in connection
        match media_type {
            MediaType::Audio => {
                connection.audio_stream_id = Some(stream_id);
            }
            MediaType::Video => {
                connection.video_stream_id = Some(stream_id);
            }
        }

        Ok(stream_id)
    }

    /// Process incoming WebRTC RTP packet (SRTP encrypted)
    pub fn process_rtp_packet(
        &mut self,
        connection_id: &Uuid,
        srtp_data: &[u8],
    ) -> MediaEngineResult<()> {
        // Get SRTP pipeline for connection
        let srtp_pipeline = self.srtp_pipelines.get(connection_id)
            .ok_or_else(|| MediaEngineError::ConfigError(
                format!("Connection {} not found", connection_id)
            ))?;

        // Decrypt SRTP packet
        let decrypted = srtp_pipeline.decrypt(srtp_data)?;

        // Find stream by SSRC
        let _stream_id = self.find_stream_by_ssrc(connection_id, decrypted.header.ssrc)?;

        // Process packet in stream manager
        // In production, would route to appropriate handler
        Ok(())
    }

    /// Process outgoing WebRTC RTP packet
    pub fn send_rtp_packet(
        &mut self,
        connection_id: &Uuid,
        _stream_id: &Uuid,
        packet: RtpPacket,
    ) -> MediaEngineResult<Vec<u8>> {
        // Get SRTP pipeline for connection
        let srtp_pipeline = self.srtp_pipelines.get(connection_id)
            .ok_or_else(|| MediaEngineError::ConfigError(
                format!("Connection {} not found", connection_id)
            ))?;

        // Encrypt packet with SRTP
        let encrypted = srtp_pipeline.encrypt(&packet)?;

        Ok(encrypted)
    }

    /// Close WebRTC connection
    pub fn close_connection(&mut self, connection_id: &Uuid) -> MediaEngineResult<()> {
        // Close streams
        if let Some(connection) = self.connections.get(connection_id) {
            if let Some(audio_stream_id) = connection.audio_stream_id {
                let _ = self.stream_manager.remove_stream(&audio_stream_id);
            }
            if let Some(video_stream_id) = connection.video_stream_id {
                let _ = self.stream_manager.remove_stream(&video_stream_id);
            }
        }

        // Remove connection
        self.connections.remove(connection_id);
        self.srtp_pipelines.remove(connection_id);

        Ok(())
    }

    /// Find stream by SSRC
    fn find_stream_by_ssrc(
        &self,
        connection_id: &Uuid,
        ssrc: u32,
    ) -> MediaEngineResult<Uuid> {
        let connection = self.connections.get(connection_id)
            .ok_or_else(|| MediaEngineError::ConfigError(
                format!("Connection {} not found", connection_id)
            ))?;

        // Check audio stream
        if let Some(audio_stream_id) = connection.audio_stream_id {
            if let Some(stream) = self.stream_manager.get_stream(&audio_stream_id) {
                if stream.config.ssrc == ssrc {
                    return Ok(audio_stream_id);
                }
            }
        }

        // Check video stream
        if let Some(video_stream_id) = connection.video_stream_id {
            if let Some(stream) = self.stream_manager.get_stream(&video_stream_id) {
                if stream.config.ssrc == ssrc {
                    return Ok(video_stream_id);
                }
            }
        }

        Err(MediaEngineError::ConfigError(
            format!("SSRC {} not found for connection {}", ssrc, connection_id)
        ))
    }

    /// Get connection state
    pub fn get_connection_state(&self, connection_id: &Uuid) -> Option<WebRtcConnectionState> {
        self.connections.get(connection_id).map(|c| c.state)
    }
}

impl Default for WebRtcMediaEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_connection() {
        let mut engine = WebRtcMediaEngine::new();
        let connection_id = Uuid::new_v4();
        
        engine.create_connection(connection_id).unwrap();
        assert_eq!(engine.get_connection_state(&connection_id), Some(WebRtcConnectionState::New));
    }

    #[test]
    fn test_dtls_handshake() {
        let mut engine = WebRtcMediaEngine::new();
        let connection_id = Uuid::new_v4();
        
        engine.create_connection(connection_id).unwrap();
        engine.set_dtls_fingerprints(
            &connection_id,
            "sha-256 AA:BB:CC:DD".to_string(),
            "sha-256 EE:FF:GG:HH".to_string(),
        ).unwrap();

        let master_key = vec![0u8; 16];
        let master_salt = vec![0u8; 14];
        engine.complete_dtls_handshake(&connection_id, master_key, master_salt).unwrap();

        assert!(engine.srtp_pipelines.contains_key(&connection_id));
    }

    #[test]
    fn test_create_stream() {
        let mut engine = WebRtcMediaEngine::new();
        let connection_id = Uuid::new_v4();
        
        engine.create_connection(connection_id).unwrap();
        
        let stream_id = engine.create_stream(
            &connection_id,
            MediaType::Audio,
            12345,
            111,
            "opus".to_string(),
            64000,
        ).unwrap();

        assert!(stream_id != Uuid::nil());
    }
}

