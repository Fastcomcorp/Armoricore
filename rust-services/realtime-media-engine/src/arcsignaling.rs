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

//! ArcSignaling Protocol Implementation
//!
//! Simplified signaling protocol for ArcRTC connection establishment and stream management.
//! More efficient than WebRTC's SDP/ICE approach.
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
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// ArcSignaling message types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ArcSignalingMessage {
    /// Connection request
    #[serde(rename = "CONNECT")]
    Connect(ConnectRequest),
    /// Connection acknowledgment
    #[serde(rename = "CONNECT_ACK")]
    ConnectAck(ConnectAck),
    /// Stream negotiation
    #[serde(rename = "STREAM_NEGOTIATE")]
    StreamNegotiate(StreamNegotiate),
    /// Stream acknowledgment
    #[serde(rename = "STREAM_ACK")]
    StreamAck(StreamAck),
    /// Quality adaptation
    #[serde(rename = "QUALITY_UPDATE")]
    QualityUpdate(QualityUpdate),
    /// Connection close
    #[serde(rename = "DISCONNECT")]
    Disconnect(Disconnect),
}

/// Connection request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectRequest {
    /// Protocol version
    pub version: String,
    /// Session ID
    pub session_id: Uuid,
    /// Peer ID
    pub peer_id: Uuid,
    /// Peer capabilities
    pub capabilities: PeerCapabilities,
    /// Optional relay server information
    pub relay_servers: Option<Vec<RelayServer>>,
}

/// Peer capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerCapabilities {
    /// Supported audio codecs
    pub audio_codecs: Vec<String>,
    /// Supported video codecs
    pub video_codecs: Vec<String>,
    /// Supported resolutions
    pub resolutions: Vec<String>,
    /// Maximum bitrate (bps)
    pub max_bitrate: u32,
    /// Encryption support
    pub encryption_supported: bool,
}

/// Relay server information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayServer {
    /// Relay server ID
    pub id: String,
    /// Relay server address
    pub address: String,
    /// Relay server port
    pub port: u16,
    /// Relay server priority
    pub priority: u8,
}

/// Connection acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectAck {
    /// Session ID
    pub session_id: Uuid,
    /// Accepted version
    pub version: String,
    /// Peer capabilities (negotiated)
    pub capabilities: PeerCapabilities,
    /// Selected relay server (if any)
    pub relay_server: Option<RelayServer>,
    /// Connection parameters
    pub connection_params: ConnectionParams,
}

/// Connection parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionParams {
    /// Initial bitrate (bps)
    pub initial_bitrate: u32,
    /// Initial resolution
    pub initial_resolution: String,
    /// Encryption enabled
    pub encryption_enabled: bool,
    /// Key exchange method
    pub key_exchange_method: String,
}

/// Stream negotiation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamNegotiate {
    /// Stream ID
    pub stream_id: Uuid,
    /// Media type
    pub media_type: ArcMediaType,
    /// Codec preference
    pub codec: String,
    /// Bitrate preference
    pub bitrate: u32,
    /// Resolution preference
    pub resolution: Option<String>,
    /// Frame rate (for video)
    pub frame_rate: Option<u32>,
}

/// ArcSignaling media type
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum ArcMediaType {
    Audio,
    Video,
}

/// Stream acknowledgment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamAck {
    /// Stream ID
    pub stream_id: Uuid,
    /// Accepted codec
    pub codec: String,
    /// Accepted bitrate
    pub bitrate: u32,
    /// Accepted resolution (if video)
    pub resolution: Option<String>,
    /// Accepted frame rate (if video)
    pub frame_rate: Option<u32>,
    /// SSRC for the stream
    pub ssrc: u32,
    /// Payload type
    pub payload_type: u8,
}

/// Quality update
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QualityUpdate {
    /// Stream ID
    pub stream_id: Uuid,
    /// New bitrate (optional)
    pub bitrate: Option<u32>,
    /// New resolution (optional, for video)
    pub resolution: Option<String>,
    /// New frame rate (optional, for video)
    pub frame_rate: Option<u32>,
    /// Quality reason
    pub reason: QualityReason,
}

/// Quality update reason
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityReason {
    /// Network conditions improved
    NetworkImproved,
    /// Network conditions degraded
    NetworkDegraded,
    /// Bandwidth available
    BandwidthAvailable,
    /// Bandwidth limited
    BandwidthLimited,
    /// User requested
    UserRequested,
}

/// Disconnect message
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Disconnect {
    /// Session ID
    pub session_id: Uuid,
    /// Disconnect reason
    pub reason: DisconnectReason,
    /// Optional message
    pub message: Option<String>,
}

/// Disconnect reason
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DisconnectReason {
    /// User initiated disconnect
    UserDisconnect,
    /// Connection timeout
    Timeout,
    /// Network error
    NetworkError,
    /// Protocol error
    ProtocolError,
    /// Server shutdown
    ServerShutdown,
}

/// ArcSignaling handler
pub struct ArcSignalingHandler {
    /// Active sessions
    sessions: std::collections::HashMap<Uuid, ArcSignalingSession>,
}

/// ArcSignaling session
#[derive(Debug, Clone)]
pub struct ArcSignalingSession {
    /// Session ID
    pub session_id: Uuid,
    /// Peer ID
    pub peer_id: Uuid,
    /// Session state
    pub state: SessionState,
    /// Negotiated capabilities
    pub capabilities: PeerCapabilities,
    /// Active streams
    pub streams: std::collections::HashMap<Uuid, StreamInfo>,
    /// Connection parameters
    pub connection_params: ConnectionParams,
}

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Connecting
    Connecting,
    /// Connected
    Connected,
    /// Negotiating
    Negotiating,
    /// Active
    Active,
    /// Disconnecting
    Disconnecting,
    /// Disconnected
    Disconnected,
}

/// Stream information
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream ID
    pub stream_id: Uuid,
    /// Media type
    pub media_type: ArcMediaType,
    /// Codec
    pub codec: String,
    /// Bitrate
    pub bitrate: u32,
    /// Resolution (if video)
    pub resolution: Option<String>,
    /// Frame rate (if video)
    pub frame_rate: Option<u32>,
    /// SSRC
    pub ssrc: u32,
    /// Payload type
    pub payload_type: u8,
}

impl ArcSignalingHandler {
    /// Create a new ArcSignaling handler
    pub fn new() -> Self {
        ArcSignalingHandler {
            sessions: std::collections::HashMap::new(),
        }
    }

    /// Handle a signaling message
    pub fn handle_message(&mut self, message: ArcSignalingMessage) -> MediaEngineResult<ArcSignalingMessage> {
        match message {
            ArcSignalingMessage::Connect(req) => self.handle_connect(req),
            ArcSignalingMessage::ConnectAck(ack) => self.handle_connect_ack(ack),
            ArcSignalingMessage::StreamNegotiate(negotiate) => self.handle_stream_negotiate(negotiate),
            ArcSignalingMessage::StreamAck(ack) => self.handle_stream_ack(ack),
            ArcSignalingMessage::QualityUpdate(update) => self.handle_quality_update(update),
            ArcSignalingMessage::Disconnect(disconnect) => self.handle_disconnect(disconnect),
        }
    }

    /// Handle connection request
    fn handle_connect(&mut self, req: ConnectRequest) -> MediaEngineResult<ArcSignalingMessage> {
        // Validate version
        if req.version != "1.0" {
            return Err(MediaEngineError::ConfigError(
                format!("Unsupported protocol version: {}", req.version)
            ));
        }

        // Store capabilities for later use
        let max_bitrate = req.capabilities.max_bitrate;
        let encryption_supported = req.capabilities.encryption_supported;
        let capabilities_clone = req.capabilities.clone();

        // Create session
        let session = ArcSignalingSession {
            session_id: req.session_id,
            peer_id: req.peer_id,
            state: SessionState::Connecting,
            capabilities: capabilities_clone.clone(),
            streams: std::collections::HashMap::new(),
            connection_params: ConnectionParams {
                initial_bitrate: max_bitrate.min(2_000_000), // Cap at 2 Mbps initially
                initial_resolution: "720p".to_string(),
                encryption_enabled: encryption_supported,
                key_exchange_method: "ECDH".to_string(),
            },
        };

        self.sessions.insert(req.session_id, session);

        // Create connection acknowledgment
        let ack = ConnectAck {
            session_id: req.session_id,
            version: req.version,
            capabilities: capabilities_clone,
            relay_server: req.relay_servers.and_then(|servers| servers.first().cloned()),
            connection_params: ConnectionParams {
                initial_bitrate: max_bitrate.min(2_000_000),
                initial_resolution: "720p".to_string(),
                encryption_enabled: encryption_supported,
                key_exchange_method: "ECDH".to_string(),
            },
        };

        Ok(ArcSignalingMessage::ConnectAck(ack))
    }

    /// Handle connection acknowledgment
    fn handle_connect_ack(&mut self, ack: ConnectAck) -> MediaEngineResult<ArcSignalingMessage> {
        if let Some(session) = self.sessions.get_mut(&ack.session_id) {
            session.state = SessionState::Connected;
            session.connection_params = ack.connection_params.clone();
            Ok(ArcSignalingMessage::ConnectAck(ack))
        } else {
            Err(MediaEngineError::StreamNotFound {
                stream_id: ack.session_id.to_string(),
            })
        }
    }

    /// Handle stream negotiation
    fn handle_stream_negotiate(&mut self, negotiate: StreamNegotiate) -> MediaEngineResult<ArcSignalingMessage> {
        // Find session (simplified - in production would track session properly)
        // For now, create a new stream info
        let stream_info = StreamInfo {
            stream_id: negotiate.stream_id,
            media_type: negotiate.media_type,
            codec: negotiate.codec.clone(),
            bitrate: negotiate.bitrate,
            resolution: negotiate.resolution.clone(),
            frame_rate: negotiate.frame_rate,
            ssrc: rand::random(),
            payload_type: 96, // Default payload type
        };

        // Create stream acknowledgment
        let ack = StreamAck {
            stream_id: negotiate.stream_id,
            codec: negotiate.codec,
            bitrate: negotiate.bitrate,
            resolution: negotiate.resolution,
            frame_rate: negotiate.frame_rate,
            ssrc: stream_info.ssrc,
            payload_type: stream_info.payload_type,
        };

        Ok(ArcSignalingMessage::StreamAck(ack))
    }

    /// Handle stream acknowledgment
    fn handle_stream_ack(&mut self, ack: StreamAck) -> MediaEngineResult<ArcSignalingMessage> {
        // Stream acknowledged - ready to start
        Ok(ArcSignalingMessage::StreamAck(ack))
    }

    /// Handle quality update
    fn handle_quality_update(&mut self, update: QualityUpdate) -> MediaEngineResult<ArcSignalingMessage> {
        // Update stream quality
        // In production, would update actual stream configuration
        Ok(ArcSignalingMessage::QualityUpdate(update))
    }

    /// Handle disconnect
    fn handle_disconnect(&mut self, disconnect: Disconnect) -> MediaEngineResult<ArcSignalingMessage> {
        // Remove session
        self.sessions.remove(&disconnect.session_id);
        Ok(ArcSignalingMessage::Disconnect(disconnect))
    }

    /// Get session
    pub fn get_session(&self, session_id: &Uuid) -> Option<&ArcSignalingSession> {
        self.sessions.get(session_id)
    }

    /// Get session mutably
    pub fn get_session_mut(&mut self, session_id: &Uuid) -> Option<&mut ArcSignalingSession> {
        self.sessions.get_mut(session_id)
    }
}

impl Default for ArcSignalingHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connect_request() {
        let mut handler = ArcSignalingHandler::new();
        
        let req = ConnectRequest {
            version: "1.0".to_string(),
            session_id: Uuid::new_v4(),
            peer_id: Uuid::new_v4(),
            capabilities: PeerCapabilities {
                audio_codecs: vec!["opus".to_string()],
                video_codecs: vec!["h264".to_string(), "vp9".to_string()],
                resolutions: vec!["720p".to_string(), "1080p".to_string()],
                max_bitrate: 5_000_000,
                encryption_supported: true,
            },
            relay_servers: None,
        };

        let message = ArcSignalingMessage::Connect(req);
        let response = handler.handle_message(message).unwrap();
        
        match response {
            ArcSignalingMessage::ConnectAck(ack) => {
                assert_eq!(ack.version, "1.0");
                assert!(ack.connection_params.encryption_enabled);
            }
            _ => panic!("Expected ConnectAck"),
        }
    }

    #[test]
    fn test_stream_negotiate() {
        let mut handler = ArcSignalingHandler::new();
        
        let negotiate = StreamNegotiate {
            stream_id: Uuid::new_v4(),
            media_type: ArcMediaType::Audio,
            codec: "opus".to_string(),
            bitrate: 64_000,
            resolution: None,
            frame_rate: None,
        };

        let message = ArcSignalingMessage::StreamNegotiate(negotiate);
        let response = handler.handle_message(message).unwrap();
        
        match response {
            ArcSignalingMessage::StreamAck(ack) => {
                assert_eq!(ack.codec, "opus");
                assert_eq!(ack.bitrate, 64_000);
            }
            _ => panic!("Expected StreamAck"),
        }
    }
}

