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

//! Stream management for media streams
//!
//! Handles stream lifecycle, state tracking, and configuration.
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
use crate::srtp_pipeline::{SrtpPipeline, SrtpConfig};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Media type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// Audio stream
    Audio,
    /// Video stream
    Video,
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is being initialized
    Initializing,
    /// Stream is active and sending/receiving
    Active,
    /// Stream is paused
    Paused,
    /// Stream is stopped
    Stopped,
    /// Stream has encountered an error
    Error,
}

/// Stream configuration
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// User ID who owns this stream
    pub user_id: Uuid,
    /// Media type (audio or video)
    pub media_type: MediaType,
    /// SSRC for this stream
    pub ssrc: u32,
    /// Payload type
    pub payload_type: u8,
    /// Codec information
    pub codec: String,
    /// Bitrate in bits per second
    pub bitrate: u32,
    /// SRTP configuration
    pub srtp_config: Option<SrtpConfig>,
}

/// Stream information
pub struct Stream {
    /// Stream ID
    pub stream_id: Uuid,
    /// Configuration
    pub config: StreamConfig,
    /// Current state
    pub state: StreamState,
    /// SRTP pipeline (if encryption enabled)
    pub srtp_pipeline: Option<Arc<SrtpPipeline>>,
    /// Statistics
    pub stats: StreamStats,
}

/// Stream statistics
#[derive(Debug, Default)]
pub struct StreamStats {
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Packets lost
    pub packets_lost: u64,
    /// Jitter in milliseconds
    pub jitter_ms: f64,
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
}

/// Stream manager
pub struct StreamManager {
    /// Active streams
    streams: HashMap<Uuid, Stream>,
    /// SSRC to stream ID mapping
    ssrc_to_stream: HashMap<u32, Uuid>,
}

impl StreamManager {
    /// Create a new stream manager
    pub fn new() -> Self {
        StreamManager {
            streams: HashMap::new(),
            ssrc_to_stream: HashMap::new(),
        }
    }

    /// Create a new stream
    pub fn create_stream(&mut self, config: StreamConfig) -> MediaEngineResult<Uuid> {
        // Check if SSRC is already in use
        if self.ssrc_to_stream.contains_key(&config.ssrc) {
            return Err(MediaEngineError::StreamExists {
                stream_id: format!("SSRC {}", config.ssrc),
            });
        }

        let stream_id = Uuid::new_v4();

        // Create SRTP pipeline if encryption is enabled
        let srtp_pipeline = if let Some(ref srtp_config) = config.srtp_config {
            Some(Arc::new(SrtpPipeline::new(srtp_config.clone())?))
        } else {
            None
        };

        let stream = Stream {
            stream_id,
            config: config.clone(),
            state: StreamState::Initializing,
            srtp_pipeline,
            stats: StreamStats::default(),
        };

        self.streams.insert(stream_id, stream);
        self.ssrc_to_stream.insert(config.ssrc, stream_id);

        Ok(stream_id)
    }

    /// Get stream by ID
    pub fn get_stream(&self, stream_id: &Uuid) -> Option<&Stream> {
        self.streams.get(stream_id)
    }

    /// Get stream by SSRC
    pub fn get_stream_by_ssrc(&self, ssrc: u32) -> Option<&Stream> {
        self.ssrc_to_stream
            .get(&ssrc)
            .and_then(|id| self.streams.get(id))
    }

    /// Get mutable stream by ID
    pub fn get_stream_mut(&mut self, stream_id: &Uuid) -> Option<&mut Stream> {
        self.streams.get_mut(stream_id)
    }

    /// Update stream state
    pub fn update_stream_state(
        &mut self,
        stream_id: &Uuid,
        new_state: StreamState,
    ) -> MediaEngineResult<()> {
        let stream = self.streams.get_mut(stream_id)
            .ok_or_else(|| MediaEngineError::StreamNotFound {
                stream_id: stream_id.to_string(),
            })?;

        // Validate state transition
        match (stream.state, new_state) {
            (StreamState::Stopped, _) if new_state != StreamState::Stopped => {
                return Err(MediaEngineError::InvalidStreamState {
                    state: format!("Cannot transition from {:?} to {:?}", stream.state, new_state),
                });
            }
            _ => {}
        }

        stream.state = new_state;
        Ok(())
    }

    /// Remove stream
    pub fn remove_stream(&mut self, stream_id: &Uuid) -> MediaEngineResult<()> {
        let stream = self.streams.remove(stream_id)
            .ok_or_else(|| MediaEngineError::StreamNotFound {
                stream_id: stream_id.to_string(),
            })?;

        self.ssrc_to_stream.remove(&stream.config.ssrc);
        Ok(())
    }

    /// Get all streams
    pub fn list_streams(&self) -> Vec<Uuid> {
        self.streams.keys().cloned().collect()
    }

    /// Get streams by user ID
    pub fn get_streams_by_user(&self, user_id: &Uuid) -> Vec<Uuid> {
        self.streams
            .iter()
            .filter(|(_, stream)| stream.config.user_id == *user_id)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Update stream statistics
    pub fn update_stats(&mut self, stream_id: &Uuid, stats: StreamStats) -> MediaEngineResult<()> {
        let stream = self.streams.get_mut(stream_id)
            .ok_or_else(|| MediaEngineError::StreamNotFound {
                stream_id: stream_id.to_string(),
            })?;

        stream.stats = stats;
        Ok(())
    }
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> StreamConfig {
        StreamConfig {
            user_id: Uuid::new_v4(),
            media_type: MediaType::Audio,
            ssrc: 12345,
            payload_type: 96,
            codec: "opus".to_string(),
            bitrate: 32000,
            srtp_config: None,
        }
    }

    #[test]
    fn test_create_stream() {
        let mut manager = StreamManager::new();
        let config = create_test_config();
        
        let stream_id = manager.create_stream(config).unwrap();
        
        assert!(manager.get_stream(&stream_id).is_some());
    }

    #[test]
    fn test_duplicate_ssrc() {
        let mut manager = StreamManager::new();
        let config1 = create_test_config();
        let mut config2 = create_test_config();
        config2.ssrc = config1.ssrc; // Same SSRC
        
        manager.create_stream(config1).unwrap();
        assert!(manager.create_stream(config2).is_err());
    }

    #[test]
    fn test_get_stream_by_ssrc() {
        let mut manager = StreamManager::new();
        let config = create_test_config();
        let ssrc = config.ssrc;
        
        let stream_id = manager.create_stream(config).unwrap();
        let found_stream = manager.get_stream_by_ssrc(ssrc).unwrap();
        
        assert_eq!(found_stream.stream_id, stream_id);
    }

    #[test]
    fn test_update_stream_state() {
        let mut manager = StreamManager::new();
        let config = create_test_config();
        let stream_id = manager.create_stream(config).unwrap();
        
        manager.update_stream_state(&stream_id, StreamState::Active).unwrap();
        let stream = manager.get_stream(&stream_id).unwrap();
        assert_eq!(stream.state, StreamState::Active);
    }

    #[test]
    fn test_remove_stream() {
        let mut manager = StreamManager::new();
        let config = create_test_config();
        let stream_id = manager.create_stream(config).unwrap();
        
        manager.remove_stream(&stream_id).unwrap();
        assert!(manager.get_stream(&stream_id).is_none());
    }
}

