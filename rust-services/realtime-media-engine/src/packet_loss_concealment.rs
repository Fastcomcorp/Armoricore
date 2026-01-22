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

//! Packet Loss Concealment (PLC) for audio
//!
//! Implements basic PLC algorithms to hide packet loss from users.
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

/// Audio PLC configuration
#[derive(Debug, Clone)]
pub struct AudioPlcConfig {
    /// Enable PLC
    pub enabled: bool,
    /// Maximum consecutive lost packets to conceal
    pub max_conceal_packets: usize,
}

impl Default for AudioPlcConfig {
    fn default() -> Self {
        AudioPlcConfig {
            enabled: true,
            max_conceal_packets: 3,
        }
    }
}

/// Audio packet loss concealment
pub struct AudioPlc {
    /// Last received audio samples
    last_samples: Vec<f32>,
    /// Configuration
    config: AudioPlcConfig,
    /// Consecutive lost packets
    consecutive_lost: usize,
}

impl AudioPlc {
    /// Create a new audio PLC
    pub fn new(config: AudioPlcConfig) -> Self {
        AudioPlc {
            last_samples: Vec::new(),
            config,
            consecutive_lost: 0,
        }
    }

    /// Process a received packet (updates internal state)
    pub fn process_packet(&mut self, _packet: &RtpPacket) -> MediaEngineResult<()> {
        // Decode audio samples from packet payload
        // For now, we'll just store the raw payload
        // In a real implementation, we'd decode Opus/AAC/etc.
        
        // Reset consecutive lost counter
        self.consecutive_lost = 0;
        
        // Store last samples (simplified - in real implementation, decode audio)
        // For Phase 1, we'll just track that we received a packet
        Ok(())
    }

    /// Conceal a lost packet
    pub fn conceal(&mut self, expected_sequence: u16) -> MediaEngineResult<Option<Vec<u32>>> {
        if !self.config.enabled {
            return Ok(None);
        }

        // Track expected sequence for debugging (will be used in Phase 2)
        let _ = expected_sequence;
        
        self.consecutive_lost += 1;

        if self.consecutive_lost > self.config.max_conceal_packets {
            // Too many lost packets, can't conceal
            return Ok(None);
        }

        // Basic PLC: repeat last samples
        // In a real implementation, we would:
        // 1. Decode last received audio samples
        // 2. Apply pitch-based extrapolation
        // 3. Generate comfort noise if needed
        // 4. Encode and return

        // For Phase 1, return None (indicating we can't generate audio yet)
        // This will be enhanced in Phase 2 with actual audio decoding/encoding
        Ok(None)
    }

    /// Reset PLC state
    pub fn reset(&mut self) {
        self.last_samples.clear();
        self.consecutive_lost = 0;
    }
}

/// Video PLC configuration
#[derive(Debug, Clone)]
pub struct VideoPlcConfig {
    /// Enable PLC
    pub enabled: bool,
    /// Maximum consecutive lost packets to conceal
    pub max_conceal_packets: usize,
    /// Enable frame interpolation
    pub enable_interpolation: bool,
    /// Enable motion compensation
    pub enable_motion_compensation: bool,
}

impl Default for VideoPlcConfig {
    fn default() -> Self {
        VideoPlcConfig {
            enabled: true,
            max_conceal_packets: 5,
            enable_interpolation: true,
            enable_motion_compensation: false, // Advanced feature
        }
    }
}

/// Video packet loss concealment
pub struct VideoPlc {
    /// Last received keyframe
    last_keyframe: Option<RtpPacket>,
    /// Last received frame (any type)
    last_frame: Option<RtpPacket>,
    /// Previous frame for interpolation
    previous_frame: Option<RtpPacket>,
    /// Configuration
    config: VideoPlcConfig,
    /// Consecutive lost packets
    consecutive_lost: usize,
    /// Frame sequence tracking
    frame_sequence: u16,
}

impl VideoPlc {
    /// Create a new video PLC
    pub fn new(config: VideoPlcConfig) -> Self {
        VideoPlc {
            last_keyframe: None,
            last_frame: None,
            previous_frame: None,
            config,
            consecutive_lost: 0,
            frame_sequence: 0,
        }
    }

    /// Process a received packet
    pub fn process_packet(&mut self, packet: &RtpPacket) -> MediaEngineResult<()> {
        // Update frame sequence
        self.frame_sequence = packet.header.sequence_number;
        
        // Store last frame
        self.previous_frame = self.last_frame.clone();
        self.last_frame = Some(packet.clone());
        
        // Store keyframes separately
        if packet.header.marker {
            self.last_keyframe = Some(packet.clone());
        }
        
        // Reset consecutive lost counter
        self.consecutive_lost = 0;
        
        Ok(())
    }

    /// Conceal a lost packet
    pub fn conceal(&mut self, expected_sequence: u16) -> MediaEngineResult<Option<RtpPacket>> {
        if !self.config.enabled {
            return Ok(None);
        }

        self.consecutive_lost += 1;

        if self.consecutive_lost > self.config.max_conceal_packets {
            // Too many lost packets, request keyframe
            return Ok(None);
        }

        // Strategy 1: Freeze last frame (simplest)
        if let Some(ref last_frame) = self.last_frame {
            let mut concealed = last_frame.clone();
            concealed.header.sequence_number = expected_sequence;
            concealed.header.timestamp = last_frame.header.timestamp; // Keep same timestamp (freeze)
            concealed.header.marker = false; // Not a keyframe
            
            // If interpolation is enabled and we have previous frame, try interpolation
            if self.config.enable_interpolation && self.consecutive_lost == 1 {
                if self.previous_frame.is_some() {
                    // Simple interpolation: blend between previous and last frame
                    // In production, this would decode frames, interpolate pixels, and re-encode
                    // For now, we use the last frame but could enhance with actual interpolation
                    return Ok(Some(concealed));
                }
            }
            
            return Ok(Some(concealed));
        }

        // Strategy 2: Use last keyframe if available
        if let Some(ref keyframe) = self.last_keyframe {
            let mut concealed = keyframe.clone();
            concealed.header.sequence_number = expected_sequence;
            concealed.header.marker = false; // Not a new keyframe
            return Ok(Some(concealed));
        }

        // No frame available
        Err(MediaEngineError::BufferError(
            "No previous frame available for concealment".to_string()
        ))
    }

    /// Reset PLC state
    pub fn reset(&mut self) {
        self.last_keyframe = None;
        self.last_frame = None;
        self.previous_frame = None;
        self.consecutive_lost = 0;
        self.frame_sequence = 0;
    }

    /// Get consecutive lost packets count
    pub fn consecutive_lost(&self) -> usize {
        self.consecutive_lost
    }

    /// Check if keyframe is needed
    pub fn needs_keyframe(&self) -> bool {
        self.consecutive_lost > self.config.max_conceal_packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_handler::{RtpHeader, RtpPacket};
    use bytes::Bytes;

    fn create_test_packet(seq: u16) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 96,
                sequence_number: seq,
                timestamp: 1000,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::from("test"),
        }
    }

    #[test]
    fn test_audio_plc_reset() {
        let mut plc = AudioPlc::new(AudioPlcConfig::default());
        plc.reset();
        assert_eq!(plc.consecutive_lost, 0);
    }

    #[test]
    fn test_video_plc_freeze_frame() {
        let config = VideoPlcConfig::default();
        let mut plc = VideoPlc::new(config);
        let mut packet = create_test_packet(1);
        packet.header.marker = true;
        
        plc.process_packet(&packet).unwrap();
        let concealed = plc.conceal(2).unwrap();
        
        assert!(concealed.is_some());
        assert_eq!(concealed.unwrap().header.sequence_number, 2);
    }

    #[test]
    fn test_video_plc_consecutive_loss() {
        let config = VideoPlcConfig::default();
        let mut plc = VideoPlc::new(config);
        let packet = create_test_packet(1);
        
        plc.process_packet(&packet).unwrap();
        
        // Simulate consecutive losses
        plc.conceal(2).unwrap();
        plc.conceal(3).unwrap();
        plc.conceal(4).unwrap();
        
        assert_eq!(plc.consecutive_lost(), 3);
    }

    #[test]
    fn test_video_plc_needs_keyframe() {
        let config = VideoPlcConfig {
            max_conceal_packets: 3,
            ..Default::default()
        };
        let mut plc = VideoPlc::new(config);
        let packet = create_test_packet(1);
        
        plc.process_packet(&packet).unwrap();
        
        // Simulate too many losses
        plc.conceal(2).unwrap();
        plc.conceal(3).unwrap();
        plc.conceal(4).unwrap();
        plc.conceal(5).unwrap();
        
        assert!(plc.needs_keyframe());
    }
}

