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

//! Video pipeline for encoding/decoding
//!
//! Supports H.264, VP9, AV1, and VVC codecs with adaptive bitrate control.
//! Uses RFC 6184 for H.264 and draft-ietf-avtcore-rtp-vvc for VVC packetization.
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
use crate::h264_payload::{H264PayloadHandler, NalUnit};
use crate::vvc_payload::{VvcPayloadHandler, VvcNalUnit};
use bytes::Bytes;

/// Video codec type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    /// H.264 (AVC)
    H264,
    /// VP9
    Vp9,
    /// AV1
    Av1,
    /// VVC (H.266)
    Vvc,
}

impl VideoCodec {
    /// Parse codec from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "h264" | "avc" | "x264" => Some(VideoCodec::H264),
            "vp9" => Some(VideoCodec::Vp9),
            "av1" => Some(VideoCodec::Av1),
            "vvc" | "h266" | "vvc266" => Some(VideoCodec::Vvc),
            _ => None,
        }
    }

    /// Get codec name as string
    pub fn as_str(&self) -> &'static str {
        match self {
            VideoCodec::H264 => "h264",
            VideoCodec::Vp9 => "vp9",
            VideoCodec::Av1 => "av1",
            VideoCodec::Vvc => "vvc",
        }
    }
}

/// Video resolution
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoResolution {
    /// 360p (640x360)
    P360,
    /// 480p (854x480)
    P480,
    /// 720p (1280x720)
    P720,
    /// 1080p (1920x1080)
    P1080,
    /// 1440p (2560x1440)
    P1440,
    /// 4K (3840x2160)
    P4K,
    /// 5K (5120x2880)
    P5K,
    /// 8K (7680x4320)
    P8K,
}

impl VideoResolution {
    /// Parse resolution from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "360p" => Some(VideoResolution::P360),
            "480p" => Some(VideoResolution::P480),
            "720p" => Some(VideoResolution::P720),
            "1080p" => Some(VideoResolution::P1080),
            "1440p" => Some(VideoResolution::P1440),
            "4k" | "2160p" => Some(VideoResolution::P4K),
            "5k" | "2880p" => Some(VideoResolution::P5K),
            "8k" | "4320p" => Some(VideoResolution::P8K),
            _ => None,
        }
    }

    /// Get resolution as string
    pub fn as_str(&self) -> &'static str {
        match self {
            VideoResolution::P360 => "360p",
            VideoResolution::P480 => "480p",
            VideoResolution::P720 => "720p",
            VideoResolution::P1080 => "1080p",
            VideoResolution::P1440 => "1440p",
            VideoResolution::P4K => "4K",
            VideoResolution::P5K => "5K",
            VideoResolution::P8K => "8K",
        }
    }

    /// Get width and height
    pub fn dimensions(&self) -> (u32, u32) {
        match self {
            VideoResolution::P360 => (640, 360),
            VideoResolution::P480 => (854, 480),
            VideoResolution::P720 => (1280, 720),
            VideoResolution::P1080 => (1920, 1080),
            VideoResolution::P1440 => (2560, 1440),
            VideoResolution::P4K => (3840, 2160),
            VideoResolution::P5K => (5120, 2880),
            VideoResolution::P8K => (7680, 4320),
        }
    }

    /// Get pixels per frame
    pub fn pixels(&self) -> u32 {
        let (w, h) = self.dimensions();
        w * h
    }
}

/// Video configuration
#[derive(Debug, Clone)]
pub struct VideoConfig {
    /// Codec type
    pub codec: VideoCodec,
    /// Bitrate in bits per second
    pub bitrate: u32,
    /// Resolution
    pub resolution: VideoResolution,
    /// Frame rate (fps)
    pub frame_rate: u32,
    /// Keyframe interval (frames)
    pub keyframe_interval: u32,
    /// Enable adaptive bitrate
    pub adaptive_bitrate: bool,
}

impl Default for VideoConfig {
    fn default() -> Self {
        VideoConfig {
            codec: VideoCodec::H264,
            bitrate: 1_000_000,  // 1 Mbps
            resolution: VideoResolution::P720,
            frame_rate: 30,
            keyframe_interval: 30,  // Keyframe every second at 30fps
            adaptive_bitrate: true,
        }
    }
}

/// Video frame
#[derive(Debug, Clone)]
pub struct VideoFrame {
    /// Raw frame data (YUV420, RGB, etc.)
    pub data: Vec<u8>,
    /// Width
    pub width: u32,
    /// Height
    pub height: u32,
    /// Timestamp
    pub timestamp: u32,
    /// Is keyframe (I-frame)
    pub is_keyframe: bool,
    /// Frame number
    pub frame_number: u64,
}

/// Video pipeline for encoding/decoding
pub struct VideoPipeline {
    config: VideoConfig,
    frame_counter: u64,
    /// H.264 payload handler (RFC 6184) - only used for H.264 codec
    h264_handler: Option<H264PayloadHandler>,
    /// VVC payload handler (draft-ietf-avtcore-rtp-vvc) - only used for VVC codec
    vvc_handler: Option<VvcPayloadHandler>,
    // Note: Actual encoder/decoder would be initialized here
    // For now, we provide the interface
    // In production, this would use FFmpeg, x264, libvpx, etc.
}

impl VideoPipeline {
    /// Create a new video pipeline
    pub fn new(config: VideoConfig) -> MediaEngineResult<Self> {
        // Validate configuration
        if config.bitrate < 100_000 || config.bitrate > 50_000_000 {
            return Err(MediaEngineError::ConfigError(
                format!("Invalid bitrate: {} (must be 100k-50M bps)", config.bitrate)
            ));
        }

        if config.frame_rate < 1 || config.frame_rate > 120 {
            return Err(MediaEngineError::ConfigError(
                format!("Invalid frame rate: {} (must be 1-120 fps)", config.frame_rate)
            ));
        }

        if config.keyframe_interval == 0 {
            return Err(MediaEngineError::ConfigError(
                "Keyframe interval must be > 0".to_string()
            ));
        }

        // Initialize H.264 payload handler if codec is H.264
        let h264_handler = if config.codec == VideoCodec::H264 {
            Some(H264PayloadHandler::new(1200)) // MTU typically 1200 bytes
        } else {
            None
        };

        // Initialize VVC payload handler if codec is VVC
        let vvc_handler = if config.codec == VideoCodec::Vvc {
            Some(VvcPayloadHandler::new(1200)) // MTU typically 1200 bytes
        } else {
            None
        };

        Ok(VideoPipeline {
            config,
            frame_counter: 0,
            h264_handler,
            vvc_handler,
        })
    }

    /// Update bitrate (for adaptive bitrate)
    pub fn update_bitrate(&mut self, new_bitrate: u32) -> MediaEngineResult<()> {
        if new_bitrate < 100_000 || new_bitrate > 50_000_000 {
            return Err(MediaEngineError::ConfigError(
                format!("Invalid bitrate: {} (must be 100k-50M bps)", new_bitrate)
            ));
        }

        self.config.bitrate = new_bitrate;
        // In production, would reconfigure encoder here
        Ok(())
    }

    /// Update resolution (for adaptive bitrate)
    pub fn update_resolution(&mut self, new_resolution: VideoResolution) -> MediaEngineResult<()> {
        self.config.resolution = new_resolution;
        // In production, would reconfigure encoder here
        Ok(())
    }

    /// Encode video frame
    pub fn encode(&mut self, frame: &VideoFrame) -> MediaEngineResult<Bytes> {
        // Validate frame dimensions match config
        let (expected_width, expected_height) = self.config.resolution.dimensions();
        if frame.width != expected_width || frame.height != expected_height {
            return Err(MediaEngineError::ConfigError(
                format!(
                    "Frame dimensions {}x{} don't match config {}x{}",
                    frame.width, frame.height, expected_width, expected_height
                )
            ));
        }

        self.frame_counter += 1;

        // Determine if this should be a keyframe
        let should_be_keyframe = frame.is_keyframe || 
            (self.frame_counter % self.config.keyframe_interval as u64 == 0);

        // In production, this would:
        // 1. Convert frame format if needed (RGB -> YUV420, etc.)
        // 2. Call encoder (x264, libvpx-vp9, libaom-av1)
        // 3. Return encoded NAL units or packets

        // For now, return placeholder
        // In production, this would be actual encoded video data
        let mut encoded = Vec::new();
        
        // Add keyframe marker if needed
        if should_be_keyframe {
            encoded.push(0x01); // Keyframe marker
        } else {
            encoded.push(0x00); // Delta frame marker
        }

        // Add frame data (placeholder - would be actual encoded data)
        encoded.extend_from_slice(&frame.data[..frame.data.len().min(100)]); // Limit size for placeholder

        Ok(Bytes::from(encoded))
    }

    /// Decode video frame
    pub fn decode(&mut self, encoded: &[u8], timestamp: u32) -> MediaEngineResult<VideoFrame> {
        if encoded.is_empty() {
            return Err(MediaEngineError::CodecError("Empty encoded data".to_string()));
        }

        // Check if keyframe
        let is_keyframe = encoded[0] == 0x01;

        // In production, this would:
        // 1. Parse NAL units or packets
        // 2. Call decoder (x264, libvpx-vp9, libaom-av1)
        // 3. Convert YUV420 -> RGB if needed
        // 4. Return decoded frame

        // For now, return placeholder frame
        let (width, height) = self.config.resolution.dimensions();
        let frame_size = (width * height * 3) as usize; // RGB
        let data = vec![0u8; frame_size.min(encoded.len().saturating_sub(1))];

        Ok(VideoFrame {
            data,
            width,
            height,
            timestamp,
            is_keyframe,
            frame_number: self.frame_counter,
        })
    }

    /// Create RTP packet(s) from encoded video
    /// 
    /// For H.264, uses RFC 6184 payload format handler for proper NAL unit packetization.
    /// Returns a vector of RTP packets (may be multiple for fragmented NAL units).
    pub fn create_rtp_packets(
        &mut self,
        encoded: Bytes,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
        is_keyframe: bool,
    ) -> MediaEngineResult<Vec<RtpPacket>> {
        // For H.264, use RFC 6184 payload format handler
        if self.config.codec == VideoCodec::H264 {
            if let Some(ref mut handler) = self.h264_handler {
                // Parse NAL unit from encoded data
                let nal_unit = NalUnit::parse(&encoded)?;
                
                // Packetize according to RFC 6184
                handler.packetize_nal_unit(&nal_unit, timestamp, ssrc, payload_type)
            } else {
                // Fallback if handler not initialized
                self.create_simple_rtp_packet(encoded, timestamp, ssrc, payload_type, is_keyframe)
                    .map(|p| vec![p])
            }
        } else if self.config.codec == VideoCodec::Vvc {
            // For VVC, use draft-ietf-avtcore-rtp-vvc payload format handler
            if let Some(ref mut handler) = self.vvc_handler {
                // Parse VVC NAL unit from encoded data
                let nal_unit = VvcNalUnit::parse(&encoded)?;
                
                // Packetize according to draft-ietf-avtcore-rtp-vvc
                handler.packetize_nal_unit(&nal_unit, timestamp, ssrc, payload_type)
            } else {
                // Fallback if handler not initialized
                self.create_simple_rtp_packet(encoded, timestamp, ssrc, payload_type, is_keyframe)
                    .map(|p| vec![p])
            }
        } else {
            // For other codecs (VP9, AV1), use simple packetization
            self.create_simple_rtp_packet(encoded, timestamp, ssrc, payload_type, is_keyframe)
                .map(|p| vec![p])
        }
    }

    /// Create a simple RTP packet (for non-H.264 codecs)
    fn create_simple_rtp_packet(
        &self,
        encoded: Bytes,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
        is_keyframe: bool,
    ) -> MediaEngineResult<RtpPacket> {
        use crate::rtp_handler::RtpHeader;

        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: is_keyframe, // Mark keyframes
            payload_type,
            sequence_number: 0, // Will be set by caller
            timestamp,
            ssrc,
            csrc: vec![],
            extension_header: None,
        };

        Ok(RtpPacket {
            header,
            payload: encoded,
        })
    }

    /// Create RTP packet from encoded video (backward compatibility)
    /// 
    /// @deprecated Use create_rtp_packets instead for proper RFC 6184 support
    pub fn create_rtp_packet(
        &mut self,
        encoded: Bytes,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
        is_keyframe: bool,
    ) -> MediaEngineResult<RtpPacket> {
        // For H.264, use RFC 6184
        if self.config.codec == VideoCodec::H264 {
            if let Some(ref mut handler) = self.h264_handler {
                handler.sequence_number = sequence_number;
                let packets = self.create_rtp_packets(encoded, timestamp, ssrc, payload_type, is_keyframe)?;
                // Return first packet (caller should handle fragmentation)
                packets.into_iter().next().ok_or_else(|| {
                    MediaEngineError::CodecError("No packets generated".to_string())
                })
            } else {
                self.create_simple_rtp_packet(encoded, timestamp, ssrc, payload_type, is_keyframe)
                    .map(|mut p| {
                        p.header.sequence_number = sequence_number;
                        p
                    })
            }
        } else {
            self.create_simple_rtp_packet(encoded, timestamp, ssrc, payload_type, is_keyframe)
                .map(|mut p| {
                    p.header.sequence_number = sequence_number;
                    p
                })
        }
    }

    /// Extract video frame from RTP packet(s)
    /// 
    /// For H.264, uses RFC 6184 depacketization to reconstruct NAL units.
    pub fn extract_video_frame(
        &mut self,
        packets: &[RtpPacket],
    ) -> MediaEngineResult<VideoFrame> {
        if packets.is_empty() {
            return Err(MediaEngineError::CodecError("No packets provided".to_string()));
        }

        // For H.264, use RFC 6184 depacketization
        if self.config.codec == VideoCodec::H264 {
            if let Some(ref handler) = self.h264_handler {
                // Depacketize RTP packets to NAL units
                let nal_units = handler.depacketize(packets)?;
                
                if nal_units.is_empty() {
                    return Err(MediaEngineError::CodecError("No NAL units extracted".to_string()));
                }

                // Combine NAL units into single encoded frame
                let mut combined_data = Vec::new();
                for nal_unit in &nal_units {
                    combined_data.extend_from_slice(&nal_unit.data);
                }

                // Check if any NAL unit is a keyframe
                let is_keyframe = nal_units.iter().any(|nal| nal.nal_type.is_keyframe());
                
                // Decode the combined frame
                self.decode(&combined_data, packets[0].header.timestamp)
                    .map(|mut frame| {
                        frame.is_keyframe = is_keyframe;
                        frame
                    })
            } else {
                // Fallback to simple extraction
                self.extract_video_frame_simple(&packets[0])
            }
        } else if self.config.codec == VideoCodec::Vvc {
            // For VVC, use draft-ietf-avtcore-rtp-vvc depacketization
            if let Some(ref handler) = self.vvc_handler {
                // Depacketize RTP packets to VVC NAL units
                let nal_units = handler.depacketize(packets)?;
                
                if nal_units.is_empty() {
                    return Err(MediaEngineError::CodecError("No VVC NAL units extracted".to_string()));
                }

                // Combine NAL units into single encoded frame
                let mut combined_data = Vec::new();
                for nal_unit in &nal_units {
                    combined_data.extend_from_slice(&nal_unit.data);
                }

                // Check if any NAL unit is a keyframe
                let is_keyframe = nal_units.iter().any(|nal| nal.nal_type.is_keyframe());
                
                // Decode the combined frame
                self.decode(&combined_data, packets[0].header.timestamp)
                    .map(|mut frame| {
                        frame.is_keyframe = is_keyframe;
                        frame
                    })
            } else {
                // Fallback to simple extraction
                self.extract_video_frame_simple(&packets[0])
            }
        } else {
            // For other codecs, use simple extraction
            self.extract_video_frame_simple(&packets[0])
        }
    }

    /// Extract video frame from single RTP packet (simple method)
    fn extract_video_frame_simple(&mut self, packet: &RtpPacket) -> MediaEngineResult<VideoFrame> {
        let is_keyframe = packet.header.marker;
        
        self.decode(&packet.payload, packet.header.timestamp)
            .map(|mut frame| {
                frame.is_keyframe = is_keyframe;
                frame
            })
    }

    /// Get current configuration
    pub fn config(&self) -> &VideoConfig {
        &self.config
    }

    /// Get current bitrate
    pub fn current_bitrate(&self) -> u32 {
        self.config.bitrate
    }

    /// Get current resolution
    pub fn current_resolution(&self) -> VideoResolution {
        self.config.resolution
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_video_codec_parsing() {
        assert_eq!(VideoCodec::from_str("h264"), Some(VideoCodec::H264));
        assert_eq!(VideoCodec::from_str("vp9"), Some(VideoCodec::Vp9));
        assert_eq!(VideoCodec::from_str("av1"), Some(VideoCodec::Av1));
    }

    #[test]
    fn test_video_resolution_parsing() {
        assert_eq!(VideoResolution::from_str("720p"), Some(VideoResolution::P720));
        assert_eq!(VideoResolution::from_str("1080p"), Some(VideoResolution::P1080));
        assert_eq!(VideoResolution::from_str("4k"), Some(VideoResolution::P4K));
    }

    #[test]
    fn test_video_resolution_dimensions() {
        let (w, h) = VideoResolution::P720.dimensions();
        assert_eq!(w, 1280);
        assert_eq!(h, 720);
    }

    #[test]
    fn test_video_pipeline_creation() {
        let config = VideoConfig::default();
        let pipeline = VideoPipeline::new(config);
        assert!(pipeline.is_ok());
    }

    #[test]
    fn test_video_pipeline_bitrate_update() {
        let config = VideoConfig::default();
        let mut pipeline = VideoPipeline::new(config).unwrap();
        
        pipeline.update_bitrate(2_000_000).unwrap();
        assert_eq!(pipeline.current_bitrate(), 2_000_000);
    }

    #[test]
    fn test_video_pipeline_resolution_update() {
        let config = VideoConfig::default();
        let mut pipeline = VideoPipeline::new(config).unwrap();
        
        pipeline.update_resolution(VideoResolution::P1080).unwrap();
        assert_eq!(pipeline.current_resolution(), VideoResolution::P1080);
    }
}

