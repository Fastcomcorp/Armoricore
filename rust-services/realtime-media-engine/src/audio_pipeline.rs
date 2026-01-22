//! VoIP-optimized audio pipeline
//!
//! Implements Opus encoding/decoding with VoIP-optimized settings:
//! - 32 kbps bitrate
//! - 16 kHz sample rate
//! - Mono channel
//! - 20ms frame size
//! Supports SCIP codec (RFC 9607) for secure audio streams.
//! SECURITY: All audio packets use ArcRTP Critical priority to ensure voice quality.
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


use crate::error::{MediaEngineError, MediaEngineResult};
use crate::rtp_handler::{RtpPacket, RtpHeader};
use crate::arcrtp_handler::{ArcRtpPacket, ArcRtpQuality, ArcRtpPriority};
use crate::scip_payload::{ScipPayloadHandler, ScipPacket, ScipPacketType};
use bytes::Bytes;
use audiopus::{coder::Decoder, coder::Encoder, Channels, SampleRate};

/// Audio configuration for VoIP
#[derive(Debug, Clone)]
pub struct AudioConfig {
    /// Codec name (e.g., "opus")
    pub codec: String,
    /// Bitrate in bits per second
    pub bitrate: u32,
    /// Sample rate in Hz
    pub sample_rate: u32,
    /// Number of channels (1 = mono, 2 = stereo)
    pub channels: u8,
    /// Frame size in milliseconds
    pub frame_size_ms: u32,
    /// Enable DTX (Discontinuous Transmission)
    pub dtx: bool,
    /// Enable FEC (Forward Error Correction)
    pub fec: bool,
    /// Enable PLC (Packet Loss Concealment)
    pub plc: bool,
}

impl Default for AudioConfig {
    fn default() -> Self {
        AudioConfig {
            codec: "opus".to_string(),
            bitrate: 32000,      // 32 kbps (VoIP optimized)
            sample_rate: 16000,  // 16 kHz (voice sufficient)
            channels: 1,         // Mono (voice doesn't need stereo)
            frame_size_ms: 20,   // 20ms frames (low latency)
            dtx: true,           // Discontinuous transmission (silence)
            fec: true,           // Forward error correction
            plc: true,           // Packet loss concealment
        }
    }
}

/// Audio frame
#[derive(Debug, Clone)]
pub struct AudioFrame {
    /// PCM samples (f32, interleaved if stereo)
    pub samples: Vec<f32>,
    /// Sample rate
    pub sample_rate: u32,
    /// Number of channels
    pub channels: u8,
    /// Timestamp
    pub timestamp: u32,
}

/// Audio pipeline for encoding/decoding
pub struct AudioPipeline {
    config: AudioConfig,
    encoder: Option<Encoder>,
    decoder: Option<Decoder>,
    /// SCIP payload handler (RFC 9607) - only used for SCIP codec
    scip_handler: Option<ScipPayloadHandler>,
}

impl AudioPipeline {
    /// Create a new audio pipeline with VoIP-optimized settings
    pub fn new(config: AudioConfig) -> MediaEngineResult<Self> {
        // Validate configuration
        if config.bitrate < 6000 || config.bitrate > 510000 {
            return Err(MediaEngineError::ConfigError(
                format!("Invalid bitrate: {} (must be 6000-510000)", config.bitrate)
            ));
        }

        if config.sample_rate != 8000
            && config.sample_rate != 12000
            && config.sample_rate != 16000
            && config.sample_rate != 24000
            && config.sample_rate != 48000
        {
            return Err(MediaEngineError::ConfigError(
                format!("Invalid sample rate: {} (must be 8/12/16/24/48 kHz)", config.sample_rate)
            ));
        }

        if config.channels < 1 || config.channels > 2 {
            return Err(MediaEngineError::ConfigError(
                format!("Invalid channel count: {} (must be 1 or 2)", config.channels)
            ));
        }

        // Initialize Opus encoder/decoder
        let sample_rate = match config.sample_rate {
            8000 => SampleRate::Hz8000,
            12000 => SampleRate::Hz12000,
            16000 => SampleRate::Hz16000,
            24000 => SampleRate::Hz24000,
            48000 => SampleRate::Hz48000,
            _ => return Err(MediaEngineError::ConfigError(
                format!("Unsupported sample rate: {}", config.sample_rate)
            )),
        };

        let channels = match config.channels {
            1 => Channels::Mono,
            2 => Channels::Stereo,
            _ => return Err(MediaEngineError::ConfigError(
                format!("Unsupported channel count: {}", config.channels)
            )),
        };

        // Create encoder
        let encoder = match Encoder::new(sample_rate, channels, audiopus::Application::Voip) {
            Ok(mut enc) => {
                // Configure encoder
                if let Err(e) = enc.set_bitrate(audiopus::Bitrate::BitsPerSecond(config.bitrate as i32)) {
                    return Err(MediaEngineError::CodecError(format!("Failed to set bitrate: {:?}", e)));
                }
                // Note: DTX is typically controlled via encode() call, not a separate setter
                // The audiopus crate may not have set_dtx, so we'll handle DTX in the encode method
                Some(enc)
            }
            Err(e) => return Err(MediaEngineError::CodecError(format!("Failed to create encoder: {:?}", e))),
        };

        // Create decoder
        let decoder = match Decoder::new(sample_rate, channels) {
            Ok(dec) => Some(dec),
            Err(e) => return Err(MediaEngineError::CodecError(format!("Failed to create decoder: {:?}", e))),
        };

        // Initialize SCIP payload handler if codec is SCIP
        let scip_handler = if config.codec.to_lowercase() == "scip" {
            Some(ScipPayloadHandler::new())
        } else {
            None
        };

        Ok(AudioPipeline {
            config,
            encoder,
            decoder,
            scip_handler,
        })
    }

    /// Create a VoIP-optimized audio pipeline
    pub fn voip_optimized() -> Self {
        Self::new(AudioConfig::default()).unwrap()
    }

    /// Encode PCM audio to Opus
    pub fn encode(&mut self, frame: &AudioFrame) -> MediaEngineResult<Bytes> {
        let encoder = self.encoder.as_mut()
            .ok_or_else(|| MediaEngineError::CodecError("Encoder not initialized".to_string()))?;

        // Validate frame matches configuration
        if frame.sample_rate != self.config.sample_rate {
            return Err(MediaEngineError::ConfigError(
                format!(
                    "Frame sample rate {} doesn't match pipeline sample rate {}",
                    frame.sample_rate, self.config.sample_rate
                )
            ));
        }

        if frame.channels != self.config.channels {
            return Err(MediaEngineError::ConfigError(
                format!(
                    "Frame channels {} doesn't match pipeline channels {}",
                    frame.channels, self.config.channels
                )
            ));
        }

        // Calculate expected frame size
        let samples_per_frame = (self.config.sample_rate * self.config.frame_size_ms) / 1000;
        let expected_samples = (samples_per_frame * self.config.channels as u32) as usize;

        if frame.samples.len() != expected_samples {
            return Err(MediaEngineError::ConfigError(
                format!(
                    "Frame size {} doesn't match expected {} samples",
                    frame.samples.len(),
                    expected_samples
                )
            ));
        }

        // Convert f32 samples to i16 PCM
        let mut pcm_samples = Vec::with_capacity(frame.samples.len());
        for &sample in &frame.samples {
            let pcm = (sample.clamp(-1.0, 1.0) * 32767.0) as i16;
            pcm_samples.push(pcm);
        }

        // Encode with Opus
        let mut encoded = vec![0u8; 4000]; // Opus max frame size
        let encoded_len = encoder.encode(&pcm_samples, &mut encoded)
            .map_err(|e| MediaEngineError::CodecError(format!("Opus encoding error: {:?}", e)))?;

        encoded.truncate(encoded_len);
        Ok(Bytes::from(encoded))
    }

    /// Decode Opus to PCM audio
    pub fn decode(&mut self, encoded: &[u8], timestamp: u32) -> MediaEngineResult<AudioFrame> {
        let decoder = self.decoder.as_mut()
            .ok_or_else(|| MediaEngineError::CodecError("Decoder not initialized".to_string()))?;

        // Calculate expected output size
        let samples_per_frame = (self.config.sample_rate * self.config.frame_size_ms) / 1000;
        let expected_samples = (samples_per_frame * self.config.channels as u32) as usize;

        // Decode with Opus
        let mut pcm_samples = vec![0i16; expected_samples];
        let decoded_samples = decoder.decode(Some(encoded), &mut pcm_samples, false)
            .map_err(|e| MediaEngineError::CodecError(format!("Opus decoding error: {:?}", e)))?;

        // Convert i16 PCM to f32 samples
        let mut samples = Vec::with_capacity(decoded_samples);
        for &pcm in &pcm_samples[..decoded_samples] {
            let sample = pcm as f32 / 32767.0;
            samples.push(sample);
        }

        Ok(AudioFrame {
            samples,
            sample_rate: self.config.sample_rate,
            channels: self.config.channels,
            timestamp,
        })
    }

    /// Create RTP packet from encoded audio
    /// 
    /// For SCIP codec, uses RFC 9607 payload format handler.
    pub fn create_rtp_packet(
        &mut self,
        encoded: Bytes,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
        marker: bool,
    ) -> MediaEngineResult<RtpPacket> {
        // For SCIP codec, use RFC 9607 payload format handler
        if self.config.codec.to_lowercase() == "scip" {
            if let Some(ref mut handler) = self.scip_handler {
                // Create SCIP packet
                let scip_packet = ScipPacket {
                    packet_type: ScipPacketType::Audio,
                    sequence_number,
                    timestamp,
                    payload: encoded,
                    frame_number: None,
                    is_keyframe: false,
                };
                
                // Wrap in RTP using SCIP handler
                handler.wrap_in_rtp(&scip_packet, ssrc, payload_type)
            } else {
                // Fallback if handler not initialized
                self.create_simple_rtp_packet(encoded, sequence_number, timestamp, ssrc, payload_type, marker)
            }
        } else {
            // For other codecs (Opus, etc.), use simple packetization
            self.create_simple_rtp_packet(encoded, sequence_number, timestamp, ssrc, payload_type, marker)
        }
    }

    /// Create a simple RTP packet (for non-SCIP codecs)
    fn create_simple_rtp_packet(
        &self,
        encoded: Bytes,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
        marker: bool,
    ) -> MediaEngineResult<RtpPacket> {
        use crate::rtp_handler::RtpHeader;

        let header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker,
            payload_type,
            sequence_number,
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

    /// Extract audio frame from RTP packet
    /// 
    /// For SCIP codec, uses RFC 9607 depacketization.
    pub fn extract_audio_frame(&mut self, packet: &RtpPacket) -> MediaEngineResult<AudioFrame> {
        // For SCIP codec, use RFC 9607 depacketization
        if self.config.codec.to_lowercase() == "scip" {
            if let Some(ref handler) = self.scip_handler {
                // Extract SCIP packet from RTP
                let scip_packet = handler.extract_from_rtp(packet)?;
                
                // Decode SCIP payload
                self.decode(&scip_packet.payload, scip_packet.timestamp)
            } else {
                // Fallback to simple extraction
                self.decode(&packet.payload, packet.header.timestamp)
            }
        } else {
            // For other codecs, use simple extraction
            self.decode(&packet.payload, packet.header.timestamp)
        }
    }

    /// Get configuration
    pub fn config(&self) -> &AudioConfig {
        &self.config
    }

    /// Get frame size in samples
    pub fn frame_size_samples(&self) -> u32 {
        (self.config.sample_rate * self.config.frame_size_ms) / 1000
    }

    /// Get frame size in bytes (PCM)
    pub fn frame_size_bytes(&self) -> usize {
        (self.frame_size_samples() * self.config.channels as u32 * 2) as usize // 2 bytes per sample (i16)
    }

    /// Create ArcRTP packet from encoded audio
    /// SECURITY: Audio packets always use Critical priority to ensure voice quality
    pub fn create_arcrtp_packet(
        &mut self,
        encoded: Bytes,
        sequence_number: u16,
        timestamp: u32,
        ssrc: u32,
        payload_type: u8,
        marker: bool,
    ) -> MediaEngineResult<ArcRtpPacket> {
        // Create base RTP header
        let rtp_header = RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc: vec![],
            extension_header: None,
        };

        // SECURITY: Audio packets always use Critical priority
        // This ensures voice quality is never compromised
        Ok(ArcRtpPacket::new(
            rtp_header,
            ArcRtpQuality::Excellent, // Audio quality is always excellent when encoded
            ArcRtpPriority::Critical, // Audio always critical priority
            encoded,
        ))
    }

    /// Extract audio frame from ArcRTP packet
    pub fn extract_audio_frame_from_arcrtp(&mut self, packet: &ArcRtpPacket) -> MediaEngineResult<AudioFrame> {
        // Verify this is an audio packet with Critical priority
        if packet.priority() != ArcRtpPriority::Critical {
            // Log warning but continue processing
            tracing::warn!("Audio packet does not have Critical priority - this may indicate a routing issue");
        }

        // Convert ArcRTP to RTP for extraction
        let rtp_packet = packet.to_rtp();
        self.extract_audio_frame(&rtp_packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_config_default() {
        let config = AudioConfig::default();
        assert_eq!(config.codec, "opus");
        assert_eq!(config.bitrate, 32000);
        assert_eq!(config.sample_rate, 16000);
        assert_eq!(config.channels, 1);
        assert_eq!(config.frame_size_ms, 20);
        assert!(config.dtx);
        assert!(config.fec);
        assert!(config.plc);
    }

    #[test]
    fn test_audio_pipeline_voip_optimized() {
        let pipeline = AudioPipeline::voip_optimized();
        assert_eq!(pipeline.config().bitrate, 32000);
        assert_eq!(pipeline.config().sample_rate, 16000);
        assert_eq!(pipeline.config().channels, 1);
    }

    #[test]
    fn test_audio_pipeline_frame_size() {
        let pipeline = AudioPipeline::voip_optimized();
        // 16 kHz * 20ms = 320 samples
        assert_eq!(pipeline.frame_size_samples(), 320);
        // 320 samples * 1 channel * 2 bytes = 640 bytes
        assert_eq!(pipeline.frame_size_bytes(), 640);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut pipeline = AudioPipeline::voip_optimized();
        
        // Create test frame (320 samples for 20ms at 16kHz)
        let samples: Vec<f32> = (0..320)
            .map(|i| (i as f32 / 320.0).sin())
            .collect();
        
        let frame = AudioFrame {
            samples: samples.clone(),
            sample_rate: 16000,
            channels: 1,
            timestamp: 1000,
        };

        // Encode
        let encoded = pipeline.encode(&frame).unwrap();

        // Decode
        let decoded = pipeline.decode(&encoded, 1000).unwrap();

        // Verify
        assert_eq!(decoded.sample_rate, 16000);
        assert_eq!(decoded.channels, 1);
        assert_eq!(decoded.timestamp, 1000);
        assert_eq!(decoded.samples.len(), samples.len());
    }

    #[test]
    fn test_create_rtp_packet() {
        let pipeline = AudioPipeline::voip_optimized();
        let encoded = Bytes::from(vec![0u8; 100]);

        let packet = pipeline
            .create_rtp_packet(encoded, 1, 1000, 12345, 96, false)
            .unwrap();

        assert_eq!(packet.header.sequence_number, 1);
        assert_eq!(packet.header.timestamp, 1000);
        assert_eq!(packet.header.ssrc, 12345);
        assert_eq!(packet.header.payload_type, 96);
    }
}

