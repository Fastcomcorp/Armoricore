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

//! Network-aware codec selection
//!
//! Automatically selects the best codec based on network conditions.
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


use crate::error::MediaEngineResult;
use crate::connection_health::{NetworkMetrics, ConnectionQuality};

/// Network profile
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProfile {
    /// Excellent: Low latency, high bandwidth, low loss
    Excellent,
    /// Good: Moderate latency, good bandwidth, low loss
    Good,
    /// Fair: Higher latency, limited bandwidth, some loss
    Fair,
    /// Poor: High latency, low bandwidth, high loss
    Poor,
}

/// Codec information
#[derive(Debug, Clone)]
pub struct CodecInfo {
    /// Audio codec name
    pub audio_codec: String,
    /// Audio bitrate (bps)
    pub audio_bitrate: u32,
    /// Video codec name (if applicable)
    pub video_codec: Option<String>,
    /// Video bitrate (bps, if applicable)
    pub video_bitrate: Option<u32>,
    /// Video resolution (if applicable)
    pub video_resolution: Option<String>,
}

/// Codec selector
pub struct CodecSelector {
    available_codecs: Vec<CodecInfo>,
}

impl CodecSelector {
    /// Create a new codec selector
    pub fn new() -> Self {
        CodecSelector {
            available_codecs: Vec::new(),
        }
    }

    /// Add available codec
    pub fn add_codec(&mut self, codec: CodecInfo) {
        self.available_codecs.push(codec);
    }

    /// Determine network profile from metrics
    pub fn determine_profile(metrics: &NetworkMetrics) -> NetworkProfile {
        if metrics.rtt_ms < 50.0
            && metrics.packet_loss_rate < 0.01
            && metrics.bandwidth_kbps > 2000.0
        {
            NetworkProfile::Excellent
        } else if metrics.rtt_ms < 100.0
            && metrics.packet_loss_rate < 0.03
            && metrics.bandwidth_kbps > 1000.0
        {
            NetworkProfile::Good
        } else if metrics.rtt_ms < 200.0
            && metrics.packet_loss_rate < 0.05
            && metrics.bandwidth_kbps > 500.0
        {
            NetworkProfile::Fair
        } else {
            NetworkProfile::Poor
        }
    }

    /// Select best codec for network conditions
    pub fn select_codec(&self, metrics: &NetworkMetrics) -> MediaEngineResult<CodecInfo> {
        let profile = Self::determine_profile(metrics);

        // Select codec based on profile
        let codec = match profile {
            NetworkProfile::Excellent => {
                // Use high-quality codecs
                CodecInfo {
                    audio_codec: "opus".to_string(),
                    audio_bitrate: 128_000,  // 128 kbps
                    video_codec: Some("vp9".to_string()),
                    video_bitrate: Some(2_000_000),  // 2 Mbps
                    video_resolution: Some("1080p".to_string()),
                }
            }
            NetworkProfile::Good => {
                CodecInfo {
                    audio_codec: "opus".to_string(),
                    audio_bitrate: 96_000,  // 96 kbps
                    video_codec: Some("vp9".to_string()),
                    video_bitrate: Some(1_500_000),  // 1.5 Mbps
                    video_resolution: Some("720p".to_string()),
                }
            }
            NetworkProfile::Fair => {
                CodecInfo {
                    audio_codec: "opus".to_string(),
                    audio_bitrate: 64_000,  // 64 kbps
                    video_codec: Some("h264".to_string()),  // H.264 more compatible
                    video_bitrate: Some(800_000),  // 800 kbps
                    video_resolution: Some("480p".to_string()),
                }
            }
            NetworkProfile::Poor => {
                // Prioritize audio, reduce video
                CodecInfo {
                    audio_codec: "opus".to_string(),
                    audio_bitrate: 48_000,  // 48 kbps
                    video_codec: Some("h264".to_string()),
                    video_bitrate: Some(400_000),  // 400 kbps
                    video_resolution: Some("360p".to_string()),
                }
            }
        };

        // Check if selected codec is available
        // For now, we always return the default selection
        // In a full implementation, we'd check against available_codecs
        Ok(codec)
    }

    /// Select codec based on connection quality
    pub fn select_codec_by_quality(&self, quality: ConnectionQuality) -> MediaEngineResult<CodecInfo> {
        let metrics = match quality {
            ConnectionQuality::Excellent => NetworkMetrics {
                rtt_ms: 40.0,
                packet_loss_rate: 0.005,
                jitter_ms: 10.0,
                bandwidth_kbps: 3000.0,
                timestamp: std::time::Instant::now(),
            },
            ConnectionQuality::Good => NetworkMetrics {
                rtt_ms: 80.0,
                packet_loss_rate: 0.02,
                jitter_ms: 30.0,
                bandwidth_kbps: 1500.0,
                timestamp: std::time::Instant::now(),
            },
            ConnectionQuality::Fair => NetworkMetrics {
                rtt_ms: 150.0,
                packet_loss_rate: 0.04,
                jitter_ms: 60.0,
                bandwidth_kbps: 800.0,
                timestamp: std::time::Instant::now(),
            },
            ConnectionQuality::Poor | ConnectionQuality::Disconnected => NetworkMetrics {
                rtt_ms: 300.0,
                packet_loss_rate: 0.08,
                jitter_ms: 100.0,
                bandwidth_kbps: 400.0,
                timestamp: std::time::Instant::now(),
            },
        };

        self.select_codec(&metrics)
    }
}

impl Default for CodecSelector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_profile_excellent() {
        let metrics = NetworkMetrics {
            rtt_ms: 40.0,
            packet_loss_rate: 0.005,
            jitter_ms: 10.0,
            bandwidth_kbps: 3000.0,
            timestamp: std::time::Instant::now(),
        };

        let profile = CodecSelector::determine_profile(&metrics);
        assert_eq!(profile, NetworkProfile::Excellent);
    }

    #[test]
    fn test_determine_profile_poor() {
        let metrics = NetworkMetrics {
            rtt_ms: 300.0,
            packet_loss_rate: 0.1,
            jitter_ms: 100.0,
            bandwidth_kbps: 200.0,
            timestamp: std::time::Instant::now(),
        };

        let profile = CodecSelector::determine_profile(&metrics);
        assert_eq!(profile, NetworkProfile::Poor);
    }

    #[test]
    fn test_select_codec_excellent() {
        let selector = CodecSelector::new();
        let metrics = NetworkMetrics {
            rtt_ms: 40.0,
            packet_loss_rate: 0.005,
            jitter_ms: 10.0,
            bandwidth_kbps: 3000.0,
            timestamp: std::time::Instant::now(),
        };

        let codec = selector.select_codec(&metrics).unwrap();
        assert_eq!(codec.audio_codec, "opus");
        assert_eq!(codec.audio_bitrate, 128_000);
        assert!(codec.video_codec.is_some());
    }

    #[test]
    fn test_select_codec_poor() {
        let selector = CodecSelector::new();
        let metrics = NetworkMetrics {
            rtt_ms: 300.0,
            packet_loss_rate: 0.1,
            jitter_ms: 100.0,
            bandwidth_kbps: 200.0,
            timestamp: std::time::Instant::now(),
        };

        let codec = selector.select_codec(&metrics).unwrap();
        assert_eq!(codec.audio_codec, "opus");
        assert_eq!(codec.audio_bitrate, 48_000);  // Lower bitrate
    }
}

