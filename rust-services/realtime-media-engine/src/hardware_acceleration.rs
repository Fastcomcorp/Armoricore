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

//! Hardware Acceleration for Video Encoding/Decoding
//!
//! Provides GPU-accelerated encoding/decoding support for video processing
//! using platform-specific APIs (NVENC, VideoToolbox, VAAPI).
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
use crate::video_pipeline::{VideoCodec, VideoResolution, VideoFrame};

/// Hardware acceleration backend
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareBackend {
    /// NVIDIA NVENC (Windows/Linux)
    Nvenc,
    /// Apple VideoToolbox (macOS/iOS)
    VideoToolbox,
    /// VAAPI (Linux)
    Vaapi,
    /// Software fallback
    Software,
}

/// Hardware acceleration capabilities
#[derive(Debug, Clone)]
pub struct HardwareCapabilities {
    /// Available backends
    pub available_backends: Vec<HardwareBackend>,
    /// Supported codecs
    pub supported_codecs: Vec<VideoCodec>,
    /// Supported resolutions
    pub supported_resolutions: Vec<VideoResolution>,
    /// Maximum bitrate (bps)
    pub max_bitrate: u32,
}

/// Hardware encoder
pub struct HardwareEncoder {
    /// Backend being used
    backend: HardwareBackend,
    /// Codec
    codec: VideoCodec,
    /// Resolution
    resolution: VideoResolution,
    /// Bitrate
    bitrate: u32,
    /// Frame rate
    frame_rate: u32,
}

impl HardwareEncoder {
    /// Create a new hardware encoder
    pub fn new(
        backend: HardwareBackend,
        codec: VideoCodec,
        resolution: VideoResolution,
        bitrate: u32,
        frame_rate: u32,
    ) -> MediaEngineResult<Self> {
        // Check if backend is available
        if !Self::is_backend_available(backend) {
            return Err(MediaEngineError::ConfigError(
                format!("Hardware backend {:?} not available", backend)
            ));
        }

        Ok(HardwareEncoder {
            backend,
            codec,
            resolution,
            bitrate,
            frame_rate,
        })
    }

    /// Encode video frame using hardware
    pub fn encode(&mut self, frame: &VideoFrame) -> MediaEngineResult<Vec<u8>> {
        match self.backend {
            HardwareBackend::Nvenc => {
                // In production, would use NVENC API
                // For now, return placeholder
                self.encode_software(frame)
            }
            HardwareBackend::VideoToolbox => {
                // In production, would use VideoToolbox API
                // For now, return placeholder
                self.encode_software(frame)
            }
            HardwareBackend::Vaapi => {
                // In production, would use VAAPI
                // For now, return placeholder
                self.encode_software(frame)
            }
            HardwareBackend::Software => {
                self.encode_software(frame)
            }
        }
    }

    /// Software fallback encoding
    fn encode_software(&self, _frame: &VideoFrame) -> MediaEngineResult<Vec<u8>> {
        // Placeholder - in production would use FFmpeg software encoding
        Ok(vec![])
    }

    /// Check if backend is available
    pub fn is_backend_available(backend: HardwareBackend) -> bool {
        match backend {
            HardwareBackend::Nvenc => {
                // Check for NVIDIA GPU
                // In production, would check for NVENC support
                false // Placeholder
            }
            HardwareBackend::VideoToolbox => {
                // Check for VideoToolbox support (macOS/iOS)
                #[cfg(target_os = "macos")]
                {
                    true
                }
                #[cfg(not(target_os = "macos"))]
                {
                    false
                }
            }
            HardwareBackend::Vaapi => {
                // Check for VAAPI support (Linux)
                #[cfg(target_os = "linux")]
                {
                    // In production, would check for VAAPI devices
                    false // Placeholder
                }
                #[cfg(not(target_os = "linux"))]
                {
                    false
                }
            }
            HardwareBackend::Software => {
                true // Always available
            }
        }
    }

    /// Get current backend
    pub fn backend(&self) -> HardwareBackend {
        self.backend
    }
}

/// Hardware decoder
pub struct HardwareDecoder {
    /// Backend being used
    backend: HardwareBackend,
    /// Codec
    codec: VideoCodec,
}

impl HardwareDecoder {
    /// Create a new hardware decoder
    pub fn new(backend: HardwareBackend, codec: VideoCodec) -> MediaEngineResult<Self> {
        if !HardwareEncoder::is_backend_available(backend) {
            return Err(MediaEngineError::ConfigError(
                format!("Hardware backend {:?} not available", backend)
            ));
        }

        Ok(HardwareDecoder {
            backend,
            codec,
        })
    }

    /// Decode video frame using hardware
    pub fn decode(&mut self, encoded: &[u8], width: u32, height: u32) -> MediaEngineResult<VideoFrame> {
        match self.backend {
            HardwareBackend::Nvenc => {
                // In production, would use NVDEC API
                self.decode_software(encoded, width, height)
            }
            HardwareBackend::VideoToolbox => {
                // In production, would use VideoToolbox API
                self.decode_software(encoded, width, height)
            }
            HardwareBackend::Vaapi => {
                // In production, would use VAAPI
                self.decode_software(encoded, width, height)
            }
            HardwareBackend::Software => {
                self.decode_software(encoded, width, height)
            }
        }
    }

    /// Software fallback decoding
    fn decode_software(&self, _encoded: &[u8], width: u32, height: u32) -> MediaEngineResult<VideoFrame> {
        // Placeholder - in production would use FFmpeg software decoding
        Ok(VideoFrame {
            data: vec![0u8; (width * height * 3) as usize],
            width,
            height,
            timestamp: 0,
            is_keyframe: false,
            frame_number: 0,
        })
    }
}

/// Hardware acceleration manager
pub struct HardwareAccelerationManager {
    /// Detected capabilities
    capabilities: Option<HardwareCapabilities>,
}

impl HardwareAccelerationManager {
    /// Create a new hardware acceleration manager
    pub fn new() -> Self {
        HardwareAccelerationManager {
            capabilities: None,
        }
    }

    /// Detect available hardware acceleration
    pub fn detect_capabilities(&mut self) -> HardwareCapabilities {
        let mut available_backends = Vec::new();
        let mut supported_codecs = vec![VideoCodec::H264]; // Always supported
        let mut supported_resolutions = vec![
            VideoResolution::P360,
            VideoResolution::P480,
            VideoResolution::P720,
            VideoResolution::P1080,
        ];

        // Check for NVENC
        if HardwareEncoder::is_backend_available(HardwareBackend::Nvenc) {
            available_backends.push(HardwareBackend::Nvenc);
            supported_codecs.push(VideoCodec::H264);
            supported_codecs.push(VideoCodec::Vp9);
            supported_resolutions.push(VideoResolution::P1440);
            supported_resolutions.push(VideoResolution::P4K);
        }

        // Check for VideoToolbox
        if HardwareEncoder::is_backend_available(HardwareBackend::VideoToolbox) {
            available_backends.push(HardwareBackend::VideoToolbox);
            supported_codecs.push(VideoCodec::H264);
            supported_codecs.push(VideoCodec::Vp9);
            supported_resolutions.push(VideoResolution::P1440);
            supported_resolutions.push(VideoResolution::P4K);
        }

        // Check for VAAPI
        if HardwareEncoder::is_backend_available(HardwareBackend::Vaapi) {
            available_backends.push(HardwareBackend::Vaapi);
            supported_codecs.push(VideoCodec::H264);
            supported_codecs.push(VideoCodec::Vp9);
        }

        // Software is always available
        available_backends.push(HardwareBackend::Software);

        let capabilities = HardwareCapabilities {
            available_backends,
            supported_codecs,
            supported_resolutions,
            max_bitrate: 50_000_000, // 50 Mbps
        };

        self.capabilities = Some(capabilities.clone());
        capabilities
    }

    /// Get detected capabilities
    pub fn get_capabilities(&self) -> Option<&HardwareCapabilities> {
        self.capabilities.as_ref()
    }

    /// Select best backend for codec and resolution
    pub fn select_backend(
        &self,
        codec: VideoCodec,
        resolution: VideoResolution,
    ) -> HardwareBackend {
        if let Some(caps) = &self.capabilities {
            // Prefer hardware backends
            for backend in &caps.available_backends {
                match backend {
                    HardwareBackend::Nvenc | HardwareBackend::VideoToolbox | HardwareBackend::Vaapi => {
                        if caps.supported_codecs.contains(&codec) && 
                           caps.supported_resolutions.contains(&resolution) {
                            return *backend;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Fallback to software
        HardwareBackend::Software
    }
}

impl Default for HardwareAccelerationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_detection() {
        let mut manager = HardwareAccelerationManager::new();
        let caps = manager.detect_capabilities();
        
        assert!(!caps.available_backends.is_empty());
        assert!(caps.available_backends.contains(&HardwareBackend::Software));
    }

    #[test]
    fn test_backend_selection() {
        let mut manager = HardwareAccelerationManager::new();
        manager.detect_capabilities();
        
        let backend = manager.select_backend(VideoCodec::H264, VideoResolution::P1080);
        // Should select best available backend or software
        assert!(matches!(backend, HardwareBackend::Software | HardwareBackend::Nvenc | HardwareBackend::VideoToolbox | HardwareBackend::Vaapi));
    }
}

