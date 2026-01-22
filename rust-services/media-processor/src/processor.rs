//! Media Processing - FFmpeg operations
// Copyright 2026 Francisco F. Pinochet, Fastcomcorp
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


use crate::downloader::FileDownloader;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs::{File, metadata};
use std::io::Read;
use tempfile::TempDir;
use tracing::{info, warn, error};
use uuid::Uuid;
use futures::future::join_all;

// SECURITY: Maximum file size limits to prevent DoS attacks
// Default: 10GB (can be overridden via MAX_FILE_SIZE_BYTES environment variable)
const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10GB

/// Result of media processing
pub struct ProcessingResult {
    pub output_dir: PathBuf,
    pub thumbnail_urls: Vec<String>,
    pub duration: u64, // Duration in seconds
    pub resolutions: Vec<String>, // Video resolutions or audio bitrates
    pub hls_playlist_path: Option<PathBuf>,
    pub mp4_files: Vec<PathBuf>, // MP4 files for each resolution/bitrate
    pub dash_manifest_path: Option<PathBuf>, // DASH manifest (future)
    pub output_files: Vec<PathBuf>, // All generated files
    pub encryption_metadata: Option<crate::encryption::EncryptionMetadata>, // Encryption metadata if enabled
    pub is_audio_only: bool, // True if this is audio-only content
    pub audio_bitrate: Option<u32>, // Audio bitrate in kbps (for audio-only)
    pub sample_rate: Option<u32>, // Sample rate in Hz (for audio-only)
}

/// Video codec configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,  // H.264 (libx264) - default, best compatibility
    VP9,   // VP9 (libvpx-vp9) - better compression, WebM
    AV1,   // AV1 (libaom-av1) - next-generation, royalty-free
    VVC,   // VVC (H.266) - latest codec, 50% better compression than HEVC, ideal for 8K
}

impl VideoCodec {
    pub fn ffmpeg_codec(&self) -> &'static str {
        match self {
            VideoCodec::H264 => "libx264",
            VideoCodec::VP9 => "libvpx-vp9",
            VideoCodec::AV1 => "libaom-av1",
            VideoCodec::VVC => "libvvc", // VVC encoder (requires FFmpeg 6.0+ with VVC support)
        }
    }
    
    /// Get hardware-accelerated FFmpeg codec if available
    /// Returns None if hardware acceleration is not available
    fn ffmpeg_hw_codec(&self, hw_backend: HardwareBackend) -> Option<&'static str> {
        match (self, hw_backend) {
            (VideoCodec::H264, HardwareBackend::Nvenc) => Some("h264_nvenc"),
            (VideoCodec::H264, HardwareBackend::VideoToolbox) => Some("h264_videotoolbox"),
            (VideoCodec::H264, HardwareBackend::Vaapi) => Some("h264_vaapi"),
            (VideoCodec::VP9, HardwareBackend::Nvenc) => Some("vp9_nvenc"),
            (VideoCodec::VP9, HardwareBackend::VideoToolbox) => Some("vp9_videotoolbox"),
            (VideoCodec::VP9, HardwareBackend::Vaapi) => Some("vp9_vaapi"),
            (VideoCodec::AV1, HardwareBackend::Nvenc) => Some("av1_nvenc"), // RTX 40 series
            (VideoCodec::AV1, HardwareBackend::VideoToolbox) => Some("av1_videotoolbox"), // Apple Silicon
            (VideoCodec::AV1, HardwareBackend::Vaapi) => Some("av1_vaapi"),
            (VideoCodec::VVC, HardwareBackend::Nvenc) => Some("vvc_nvenc"), // RTX 40 series
            _ => None,
        }
    }

    /// Get codec-specific FFmpeg arguments
    pub fn ffmpeg_args(&self) -> Vec<&'static str> {
        match self {
            VideoCodec::H264 => vec!["-preset", "medium", "-crf", "23"],
            VideoCodec::VP9 => vec!["-deadline", "good", "-cpu-used", "2", "-crf", "30"],
            VideoCodec::AV1 => vec!["-cpu-used", "4", "-crf", "30"],
            VideoCodec::VVC => vec!["-preset", "medium", "-crf", "28", "-tune", "zerolatency"],
        }
    }
    
    /// Get recommended codec for resolution
    /// VVC is recommended for 8K/5K, H.264 for lower resolutions
    pub fn recommended_for_resolution(resolution: &str) -> Self {
        match resolution {
            "8K" | "4320p" | "5K" | "2880p" => VideoCodec::VVC, // VVC for high-res
            "4K" | "2160p" => VideoCodec::VVC, // VVC also good for 4K
            _ => VideoCodec::H264, // H.264 for lower resolutions (better compatibility)
        }
    }

    /// Get container format for this codec
    #[allow(dead_code)] // Method is part of public API, may be used by external code
    fn container_format(&self) -> &'static str {
        match self {
            VideoCodec::H264 => "mp4", // H.264 typically uses MP4
            VideoCodec::VP9 => "webm", // VP9 typically uses WebM
            VideoCodec::AV1 => "mp4",  // AV1 can use MP4 or WebM, defaulting to MP4
            VideoCodec::VVC => "mp4",  // VVC typically uses MP4
        }
    }
}

/// Audio codec configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    Aac,    // AAC (default, best compatibility)
    Opus,   // Opus (better quality, modern browsers)
    Mp3,    // MP3 (legacy support)
    Vorbis, // Vorbis (WebM)
    Flac,   // FLAC (lossless, high quality)
}

impl AudioCodec {
    pub fn ffmpeg_codec(&self) -> &'static str {
        match self {
            AudioCodec::Aac => "aac",
            AudioCodec::Opus => "libopus",
            AudioCodec::Mp3 => "libmp3lame",
            AudioCodec::Vorbis => "libvorbis",
            AudioCodec::Flac => "flac",
        }
    }

    pub fn bitrate(&self) -> Option<&'static str> {
        match self {
            AudioCodec::Aac => Some("128k"),
            AudioCodec::Opus => Some("128k"),
            AudioCodec::Mp3 => Some("192k"),
            AudioCodec::Vorbis => Some("128k"),
            AudioCodec::Flac => None, // FLAC is lossless, no bitrate setting
        }
    }

    /// Check if codec is lossless
    fn is_lossless(&self) -> bool {
        matches!(self, AudioCodec::Flac)
    }
}

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

/// Media processor using FFmpeg
pub struct MediaProcessor {
    ffmpeg_available: bool,
    downloader: Option<FileDownloader>,
    video_codec: VideoCodec,
    audio_codec: AudioCodec,
    encryption: Option<crate::encryption::ContentEncryption>,
    hardware_backend: Option<HardwareBackend>,
}

impl MediaProcessor {
    pub fn new() -> Self {
        let ffmpeg_available = Self::check_ffmpeg_available();
        if !ffmpeg_available {
            warn!("FFmpeg is not available - will use mock processing");
        }
        let hardware_backend = Self::detect_hardware_backend();
        if let Some(backend) = hardware_backend {
            info!(backend = ?backend, "Hardware acceleration detected");
        }
        Self {
            encryption: None, // Encryption disabled by default
            ffmpeg_available,
            downloader: None,
            video_codec: Self::get_video_codec_from_env(),
            audio_codec: Self::get_audio_codec_from_env(),
            hardware_backend,
        }
    }

    /// Create with object storage config for S3 downloads
    pub fn with_storage_config(
        s3_config: Option<armoricore_config::ObjectStorageConfig>,
    ) -> Self {
        let ffmpeg_available = Self::check_ffmpeg_available();
        if !ffmpeg_available {
            warn!("FFmpeg is not available - will use mock processing");
        }
        let hardware_backend = Self::detect_hardware_backend();
        if let Some(backend) = hardware_backend {
            info!(backend = ?backend, "Hardware acceleration detected");
        }
        Self {
            ffmpeg_available,
            downloader: Some(FileDownloader::new(s3_config)),
            video_codec: Self::get_video_codec_from_env(),
            hardware_backend,
            audio_codec: Self::get_audio_codec_from_env(),
            encryption: None, // Encryption disabled by default
        }
    }

    /// Create with encryption enabled
    pub fn with_encryption(
        key_store: Option<armoricore_keys::key_store::KeyStore>,
    ) -> Self {
        let ffmpeg_available = Self::check_ffmpeg_available();
        if !ffmpeg_available {
            warn!("FFmpeg is not available - will use mock processing");
        }
        let hardware_backend = Self::detect_hardware_backend();
        if let Some(backend) = hardware_backend {
            info!(backend = ?backend, "Hardware acceleration detected");
        }
        Self {
            ffmpeg_available,
            downloader: None,
            video_codec: Self::get_video_codec_from_env(),
            audio_codec: Self::get_audio_codec_from_env(),
            encryption: Some(crate::encryption::ContentEncryption::new(key_store)),
            hardware_backend,
        }
    }

    /// Create with both storage config and encryption
    #[allow(dead_code)] // Method is part of public API
    pub fn with_storage_and_encryption(
        s3_config: Option<armoricore_config::ObjectStorageConfig>,
        key_store: Option<armoricore_keys::key_store::KeyStore>,
    ) -> Self {
        let ffmpeg_available = Self::check_ffmpeg_available();
        if !ffmpeg_available {
            warn!("FFmpeg is not available - will use mock processing");
        }
        let hardware_backend = Self::detect_hardware_backend();
        if let Some(backend) = hardware_backend {
            info!(backend = ?backend, "Hardware acceleration detected");
        }
        Self {
            ffmpeg_available,
            downloader: Some(FileDownloader::new(s3_config)),
            hardware_backend,
            video_codec: Self::get_video_codec_from_env(),
            audio_codec: Self::get_audio_codec_from_env(),
            encryption: Some(crate::encryption::ContentEncryption::new(key_store)),
        }
    }

    /// Get video codec from environment variable
    fn get_video_codec_from_env() -> VideoCodec {
        use std::env;
        match env::var("VIDEO_CODEC").as_deref() {
            Ok("vp9") => VideoCodec::VP9,
            Ok("av1") => VideoCodec::AV1,
            _ => VideoCodec::H264, // Default to H.264
        }
    }

    /// Get audio codec from environment variable
    fn get_audio_codec_from_env() -> AudioCodec {
        use std::env;
        match env::var("AUDIO_CODEC").as_deref() {
            Ok("opus") => AudioCodec::Opus,
            Ok("mp3") => AudioCodec::Mp3,
            Ok("vorbis") => AudioCodec::Vorbis,
            Ok("flac") => AudioCodec::Flac,
            _ => AudioCodec::Aac, // Default to AAC
        }
    }

    /// Select audio codec for a specific resolution
    /// Uses resolution-based selection if enabled, otherwise uses configured codec
    fn select_audio_codec_for_resolution(&self, resolution: &str) -> AudioCodec {
        use std::env;
        
        // Check if resolution-based selection is enabled
        let use_resolution_based = env::var("AUDIO_RESOLUTION_BASED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        if !use_resolution_based {
            // Use configured codec for all resolutions
            return self.audio_codec;
        }

        // Resolution-based selection
        match resolution {
            "8K" | "4320p" | "5K" | "2880p" | "4K" | "2160p" => {
                // High-res: Use FLAC if enabled, otherwise Opus at higher bitrate
                if env::var("HIGH_RES_USE_FLAC")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(false)
                {
                    AudioCodec::Flac
                } else {
                    // Use Opus for high-res (better than AAC)
                    AudioCodec::Opus
                }
            }
            "1440p" | "1080p" => {
                // Medium-res: Use Opus (good quality, efficient)
                AudioCodec::Opus
            }
            _ => {
                // Lower resolutions: Use configured codec (usually AAC for compatibility)
                self.audio_codec
            }
        }
    }

    /// Check if dual audio tracks should be generated for high-res
    fn should_generate_dual_audio_tracks(&self, resolution: &str) -> bool {
        use std::env;
        
        // Check if dual tracks are enabled
        let dual_tracks_enabled = env::var("ENABLE_DUAL_AUDIO_TRACKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false);

        if !dual_tracks_enabled {
            return false;
        }

        // Generate dual tracks only for high-res (8K, 5K, 4K)
        matches!(resolution, "8K" | "4320p" | "5K" | "2880p" | "4K" | "2160p")
    }

    /// Get audio codecs for dual track generation
    /// Returns (primary_codec, optional_secondary_codec)
    fn get_audio_codecs_for_resolution(&self, resolution: &str) -> (AudioCodec, Option<AudioCodec>) {
        let primary = self.select_audio_codec_for_resolution(resolution);
        
        if self.should_generate_dual_audio_tracks(resolution) {
            // For high-res dual tracks: Opus (primary) + FLAC (secondary)
            if primary == AudioCodec::Flac {
                // If FLAC is primary, make Opus secondary
                (AudioCodec::Flac, Some(AudioCodec::Opus))
            } else {
                // If Opus is primary, make FLAC secondary
                (AudioCodec::Opus, Some(AudioCodec::Flac))
            }
        } else {
            (primary, None)
        }
    }

    /// Process a media file: transcode, segment, generate thumbnails
    pub async fn process_media(
        &self,
        media_id: &Uuid,
        file_path: &str,
        content_type: &str,
    ) -> anyhow::Result<ProcessingResult> {
        info!(
            media_id = %media_id,
            file_path = file_path,
            content_type = content_type,
            "Starting media processing"
        );

        // Create temporary directory for processing
        let temp_dir = TempDir::new()?;
        let output_dir = temp_dir.path().to_path_buf();

        info!(
            media_id = %media_id,
            output_dir = %output_dir.display(),
            "Created temporary processing directory"
        );

        // Check if this is a video or audio file
        let is_video = content_type.starts_with("video/");
        let is_audio = content_type.starts_with("audio/");

        if !is_video && !is_audio {
            return Err(anyhow::anyhow!("Unsupported content type: {}", content_type));
        }

        if !self.ffmpeg_available {
            warn!("FFmpeg not available - using mock processing");
            return self.mock_processing(media_id, output_dir).await;
        }

        // Download source file from S3/HTTP if needed
        let input_path = if file_path.starts_with("s3://")
            || file_path.starts_with("http://")
            || file_path.starts_with("https://")
        {
            // Download from remote source
            let downloader = self
                .downloader
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Downloader not configured. Cannot download remote files. \
                         Provide object storage config or use local file paths."
                    )
                })?;

            // Create temporary file for download
            let temp_file = output_dir.join(format!("source_{}.tmp", media_id));
            downloader
                .download_file(file_path, &temp_file, media_id)
                .await?;

            temp_file
        } else {
            // Local file path
            PathBuf::from(file_path)
        };

        if !input_path.exists() {
            return Err(anyhow::anyhow!("Input file does not exist: {}", file_path));
        }

        // SECURITY: Validate file size to prevent DoS attacks from oversized files
        self.validate_file_size(&input_path)?;

        // SECURITY: Validate file content using magic bytes (not just Content-Type header)
        // This prevents file type confusion attacks where malicious files are uploaded
        // with incorrect Content-Type headers
        self.validate_file_content(&input_path, content_type)?;

        // Extract metadata based on content type
        let duration = self.extract_duration(&input_path).await?;

        if is_audio {
            // Audio-only processing
            let (audio_bitrate, sample_rate) = self.extract_audio_metadata(&input_path).await?;
            
            info!(
                media_id = %media_id,
                duration = duration,
                bitrate = audio_bitrate,
                sample_rate = sample_rate,
                "Extracted audio metadata"
            );

            // Determine target audio bitrates (for adaptive streaming)
            let target_bitrates = self.determine_audio_bitrates(audio_bitrate);

            // Transcode audio to HLS with multiple bitrates
            let hls_playlist_path = self
                .transcode_audio_to_hls(&input_path, &output_dir, &target_bitrates, media_id)
                .await?;

            // Generate audio-only MP4 files for each bitrate
            let mp4_files = self
                .transcode_audio_to_mp4(&input_path, &output_dir, &target_bitrates, media_id)
                .await?;

            // Generate DASH manifest (future implementation)
            let dash_manifest_path = self
                .generate_dash_manifest(&output_dir, &target_bitrates, media_id)
                .await?;

            // No thumbnails for audio-only

            // Collect all output files
            let mut output_files = vec![];
            if let Some(ref playlist) = hls_playlist_path {
                output_files.push(playlist.clone());
            }
            output_files.extend(mp4_files.iter().cloned());
            if let Some(ref dash_manifest) = dash_manifest_path {
                output_files.push(dash_manifest.clone());
            }

            // Generate thumbnail URLs (empty for audio-only)
            let thumbnail_urls: Vec<String> = vec![];

            info!(
                media_id = %media_id,
                duration = duration,
                bitrates = ?target_bitrates,
                hls_variants = if hls_playlist_path.is_some() { target_bitrates.len() } else { 0 },
                mp4_files = mp4_files.len(),
                "Audio processing completed"
            );

            Ok(ProcessingResult {
                output_dir,
                thumbnail_urls,
                duration,
                resolutions: target_bitrates,
                hls_playlist_path,
                mp4_files,
                dash_manifest_path,
                output_files,
                encryption_metadata: None,
                is_audio_only: true,
                audio_bitrate: Some(audio_bitrate),
                sample_rate: Some(sample_rate),
            })
        } else {
            // Video processing (existing logic)
            let (width, height) = self.extract_resolution(&input_path).await?;

            info!(
                media_id = %media_id,
                duration = duration,
                resolution = format!("{}x{}", width, height),
                "Extracted video metadata"
            );

            // Determine target resolutions based on source
            let target_resolutions = self.determine_resolutions(width, height);

            // Transcode to multiple bitrates and create HLS segments
            let hls_playlist_path = self
                .transcode_to_hls(&input_path, &output_dir, &target_resolutions, media_id)
                .await?;

            // Generate MP4 files for each resolution
            let mp4_files = self
                .transcode_to_mp4(&input_path, &output_dir, &target_resolutions, media_id)
                .await?;

            // Generate DASH manifest (future implementation)
            let dash_manifest_path = self
                .generate_dash_manifest(&output_dir, &target_resolutions, media_id)
                .await?;

            // Generate thumbnails
            let thumbnail_paths = self
                .generate_thumbnails(&input_path, &output_dir, media_id, 3)
                .await?;

            // Collect all output files
            let mut output_files = vec![];
            if let Some(ref playlist) = hls_playlist_path {
                output_files.push(playlist.clone());
            }
            output_files.extend(mp4_files.iter().cloned());
            if let Some(ref dash_manifest) = dash_manifest_path {
                output_files.push(dash_manifest.clone());
            }
            output_files.extend(thumbnail_paths.iter().cloned());

            // Generate thumbnail URLs (will be uploaded to S3)
            let thumbnail_urls: Vec<String> = thumbnail_paths
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    format!(
                        "https://cdn.example.com/media/{}/thumb_{}.jpg",
                        media_id,
                        i + 1
                    )
                })
                .collect();

            info!(
                media_id = %media_id,
                duration = duration,
                resolutions = ?target_resolutions,
                hls_variants = if hls_playlist_path.is_some() { target_resolutions.len() } else { 0 },
                mp4_files = mp4_files.len(),
                thumbnails = thumbnail_paths.len(),
                "Media processing completed"
            );

            Ok(ProcessingResult {
                output_dir,
                thumbnail_urls,
                duration,
                resolutions: target_resolutions,
                hls_playlist_path,
                mp4_files,
                dash_manifest_path,
                output_files,
                encryption_metadata: None,
                is_audio_only: false,
                audio_bitrate: None,
                sample_rate: None,
            })
        }
    }

    /// Extract video duration using FFprobe
    async fn extract_duration(&self, input_path: &Path) -> anyhow::Result<u64> {
        let output = Command::new("ffprobe")
            .args(&[
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to extract duration"));
        }

        let duration_str = String::from_utf8(output.stdout)?;
        let duration_f64: f64 = duration_str.trim().parse()?;
        Ok(duration_f64 as u64)
    }

    /// Extract video resolution
    async fn extract_resolution(&self, input_path: &Path) -> anyhow::Result<(u32, u32)> {
        let output = Command::new("ffprobe")
            .args(&[
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=width,height",
                "-of",
                "csv=s=x:p=0",
                input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
            ])
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to extract resolution"));
        }

        let resolution_str = String::from_utf8(output.stdout)?;
        let parts: Vec<&str> = resolution_str.trim().split('x').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid resolution format"));
        }

        let width: u32 = parts[0].parse()?;
        let height: u32 = parts[1].parse()?;

        Ok((width, height))
    }

    /// Extract audio metadata (bitrate and sample rate)
    async fn extract_audio_metadata(&self, input_path: &Path) -> anyhow::Result<(u32, u32)> {
        // Extract bitrate
        let bitrate_output = Command::new("ffprobe")
            .args(&[
                "-v",
                "error",
                "-select_streams",
                "a:0",
                "-show_entries",
                "stream=bit_rate",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
            ])
            .output()?;

        let bitrate = if bitrate_output.status.success() {
            let bitrate_str = String::from_utf8(bitrate_output.stdout)?;
            bitrate_str.trim().parse::<u32>().unwrap_or(128000) / 1000 // Convert to kbps
        } else {
            128 // Default to 128 kbps if extraction fails
        };

        // Extract sample rate
        let sample_rate_output = Command::new("ffprobe")
            .args(&[
                "-v",
                "error",
                "-select_streams",
                "a:0",
                "-show_entries",
                "stream=sample_rate",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
            ])
            .output()?;

        let sample_rate = if sample_rate_output.status.success() {
            let sample_rate_str = String::from_utf8(sample_rate_output.stdout)?;
            sample_rate_str.trim().parse::<u32>().unwrap_or(44100) // Default to 44.1 kHz
        } else {
            44100 // Default to 44.1 kHz if extraction fails
        };

        Ok((bitrate, sample_rate))
    }

    /// Determine target resolutions based on source resolution
    fn determine_resolutions(&self, _width: u32, height: u32) -> Vec<String> {
        let mut resolutions = Vec::new();

        // Support up to 8K (4320p) - no artificial cap
        // Add resolutions from highest to lowest for proper ordering in playlist
        
        if height >= 4320 {
            resolutions.push("8K".to_string());  // 8K (4320p)
        }
        if height >= 2880 {
            resolutions.push("5K".to_string());  // 5K (2880p)
        }
        if height >= 2160 {
            resolutions.push("4K".to_string());  // 4K (2160p)
        }
        if height >= 1440 {
            resolutions.push("1440p".to_string());  // 1440p (QHD)
        }
        if height >= 1080 {
            resolutions.push("1080p".to_string());
        }
        if height >= 720 {
            resolutions.push("720p".to_string());
        }
        if height >= 480 {
            resolutions.push("480p".to_string());
        }
        if height >= 360 {
            resolutions.push("360p".to_string());
        }
        
        // Always include at least one resolution
        if resolutions.is_empty() {
            resolutions.push(format!("{}p", height));
        }

        resolutions
    }

    /// Determine target audio bitrates for adaptive streaming
    /// Returns a list of bitrate strings (e.g., ["320k", "192k", "128k", "64k"])
    fn determine_audio_bitrates(&self, source_bitrate: u32) -> Vec<String> {
        let mut bitrates = Vec::new();

        // For FLAC (lossless), we might want to offer multiple lossy options
        // For lossy codecs, we offer multiple bitrate options
        if self.audio_codec.is_lossless() {
            // For FLAC, offer high-quality lossy transcodes
            bitrates.push("320k".to_string());
            bitrates.push("192k".to_string());
            bitrates.push("128k".to_string());
            bitrates.push("64k".to_string());
        } else {
            // For lossy codecs, offer variants around the source bitrate
            if source_bitrate >= 320 {
                bitrates.push("320k".to_string());
            }
            if source_bitrate >= 192 {
                bitrates.push("192k".to_string());
            }
            if source_bitrate >= 128 {
                bitrates.push("128k".to_string());
            }
            if source_bitrate >= 64 {
                bitrates.push("64k".to_string());
            }
            // Always include at least one bitrate
            if bitrates.is_empty() {
                bitrates.push("128k".to_string());
            }
        }

        bitrates
    }

    /// Transcode video to HLS with multiple bitrates
    /// Uses parallel processing for faster encoding of multiple resolutions
    async fn transcode_to_hls(
        &self,
        input_path: &Path,
        output_dir: &Path,
        resolutions: &[String],
        media_id: &Uuid,
    ) -> anyhow::Result<Option<PathBuf>> {
        info!(
            "Transcoding to HLS with {} resolution(s): {:?}",
            resolutions.len(),
            resolutions
        );

        // Process resolutions in parallel for better performance
        let tasks: Vec<_> = resolutions.iter()
            .map(|resolution| {
                let input = input_path.to_path_buf();
                let output = output_dir.to_path_buf();
                let res = resolution.clone();
                let media_id = *media_id;
                let video_codec = self.video_codec;
                let audio_codec = self.audio_codec;
                
                tokio::spawn(async move {
                    Self::transcode_single_resolution_hls(
                        &input,
                        &output,
                        &res,
                        media_id,
                        video_codec,
                        audio_codec,
                    ).await
                })
            })
            .collect();
        
        // Wait for all tasks to complete
        let results: Vec<_> = join_all(tasks).await;
        
        let mut variant_playlists = Vec::new();
        for result in results {
            match result {
                Ok(Ok(Some((resolution, playlist_path)))) => {
                    variant_playlists.push((resolution, playlist_path));
                }
                Ok(Ok(None)) => {
                    // Resolution skipped (e.g., codec not available)
                    continue;
                }
                Ok(Err(e)) => {
                    warn!("Failed to transcode resolution: {}", e);
                    continue;
                }
                Err(e) => {
                    warn!("Task panicked: {:?}", e);
                    continue;
                }
            }
        }

        if variant_playlists.is_empty() {
            return Err(anyhow::anyhow!("Failed to transcode any variants"));
        }

        // Create master playlist
        let master_playlist_path = output_dir.join("master.m3u8");
        Self::create_master_playlist(&master_playlist_path, &variant_playlists, media_id)?;

        info!(
            variants = variant_playlists.len(),
            "HLS transcoding completed with multiple bitrates (parallel processing)"
        );

        Ok(Some(master_playlist_path))
    }
    
    /// Transcode a single resolution to HLS (used for parallel processing)
    async fn transcode_single_resolution_hls(
        input_path: &Path,
        output_dir: &Path,
        resolution: &str,
        _media_id: Uuid,
        _video_codec: VideoCodec,
        audio_codec: AudioCodec,
    ) -> anyhow::Result<Option<(String, PathBuf)>> {
        let (width, height, bitrate) = Self::get_resolution_params(resolution);
        
        // Get audio codec(s) for this resolution
        let (primary_audio_codec, _secondary_audio_codec) = Self::get_audio_codecs_for_resolution_static(resolution, audio_codec);
        
        let variant_dir = output_dir.join(resolution);
        std::fs::create_dir_all(&variant_dir)?;
        
        let variant_playlist = variant_dir.join("playlist.m3u8");
        let segment_pattern = variant_dir.join("segment_%03d.ts");

        info!(
            resolution = resolution,
            width = width,
            height = height,
            bitrate = bitrate,
            primary_audio = ?primary_audio_codec,
            "Transcoding variant (parallel)"
        );

        // Select optimal codec for this resolution
        let codec_to_use = VideoCodec::recommended_for_resolution(resolution);
        
        // Try to use hardware acceleration if available
        // Note: For static function, we detect hardware on the fly
        let hardware_backend = Self::detect_hardware_backend();
        let video_codec_name = if let Some(backend) = hardware_backend {
            if let Some(hw_codec) = codec_to_use.ffmpeg_hw_codec(backend) {
                info!(resolution = resolution, hw_codec = hw_codec, "Using hardware acceleration");
                hw_codec
            } else {
                codec_to_use.ffmpeg_codec()
            }
        } else {
            codec_to_use.ffmpeg_codec()
        };
        
        // Build FFmpeg command for HLS transcoding
        let maxrate_str = format!("{}k", bitrate);
        let bufsize_str = format!("{}k", bitrate * 2);
        
        // Use high-quality Lanczos downscaling for 8K→4K/5K conversions
        let vf_filter = if resolution == "4K" || resolution == "2160p" {
            format!("scale={}:{}:flags=lanczos+accurate_rnd+full_chroma_int:force_original_aspect_ratio=decrease,pad={}:{}:(ow-iw)/2:(oh-ih)/2", width, height, width, height)
        } else {
            format!("scale={}:{}:force_original_aspect_ratio=decrease,pad={}:{}:(ow-iw)/2:(oh-ih)/2", width, height, width, height)
        };
        
        let mut ffmpeg_args = vec![
            "-i",
            input_path.to_str()
                .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
            "-c:v",
            video_codec_name,
        ];

        // Add codec-specific arguments (hardware encoders may have different args)
        if !video_codec_name.contains("nvenc") && !video_codec_name.contains("videotoolbox") && !video_codec_name.contains("vaapi") {
            // Only add software codec args for software encoders
            ffmpeg_args.extend_from_slice(&codec_to_use.ffmpeg_args());
        } else {
            // Hardware encoders use different parameters
            // Add hardware-specific presets
            if video_codec_name.contains("nvenc") {
                ffmpeg_args.extend_from_slice(&["-preset", "p4", "-rc", "vbr", "-cq", "23"]);
            } else if video_codec_name.contains("videotoolbox") {
                ffmpeg_args.extend_from_slice(&["-allow_sw", "1", "-realtime", "1"]);
            } else if video_codec_name.contains("vaapi") {
                ffmpeg_args.extend_from_slice(&["-vaapi_device", "/dev/dri/renderD128"]);
            }
        }

        // Add bitrate control
        ffmpeg_args.extend_from_slice(&[
            "-maxrate",
            &maxrate_str,
            "-bufsize",
            &bufsize_str,
            "-vf",
            &vf_filter,
            "-c:a",
            primary_audio_codec.ffmpeg_codec(),
        ]);

        // Add bitrate for lossy codecs
        if let Some(audio_bitrate) = primary_audio_codec.bitrate() {
            let bitrate_to_use = if matches!(resolution, "8K" | "4320p" | "5K" | "2880p" | "4K" | "2160p") 
                && primary_audio_codec == AudioCodec::Opus {
                "192k"
            } else {
                audio_bitrate
            };
            ffmpeg_args.push("-b:a");
            ffmpeg_args.push(bitrate_to_use);
        }

        // Add HLS-specific options
        let segment_filename = segment_pattern.to_str()
            .ok_or_else(|| anyhow::anyhow!("Segment pattern contains invalid UTF-8: {:?}", segment_pattern))?;
        let playlist_path = variant_playlist.to_str()
            .ok_or_else(|| anyhow::anyhow!("Playlist path contains invalid UTF-8: {:?}", variant_playlist))?;
        
        ffmpeg_args.extend_from_slice(&[
            "-hls_time",
            "10",
            "-hls_list_size",
            "0",
            "-hls_segment_filename",
            segment_filename,
            "-f",
            "hls",
            playlist_path,
        ]);

        let status = Command::new("ffmpeg")
            .args(&ffmpeg_args)
            .status()?;

        if !status.success() {
            warn!(resolution = resolution, "Failed to transcode variant, skipping");
            return Ok(None);
        }

        info!(resolution = resolution, "Variant transcoding completed (parallel)");
        Ok(Some((resolution.to_string(), variant_playlist)))
    }
    
    /// Get audio codecs for resolution (static version for parallel processing)
    fn get_audio_codecs_for_resolution_static(resolution: &str, default_audio_codec: AudioCodec) -> (AudioCodec, Option<AudioCodec>) {
        // For high-res (8K, 5K, 4K), use Opus + FLAC dual tracks
        if matches!(resolution, "8K" | "4320p" | "5K" | "2880p" | "4K" | "2160p") {
            (AudioCodec::Opus, Some(AudioCodec::Flac))
        } else {
            (default_audio_codec, None)
        }
    }


    /// Get resolution parameters (width, height, bitrate) for a resolution string
    fn get_resolution_params(resolution: &str) -> (u32, u32, u32) {
        match resolution {
            "8K" | "4320p" => (7680, 4320, 50000),  // 50 Mbps (8K UHD-2)
            "5K" | "2880p" => (5120, 2880, 25000),  // 25 Mbps (5K)
            "4K" | "2160p" => (3840, 2160, 15000),  // 15 Mbps (4K UHD)
            "1440p" => (2560, 1440, 8000),          // 8 Mbps (QHD)
            "1080p" => (1920, 1080, 5000),          // 5 Mbps (Full HD)
            "720p" => (1280, 720, 2500),            // 2.5 Mbps (HD)
            "480p" => (854, 480, 1000),             // 1 Mbps (SD)
            "360p" => (640, 360, 600),              // 600 kbps
            _ => {
                // Try to parse custom resolution like "240p"
                if let Some(height_str) = resolution.strip_suffix('p') {
                    if let Ok(height) = height_str.parse::<u32>() {
                        let width = (height * 16) / 9; // Assume 16:9 aspect ratio
                        // Bitrate estimation: higher resolutions need more bandwidth
                        let bitrate = if height >= 2160 {
                            height * 7 // 4K+ needs more bitrate
                        } else if height >= 1080 {
                            height * 5 // Full HD
                        } else {
                            height * 4 // Lower resolutions
                        };
                        return (width, height, bitrate);
                    }
                }
                (1280, 720, 2500) // Default to 720p
            }
        }
    }

    /// Create master HLS playlist referencing all variants
    fn create_master_playlist(
        master_path: &Path,
        variant_playlists: &[(String, PathBuf)],
        _media_id: &Uuid,
    ) -> anyhow::Result<()> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(master_path)?;
        
        // Write HLS master playlist header
        writeln!(file, "#EXTM3U")?;
        writeln!(file, "#EXT-X-VERSION:3")?;

        // Add each variant
        let master_parent = master_path.parent()
            .ok_or_else(|| anyhow::anyhow!("Master playlist path has no parent directory: {:?}", master_path))?;
        for (resolution, variant_playlist) in variant_playlists {
            // Get relative path from master to variant
            let relative_path = variant_playlist
                .strip_prefix(master_parent)
                .unwrap_or(variant_playlist);
            
            let (_, _, bitrate) = Self::get_resolution_params(resolution);
            
            // Write variant entry
            writeln!(file, "#EXT-X-STREAM-INF:BANDWIDTH={},RESOLUTION={}", 
                bitrate * 1000, // Convert to bps
                Self::get_resolution_string(resolution)
            )?;
            writeln!(file, "{}", relative_path.to_str()
                .ok_or_else(|| anyhow::anyhow!("Relative path contains invalid UTF-8: {:?}", relative_path))?)?;
        }

        info!(
            master_playlist = %master_path.display(),
            variants = variant_playlists.len(),
            "Created master HLS playlist"
        );

        Ok(())
    }

    /// Get resolution string for HLS (e.g., "1920x1080")
    fn get_resolution_string(resolution: &str) -> String {
        let (width, height, _) = Self::get_resolution_params(resolution);
        format!("{}x{}", width, height)
    }

    /// Transcode audio to HLS with multiple bitrates (audio-only)
    async fn transcode_audio_to_hls(
        &self,
        input_path: &Path,
        output_dir: &Path,
        bitrates: &[String],
        media_id: &Uuid,
    ) -> anyhow::Result<Option<PathBuf>> {
        info!(
            "Transcoding audio to HLS with {} bitrate(s): {:?}",
            bitrates.len(),
            bitrates
        );

        let mut variant_playlists = Vec::new();

        // Transcode each bitrate variant
        for bitrate_str in bitrates {
            let variant_dir = output_dir.join(bitrate_str);
            std::fs::create_dir_all(&variant_dir)?;
            
            let variant_playlist = variant_dir.join("playlist.m3u8");
            let segment_pattern = variant_dir.join("segment_%03d.ts");

            info!(
                bitrate = bitrate_str,
                "Transcoding audio variant"
            );

            // Build FFmpeg command for audio-only HLS transcoding
            let mut ffmpeg_args = vec![
                "-i",
                input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
                "-vn", // No video
                "-c:a",
                self.audio_codec.ffmpeg_codec(),
            ];

            // Add bitrate for lossy codecs (FLAC is lossless, no bitrate)
            if let Some(_audio_bitrate) = self.audio_codec.bitrate() {
                // Use the target bitrate from the bitrate list
                ffmpeg_args.push("-b:a");
                ffmpeg_args.push(bitrate_str);
            } else if self.audio_codec.is_lossless() {
                // For FLAC, we might transcode to lossy variants
                // Use the bitrate from the list (e.g., "320k")
                ffmpeg_args.push("-b:a");
                ffmpeg_args.push(bitrate_str);
                // Override codec to AAC for lossy variants from FLAC source
                if let Some(pos) = ffmpeg_args.iter().position(|x| *x == "-c:a") {
                    ffmpeg_args[pos + 1] = "aac"; // Use AAC for lossy variants
                }
            }

            // Add HLS-specific options
            let segment_filename = segment_pattern.to_str()
                .ok_or_else(|| anyhow::anyhow!("Segment pattern contains invalid UTF-8: {:?}", segment_pattern))?;
            let playlist_path = variant_playlist.to_str()
                .ok_or_else(|| anyhow::anyhow!("Playlist path contains invalid UTF-8: {:?}", variant_playlist))?;
            
            ffmpeg_args.extend_from_slice(&[
                "-hls_time",
                "10", // 10 second segments
                "-hls_list_size",
                "0", // Keep all segments
                "-hls_segment_filename",
                segment_filename,
                "-f",
                "hls",
                playlist_path,
            ]);

            let status = Command::new("ffmpeg")
                .args(&ffmpeg_args)
                .status()?;

            if !status.success() {
                warn!(bitrate = bitrate_str, "Failed to transcode audio variant, skipping");
                continue;
            }

            variant_playlists.push((bitrate_str.clone(), variant_playlist));
            info!(bitrate = bitrate_str, "Audio variant transcoding completed");
        }

        if variant_playlists.is_empty() {
            return Err(anyhow::anyhow!("Failed to transcode any audio variants"));
        }

        // Create master playlist for audio
        let master_playlist_path = output_dir.join("master.m3u8");
        Self::create_audio_master_playlist(&master_playlist_path, &variant_playlists, media_id)?;

        info!(
            variants = variant_playlists.len(),
            "Audio HLS transcoding completed with multiple bitrates"
        );

        Ok(Some(master_playlist_path))
    }

    /// Create master HLS playlist for audio-only content
    fn create_audio_master_playlist(
        master_path: &Path,
        variant_playlists: &[(String, PathBuf)],
        _media_id: &Uuid,
    ) -> anyhow::Result<()> {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create(master_path)?;
        
        // Write HLS master playlist header
        writeln!(file, "#EXTM3U")?;
        writeln!(file, "#EXT-X-VERSION:3")?;

        // Write variant entries
        let master_parent = master_path.parent()
            .ok_or_else(|| anyhow::anyhow!("Master playlist path has no parent directory: {:?}", master_path))?;
        for (bitrate_str, variant_path) in variant_playlists {
            let relative_path = variant_path
                .strip_prefix(master_parent)
                .unwrap_or(variant_path);
            
            // Parse bitrate (e.g., "320k" -> 320000)
            let bitrate_value = bitrate_str
                .trim_end_matches('k')
                .parse::<u32>()
                .unwrap_or(128)
                * 1000;

            writeln!(file, "#EXT-X-STREAM-INF:BANDWIDTH={}", bitrate_value)?;
            writeln!(file, "{}", relative_path.to_str()
                .ok_or_else(|| anyhow::anyhow!("Relative path contains invalid UTF-8: {:?}", relative_path))?)?;
        }

        info!(
            master_playlist = %master_path.display(),
            variants = variant_playlists.len(),
            "Created master audio HLS playlist"
        );

        Ok(())
    }

    /// Transcode audio to MP4 format for each bitrate (audio-only)
    async fn transcode_audio_to_mp4(
        &self,
        input_path: &Path,
        output_dir: &Path,
        bitrates: &[String],
        _media_id: &Uuid,
    ) -> anyhow::Result<Vec<PathBuf>> {
        if !self.ffmpeg_available {
            warn!("FFmpeg not available - skipping audio MP4 generation");
            return Ok(vec![]);
        }

        info!(
            "Transcoding audio to MP4 with {} bitrate(s): {:?}",
            bitrates.len(),
            bitrates
        );

        let mut mp4_files = Vec::new();

        // Transcode each bitrate variant to MP4
        for bitrate_str in bitrates {
            let mp4_filename = format!("{}.mp4", bitrate_str);
            let mp4_path = output_dir.join(&mp4_filename);

            info!(
                bitrate = bitrate_str,
                "Transcoding audio variant to MP4"
            );

            // Build FFmpeg command for audio-only MP4 transcoding
            let mut ffmpeg_args = vec![
                "-i",
                input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
                "-vn", // No video
                "-c:a",
                self.audio_codec.ffmpeg_codec(),
            ];

            // Add bitrate for lossy codecs (FLAC is lossless, no bitrate)
            if let Some(_audio_bitrate) = self.audio_codec.bitrate() {
                // Use the target bitrate from the bitrate list
                ffmpeg_args.push("-b:a");
                ffmpeg_args.push(bitrate_str);
            } else if self.audio_codec.is_lossless() {
                // For FLAC, we might transcode to lossy variants
                // Use the bitrate from the list (e.g., "320k")
                ffmpeg_args.push("-b:a");
                ffmpeg_args.push(bitrate_str);
                // Override codec to AAC for lossy variants from FLAC source
                if let Some(pos) = ffmpeg_args.iter().position(|x| *x == "-c:a") {
                    ffmpeg_args[pos + 1] = "aac"; // Use AAC for lossy variants
                }
            }

            // Add MP4-specific options for progressive download
            let mp4_path_str = mp4_path.to_str().unwrap();
            ffmpeg_args.extend_from_slice(&[
                "-movflags",
                "+faststart", // Enable progressive download
                "-f",
                "mp4",
                mp4_path_str,
            ]);

            let status = Command::new("ffmpeg")
                .args(&ffmpeg_args)
                .status()?;

            if !status.success() {
                warn!(bitrate = bitrate_str, "Failed to transcode audio variant to MP4, skipping");
                continue;
            }

            mp4_files.push(mp4_path);
            info!(bitrate = bitrate_str, "Audio variant MP4 transcoding completed");
        }

        info!(
            mp4_files = mp4_files.len(),
            "Audio MP4 transcoding completed"
        );

        Ok(mp4_files)
    }

    /// Transcode video to MP4/WebM format for each resolution
    /// 
    /// Generates video files for each resolution variant with:
    /// - Selected video codec (H.264, VP9, AV1)
    /// - Selected audio codec (AAC, Opus, MP3, Vorbis, FLAC)
    /// - Progressive download support (faststart for MP4)
    /// - Optimized for streaming
    async fn transcode_to_mp4(
        &self,
        input_path: &Path,
        output_dir: &Path,
        resolutions: &[String],
        _media_id: &Uuid,
    ) -> anyhow::Result<Vec<PathBuf>> {
        if !self.ffmpeg_available {
            warn!("FFmpeg not available - skipping MP4 generation");
            return Ok(vec![]);
        }

        info!(
            "Transcoding to MP4 with {} resolution(s): {:?}",
            resolutions.len(),
            resolutions
        );

        let mut mp4_files = Vec::new();

        // Transcode each resolution variant to MP4
        for resolution in resolutions {
            let (width, height, bitrate) = Self::get_resolution_params(resolution);
            
            // Get audio codec(s) for this resolution
            let (primary_audio_codec, secondary_audio_codec) = self.get_audio_codecs_for_resolution(resolution);
            
            let mp4_filename = format!("{}.mp4", resolution);
            let mp4_path = output_dir.join(&mp4_filename);

            info!(
                resolution = resolution,
                width = width,
                height = height,
                bitrate = bitrate,
                primary_audio = ?primary_audio_codec,
                "Transcoding variant to MP4"
            );

            // Build FFmpeg command for MP4 transcoding
            let maxrate_str = format!("{}k", bitrate);
            let bufsize_str = format!("{}k", bitrate * 2);
            let vf_filter = format!(
                "scale={}:{}:force_original_aspect_ratio=decrease,pad={}:{}:(ow-iw)/2:(oh-ih)/2",
                width, height, width, height
            );
            
            let mut ffmpeg_args = vec![
                "-i",
                input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
                "-c:v",
                self.video_codec.ffmpeg_codec(),
            ];

            // Add codec-specific arguments
            ffmpeg_args.extend_from_slice(&self.video_codec.ffmpeg_args());

            // Add bitrate control
            ffmpeg_args.extend_from_slice(&[
                "-maxrate",
                &maxrate_str,
                "-bufsize",
                &bufsize_str,
                "-vf",
                &vf_filter,
                "-c:a",
                primary_audio_codec.ffmpeg_codec(),
            ]);

            // Add bitrate for lossy codecs (FLAC is lossless, no bitrate)
            // Use higher bitrate for high-res Opus
            if let Some(audio_bitrate) = primary_audio_codec.bitrate() {
                let bitrate_to_use = if matches!(resolution.as_str(), "8K" | "4320p" | "5K" | "2880p" | "4K" | "2160p") 
                    && primary_audio_codec == AudioCodec::Opus {
                    // Use 192 kbps for high-res Opus (better quality)
                    "192k"
                } else {
                    audio_bitrate
                };
                ffmpeg_args.push("-b:a");
                ffmpeg_args.push(bitrate_to_use);
            }

            // Add container-specific options
            let mp4_path_str = mp4_path.to_str().unwrap();
            let container_format = match self.video_codec {
                VideoCodec::VP9 => "webm", // VP9 typically uses WebM
                _ => "mp4", // H.264 and AV1 use MP4
            };
            
            if container_format == "mp4" {
                ffmpeg_args.extend_from_slice(&[
                    "-movflags",
                    "+faststart", // Move MOOV atom to beginning for progressive download
                    "-f",
                    "mp4",
                    "-y", // Overwrite output file
                    mp4_path_str,
                ]);
            } else {
                // WebM container
                ffmpeg_args.extend_from_slice(&[
                    "-f",
                    "webm",
                    "-y", // Overwrite output file
                    mp4_path_str,
                ]);
            }

            let status = Command::new("ffmpeg")
                .args(&ffmpeg_args)
                .status()?;

            if !status.success() {
                warn!(resolution = resolution, "Failed to transcode variant to MP4, skipping");
                continue;
            }

            if mp4_path.exists() {
                mp4_files.push(mp4_path.clone());
                info!(
                    resolution = resolution,
                    file = %mp4_path.display(),
                    "MP4 variant transcoding completed"
                );
            } else {
                warn!(
                    resolution = resolution,
                    file = %mp4_path.display(),
                    "MP4 file was not created"
                );
            }

            // Generate secondary audio track MP4 if dual tracks enabled
            if let Some(secondary_codec) = secondary_audio_codec {
                let secondary_mp4_filename = format!("{}-{}.mp4", resolution, secondary_codec.ffmpeg_codec());
                let secondary_mp4_path = output_dir.join(&secondary_mp4_filename);

                info!(
                    resolution = resolution,
                    secondary_codec = ?secondary_codec,
                    "Generating secondary audio track MP4"
                );

                // Build FFmpeg command for secondary audio track MP4
                let mut secondary_ffmpeg_args = vec![
                    "-i",
                    input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
                    "-c:v",
                    self.video_codec.ffmpeg_codec(),
                ];

                // Add codec-specific arguments
                secondary_ffmpeg_args.extend_from_slice(&self.video_codec.ffmpeg_args());

                // Add bitrate control
                secondary_ffmpeg_args.extend_from_slice(&[
                    "-maxrate",
                    &maxrate_str,
                    "-bufsize",
                    &bufsize_str,
                    "-vf",
                    &vf_filter,
                    "-c:a",
                    secondary_codec.ffmpeg_codec(),
                ]);

                // Add bitrate for lossy codecs
                if let Some(audio_bitrate) = secondary_codec.bitrate() {
                    secondary_ffmpeg_args.push("-b:a");
                    secondary_ffmpeg_args.push(audio_bitrate);
                }

                // Add container-specific options
                let secondary_mp4_path_str = secondary_mp4_path.to_str().unwrap();
                let container_format = match self.video_codec {
                    VideoCodec::VP9 => "webm",
                    _ => "mp4",
                };
                
                if container_format == "mp4" {
                    secondary_ffmpeg_args.extend_from_slice(&[
                        "-movflags",
                        "+faststart",
                        "-f",
                        "mp4",
                        "-y",
                        secondary_mp4_path_str,
                    ]);
                } else {
                    secondary_ffmpeg_args.extend_from_slice(&[
                        "-f",
                        "webm",
                        "-y",
                        secondary_mp4_path_str,
                    ]);
                }

                let secondary_status = Command::new("ffmpeg")
                    .args(&secondary_ffmpeg_args)
                    .status()?;

                if secondary_status.success() && secondary_mp4_path.exists() {
                    mp4_files.push(secondary_mp4_path.clone());
                    info!(
                        resolution = resolution,
                        secondary_codec = ?secondary_codec,
                        file = %secondary_mp4_path.display(),
                        "Secondary audio track MP4 generated"
                    );
                } else {
                    warn!(
                        resolution = resolution,
                        secondary_codec = ?secondary_codec,
                        "Failed to generate secondary audio track MP4, skipping"
                    );
                }
            }
        }

        info!(
            mp4_files = mp4_files.len(),
            "MP4 transcoding completed"
        );

        Ok(mp4_files)
    }

    /// Generate DASH manifest for adaptive streaming (Future Implementation)
    /// 
    /// This function will generate a DASH manifest (.mpd file) for adaptive streaming.
    /// Currently returns None as placeholder for future implementation.
    /// 
    /// Future implementation will:
    /// - Generate DASH manifest (.mpd) file
    /// - Reference all resolution variants
    /// - Support both HLS and DASH formats
    /// - Include period and adaptation set definitions
    async fn generate_dash_manifest(
        &self,
        _output_dir: &Path,
        _resolutions: &[String],
        _media_id: &Uuid,
    ) -> anyhow::Result<Option<PathBuf>> {
        // TODO: Implement DASH manifest generation
        // This will generate a DASH manifest (.mpd) file:
        // - Create MPD (Media Presentation Description) XML
        // - Define periods and adaptation sets
        // - Reference video and audio representations
        // - Support multi-period for live streaming
        
        info!("DASH manifest generation not yet implemented - returning None");
        Ok(None)
    }

    /// Generate thumbnails from video
    async fn generate_thumbnails(
        &self,
        input_path: &Path,
        output_dir: &Path,
        _media_id: &Uuid,
        count: usize,
    ) -> anyhow::Result<Vec<PathBuf>> {
        info!("Generating {} thumbnails", count);

        // First, get video duration
        let duration = self.extract_duration(input_path).await?;

        let mut thumbnail_paths = Vec::new();

        // Generate thumbnails at evenly spaced intervals
        for i in 0..count {
            let timestamp = (duration as f64 / (count + 1) as f64) * (i + 1) as f64;
            let thumbnail_path = output_dir.join(format!("thumb_{}.jpg", i + 1));

            let status = Command::new("ffmpeg")
                .args(&[
                    "-i",
                    input_path.to_str()
                    .ok_or_else(|| anyhow::anyhow!("Input path contains invalid UTF-8: {:?}", input_path))?,
                    "-ss",
                    &timestamp.to_string(),
                    "-vframes",
                    "1",
                    "-q:v",
                    "2", // High quality
                    "-y", // Overwrite
                    thumbnail_path.to_str()
                        .ok_or_else(|| anyhow::anyhow!("Thumbnail path contains invalid UTF-8: {:?}", thumbnail_path))?,
                ])
                .status()?;

            if status.success() {
                thumbnail_paths.push(thumbnail_path);
            } else {
                warn!("Failed to generate thumbnail {}", i + 1);
            }
        }

        info!("Generated {} thumbnails", thumbnail_paths.len());
        Ok(thumbnail_paths)
    }

    /// Mock processing (fallback when FFmpeg is not available)
    async fn mock_processing(
        &self,
        media_id: &Uuid,
        output_dir: PathBuf,
    ) -> anyhow::Result<ProcessingResult> {
        warn!("Using mock processing");

        // Simulate processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        let thumbnail_urls = vec![
            format!("https://cdn.example.com/media/{}/thumb_1.jpg", media_id),
            format!("https://cdn.example.com/media/{}/thumb_2.jpg", media_id),
        ];

        Ok(ProcessingResult {
            output_dir,
            thumbnail_urls,
            duration: 3600,
            resolutions: vec!["1080p".to_string(), "720p".to_string(), "480p".to_string()],
            hls_playlist_path: None,
            mp4_files: vec![],
            dash_manifest_path: None,
            output_files: vec![],
            encryption_metadata: None,
            is_audio_only: false,
            audio_bitrate: None,
            sample_rate: None,
        })
    }

    /// SECURITY: Validate file size to prevent DoS attacks
    /// Rejects files that exceed the maximum allowed size
    fn validate_file_size(&self, file_path: &Path) -> anyhow::Result<()> {
        use std::env;
        
        // Get max file size from environment variable or use default
        let max_size = env::var("MAX_FILE_SIZE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_FILE_SIZE_BYTES);
        
        // Get file metadata
        let file_metadata = metadata(file_path)
            .map_err(|e| anyhow::anyhow!("Failed to get file metadata: {}", e))?;
        
        let file_size = file_metadata.len();
        
        if file_size > max_size {
            error!(
                file_path = %file_path.display(),
                file_size = file_size,
                max_size = max_size,
                "File size exceeds maximum allowed size - potential DoS attack"
            );
            return Err(anyhow::anyhow!(
                "File size ({}) exceeds maximum allowed size ({}). \
                 This may indicate a DoS attack attempt.",
                Self::format_size(file_size),
                Self::format_size(max_size)
            ));
        }
        
        info!(
            file_path = %file_path.display(),
            file_size = file_size,
            max_size = max_size,
            "File size validated successfully"
        );
        
        Ok(())
    }

    /// SECURITY: Validate file content using magic bytes
    /// This prevents file type confusion attacks where malicious files are uploaded
    /// with incorrect Content-Type headers
    fn validate_file_content(&self, file_path: &Path, claimed_content_type: &str) -> anyhow::Result<()> {
        use infer::Infer;
        
        // Read first 1KB of file to check magic bytes
        let mut file = File::open(file_path)
            .map_err(|e| anyhow::anyhow!("Failed to open file for validation: {}", e))?;
        
        let mut buffer = vec![0u8; 1024];
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| anyhow::anyhow!("Failed to read file for validation: {}", e))?;
        
        if bytes_read == 0 {
            return Err(anyhow::anyhow!("File is empty"));
        }
        
        buffer.truncate(bytes_read);
        
        // Use infer crate to detect actual file type from magic bytes
        let infer = Infer::new();
        let detected_type = infer.get(&buffer);
        
        match detected_type {
            Some(actual_type) => {
                let actual_mime = actual_type.mime_type();
                
                // Check if detected type matches claimed content type
                let is_valid = match claimed_content_type {
                    ct if ct.starts_with("video/") => {
                        // Accept video types
                        actual_mime.starts_with("video/") || 
                        // Also accept some container formats that can contain video
                        matches!(actual_mime, 
                            "application/octet-stream" | // Some video files may be detected as this
                            "application/x-matroska" | // MKV files
                            "application/vnd.apple.mpegurl" // HLS playlists
                        )
                    }
                    ct if ct.starts_with("audio/") => {
                        // Accept audio types
                        actual_mime.starts_with("audio/") ||
                        // Also accept some container formats that can contain audio
                        matches!(actual_mime,
                            "application/octet-stream" | // Some audio files may be detected as this
                            "application/x-matroska" | // MKV files can contain audio
                            "application/vnd.apple.mpegurl" // HLS playlists
                        )
                    }
                    _ => false,
                };
                
                if !is_valid {
                    error!(
                        file_path = %file_path.display(),
                        claimed_type = claimed_content_type,
                        actual_type = actual_mime,
                        "File content type mismatch detected - potential security issue"
                    );
                    return Err(anyhow::anyhow!(
                        "File content type mismatch: claimed '{}' but file is actually '{}'. \
                         This may indicate a file type confusion attack.",
                        claimed_content_type,
                        actual_mime
                    ));
                }
                
                info!(
                    file_path = %file_path.display(),
                    claimed_type = claimed_content_type,
                    actual_type = actual_mime,
                    "File content type validated successfully"
                );
            }
            None => {
                // File type could not be determined from magic bytes
                // This could be a legitimate file format not recognized by infer
                // Log a warning but allow processing to continue
                // (FFmpeg will handle validation during actual processing)
                warn!(
                    file_path = %file_path.display(),
                    claimed_type = claimed_content_type,
                    "Could not determine file type from magic bytes - proceeding with caution"
                );
            }
        }
        
        Ok(())
    }

    /// Format file size in human-readable format
    fn format_size(bytes: u64) -> String {
        const KB: u64 = 1024;
        const MB: u64 = KB * 1024;
        const GB: u64 = MB * 1024;
        const TB: u64 = GB * 1024;
        
        if bytes >= TB {
            format!("{:.2} TB", bytes as f64 / TB as f64)
        } else if bytes >= GB {
            format!("{:.2} GB", bytes as f64 / GB as f64)
        } else if bytes >= MB {
            format!("{:.2} MB", bytes as f64 / MB as f64)
        } else if bytes >= KB {
            format!("{:.2} KB", bytes as f64 / KB as f64)
        } else {
            format!("{} bytes", bytes)
        }
    }

    /// Check if FFmpeg is available
    fn check_ffmpeg_available() -> bool {
        match Command::new("ffmpeg").arg("-version").output() {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }
    
    /// Detect available hardware acceleration backend
    fn detect_hardware_backend() -> Option<HardwareBackend> {
        // Check NVENC (NVIDIA)
        if Self::check_nvenc_available() {
            return Some(HardwareBackend::Nvenc);
        }
        
        // Check VideoToolbox (macOS)
        #[cfg(target_os = "macos")]
        {
            if Self::check_videotoolbox_available() {
                return Some(HardwareBackend::VideoToolbox);
            }
        }
        
        // Check VAAPI (Linux)
        #[cfg(target_os = "linux")]
        {
            if Self::check_vaapi_available() {
                return Some(HardwareBackend::Vaapi);
            }
        }
        
        None
    }
    
    /// Check if NVENC is available
    fn check_nvenc_available() -> bool {
        // Check if FFmpeg has NVENC support
        match Command::new("ffmpeg")
            .args(&["-hide_banner", "-encoders"])
            .output()
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.contains("h264_nvenc") || output_str.contains("hevc_nvenc")
            }
            Err(_) => false,
        }
    }
    
    /// Check if VideoToolbox is available (macOS)
    #[cfg(target_os = "macos")]
    fn check_videotoolbox_available() -> bool {
        match Command::new("ffmpeg")
            .args(&["-hide_banner", "-encoders"])
            .output()
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.contains("h264_videotoolbox") || output_str.contains("hevc_videotoolbox")
            }
            Err(_) => false,
        }
    }
    
    /// Check if VAAPI is available (Linux)
    #[cfg(target_os = "linux")]
    fn check_vaapi_available() -> bool {
        match Command::new("ffmpeg")
            .args(&["-hide_banner", "-encoders"])
            .output()
        {
            Ok(output) => {
                let output_str = String::from_utf8_lossy(&output.stdout);
                output_str.contains("h264_vaapi") || output_str.contains("hevc_vaapi")
            }
            Err(_) => false,
        }
    }
    
    #[cfg(not(target_os = "macos"))]
    fn check_videotoolbox_available() -> bool {
        false
    }
    
    #[cfg(not(target_os = "linux"))]
    fn check_vaapi_available() -> bool {
        false
    }
}

impl Default for MediaProcessor {
    fn default() -> Self {
        Self::new()
    }
}
