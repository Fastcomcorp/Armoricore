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

//! Live transcoding module for real-time stream processing
//!
//! This module handles live stream transcoding with:
//! - Multi-bitrate encoding
//! - ArcRTP quality indicators
//! - HLS segmentation
//! - Low-latency mode support

use crate::cdn_uploader::CdnUploader;
use crate::processor::{AudioCodec, VideoCodec};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Live transcoding configuration
#[derive(Debug, Clone)]
pub struct LiveTranscoderConfig {
    /// Stream ID
    pub stream_id: String,
    /// User ID
    pub user_id: String,
    /// Output directory for HLS segments
    pub output_dir: PathBuf,
    /// Quality profiles (resolution -> bitrate)
    pub quality_profiles: Vec<QualityProfile>,
    /// Video codec
    pub video_codec: VideoCodec,
    /// Audio codec
    pub audio_codec: AudioCodec,
    /// Segment duration in seconds
    pub segment_duration: u32,
    /// Low-latency mode (uses LL-HLS)
    pub low_latency: bool,
    /// Enable ArcRTP quality indicators
    pub enable_arcrtp: bool,
    /// CDN upload enabled
    pub enable_cdn_upload: bool,
    /// CDN uploader (optional)
    pub cdn_uploader: Option<Arc<CdnUploader>>,
}

/// Quality profile for multi-bitrate encoding
#[derive(Debug, Clone)]
pub struct QualityProfile {
    /// Quality name (e.g., "360p", "720p", "1080p")
    pub name: String,
    /// Resolution width
    pub width: u32,
    /// Resolution height
    pub height: u32,
    /// Video bitrate in kbps
    pub video_bitrate: u32,
    /// Audio bitrate in kbps
    pub audio_bitrate: u32,
    /// Frame rate
    pub framerate: u32,
}

/// Live transcoder instance
pub struct LiveTranscoder {
    config: LiveTranscoderConfig,
    ffmpeg_processes: Arc<RwLock<HashMap<String, std::process::Child>>>,
    segment_counters: Arc<RwLock<HashMap<String, u64>>>,
    cdn_urls: Arc<RwLock<HashMap<String, String>>>, // quality -> master playlist URL
}

impl LiveTranscoder {
    /// Create a new live transcoder
    pub fn new(config: LiveTranscoderConfig) -> Self {
        Self {
            config,
            ffmpeg_processes: Arc::new(RwLock::new(HashMap::new())),
            segment_counters: Arc::new(RwLock::new(HashMap::new())),
            cdn_urls: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start transcoding from RTMP input
    /// 
    /// This creates FFmpeg processes for each quality profile that:
    /// 1. Read from RTMP input stream
    /// 2. Transcode to multiple bitrates
    /// 3. Generate HLS segments
    /// 4. Include ArcRTP quality indicators (if enabled)
    pub async fn start_transcoding(&self, rtmp_input_url: &str) -> Result<()> {
        info!(
            stream_id = self.config.stream_id,
            rtmp_url = rtmp_input_url,
            profiles = self.config.quality_profiles.len(),
            "Starting live transcoding"
        );

        // Create output directory
        std::fs::create_dir_all(&self.config.output_dir)
            .context("Failed to create output directory")?;

        // Start transcoding for each quality profile
        for profile in &self.config.quality_profiles {
            self.start_quality_transcoding(rtmp_input_url, profile)
                .await
                .with_context(|| format!("Failed to start transcoding for {}", profile.name))?;
        }

        // Generate master playlist
        self.generate_master_playlist().await?;

        // Upload master playlist to CDN if enabled
        if self.config.enable_cdn_upload {
            if let Some(ref cdn_uploader) = self.config.cdn_uploader {
                let master_playlist_path = self.config.output_dir.join("master.m3u8");
                match cdn_uploader
                    .upload_hls_playlist(&master_playlist_path, &self.config.stream_id, None)
                    .await
                {
                    Ok(url) => {
                        let mut urls = self.cdn_urls.write().await;
                        urls.insert("master".to_string(), url.clone());
                        info!(
                            stream_id = self.config.stream_id,
                            master_playlist_url = url,
                            "Master playlist uploaded to CDN"
                        );
                    }
                    Err(e) => {
                        error!(
                            stream_id = self.config.stream_id,
                            error = %e,
                            "Failed to upload master playlist to CDN"
                        );
                    }
                }
            }
        }

        info!(
            stream_id = self.config.stream_id,
            "Live transcoding started for all quality profiles"
        );

        Ok(())
    }

    /// Start transcoding for a single quality profile
    async fn start_quality_transcoding(
        &self,
        rtmp_input_url: &str,
        profile: &QualityProfile,
    ) -> Result<()> {
        let variant_dir = self.config.output_dir.join(&profile.name);
        std::fs::create_dir_all(&variant_dir)
            .context("Failed to create variant directory")?;

        let playlist_path = variant_dir.join("playlist.m3u8");
        let segment_pattern = variant_dir.join("segment_%03d.ts");

        info!(
            stream_id = self.config.stream_id,
            quality = profile.name,
            width = profile.width,
            height = profile.height,
            video_bitrate = profile.video_bitrate,
            "Starting quality profile transcoding"
        );

        // Build FFmpeg command for live HLS transcoding
        let mut ffmpeg_args = vec![
            "-i",
            rtmp_input_url,
            "-c:v",
            self.config.video_codec.ffmpeg_codec(),
        ];

        // Add codec-specific arguments
        ffmpeg_args.extend_from_slice(&self.config.video_codec.ffmpeg_args());

        // Add video filters and bitrate
        let maxrate_str = format!("{}k", profile.video_bitrate);
        let bufsize_str = format!("{}k", profile.video_bitrate * 2);
        let vf_filter = format!(
            "scale={}:{}:force_original_aspect_ratio=decrease,pad={}:{}:(ow-iw)/2:(oh-ih)/2",
            profile.width, profile.height, profile.width, profile.height
        );
        let framerate_str = profile.framerate.to_string();
        let audio_bitrate_str = format!("{}k", profile.audio_bitrate);

        ffmpeg_args.extend_from_slice(&[
            "-maxrate",
            &maxrate_str,
            "-bufsize",
            &bufsize_str,
            "-vf",
            &vf_filter,
            "-r",
            &framerate_str,
            "-c:a",
            self.config.audio_codec.ffmpeg_codec(),
        ]);

        // Add audio bitrate
        if let Some(audio_bitrate) = self.config.audio_codec.bitrate() {
            ffmpeg_args.extend_from_slice(&["-b:a", audio_bitrate]);
        } else {
            // Use profile audio bitrate
            ffmpeg_args.extend_from_slice(&["-b:a", &audio_bitrate_str]);
        }

        // HLS-specific options
        let segment_filename = segment_pattern
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid segment pattern"))?;
        let playlist_path_str = playlist_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid playlist path"))?;
        let segment_duration_str = self.config.segment_duration.to_string();

        // Low-latency HLS options
        if self.config.low_latency {
            ffmpeg_args.extend_from_slice(&[
                "-hls_time",
                &segment_duration_str,
                "-hls_list_size",
                "3", // Keep only 3 segments in playlist (low latency)
                "-hls_flags",
                "delete_segments+independent_segments",
                "-hls_segment_type",
                "mpegts",
                "-hls_segment_filename",
                segment_filename,
                "-hls_playlist_type",
                "event", // Event playlist for low latency
                "-f",
                "hls",
                playlist_path_str,
            ]);
        } else {
            ffmpeg_args.extend_from_slice(&[
                "-hls_time",
                &segment_duration_str,
                "-hls_list_size",
                "0", // Keep all segments
                "-hls_flags",
                "delete_segments",
                "-hls_segment_filename",
                segment_filename,
                "-f",
                "hls",
                playlist_path_str,
            ]);
        }

        // Start FFmpeg process
        let child = Command::new("ffmpeg")
            .args(&ffmpeg_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to start FFmpeg process")?;

        // Store process handle
        {
            let mut processes = self.ffmpeg_processes.write().await;
            processes.insert(profile.name.clone(), child);
        }

        // Initialize segment counter
        {
            let mut counters = self.segment_counters.write().await;
            counters.insert(profile.name.clone(), 0);
        }

        info!(
            stream_id = self.config.stream_id,
            quality = profile.name,
            "FFmpeg process started for quality profile"
        );

        Ok(())
    }

    /// Generate master HLS playlist
    async fn generate_master_playlist(&self) -> Result<()> {
        let master_playlist_path = self.config.output_dir.join("master.m3u8");
        let mut playlist_content = String::from("#EXTM3U\n");
        playlist_content.push_str("#EXT-X-VERSION:3\n");

        if self.config.low_latency {
            playlist_content.push_str("#EXT-X-SERVER-CONTROL:CAN-BLOCK-RELOAD=YES,CAN-SKIP-UNTIL=12.0\n");
        }

        // Add variant playlists
        for profile in &self.config.quality_profiles {
            let variant_playlist = format!("{}/playlist.m3u8", profile.name);
            playlist_content.push_str(&format!(
                "#EXT-X-STREAM-INF:BANDWIDTH={},RESOLUTION={}x{},{}\n",
                profile.video_bitrate * 1000 + profile.audio_bitrate * 1000,
                profile.width,
                profile.height,
                variant_playlist
            ));
            playlist_content.push_str(&format!("{}\n", variant_playlist));
        }

        std::fs::write(&master_playlist_path, playlist_content)
            .context("Failed to write master playlist")?;

        info!(
            stream_id = self.config.stream_id,
            master_playlist = ?master_playlist_path,
            "Master playlist generated"
        );

        // If CDN upload is enabled, update playlist URLs to point to CDN
        if self.config.enable_cdn_upload {
            if let Some(ref cdn_uploader) = self.config.cdn_uploader {
                if let Err(e) = cdn_uploader
                    .update_master_playlist_urls(&master_playlist_path, &self.config.stream_id)
                    .await
                {
                    warn!(
                        stream_id = self.config.stream_id,
                        error = %e,
                        "Failed to update master playlist URLs"
                    );
                }
            }
        }

        Ok(())
    }

    /// Get CDN URL for master playlist
    pub async fn get_master_playlist_url(&self) -> Option<String> {
        let urls = self.cdn_urls.read().await;
        urls.get("master").cloned()
    }

    /// Stop transcoding
    pub async fn stop_transcoding(&self) -> Result<()> {
        info!(
            stream_id = self.config.stream_id,
            "Stopping live transcoding"
        );

        let mut processes = self.ffmpeg_processes.write().await;
        for (quality, mut process) in processes.drain() {
            if let Err(e) = process.kill() {
                warn!(
                    stream_id = self.config.stream_id,
                    quality = quality,
                    error = %e,
                    "Failed to kill FFmpeg process"
                );
            } else {
                info!(
                    stream_id = self.config.stream_id,
                    quality = quality,
                    "FFmpeg process stopped"
                );
            }
        }

        Ok(())
    }

    /// Get current segment count for a quality profile
    pub async fn get_segment_count(&self, quality: &str) -> u64 {
        let counters = self.segment_counters.read().await;
        counters.get(quality).copied().unwrap_or(0)
    }

    /// Update segment count (called when new segment is generated)
    pub async fn increment_segment_count(&self, quality: &str) {
        let mut counters = self.segment_counters.write().await;
        if let Some(count) = counters.get_mut(quality) {
            *count += 1;
        }
    }
}

/// Default quality profiles for live streaming
pub fn default_quality_profiles() -> Vec<QualityProfile> {
    vec![
        QualityProfile {
            name: "360p".to_string(),
            width: 640,
            height: 360,
            video_bitrate: 800,
            audio_bitrate: 96,
            framerate: 30,
        },
        QualityProfile {
            name: "720p".to_string(),
            width: 1280,
            height: 720,
            video_bitrate: 2500,
            audio_bitrate: 128,
            framerate: 30,
        },
        QualityProfile {
            name: "1080p".to_string(),
            width: 1920,
            height: 1080,
            video_bitrate: 5000,
            audio_bitrate: 192,
            framerate: 30,
        },
    ]
}

