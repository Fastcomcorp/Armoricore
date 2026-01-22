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

//! CDN Uploader for Live Stream Segments
//!
//! Handles uploading HLS segments and playlists to CDN (Akamai) in real-time

use crate::storage::ObjectStorage;
use anyhow::{Context, Result};
use armoricore_config::ObjectStorageConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// CDN uploader for live stream segments
pub struct CdnUploader {
    storage: Arc<ObjectStorage>,
    base_url: String,
    upload_queue: mpsc::Sender<UploadTask>,
    #[allow(dead_code)]
    upload_handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for CdnUploader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CdnUploader")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Upload task for queued uploads
#[derive(Debug, Clone)]
struct UploadTask {
    local_path: PathBuf,
    s3_key: String,
    content_type: String,
    stream_id: String,
    quality: String,
}

impl CdnUploader {
    /// Create a new CDN uploader
    pub fn new(storage_config: ObjectStorageConfig) -> Self {
        let storage = Arc::new(ObjectStorage::new(storage_config.clone()));
        
        // Extract base URL from config (same logic as ObjectStorage)
        let base_url = if storage_config.endpoint.starts_with("http") {
            storage_config.endpoint.trim_end_matches('/').to_string()
        } else if storage_config.endpoint.starts_with("s3://") {
            format!("https://{}.akamai.com", storage_config.bucket)
        } else {
            format!("https://{}.akamai.com", storage_config.bucket)
        };
        
        let (tx, rx) = mpsc::channel::<UploadTask>(1000); // Queue up to 1000 uploads

        // Start upload worker
        let storage_clone = Arc::clone(&storage);
        let upload_handle = tokio::spawn(Self::upload_worker(rx, storage_clone));

        Self {
            storage,
            base_url,
            upload_queue: tx,
            upload_handle: Some(upload_handle),
        }
    }

    /// Upload worker that processes upload queue
    async fn upload_worker(
        mut rx: mpsc::Receiver<UploadTask>,
        storage: Arc<ObjectStorage>,
    ) {
        info!("CDN upload worker started");

        while let Some(task) = rx.recv().await {
            match storage
                .upload_file(&task.local_path, &task.s3_key, &task.content_type)
                .await
            {
                Ok(url) => {
                    info!(
                        stream_id = task.stream_id,
                        quality = task.quality,
                        s3_key = task.s3_key,
                        url = url,
                        "Segment uploaded to CDN"
                    );
                }
                Err(e) => {
                    error!(
                        stream_id = task.stream_id,
                        quality = task.quality,
                        s3_key = task.s3_key,
                        error = %e,
                        "Failed to upload segment to CDN"
                    );
                }
            }
        }

        warn!("CDN upload worker stopped");
    }

    /// Upload an HLS segment
    pub async fn upload_hls_segment(
        &self,
        segment_path: &Path,
        stream_id: &str,
        quality: &str,
        segment_number: u64,
    ) -> Result<String> {
        let s3_key = format!("live/{}/{}/segment_{:03}.ts", stream_id, quality, segment_number);
        let content_type = "video/mp2t";

        // For live streaming, we want minimal cache (segments are frequently updated)
        // Queue the upload for async processing
        let task = UploadTask {
            local_path: segment_path.to_path_buf(),
            s3_key: s3_key.clone(),
            content_type: content_type.to_string(),
            stream_id: stream_id.to_string(),
            quality: quality.to_string(),
        };

        self.upload_queue
            .send(task)
            .await
            .map_err(|_| anyhow::anyhow!("Upload queue is full"))?;

        // Generate CDN URL (will be available after upload completes)
        let url = format!("{}/{}", &self.base_url, s3_key);
        Ok(url)
    }

    /// Upload an HLS playlist
    pub async fn upload_hls_playlist(
        &self,
        playlist_path: &Path,
        stream_id: &str,
        quality: Option<&str>,
    ) -> Result<String> {
        let (s3_key, content_type) = if let Some(quality) = quality {
            // Variant playlist
            (
                format!("live/{}/{}/playlist.m3u8", stream_id, quality),
                "application/vnd.apple.mpegurl",
            )
        } else {
            // Master playlist
            (
                format!("live/{}/master.m3u8", stream_id),
                "application/vnd.apple.mpegurl",
            )
        };

        // Upload immediately (playlists are small and need to be available quickly)
        let url = self
            .storage
            .upload_file(playlist_path, &s3_key, content_type)
            .await
            .context("Failed to upload HLS playlist")?;

        info!(
            stream_id = stream_id,
            quality = quality,
            s3_key = s3_key,
            url = url,
            "HLS playlist uploaded to CDN"
        );

        Ok(url)
    }

    /// Update playlist URLs in master playlist to point to CDN
    pub async fn update_master_playlist_urls(
        &self,
        master_playlist_path: &Path,
        stream_id: &str,
    ) -> Result<()> {
        let content = fs::read_to_string(master_playlist_path)
            .await
            .context("Failed to read master playlist")?;

        let base_url = &self.base_url;
        let mut updated_content = String::new();
        let mut lines = content.lines();

        // Copy header lines
        while let Some(line) = lines.next() {
            if line.starts_with("#EXT-X-STREAM-INF") {
                updated_content.push_str(line);
                updated_content.push('\n');
                // Next line should be the playlist path
                if let Some(playlist_line) = lines.next() {
                    // Convert relative path to CDN URL
                    let cdn_url = if playlist_line.starts_with("http") {
                        playlist_line.to_string()
                    } else {
                        // Extract quality from path (e.g., "720p/playlist.m3u8")
                        let quality = playlist_line
                            .split('/')
                            .next()
                            .unwrap_or("unknown");
                        format!("{}/live/{}/{}/playlist.m3u8", base_url, stream_id, quality)
                    };
                    updated_content.push_str(&cdn_url);
                    updated_content.push('\n');
                }
            } else {
                updated_content.push_str(line);
                updated_content.push('\n');
            }
        }

        // Write updated content back
        fs::write(master_playlist_path, updated_content)
            .await
            .context("Failed to write updated master playlist")?;

        Ok(())
    }

    /// Get base URL for CDN
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Shutdown upload worker
    pub async fn shutdown(&mut self) {
        drop(self.upload_queue.clone());
        if let Some(handle) = self.upload_handle.take() {
            handle.await.ok();
        }
    }
}


