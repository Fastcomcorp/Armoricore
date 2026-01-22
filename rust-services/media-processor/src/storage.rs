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

//! Object Storage - S3-compatible storage operations (Akamai-compatible)
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


use armoricore_config::ObjectStorageConfig;
use rusoto_core::{credential::StaticProvider, request::HttpClient, Region};
use rusoto_s3::{PutObjectRequest, S3Client, S3};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::processor::ProcessingResult;
use crate::retry::{RetryConfig, is_retryable_upload_error, retry_with_backoff};

/// Object storage client for S3-compatible storage (Akamai)
pub struct ObjectStorage {
    client: Option<Arc<S3Client>>,
    config: ObjectStorageConfig,
    base_url: String,
    retry_config: RetryConfig,
}

impl ObjectStorage {
    /// Create a new object storage client
    pub fn new(config: ObjectStorageConfig) -> Self {
        info!(
            endpoint = config.endpoint,
            bucket = config.bucket,
            "Initializing object storage client for Akamai"
        );

        // Extract base URL from endpoint
        // For Akamai, endpoint might be like: https://your-bucket.akamai.com
        // or s3://bucket-name with a separate CDN URL
        let base_url = if config.endpoint.starts_with("http") {
            // If endpoint is a full URL, use it as base
            let url = config.endpoint.trim_end_matches('/');
            url.to_string()
        } else if config.endpoint.starts_with("s3://") {
            // If it's an s3:// URL, construct from bucket
            format!("https://{}.akamai.com", config.bucket)
        } else {
            format!("https://{}.akamai.com", config.bucket)
        };

        // Initialize S3 client for Akamai (S3-compatible)
        let client = Self::create_s3_client(&config)
            .map(Arc::new);

        Self {
            client,
            config,
            base_url,
            retry_config: RetryConfig::from_env(),
        }
    }

    /// Create S3 client configured for Akamai Object Storage
    fn create_s3_client(config: &ObjectStorageConfig) -> Option<S3Client> {
        // Create credentials provider
        let credentials = StaticProvider::new_minimal(
            config.access_key.clone(),
            config.secret_key.clone(),
        );

        // Determine region - Akamai typically uses us-east-1 or a custom region
        let region = if let Some(ref region_str) = config.region {
            Region::Custom {
                name: region_str.clone(),
                endpoint: Self::extract_endpoint(&config.endpoint),
            }
        } else {
            // Default to custom region with Akamai endpoint
            Region::Custom {
                name: "akamai".to_string(),
                endpoint: Self::extract_endpoint(&config.endpoint),
            }
        };

        let endpoint_str = match &region {
            Region::Custom { endpoint, .. } => endpoint.clone(),
            _ => "default".to_string(),
        };
        
        info!(
            endpoint = endpoint_str,
            "Creating S3 client for Akamai Object Storage"
        );

        // Create HTTP client
        let http_client = match HttpClient::new() {
            Ok(client) => client,
            Err(e) => {
                warn!(error = %e, "Failed to create HTTP client");
                return None;
            }
        };

        Some(S3Client::new_with(http_client, credentials, region))
    }

    /// Extract endpoint URL from configuration
    fn extract_endpoint(endpoint: &str) -> String {
        if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
            endpoint.to_string()
        } else if endpoint.starts_with("s3://") {
            // Convert s3://bucket to https://bucket.akamai.com
            let bucket = endpoint.strip_prefix("s3://").unwrap_or(endpoint);
            format!("https://{}.akamai.com", bucket)
        } else {
            format!("https://{}.akamai.com", endpoint)
        }
    }

    /// Upload processed files to object storage
    pub async fn upload_processed_files(
        &self,
        media_id: &Uuid,
        processing_result: &ProcessingResult,
    ) -> anyhow::Result<armoricore_types::schemas::PlaybackUrls> {
        info!(
            media_id = %media_id,
            bucket = self.config.bucket,
            files_count = processing_result.output_files.len(),
            "Uploading processed files to Akamai Object Storage"
        );

        // If client is not available, use mock
        let client = match &self.client {
            Some(c) => c,
            None => {
                warn!("S3 client not available, using mock URLs");
                return self.generate_mock_urls(media_id);
            }
        };

        // Upload all generated files
        let mut uploaded_urls = Vec::new();

        // Upload HLS master playlist and all variants
        let hls_url = if let Some(ref playlist_path) = processing_result.hls_playlist_path {
            // Upload master playlist
            let master_s3_key = format!("media/{}/master.m3u8", media_id);
            match self.upload_file(playlist_path, &master_s3_key, "application/vnd.apple.mpegurl").await {
                Ok(url) => {
                    uploaded_urls.push(url.clone());
                    
                    // Upload all variant playlists and segments
                    let output_dir = playlist_path.parent()
                        .ok_or_else(|| anyhow::anyhow!("Playlist path has no parent directory: {:?}", playlist_path))?;
                    self.upload_hls_variants(output_dir, media_id).await?;
                    
                    Some(url)
                }
                Err(e) => {
                    error!(error = %e, "Failed to upload HLS master playlist");
                    None
                }
            }
        } else {
            None
        };

        // Upload MP4 files
        let mut mp4_urls = std::collections::HashMap::new();
        if !processing_result.mp4_files.is_empty() {
            for mp4_file in &processing_result.mp4_files {
                // Extract resolution from filename (e.g., "1080p.mp4" -> "1080p")
                if let Some(file_name) = mp4_file.file_name() {
                    if let Some(name_str) = file_name.to_str() {
                        if let Some(resolution) = name_str.strip_suffix(".mp4") {
                            let s3_key = format!("media/{}/{}", media_id, name_str);
                            match self.upload_file(mp4_file, &s3_key, "video/mp4").await {
                                Ok(url) => {
                                    uploaded_urls.push(url.clone());
                                    mp4_urls.insert(resolution.to_string(), url);
                                    let mp4_url = mp4_urls.get(resolution)
                                        .ok_or_else(|| anyhow::anyhow!("MP4 URL not found for resolution: {}", resolution))?;
                                    info!(
                                        resolution = resolution,
                                        url = %mp4_url,
                                        "Uploaded MP4 file"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        error = %e,
                                        resolution = resolution,
                                        "Failed to upload MP4 file"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Upload thumbnails
        let thumbnail_urls = self.upload_thumbnails(client, media_id, processing_result).await?;

        // For now, DASH is not generated, but structure is ready
        let dash_url = None;

        info!(
            media_id = %media_id,
            hls_url = ?hls_url,
            mp4_files = mp4_urls.len(),
            thumbnails = thumbnail_urls.len(),
            "Files uploaded to Akamai Object Storage"
        );

        Ok(armoricore_types::schemas::PlaybackUrls {
            hls: hls_url,
            mp4: mp4_urls,
            dash: dash_url,
        })
    }

    /// Upload thumbnails
    async fn upload_thumbnails(
        &self,
        _client: &S3Client,
        media_id: &Uuid,
        processing_result: &ProcessingResult,
    ) -> anyhow::Result<Vec<String>> {
        let _ = _client; // Suppress unused warning
        
        // Find thumbnail files in output directory
        let mut thumbnail_paths = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&processing_result.output_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if file_name.starts_with("thumb_") && file_name.ends_with(".jpg") {
                        let file_name_str = file_name.to_string();
                        thumbnail_paths.push((path, file_name_str));
                    }
                }
            }
        }

        // Upload each thumbnail
        let mut uploaded_urls = Vec::new();
        for (thumb_path, file_name) in thumbnail_paths {
            let s3_key = format!("media/{}/{}", media_id, file_name);
            match self.upload_file(&thumb_path, &s3_key, "image/jpeg").await {
                Ok(url) => uploaded_urls.push(url),
                Err(e) => {
                    warn!(error = %e, file = file_name, "Failed to upload thumbnail");
                }
            }
        }

        // If no thumbnails were uploaded, use the URLs from processing result
        if uploaded_urls.is_empty() {
            Ok(processing_result.thumbnail_urls.clone())
        } else {
            Ok(uploaded_urls)
        }
    }

    /// Upload HLS playlist
    #[allow(dead_code)] // Method is part of public API, may be used by external code
    async fn upload_hls_playlist(
        &self,
        _client: &S3Client,
        _media_id: &Uuid,
        _processing_result: &ProcessingResult,
    ) -> anyhow::Result<Option<String>> {
        // TODO: Upload actual HLS playlist when FFmpeg generates it
        // For now, generate URL
        let _ = (_client, _processing_result); // Suppress unused warnings
        let hls_key = format!("media/{}/playlist.m3u8", _media_id);
        let hls_url = format!("{}/{}", self.base_url, hls_key);
        Ok(Some(hls_url))
    }

    /// Upload DASH manifest
    #[allow(dead_code)] // Method is part of public API, may be used by external code
    async fn upload_dash_manifest(
        &self,
        _client: &S3Client,
        _media_id: &Uuid,
        _processing_result: &ProcessingResult,
    ) -> anyhow::Result<Option<String>> {
        // TODO: Upload actual DASH manifest when FFmpeg generates it
        // For now, generate URL
        let _ = (_client, _processing_result); // Suppress unused warnings
        let dash_key = format!("media/{}/manifest.mpd", _media_id);
        let dash_url = format!("{}/{}", self.base_url, dash_key);
        Ok(Some(dash_url))
    }

    /// Upload a single file to S3-compatible storage with retry logic
    pub async fn upload_file(
        &self,
        local_path: &Path,
        s3_key: &str,
        content_type: &str,
    ) -> anyhow::Result<String> {
        let client = match &self.client {
            Some(c) => c,
            None => {
                return Err(anyhow::anyhow!("S3 client not available"));
            }
        };

        info!(
            local_path = %local_path.display(),
            s3_key = s3_key,
            content_type = content_type,
            "Uploading file to Akamai Object Storage"
        );

        // Read file content once (before retries)
        let file_content = fs::read(local_path)
            .map_err(|e| anyhow::anyhow!("Failed to read file: {}", e))?;

        let bucket = self.config.bucket.clone();
        let s3_key_owned = s3_key.to_string();
        let content_type_owned = content_type.to_string();
        let base_url = self.base_url.clone();
        let retry_config = self.retry_config.clone();

        // Upload file with retry logic
        let client_arc = Arc::clone(client);
        let url: String = retry_with_backoff(&retry_config, || {
            let client = Arc::clone(&client_arc);
            let bucket = bucket.clone();
            let s3_key = s3_key_owned.clone();
            let content_type = content_type_owned.clone();
            let file_content = file_content.clone();
            let base_url = base_url.clone();

            Box::pin(async move {
                // Create put object request
                let put_request = PutObjectRequest {
                    bucket: bucket.clone(),
                    key: s3_key.clone(),
                    body: Some(file_content.clone().into()),
                    content_type: Some(content_type.clone()),
                    cache_control: Some("public, max-age=31536000".to_string()), // 1 year cache
                    ..Default::default()
                };

                // Upload file
                client
                    .put_object(put_request)
                    .await
                    .map_err(|e| {
                        let error = anyhow::anyhow!("Failed to upload file: {}", e);
                        // Only retry if error is retryable
                        if !is_retryable_upload_error(&error) {
                            warn!(
                                error = %error,
                                s3_key = s3_key,
                                "Non-retryable upload error, will not retry"
                            );
                        }
                        error
                    })?;

                // Generate public URL
                let url = format!("{}/{}", base_url, s3_key);

                Ok::<String, anyhow::Error>(url)
            })
        })
        .await?;

        info!(
            s3_key = s3_key,
            url = url,
            "File uploaded successfully"
        );

        Ok(url)
    }

    /// Upload HLS variants (playlists and segments)
    async fn upload_hls_variants(
        &self,
        output_dir: &Path,
        media_id: &Uuid,
    ) -> anyhow::Result<()> {
        // Find all resolution directories (1080p, 720p, 480p, etc.)
        if let Ok(entries) = std::fs::read_dir(output_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // This is a variant directory (e.g., "1080p", "720p")
                    if let Some(variant_name) = path.file_name().and_then(|n| n.to_str()) {
                        // Upload variant playlist
                        let variant_playlist = path.join("playlist.m3u8");
                        if variant_playlist.exists() {
                            let s3_key = format!("media/{}/{}/playlist.m3u8", media_id, variant_name);
                            if let Err(e) = self.upload_file(&variant_playlist, &s3_key, "application/vnd.apple.mpegurl").await {
                                warn!(error = %e, variant = variant_name, "Failed to upload variant playlist");
                            }
                        }

                        // Upload all segments in this variant directory
                        if let Ok(segment_entries) = std::fs::read_dir(&path) {
                            for segment_entry in segment_entries.flatten() {
                                let segment_path = segment_entry.path();
                                if segment_path.extension().and_then(|s| s.to_str()) == Some("ts") {
                                    if let Some(segment_name) = segment_path.file_name().and_then(|n| n.to_str()) {
                                        let s3_key = format!("media/{}/{}/{}", media_id, variant_name, segment_name);
                                        if let Err(e) = self.upload_file(&segment_path, &s3_key, "video/mp2t").await {
                                            warn!(error = %e, variant = variant_name, segment = segment_name, "Failed to upload segment");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Generate mock URLs (fallback when S3 client is not available)
    fn generate_mock_urls(
        &self,
        media_id: &Uuid,
    ) -> anyhow::Result<armoricore_types::schemas::PlaybackUrls> {
        let hls_url = format!("{}/media/{}/master.m3u8", self.base_url, media_id);
        let dash_url = format!("{}/media/{}/manifest.mpd", self.base_url, media_id);

        Ok(armoricore_types::schemas::PlaybackUrls {
            hls: Some(hls_url),
            dash: Some(dash_url),
            mp4: std::collections::HashMap::new(), // TODO: Generate MP4 URLs when implemented
        })
    }
}
