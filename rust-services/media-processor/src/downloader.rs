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

//! File Downloader - Downloads files from S3, HTTP, or HTTPS
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
use rusoto_s3::{GetObjectRequest, S3Client, S3};
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

/// File downloader for remote sources
pub struct FileDownloader {
    s3_client: Option<S3Client>,
    #[allow(dead_code)] // s3_config is stored for potential future use
    s3_config: Option<ObjectStorageConfig>,
}

impl FileDownloader {
    /// Create a new file downloader
    pub fn new(s3_config: Option<ObjectStorageConfig>) -> Self {
        let s3_client = s3_config.as_ref().and_then(|config| {
            Self::create_s3_client(config)
        });

        Self {
            s3_client,
            s3_config,
        }
    }

    /// Download a file from remote source (S3, HTTP, HTTPS)
    pub async fn download_file(
        &self,
        source_url: &str,
        destination: &Path,
        media_id: &Uuid,
    ) -> anyhow::Result<PathBuf> {
        info!(
            media_id = %media_id,
            source = source_url,
            destination = %destination.display(),
            "Downloading file from remote source"
        );

        if source_url.starts_with("s3://") {
            self.download_from_s3(source_url, destination, media_id).await
        } else if source_url.starts_with("http://") || source_url.starts_with("https://") {
            self.download_from_http(source_url, destination, media_id).await
        } else {
            Err(anyhow::anyhow!("Unsupported URL scheme: {}", source_url))
        }
    }

    /// Download file from S3
    async fn download_from_s3(
        &self,
        s3_url: &str,
        destination: &Path,
        media_id: &Uuid,
    ) -> anyhow::Result<PathBuf> {
        let client = match &self.s3_client {
            Some(c) => c,
            None => {
                return Err(anyhow::anyhow!(
                    "S3 client not configured. Cannot download from S3."
                ));
            }
        };

        // Parse S3 URL: s3://bucket/key
        let (bucket, key) = Self::parse_s3_url(s3_url)?;

        info!(
            media_id = %media_id,
            bucket = bucket,
            key = key,
            "Downloading from S3"
        );

        // Create get object request
        let get_request = GetObjectRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            ..Default::default()
        };

        // Download object
        let result = client
            .get_object(get_request)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to download from S3: {}", e))?;

        // Get the body stream
        let body = result.body.ok_or_else(|| anyhow::anyhow!("S3 response has no body"))?;

        // Read the stream into bytes (rusoto ByteStream is blocking)
        // Use spawn_blocking to avoid blocking the async runtime
        let destination_clone = destination.to_path_buf();
        let total_bytes = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            use std::fs::File;
            
            let mut file = File::create(&destination_clone)
                .map_err(|e| anyhow::anyhow!("Failed to create destination file: {}", e))?;
            
            // ByteStream implements Read trait
            let mut reader = body.into_blocking_read();
            let mut buffer = [0u8; 8192]; // 8KB buffer
            let mut total_bytes = 0u64;
            
            loop {
                let bytes_read = reader.read(&mut buffer)
                    .map_err(|e| anyhow::anyhow!("Failed to read S3 stream: {}", e))?;
                
                if bytes_read == 0 {
                    break; // EOF
                }
                
                file.write_all(&buffer[..bytes_read])
                    .map_err(|e| anyhow::anyhow!("Failed to write chunk: {}", e))?;
                
                total_bytes += bytes_read as u64;
            }
            
            Ok::<u64, anyhow::Error>(total_bytes)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Task join error: {}", e))??;

        info!(
            media_id = %media_id,
            size = total_bytes,
            destination = %destination.display(),
            "File downloaded from S3"
        );

        Ok(destination.to_path_buf())
    }

    /// Download file from HTTP/HTTPS
    async fn download_from_http(
        &self,
        url: &str,
        destination: &Path,
        media_id: &Uuid,
    ) -> anyhow::Result<PathBuf> {
        info!(
            media_id = %media_id,
            url = url,
            "Downloading from HTTP/HTTPS"
        );

        // Create HTTP client
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300)) // 5 minute timeout
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;

        // Download file
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "HTTP request failed with status: {}",
                response.status()
            ));
        }

        // Stream response to file using async file I/O
        use tokio::fs::File as TokioFile;
        use tokio::io::AsyncWriteExt;
        let mut file = TokioFile::create(destination)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create destination file: {}", e))?;

        let mut stream = response.bytes_stream();
        use futures::StreamExt;
        let mut total_bytes = 0u64;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| anyhow::anyhow!("Failed to read chunk: {}", e))?;
            file.write_all(&chunk)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to write chunk: {}", e))?;
            total_bytes += chunk.len() as u64;

            // Log progress every 10MB
            if total_bytes % (10 * 1024 * 1024) == 0 {
                info!(
                    media_id = %media_id,
                    downloaded = total_bytes,
                    "Download progress"
                );
            }
        }

        info!(
            media_id = %media_id,
            size = total_bytes,
            destination = %destination.display(),
            "File downloaded from HTTP/HTTPS"
        );

        Ok(destination.to_path_buf())
    }

    /// Parse S3 URL into bucket and key
    fn parse_s3_url(s3_url: &str) -> anyhow::Result<(&str, &str)> {
        // Remove s3:// prefix
        let path = s3_url
            .strip_prefix("s3://")
            .ok_or_else(|| anyhow::anyhow!("Invalid S3 URL format"))?;

        // Find first slash to separate bucket and key
        if let Some(slash_pos) = path.find('/') {
            let bucket = &path[..slash_pos];
            let key = &path[slash_pos + 1..];
            Ok((bucket, key))
        } else {
            // No key, just bucket
            Err(anyhow::anyhow!("S3 URL must include a key: {}", s3_url))
        }
    }

    /// Create S3 client for downloading
    fn create_s3_client(config: &ObjectStorageConfig) -> Option<S3Client> {
        // Create credentials provider
        let credentials = StaticProvider::new_minimal(
            config.access_key.clone(),
            config.secret_key.clone(),
        );

        // Determine region
        let region = if let Some(ref region_str) = config.region {
            Region::Custom {
                name: region_str.clone(),
                endpoint: Self::extract_endpoint(&config.endpoint),
            }
        } else {
            Region::Custom {
                name: "akamai".to_string(),
                endpoint: Self::extract_endpoint(&config.endpoint),
            }
        };

        // Create HTTP client
        let http_client = match HttpClient::new() {
            Ok(client) => client,
            Err(e) => {
                warn!(error = %e, "Failed to create HTTP client for S3 download");
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
            let bucket = endpoint.strip_prefix("s3://").unwrap_or(endpoint);
            format!("https://{}.akamai.com", bucket)
        } else {
            format!("https://{}.akamai.com", endpoint)
        }
    }
}

