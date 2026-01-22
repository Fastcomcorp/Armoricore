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

//! File Downloader Unit Tests

use media_processor::downloader::FileDownloader;
use tempfile::TempDir;
use uuid::Uuid;

#[tokio::test]
async fn test_file_downloader_new() {
    let downloader = FileDownloader::new(None);
    // Should create without panicking
    let _ = downloader;
}

// Note: parse_s3_url is private, so we test it indirectly through download_file
// These tests verify the downloader behavior without accessing private methods

#[tokio::test]
async fn test_unsupported_url_scheme() {
    let downloader = FileDownloader::new(None);
    let media_id = Uuid::new_v4();
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path().join("test_file");

    // Try to download with unsupported scheme
    let result = downloader
        .download_file("ftp://example.com/file.mp4", &dest, &media_id)
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Unsupported URL scheme"));
}

#[tokio::test]
async fn test_s3_download_without_config() {
    let downloader = FileDownloader::new(None);
    let media_id = Uuid::new_v4();
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path().join("test_file");

    // Try to download from S3 without S3 client configured
    let result = downloader
        .download_file("s3://bucket/key", &dest, &media_id)
        .await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.to_string().contains("S3 client not configured"));
}

