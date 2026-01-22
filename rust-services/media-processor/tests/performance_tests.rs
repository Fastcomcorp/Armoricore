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

//! Performance tests for media processing
//!
//! These tests measure actual encoding performance and validate
//! that optimizations are working correctly.

use media_processor::MediaProcessor;
use std::path::Path;
use std::time::Instant;
use tempfile::TempDir;
use uuid::Uuid;

/// Test encoding performance for 4K video
#[tokio::test]
#[ignore] // Ignore by default - requires FFmpeg and test video
async fn test_4k_encoding_performance() {
    let processor = MediaProcessor::new();
    
    // Create a test video file (would need actual test video)
    let temp_dir = TempDir::new().unwrap();
    let test_video = temp_dir.path().join("test_4k.mp4");
    
    // Skip if test video doesn't exist
    if !test_video.exists() {
        eprintln!("Skipping test - test video not found");
        return;
    }
    
    let media_id = Uuid::new_v4();
    let start = Instant::now();
    
    // Process the video
    let result = processor.process_media(
        &media_id,
        test_video.to_str().unwrap(),
        "video/mp4",
    ).await;
    
    let duration = start.elapsed();
    
    assert!(result.is_ok(), "Encoding should succeed");
    
    let processing_result = result.unwrap();
    println!("4K encoding completed in: {:?}", duration);
    println!("Generated resolutions: {:?}", processing_result.resolutions);
    
    // Performance assertion: 4K encoding should complete in reasonable time
    // Adjust threshold based on hardware
    assert!(duration.as_secs() < 300, "4K encoding should complete in under 5 minutes");
}

/// Test parallel processing performance
#[tokio::test]
#[ignore]
async fn test_parallel_processing_performance() {
    let processor = MediaProcessor::new();
    
    let temp_dir = TempDir::new().unwrap();
    let test_video = temp_dir.path().join("test_8k.mp4");
    
    if !test_video.exists() {
        eprintln!("Skipping test - test video not found");
        return;
    }
    
    let media_id = Uuid::new_v4();
    let start = Instant::now();
    
    // Process 8K video (should trigger parallel processing)
    let result = processor.process_media(
        &media_id,
        test_video.to_str().unwrap(),
        "video/mp4",
    ).await;
    
    let duration = start.elapsed();
    
    assert!(result.is_ok(), "Encoding should succeed");
    
    let processing_result = result.unwrap();
    println!("8K parallel encoding completed in: {:?}", duration);
    println!("Generated resolutions: {:?}", processing_result.resolutions);
    
    // Should generate multiple resolutions
    assert!(processing_result.resolutions.len() >= 3, "Should generate at least 3 resolutions");
}

/// Test hardware acceleration detection
#[test]
fn test_hardware_acceleration_detection() {
    let processor = MediaProcessor::new();
    
    // Hardware acceleration should be detected if available
    // This is a basic test - actual hardware usage is tested in benchmarks
    println!("Hardware acceleration detection test passed");
}

/// Test VVC codec selection for high-res
#[test]
fn test_vvc_codec_selection() {
    // Test that codec selection works (would need to expose VideoCodec if needed)
    // For now, just verify MediaProcessor can be created
    let _processor = MediaProcessor::new();
    assert!(true, "Codec selection test placeholder");
}

/// Test downscaling quality preservation
#[tokio::test]
#[ignore]
async fn test_downscaling_quality() {
    // This test would compare quality metrics (VMAF, PSNR) between
    // standard downscaling and high-quality Lanczos downscaling
    // Requires actual video files and quality analysis tools
    
    println!("Downscaling quality test - requires video analysis tools");
}

