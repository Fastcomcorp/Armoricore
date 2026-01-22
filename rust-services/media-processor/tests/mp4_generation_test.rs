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

//! Integration tests for MP4 generation

use media_processor::processor::MediaProcessor;
use tempfile::TempDir;
use uuid::Uuid;

/// Test MP4 generation end-to-end through process_media
/// 
/// This test requires:
/// 1. FFmpeg to be installed
/// 2. Creates a test video file using FFmpeg
#[tokio::test]
#[ignore] // Ignore by default - requires FFmpeg
async fn test_mp4_generation_end_to_end() {
    // Check if FFmpeg is available
    let processor = MediaProcessor::new();
    
    // Create temporary directory for output
    let output_dir = TempDir::new().expect("Failed to create temp directory");
    let media_id = Uuid::new_v4();
    
    // Create a test video file using FFmpeg
    let test_video_path = output_dir.path().join("test_input.mp4");
    
    // Generate a simple test video using FFmpeg
    // This creates a 10-second test pattern video
    println!("🎬 Creating test video file...");
    let ffmpeg_status = std::process::Command::new("ffmpeg")
        .args(&[
            "-f", "lavfi",
            "-i", "testsrc=duration=10:size=1280x720:rate=30",
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-crf", "23",
            "-c:a", "aac",
            "-b:a", "128k",
            "-y", // Overwrite
            test_video_path.to_str().unwrap(),
        ])
        .output();
    
    if ffmpeg_status.is_err() {
        eprintln!("⚠️  FFmpeg not available");
        eprintln!("   Skipping MP4 generation test");
        return;
    }
    
    let ffmpeg_output = ffmpeg_status.unwrap();
    if !ffmpeg_output.status.success() {
        eprintln!("⚠️  Failed to create test video");
        eprintln!("   FFmpeg stderr: {}", String::from_utf8_lossy(&ffmpeg_output.stderr));
        eprintln!("   Skipping MP4 generation test");
        return;
    }
    
    if !test_video_path.exists() {
        eprintln!("⚠️  Test video file was not created");
        eprintln!("   Skipping MP4 generation test");
        return;
    }
    
    println!("✅ Test video created: {:?}", test_video_path);
    
    // Process the media file - this will generate HLS, MP4, and thumbnails
    println!("🎬 Starting media processing (HLS + MP4 generation)...");
    
    // Note: process_media uses TempDir internally, which gets cleaned up when it returns.
    // We need to check the files while they still exist, or copy them to a persistent location.
    // For now, we'll verify the ProcessingResult contains the expected data.
    
    let result = processor
        .process_media(
            &media_id,
            test_video_path.to_str().unwrap(),
            "video/mp4",
        )
        .await
        .expect("Media processing should succeed");
    
    println!("✅ Media processing completed");
    println!("   Generated {} MP4 files", result.mp4_files.len());
    println!("   Generated {} resolutions", result.resolutions.len());
    println!("   Output directory: {:?}", result.output_dir);
    
    // Verify MP4 files were created (check the result, not file system since TempDir is cleaned up)
    assert!(!result.mp4_files.is_empty(), "Should generate at least one MP4 file");
    
    println!("\n📹 MP4 Files in ProcessingResult:");
    for mp4_file in &result.mp4_files {
        let filename = mp4_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        println!("   {}", filename);
        
        // Verify filename format
        assert!(
            filename.ends_with(".mp4"),
            "MP4 file should have .mp4 extension: {}",
            filename
        );
        
        // Verify resolution is in filename
        let has_resolution = result.resolutions.iter().any(|r| filename.starts_with(r));
        assert!(
            has_resolution,
            "MP4 filename should start with a resolution: {}",
            filename
        );
    }
    
    // Since TempDir is cleaned up, we can't check file existence.
    // Instead, we'll verify the processing completed successfully by checking:
    // 1. MP4 files are listed in result
    // 2. Resolutions match expected
    // 3. File count matches resolution count
    
    assert_eq!(
        result.mp4_files.len(),
        result.resolutions.len(),
        "Should generate one MP4 file per resolution"
    );
    
    // Verify each resolution has a corresponding MP4 file
    for resolution in &result.resolutions {
        let expected_filename = format!("{}.mp4", resolution);
        let mp4_exists = result.mp4_files.iter().any(|f| {
            f.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == expected_filename)
                .unwrap_or(false)
        });
        assert!(
            mp4_exists,
            "Should have MP4 file for resolution: {}",
            resolution
        );
    }
    
    // Print summary
    println!("\n📊 Resolution Summary:");
    for resolution in &result.resolutions {
        let expected_filename = format!("{}.mp4", resolution);
        let mp4_exists = result.mp4_files.iter().any(|f| {
            f.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == expected_filename)
                .unwrap_or(false)
        });
        
        if mp4_exists {
            println!("   ✓ {} - MP4 generated", resolution);
        } else {
            println!("   ⚠️  {} - MP4 not found", resolution);
        }
    }
    
    println!("\n✅ MP4 generation test completed successfully!");
    println!("   Total MP4 files: {}", result.mp4_files.len());
    println!("   Total resolutions: {}", result.resolutions.len());
    println!("   Note: Files were created in TempDir (now cleaned up)");
    println!("   In production, files would be uploaded to object storage before cleanup");
}

/// Test MP4 generation error handling
#[tokio::test]
async fn test_mp4_generation_error_handling() {
    let processor = MediaProcessor::new();
    let media_id = Uuid::new_v4();
    
    // Test with non-existent input file
    let result = processor
        .process_media(
            &media_id,
            "/nonexistent/path/to/video.mp4",
            "video/mp4",
        )
        .await;
    
    // Should return an error for non-existent file
    assert!(result.is_err(), "Should return error for non-existent file");
}

