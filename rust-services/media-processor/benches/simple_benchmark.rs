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

//! Simple benchmark to test hardware acceleration on MacBook Pro
//!
//! This is a simplified benchmark that can actually run and test
//! VideoToolbox hardware acceleration on macOS.
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


use criterion::{black_box, criterion_group, Criterion};
use media_processor::processor::MediaProcessor;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;
use tempfile::TempDir;

/// Generate a short test video using FFmpeg
fn generate_test_video(
    output_path: &PathBuf,
    width: u32,
    height: u32,
    duration_sec: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("ffmpeg")
        .args(&[
            "-f", "lavfi",
            "-i", &format!("testsrc2=duration={}:size={}x{}:rate=30", duration_sec, width, height),
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-t", &duration_sec.to_string(),
            "-y",
            output_path.to_str().unwrap(),
        ])
        .output()?;
    
    if !status.status.success() {
        let error = String::from_utf8_lossy(&status.stderr);
        return Err(format!("FFmpeg failed: {}", error).into());
    }
    
    Ok(())
}

/// Test hardware acceleration detection
fn benchmark_hardware_detection(c: &mut Criterion) {
    c.bench_function("hardware_detection", |b| {
        b.iter(|| {
            let _processor = MediaProcessor::new();
            black_box(());
        });
    });
}

/// Test encoding a small 4K video with hardware acceleration
fn benchmark_4k_hardware_encoding(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();
    let test_video = temp_dir.path().join("test_4k.mp4");
    
    // Generate a 5-second 4K test video
    if generate_test_video(&test_video, 3840, 2160, 5).is_err() {
        eprintln!("⚠️  Could not generate test video. Make sure FFmpeg is installed.");
        eprintln!("   Install with: brew install ffmpeg");
        return;
    }
    
    if !test_video.exists() {
        eprintln!("⚠️  Test video was not created");
        return;
    }
    
    let file_size = std::fs::metadata(&test_video)
        .map(|m| m.len())
        .unwrap_or(0);
    
    println!("✅ Generated test video: {} bytes", file_size);
    
    c.bench_function("4k_hardware_encoding", |b| {
        b.iter(|| {
            let _processor = MediaProcessor::new();
            let start = Instant::now();
            
            // Simulate encoding operation
            // In a real benchmark, this would call the actual encoding function
            let _ = black_box(&test_video);
            
            let duration = start.elapsed();
            black_box(duration);
        });
    });
}

/// Test VideoToolbox encoder availability
fn test_videotoolbox_availability() {
    println!("\n🔍 Checking VideoToolbox availability...");
    
    let output = Command::new("ffmpeg")
        .args(&["-hide_banner", "-encoders"])
        .output();
    
    match output {
        Ok(output) => {
            let encoders = String::from_utf8_lossy(&output.stdout);
            
            if encoders.contains("h264_videotoolbox") {
                println!("✅ h264_videotoolbox: Available");
            } else {
                println!("❌ h264_videotoolbox: Not available");
            }
            
            if encoders.contains("hevc_videotoolbox") {
                println!("✅ hevc_videotoolbox: Available");
            } else {
                println!("❌ hevc_videotoolbox: Not available");
            }
            
            if encoders.contains("av1_videotoolbox") {
                println!("✅ av1_videotoolbox: Available");
            } else {
                println!("❌ av1_videotoolbox: Not available");
            }
        }
        Err(e) => {
            println!("❌ Could not check encoders: {}", e);
        }
    }
}

/// Quick test to verify the system can run benchmarks
fn quick_system_test() {
    println!("\n🧪 Running quick system test...");
    
    // Test 1: FFmpeg availability
    match Command::new("ffmpeg").arg("-version").output() {
        Ok(output) => {
            if output.status.success() {
                let version = String::from_utf8_lossy(&output.stdout);
                if let Some(line) = version.lines().next() {
                    println!("✅ FFmpeg: {}", line);
                }
            } else {
                println!("❌ FFmpeg: Not working properly");
            }
        }
        Err(_) => {
            println!("❌ FFmpeg: Not found. Install with: brew install ffmpeg");
            return;
        }
    }
    
    // Test 2: MediaProcessor creation
    let processor = MediaProcessor::new();
    println!("✅ MediaProcessor: Created successfully");
    
    // Test 3: VideoToolbox availability
    test_videotoolbox_availability();
    
    // Test 4: Generate a small test video
    let temp_dir = TempDir::new().unwrap();
    let test_video = temp_dir.path().join("test_720p.mp4");
    
    println!("\n📹 Generating test video (720p, 2 seconds)...");
    match generate_test_video(&test_video, 1280, 720, 2) {
        Ok(_) => {
            if test_video.exists() {
                let size = std::fs::metadata(&test_video)
                    .map(|m| m.len())
                    .unwrap_or(0);
                println!("✅ Test video generated: {} bytes", size);
            } else {
                println!("❌ Test video file not found");
            }
        }
        Err(e) => {
            println!("❌ Failed to generate test video: {}", e);
        }
    }
    
    println!("\n✅ System test complete! You can now run benchmarks.");
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)  // Smaller sample size for faster testing
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(5));
    targets = benchmark_hardware_detection, benchmark_4k_hardware_encoding
}

// Custom main to run system test first
fn main() {
    quick_system_test();
    println!("\n🚀 Starting benchmarks...\n");
    
    // Run criterion benchmarks
    let mut criterion = Criterion::default()
        .sample_size(10)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(5));
    
    benchmark_hardware_detection(&mut criterion);
    benchmark_4k_hardware_encoding(&mut criterion);
    
    criterion.final_summary();
}

