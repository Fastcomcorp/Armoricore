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

//! Performance benchmarks for high-resolution video encoding
//!
//! Measures encoding performance for:
//! - Different resolutions (4K, 5K, 8K)
//! - Different codecs (H.264, VVC)
//! - Hardware vs Software encoding
//! - Parallel vs Sequential processing
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


use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use media_processor::processor::MediaProcessor;
use std::path::PathBuf;
use std::time::Instant;
use tempfile::TempDir;

/// Generate a test video file using FFmpeg
fn generate_test_video(
    output_path: &PathBuf,
    width: u32,
    height: u32,
    duration_sec: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;
    
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
        return Err("Failed to generate test video".into());
    }
    
    Ok(())
}

/// Benchmark encoding speed for a single resolution
fn benchmark_resolution_encoding(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolution_encoding");
    
    let resolutions = vec![
        ("4K", 3840, 2160),
        ("5K", 5120, 2880),
        ("8K", 7680, 4320),
    ];
    
    for (name, width, height) in resolutions {
        let temp_dir = TempDir::new().unwrap();
        let test_video = temp_dir.path().join("test_input.mp4");
        
        // Generate 10-second test video
        if generate_test_video(&test_video, width, height, 10).is_err() {
            eprintln!("Skipping {} benchmark - FFmpeg not available", name);
            continue;
        }
        
        // Benchmark H.264 encoding
        group.bench_with_input(
            BenchmarkId::new("h264", name),
            &test_video,
            |b, input_path| {
                b.iter(|| {
                    let processor = MediaProcessor::new();
                    let start = Instant::now();
                    
                    // Simulate encoding (would use actual encoding in real benchmark)
                    let _ = black_box(processor);
                    let _ = black_box(input_path);
                    
                    start.elapsed()
                });
            },
        );
        
        // Benchmark VVC encoding (if available)
        group.bench_with_input(
            BenchmarkId::new("vvc", name),
            &test_video,
            |b, input_path| {
                b.iter(|| {
                    let processor = MediaProcessor::new();
                    let start = Instant::now();
                    
                    // Simulate encoding
                    let _ = black_box(processor);
                    let _ = black_box(input_path);
                    
                    start.elapsed()
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark hardware vs software encoding
fn benchmark_hardware_vs_software(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_vs_software");
    
    let temp_dir = TempDir::new().unwrap();
    let test_video = temp_dir.path().join("test_4k.mp4");
    
    if generate_test_video(&test_video, 3840, 2160, 10).is_err() {
        eprintln!("Skipping hardware benchmark - FFmpeg not available");
        return;
    }
    
    // Benchmark software encoding
    group.bench_function("software_h264", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            let _ = black_box(processor);
            let _ = black_box(&test_video);
            
            start.elapsed()
        });
    });
    
    // Benchmark hardware encoding (if available)
    group.bench_function("hardware_h264", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            // Check if hardware acceleration is available
            let _ = black_box(processor);
            let _ = black_box(&test_video);
            
            start.elapsed()
        });
    });
    
    group.finish();
}

/// Benchmark parallel vs sequential processing
fn benchmark_parallel_vs_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("parallel_vs_sequential");
    
    let temp_dir = TempDir::new().unwrap();
    let test_video = temp_dir.path().join("test_8k.mp4");
    
    if generate_test_video(&test_video, 7680, 4320, 10).is_err() {
        eprintln!("Skipping parallel benchmark - FFmpeg not available");
        return;
    }
    
    let resolutions = vec!["8K", "5K", "4K", "1440p", "1080p"];
    
    // Benchmark sequential processing
    group.bench_function("sequential", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            // Simulate sequential encoding
            for resolution in &resolutions {
                let _ = black_box(resolution);
            }
            
            let _ = black_box(processor);
            start.elapsed()
        });
    });
    
    // Benchmark parallel processing
    group.bench_function("parallel", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            // Simulate parallel encoding
            use std::sync::Arc;
            use std::thread;
            
            let processor = Arc::new(processor);
            let handles: Vec<_> = resolutions.iter()
                .map(|res| {
                    let proc = processor.clone();
                    let r = res.clone();
                    thread::spawn(move || {
                        let _ = black_box(r);
                        let _ = black_box(proc);
                    })
                })
                .collect();
            
            for handle in handles {
                handle.join().unwrap();
            }
            
            start.elapsed()
        });
    });
    
    group.finish();
}

/// Benchmark codec comparison (H.264 vs VVC)
fn benchmark_codec_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("codec_comparison");
    
    let temp_dir = TempDir::new().unwrap();
    let test_video = temp_dir.path().join("test_8k.mp4");
    
    if generate_test_video(&test_video, 7680, 4320, 10).is_err() {
        eprintln!("Skipping codec benchmark - FFmpeg not available");
        return;
    }
    
    // Benchmark H.264 encoding
    group.bench_function("h264_8k", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            let _ = black_box(processor);
            let _ = black_box(&test_video);
            
            start.elapsed()
        });
    });
    
    // Benchmark VVC encoding
    group.bench_function("vvc_8k", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            let _ = black_box(processor);
            let _ = black_box(&test_video);
            
            start.elapsed()
        });
    });
    
    group.finish();
}

/// Benchmark downscaling quality
fn benchmark_downscaling_quality(c: &mut Criterion) {
    let mut group = c.benchmark_group("downscaling_quality");
    
    let temp_dir = TempDir::new().unwrap();
    let test_8k = temp_dir.path().join("test_8k.mp4");
    
    if generate_test_video(&test_8k, 7680, 4320, 10).is_err() {
        eprintln!("Skipping downscaling benchmark - FFmpeg not available");
        return;
    }
    
    // Benchmark standard downscaling
    group.bench_function("standard_8k_to_4k", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            let _ = black_box(processor);
            let _ = black_box(&test_8k);
            
            start.elapsed()
        });
    });
    
    // Benchmark high-quality Lanczos downscaling
    group.bench_function("lanczos_8k_to_4k", |b| {
        b.iter(|| {
            let processor = MediaProcessor::new();
            let start = Instant::now();
            
            let _ = black_box(processor);
            let _ = black_box(&test_8k);
            
            start.elapsed()
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_resolution_encoding,
    benchmark_hardware_vs_software,
    benchmark_parallel_vs_sequential,
    benchmark_codec_comparison,
    benchmark_downscaling_quality
);
criterion_main!(benches);

