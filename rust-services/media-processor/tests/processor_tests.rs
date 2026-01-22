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

//! Media Processor Unit Tests

use media_processor::processor::{AudioCodec, VideoCodec, MediaProcessor};
use uuid::Uuid;

#[tokio::test]
async fn test_audio_codec_variants() {
    // Test that all audio codec variants exist
    let _aac = AudioCodec::Aac;
    let _opus = AudioCodec::Opus;
    let _mp3 = AudioCodec::Mp3;
    let _vorbis = AudioCodec::Vorbis;
    let _flac = AudioCodec::Flac;
    
    // Verify they are different
    assert_ne!(AudioCodec::Aac, AudioCodec::Opus);
    assert_ne!(AudioCodec::Flac, AudioCodec::Mp3);
}

#[tokio::test]
async fn test_video_codec_variants() {
    // Test that all video codec variants exist
    let _h264 = VideoCodec::H264;
    let _vp9 = VideoCodec::VP9;
    let _av1 = VideoCodec::AV1;
    
    // Verify they are different
    assert_ne!(VideoCodec::H264, VideoCodec::VP9);
    assert_ne!(VideoCodec::VP9, VideoCodec::AV1);
    assert_ne!(VideoCodec::H264, VideoCodec::AV1);
}

#[tokio::test]
async fn test_media_processor_new() {
    let processor = MediaProcessor::new();
    // Should create without panicking
    let _ = processor;
}

#[tokio::test]
async fn test_media_processor_with_storage_config() {
    let processor = MediaProcessor::with_storage_config(None);
    // Should create without panicking
    let _ = processor;
}

#[tokio::test]
async fn test_unsupported_content_type() {
    let processor = MediaProcessor::new();
    let media_id = Uuid::new_v4();
    
    // Try to process a non-video/audio file
    let result = processor
        .process_media(&media_id, "/path/to/file.pdf", "application/pdf")
        .await;
    
    assert!(result.is_err());
    let error_message = result.err().unwrap().to_string();
    assert!(error_message.contains("Unsupported content type"));
}

#[tokio::test]
async fn test_audio_only_content_type() {
    let processor = MediaProcessor::new();
    let media_id = Uuid::new_v4();
    
    // Try to process an audio file (should be accepted, but will fail without FFmpeg/file)
    // This test just verifies the content type is accepted
    let result = processor
        .process_media(&media_id, "/path/to/file.flac", "audio/flac")
        .await;
    
    // Should not fail with "Unsupported content type" error
    // (will fail for other reasons like file not found, which is expected)
    if let Err(e) = result {
        let error_message = e.to_string();
        assert!(!error_message.contains("Unsupported content type"), 
            "Audio content type should be supported");
    }
}

