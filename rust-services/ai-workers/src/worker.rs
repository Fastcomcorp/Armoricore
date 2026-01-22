//! AI Worker - Processes AI-related events
// Copyright 2026 Francisco F. Pinochet, Fastcomcorp
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


use ai_connectors::AIServiceManager;
use armoricore_types::events::{Event, EventType};
use message_bus_client::traits::MessageBusClient;
use futures::StreamExt;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// AI Worker for processing AI-related events
pub struct AIWorker {
    message_bus: Arc<dyn MessageBusClient>,
    ai_manager: AIServiceManager,
}

impl AIWorker {
    /// Create a new AI Worker
    pub fn new(
        message_bus: Arc<dyn MessageBusClient>,
        ai_manager: AIServiceManager,
    ) -> Self {
        Self {
            message_bus,
            ai_manager,
        }
    }

    /// Start the AI worker
    pub async fn start(&self) -> anyhow::Result<()> {
        info!("Starting AI Worker");

        // Subscribe to AI-related events
        let mut transcription_stream = self.message_bus.subscribe("transcription.requested");
        let mut captioning_stream = self.message_bus.subscribe("captioning.requested");
        let mut moderation_stream = self.message_bus.subscribe("moderation.requested");
        let mut translation_stream = self.message_bus.subscribe("translation.requested");

        info!("AI Worker subscribed to events");

        // Process events from all streams
        loop {
            tokio::select! {
                Some(result) = transcription_stream.next() => {
                    match result {
                        Ok(event) => {
                            if let Err(e) = self.process_event(&event).await {
                                error!(error = %e, event_id = %event.event_id, "Failed to process transcription event");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving transcription event");
                        }
                    }
                }
                Some(result) = captioning_stream.next() => {
                    match result {
                        Ok(event) => {
                            if let Err(e) = self.process_event(&event).await {
                                error!(error = %e, event_id = %event.event_id, "Failed to process captioning event");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving captioning event");
                        }
                    }
                }
                Some(result) = moderation_stream.next() => {
                    match result {
                        Ok(event) => {
                            if let Err(e) = self.process_event(&event).await {
                                error!(error = %e, event_id = %event.event_id, "Failed to process moderation event");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving moderation event");
                        }
                    }
                }
                Some(result) = translation_stream.next() => {
                    match result {
                        Ok(event) => {
                            if let Err(e) = self.process_event(&event).await {
                                error!(error = %e, event_id = %event.event_id, "Failed to process translation event");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving translation event");
                        }
                    }
                }
            }
        }
    }

    /// Process an AI-related event
    async fn process_event(&self, event: &Event) -> anyhow::Result<()> {
        info!(event_id = %event.event_id, event_type = ?event.event_type, "Processing AI event");

        match event.event_type {
            EventType::TranscriptionRequested => {
                self.handle_transcription_request(event).await?;
            }
            EventType::CaptioningRequested => {
                self.handle_captioning_request(event).await?;
            }
            EventType::ModerationRequested => {
                self.handle_moderation_request(event).await?;
            }
            EventType::TranslationRequested => {
                self.handle_translation_request(event).await?;
            }
            _ => {
                warn!(event_type = ?event.event_type, "Unhandled event type");
            }
        }

        Ok(())
    }

    /// Handle transcription request
    async fn handle_transcription_request(&self, event: &Event) -> anyhow::Result<()> {
        info!(event_id = %event.event_id, "Handling transcription request");

        // Extract media ID and file path from event
        let media_id = event.payload.get("media_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid media_id"))?;

        let file_path = event.payload.get("file_path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing file_path"))?;

        let language = event.payload.get("language")
            .and_then(|v| v.as_str());

        // Download file if it's a URL
        let local_file_path = if file_path.starts_with("http://") || file_path.starts_with("https://") {
            // Download from URL
            let temp_dir = std::env::temp_dir();
            let temp_file = temp_dir.join(format!("audio_{}.mp3", media_id));
            
            info!(url = file_path, "Downloading audio file from URL");
            
            // SECURITY: Use HTTP client with timeout to prevent resource exhaustion
            // Default timeout: 60 seconds for file downloads (configurable via AI_DOWNLOAD_TIMEOUT_SECONDS)
            let timeout_seconds = std::env::var("AI_DOWNLOAD_TIMEOUT_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(60);
            
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_seconds))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;
            
            let response = client.get(file_path).send().await?;
            let bytes = response.bytes().await?;
            tokio::fs::write(&temp_file, &bytes).await?;
            
            temp_file.to_string_lossy().to_string()
        } else if file_path.starts_with("s3://") {
            // TODO: Download from S3 (would need S3 client)
            return Err(anyhow::anyhow!("S3 download not yet implemented"));
        } else {
            // Local file path
            file_path.to_string()
        };

        // Extract audio if it's a video file
        let (audio_file_path, needs_cleanup_local) = if local_file_path.ends_with(".mp4") || 
                               local_file_path.ends_with(".mov") || 
                               local_file_path.ends_with(".avi") {
            // Extract audio using FFmpeg
            let temp_dir = std::env::temp_dir();
            let audio_file = temp_dir.join(format!("audio_{}.mp3", media_id));
            
            info!(video_file = local_file_path, "Extracting audio from video");
            
            let output = tokio::process::Command::new("ffmpeg")
                .arg("-i")
                .arg(&local_file_path)
                .arg("-vn")  // No video
                .arg("-acodec")
                .arg("libmp3lame")
                .arg("-y")  // Overwrite output file
                .arg(&audio_file)
                .output()
                .await?;

            if !output.status.success() {
                let error = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow::anyhow!("FFmpeg failed: {}", error));
            }

            (audio_file.to_string_lossy().to_string(), true)
        } else {
            (local_file_path.clone(), false)
        };

        // Read audio file
        let audio_data = tokio::fs::read(&audio_file_path).await?;

        // Call AI connector to transcribe
        info!(audio_size = audio_data.len(), "Calling transcription API");
        let transcription_result = self.ai_manager.transcribe(&audio_data, language).await?;

        // Clean up temporary files
        if needs_cleanup_local {
            let _ = tokio::fs::remove_file(&audio_file_path).await;
        }
        if local_file_path != file_path && (local_file_path.starts_with("http://") || local_file_path.starts_with("https://")) {
            let _ = tokio::fs::remove_file(&local_file_path).await;
        }

        // Publish transcription complete event
        let segments_json: Option<Vec<serde_json::Value>> = transcription_result.segments.as_ref().map(|segs| {
            segs.iter().map(|seg| {
                serde_json::json!({
                    "start": seg.start,
                    "end": seg.end,
                    "text": seg.text,
                })
            }).collect()
        });

        let result_event = Event {
            event_id: Uuid::new_v4(),
            event_type: armoricore_types::events::EventType::TranscriptionComplete,
            source: "ai-workers".to_string(),
            payload: serde_json::json!({
                "media_id": media_id,
                "transcription": transcription_result.text,
                "language": transcription_result.language.unwrap_or_else(|| "unknown".to_string()),
                "segments": segments_json,
            }),
            timestamp: chrono::Utc::now(),
        };

        self.message_bus
            .publish(&result_event)
            .await?;

        info!(
            event_id = %event.event_id,
            transcription_length = transcription_result.text.len(),
            "Transcription completed"
        );
        Ok(())
    }

    /// Handle captioning request
    async fn handle_captioning_request(&self, event: &Event) -> anyhow::Result<()> {
        info!(event_id = %event.event_id, "Handling captioning request");

        // Extract transcription from event
        let _transcription_text = event.payload.get("transcription")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing transcription"))?;

        let language = event.payload.get("language")
            .and_then(|v| v.as_str())
            .unwrap_or("en");

        // TODO: Call AI connector to generate captions
        warn!("Captioning not fully implemented - placeholder");

        // Publish placeholder event
        let media_id = event.payload.get("media_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| anyhow::anyhow!("Missing or invalid media_id"))?;

        let result_event = Event {
            event_id: Uuid::new_v4(),
            event_type: armoricore_types::events::EventType::CaptioningComplete,
            source: "ai-workers".to_string(),
            payload: serde_json::json!({
                "media_id": media_id,
                "captions": [],
                "language": language,
            }),
            timestamp: chrono::Utc::now(),
        };

        self.message_bus
            .publish(&result_event)
            .await?;

        info!(event_id = %event.event_id, "Captioning request processed (placeholder)");
        Ok(())
    }

    /// Handle moderation request
    async fn handle_moderation_request(&self, event: &Event) -> anyhow::Result<()> {
        info!(event_id = %event.event_id, "Handling moderation request");

        let content = event.payload.get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing content"))?;

        let content_type = event.payload.get("content_type")
            .and_then(|v| v.as_str())
            .unwrap_or("text");

        // Call AI connector to moderate
        match self.ai_manager.moderate(content, content_type).await {
            Ok(result) => {
                let result_event = Event {
                    event_id: Uuid::new_v4(),
                    event_type: armoricore_types::events::EventType::ModerationComplete,
                    source: "ai-workers".to_string(),
                    payload: serde_json::json!({
                        "flagged": result.flagged,
                        "categories": result.categories,
                        "severity": result.severity,
                    }),
                    timestamp: chrono::Utc::now(),
                };

                self.message_bus
                    .publish(&result_event)
                    .await?;

                info!(event_id = %event.event_id, flagged = result.flagged, "Moderation completed");
            }
            Err(e) => {
                error!(error = %e, event_id = %event.event_id, "Moderation failed");
                // Publish error event
                let error_event = Event {
                    event_id: Uuid::new_v4(),
                    event_type: armoricore_types::events::EventType::ModerationFailed,
                    source: "ai-workers".to_string(),
                    payload: serde_json::json!({
                        "error": e.to_string(),
                    }),
                    timestamp: chrono::Utc::now(),
                };

                self.message_bus
                    .publish(&error_event)
                    .await?;
            }
        }

        Ok(())
    }

    /// Handle translation request
    async fn handle_translation_request(&self, event: &Event) -> anyhow::Result<()> {
        info!(event_id = %event.event_id, "Handling translation request");

        let text = event.payload.get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing text"))?;

        let to_language = event.payload.get("to_language")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing to_language"))?;

        let from_language = event.payload.get("from_language")
            .and_then(|v| v.as_str());

        // Call AI connector to translate
        match self.ai_manager.translate(text, from_language, to_language).await {
            Ok(translated_text) => {
                let result_event = Event {
                    event_id: Uuid::new_v4(),
                    event_type: armoricore_types::events::EventType::TranslationComplete,
                    source: "ai-workers".to_string(),
                    payload: serde_json::json!({
                        "original_text": text,
                        "translated_text": translated_text,
                        "from_language": from_language.unwrap_or("auto"),
                        "to_language": to_language,
                    }),
                    timestamp: chrono::Utc::now(),
                };

                self.message_bus
                    .publish(&result_event)
                    .await?;

                info!(
                    event_id = %event.event_id,
                    to_language = to_language,
                    "Translation completed"
                );
            }
            Err(e) => {
                error!(error = %e, event_id = %event.event_id, "Translation failed");
                // Publish error event
                let error_event = Event {
                    event_id: Uuid::new_v4(),
                    event_type: armoricore_types::events::EventType::TranslationFailed,
                    source: "ai-workers".to_string(),
                    payload: serde_json::json!({
                        "error": e.to_string(),
                        "text": text,
                        "to_language": to_language,
                    }),
                    timestamp: chrono::Utc::now(),
                };

                self.message_bus
                    .publish(&error_event)
                    .await?;
            }
        }

        Ok(())
    }
}

