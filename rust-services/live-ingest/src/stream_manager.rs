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

use crate::error::{LiveIngestError, Result};
use crate::recorder::StreamRecorder;
use armoricore_types::events::{Event, EventType};
use message_bus_client::{MessageBusClient, NatsClient};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ActiveStream {
    pub stream_id: String,
    pub user_id: String,
    pub stream_key: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ingest_protocol: String, // rtmp, srt, webrtc
}

pub struct StreamManager {
    active_streams: Arc<RwLock<HashMap<String, ActiveStream>>>,
    recorders: Arc<RwLock<HashMap<String, Arc<StreamRecorder>>>>,
    message_bus: Arc<dyn MessageBusClient>,
    recordings_base_dir: PathBuf,
}

impl StreamManager {
    pub async fn new(message_bus_url: &str, recordings_base_dir: Option<PathBuf>) -> Result<Self> {
        let message_bus = Arc::new(
            NatsClient::new(message_bus_url, None)
                .await
                .map_err(|e| LiveIngestError::StreamManager(format!("Failed to connect to message bus: {}", e)))?,
        );

        let recordings_dir = recordings_base_dir.unwrap_or_else(|| PathBuf::from("/tmp/recordings"));

        Ok(Self {
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            recorders: Arc::new(RwLock::new(HashMap::new())),
            message_bus,
            recordings_base_dir: recordings_dir,
        })
    }

    /// Register a new active stream
    pub async fn register_stream(
        &self,
        stream_key: String,
        user_id: String,
        ingest_protocol: String,
    ) -> Result<String> {
        let stream_id = Uuid::new_v4().to_string();

        let stream = ActiveStream {
            stream_id: stream_id.clone(),
            user_id,
            stream_key: stream_key.clone(),
            started_at: chrono::Utc::now(),
            ingest_protocol,
        };

        {
            let mut streams = self.active_streams.write().await;
            streams.insert(stream_key.clone(), stream.clone());
        }

        info!(
            stream_id = stream_id,
            stream_key = stream_key,
            user_id = stream.user_id,
            protocol = stream.ingest_protocol,
            "Stream registered"
        );

        // Publish stream.started event
        self.publish_stream_event("stream.started", &stream_id, &stream.user_id)
            .await?;

        // Start recording if enabled (check from database via API or config)
        // For now, we'll start recording for all streams
        // In production, this would check the stream's is_recording_enabled flag
        self.start_recording_if_enabled(&stream_id, &stream.user_id).await?;

        Ok(stream_id)
    }

    /// Unregister a stream
    pub async fn unregister_stream(&self, stream_key: &str) -> Result<()> {
        let stream = {
            let mut streams = self.active_streams.write().await;
            streams.remove(stream_key)
        };

        if let Some(stream) = stream {
            info!(
                stream_id = stream.stream_id,
                stream_key = stream_key,
                "Stream unregistered"
            );

            // Stop recording if active
            self.stop_recording(&stream.stream_id).await?;

            // Publish stream.ended event
            self.publish_stream_event("stream.ended", &stream.stream_id, &stream.user_id)
                .await?;
        } else {
            warn!(stream_key = stream_key, "Attempted to unregister non-existent stream");
        }

        Ok(())
    }

    /// Get active stream by stream key
    pub async fn get_stream(&self, stream_key: &str) -> Option<ActiveStream> {
        let streams = self.active_streams.read().await;
        streams.get(stream_key).cloned()
    }

    /// List all active streams
    pub async fn list_active_streams(&self) -> Vec<ActiveStream> {
        let streams = self.active_streams.read().await;
        streams.values().cloned().collect()
    }

    /// Publish a stream event to the message bus
    async fn publish_stream_event(
        &self,
        event_type: &str,
        stream_id: &str,
        user_id: &str,
    ) -> Result<()> {
        let event_type_enum = match event_type {
            "stream.started" => EventType::StreamStarted,
            "stream.ended" => EventType::StreamEnded,
            "stream.failed" => EventType::StreamFailed,
            _ => return Err(LiveIngestError::StreamManager(format!("Invalid event type: {}", event_type))),
        };

        let event = Event::new(
            event_type_enum,
            "live-ingest",
            serde_json::json!({
                "stream_id": stream_id,
                "user_id": user_id,
            }),
        ).map_err(|e| LiveIngestError::StreamManager(format!("Failed to create event: {}", e)))?;

        self.message_bus
            .publish(&event)
            .await
            .map_err(|e| LiveIngestError::StreamManager(format!("Failed to publish event: {}", e)))?;

        info!(
            event_type = event_type,
            stream_id = stream_id,
            "Stream event published"
        );

        Ok(())
    }

    /// Start recording for a stream if enabled
    async fn start_recording_if_enabled(&self, stream_id: &str, _user_id: &str) -> Result<()> {
        // TODO: Check if recording is enabled for this stream via API
        // For now, we'll start recording for all streams
        // In production, this would query the database via HTTP API

        let recording_id = Uuid::new_v4().to_string();
        let segments_dir = self.recordings_base_dir.join(stream_id);
        let storage_path = format!("recordings/{}", stream_id);

        let recorder = Arc::new(StreamRecorder::new(
            stream_id.to_string(),
            recording_id.clone(),
            segments_dir,
            storage_path,
            Arc::clone(&self.message_bus),
        ));

        recorder.start_recording().await
            .map_err(|e| LiveIngestError::StreamManager(format!("Failed to start recording: {}", e)))?;

        {
            let mut recorders = self.recorders.write().await;
            recorders.insert(stream_id.to_string(), recorder);
        }

        info!(
            stream_id = stream_id,
            recording_id = recording_id,
            "Recording started for stream"
        );

        Ok(())
    }

    /// Stop recording for a stream
    async fn stop_recording(&self, stream_id: &str) -> Result<()> {
        let recorder = {
            let mut recorders = self.recorders.write().await;
            recorders.remove(stream_id)
        };

        if let Some(recorder) = recorder {
            match recorder.stop_recording().await {
                Ok(result) => {
                    info!(
                        stream_id = stream_id,
                        recording_id = result.recording_id,
                        total_segments = result.total_segments,
                        total_size_bytes = result.total_size_bytes,
                        "Recording stopped and VOD conversion triggered"
                    );
                }
                Err(e) => {
                    error!(
                        stream_id = stream_id,
                        error = %e,
                        "Failed to stop recording"
                    );
                }
            }
        }

        Ok(())
    }

    /// Record a segment (called when a new segment is generated)
    pub async fn record_segment(
        &self,
        stream_id: &str,
        segment_path: &PathBuf,
        quality: &str,
        segment_number: u64,
    ) -> Result<()> {
        let recorder = {
            let recorders = self.recorders.read().await;
            recorders.get(stream_id).cloned()
        };

        if let Some(recorder) = recorder {
            recorder.record_segment(segment_path, quality, segment_number).await
                .map_err(|e| LiveIngestError::StreamManager(format!("Failed to record segment: {}", e)))?;
        }

        Ok(())
    }
}

