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

//! Live transcoding worker
//!
//! Consumes stream.started events and starts live transcoding

use crate::cdn_uploader::CdnUploader;
use crate::live_transcoder::{default_quality_profiles, LiveTranscoder, LiveTranscoderConfig};
use crate::processor::{AudioCodec, VideoCodec};
use anyhow::Context;
use armoricore_config::ObjectStorageConfig;
use armoricore_types::{Event, EventType};
use message_bus_client::traits::MessageBusClient;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

/// Live transcoding worker
pub struct LiveTranscoderWorker {
    message_bus: Arc<dyn MessageBusClient>,
    active_transcoders: Arc<RwLock<HashMap<String, Arc<LiveTranscoder>>>>,
    output_base_dir: PathBuf,
    cdn_uploader: Option<Arc<CdnUploader>>,
}

impl LiveTranscoderWorker {
    /// Create a new live transcoder worker
    pub fn new(
        message_bus: Arc<dyn MessageBusClient>,
        output_base_dir: PathBuf,
        storage_config: Option<ObjectStorageConfig>,
    ) -> Self {
        let cdn_uploader = storage_config.map(|config| Arc::new(CdnUploader::new(config)));

        Self {
            message_bus,
            active_transcoders: Arc::new(RwLock::new(HashMap::new())),
            output_base_dir,
            cdn_uploader,
        }
    }

    /// Run the worker - consume stream events and start/stop transcoding
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("Subscribing to stream events");

        // Subscribe to stream.started and stream.ended events
        let mut started_stream = self.message_bus.subscribe("stream.started");
        let mut ended_stream = self.message_bus.subscribe("stream.ended");

        info!("Waiting for stream events...");

        loop {
            tokio::select! {
                Some(event_result) = started_stream.next() => {
                    match event_result {
                        Ok(event) => {
                            if let Err(e) = self.handle_stream_started(&event).await {
                                error!(
                                    event_id = %event.event_id,
                                    error = %e,
                                    "Failed to handle stream.started event"
                                );
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving stream.started event");
                        }
                    }
                }
                Some(event_result) = ended_stream.next() => {
                    match event_result {
                        Ok(event) => {
                            if let Err(e) = self.handle_stream_ended(&event).await {
                                error!(
                                    event_id = %event.event_id,
                                    error = %e,
                                    "Failed to handle stream.ended event"
                                );
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Error receiving stream.ended event");
                        }
                    }
                }
            }
        }
    }

    /// Handle stream.started event
    async fn handle_stream_started(&self, event: &Event) -> anyhow::Result<()> {
        if event.event_type != EventType::StreamStarted {
            return Ok(());
        }

        let payload: serde_json::Value = event.payload.clone();
        let stream_id = payload["stream_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing stream_id in payload"))?
            .to_string();
        let user_id = payload["user_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing user_id in payload"))?
            .to_string();

        info!(
            stream_id = stream_id,
            user_id = user_id,
            "Received stream.started event"
        );

        // Get RTMP URL from payload or construct it
        // In a real implementation, this would come from the database or event payload
        let rtmp_url = format!("rtmp://localhost:1935/live/{}", stream_id);

        // Create output directory for this stream
        let output_dir = self.output_base_dir.join(&stream_id);
        std::fs::create_dir_all(&output_dir)
            .context("Failed to create output directory")?;

        // Create transcoder configuration
        let enable_cdn_upload = self.cdn_uploader.is_some();
        let config = LiveTranscoderConfig {
            stream_id: stream_id.clone(),
            user_id,
            output_dir: output_dir.clone(),
            quality_profiles: default_quality_profiles(),
            video_codec: VideoCodec::H264, // Default to H264 for compatibility
            audio_codec: AudioCodec::Aac, // Default to AAC for compatibility
            segment_duration: 10, // 10 second segments
            low_latency: false, // Can be enabled per stream
            enable_arcrtp: true, // Enable ArcRTP quality indicators
            enable_cdn_upload,
            cdn_uploader: self.cdn_uploader.clone(),
        };

        // Create and start transcoder
        let transcoder = Arc::new(LiveTranscoder::new(config));
        transcoder
            .start_transcoding(&rtmp_url)
            .await
            .context("Failed to start transcoding")?;

        // Store active transcoder
        {
            let mut transcoders = self.active_transcoders.write().await;
            transcoders.insert(stream_id.clone(), transcoder);
        }

        info!(
            stream_id = stream_id,
            output_dir = ?output_dir,
            "Live transcoding started"
        );

        Ok(())
    }

    /// Handle stream.ended event
    async fn handle_stream_ended(&self, event: &Event) -> anyhow::Result<()> {
        if event.event_type != EventType::StreamEnded {
            return Ok(());
        }

        let payload: serde_json::Value = event.payload.clone();
        let stream_id = payload["stream_id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing stream_id in payload"))?
            .to_string();

        info!(
            stream_id = stream_id,
            "Received stream.ended event"
        );

        // Stop transcoding
        let transcoder = {
            let mut transcoders = self.active_transcoders.write().await;
            transcoders.remove(&stream_id)
        };

        if let Some(transcoder) = transcoder {
            if let Err(e) = transcoder.stop_transcoding().await {
                error!(
                    stream_id = stream_id,
                    error = %e,
                    "Failed to stop transcoding"
                );
            } else {
                info!(
                    stream_id = stream_id,
                    "Live transcoding stopped"
                );
            }
        } else {
            warn!(
                stream_id = stream_id,
                "No active transcoder found for stream"
            );
        }

        Ok(())
    }
}

