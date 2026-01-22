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

//! Media Worker - Event Processing
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


use crate::processor::MediaProcessor;
use crate::storage::ObjectStorage;
use armoricore_types::{
    schemas::{MediaReadyPayload, MediaUploadedPayload, PlaybackUrls},
    Event, EventType,
};
use message_bus_client::traits::MessageBusClient;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Media Worker that processes media upload events
pub struct MediaWorker {
    message_bus: Arc<dyn MessageBusClient>,
    processor: MediaProcessor,
    storage: ObjectStorage,
}

impl MediaWorker {
    /// Create a new media worker
    pub fn new(
        message_bus: Arc<dyn MessageBusClient>,
        storage_config: armoricore_config::ObjectStorageConfig,
    ) -> Self {
        let storage_config_clone = storage_config.clone();
        Self {
            message_bus,
            processor: MediaProcessor::with_storage_config(Some(storage_config_clone)),
            storage: ObjectStorage::new(storage_config),
        }
    }

    /// Run the worker - consume events and process them
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("Subscribing to media.uploaded events");

        let mut event_stream = self.message_bus.subscribe("media.uploaded");

        info!("Waiting for media upload events...");

        while let Some(event_result) = event_stream.next().await {
            match event_result {
                Ok(event) => {
                    info!(
                        event_id = %event.event_id,
                        event_type = ?event.event_type,
                        "Received media upload event"
                    );

                    if let Err(e) = self.process_media_upload(&event).await {
                        error!(
                            event_id = %event.event_id,
                            error = %e,
                            "Failed to process media upload"
                        );
                    }
                }
                Err(e) => {
                    error!(error = %e, "Error receiving event from message bus");
                    // Continue processing - don't crash on individual event errors
                }
            }
        }

        warn!("Event stream ended");
        Ok(())
    }

    /// Process a single media upload event
    async fn process_media_upload(&self, event: &Event) -> anyhow::Result<()> {
        // Deserialize the payload
        let payload: MediaUploadedPayload = event
            .payload_as()
            .map_err(|e| anyhow::anyhow!("Invalid payload: {}", e))?;

        info!(
            media_id = %payload.media_id,
            user_id = %payload.user_id,
            file_path = payload.file_path,
            content_type = payload.content_type,
            "Processing media upload"
        );

        // Process the media file
        match self
            .processor
            .process_media(
                &payload.media_id,
                &payload.file_path,
                &payload.content_type,
            )
            .await
        {
            Ok(processing_result) => {
                // Upload processed files to object storage
                let upload_result = self
                    .storage
                    .upload_processed_files(
                        &payload.media_id,
                        &processing_result,
                    )
                    .await;

                match upload_result {
                    Ok(playback_urls) => {
                        // Publish media.ready event
                        self.publish_media_ready(
                            payload.media_id,
                            playback_urls,
                            processing_result.thumbnail_urls,
                            processing_result.duration,
                            processing_result.resolutions,
                        )
                        .await?;

                        info!(
                            media_id = %payload.media_id,
                            "Media processing completed successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            media_id = %payload.media_id,
                            error = %e,
                            "Failed to upload processed files"
                        );
                        return Err(e);
                    }
                }
            }
            Err(e) => {
                error!(
                    media_id = %payload.media_id,
                    error = %e,
                    "Failed to process media"
                );
                return Err(e);
            }
        }

        Ok(())
    }

    /// Publish a media.ready event
    async fn publish_media_ready(
        &self,
        media_id: Uuid,
        playback_urls: PlaybackUrls,
        thumbnail_urls: Vec<String>,
        duration: u64,
        resolutions: Vec<String>,
    ) -> anyhow::Result<()> {
        let payload = MediaReadyPayload {
            media_id,
            playback_urls,
            thumbnail_urls,
            duration,
            resolutions,
        };

        let event = Event::new(EventType::MediaReady, "media-processor", payload)
            .map_err(|e| anyhow::anyhow!("Failed to create event: {}", e))?;

        self.message_bus
            .publish(&event)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish event: {}", e))?;

        Ok(())
    }
}

