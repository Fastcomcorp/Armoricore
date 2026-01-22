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

//! Event type definitions for the message bus
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


use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schemas::*;
use crate::error::{ArmoricoreError, Result};

/// Event type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Media events
    #[serde(rename = "media.uploaded")]
    MediaUploaded,
    #[serde(rename = "media.ready")]
    MediaReady,
    
    
    // Transcription events
    #[serde(rename = "transcription.requested")]
    TranscriptionRequested,
    #[serde(rename = "transcription.complete")]
    TranscriptionComplete,
    #[serde(rename = "transcription.failed")]
    TranscriptionFailed,
    // Captioning events
    #[serde(rename = "captioning.requested")]
    CaptioningRequested,
    #[serde(rename = "captioning.complete")]
    CaptioningComplete,
    #[serde(rename = "captioning.failed")]
    CaptioningFailed,
    // Moderation events
    #[serde(rename = "moderation.requested")]
    ModerationRequested,
    #[serde(rename = "moderation.complete")]
    ModerationComplete,
    #[serde(rename = "moderation.failed")]
    ModerationFailed,
    // Translation events
    #[serde(rename = "translation.requested")]
    TranslationRequested,
    #[serde(rename = "translation.complete")]
    TranslationComplete,
    #[serde(rename = "translation.failed")]
    TranslationFailed,
    
    // Chat events
    #[serde(rename = "chat.message")]
    ChatMessage,
    
    // Presence events
    #[serde(rename = "presence.update")]
    PresenceUpdate,
    
    // Live streaming events
    #[serde(rename = "stream.started")]
    StreamStarted,
    #[serde(rename = "stream.ended")]
    StreamEnded,
    #[serde(rename = "stream.failed")]
    StreamFailed,
}

/// Base event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event type identifier
    pub event_type: EventType,
    
    /// Unique event identifier
    pub event_id: Uuid,
    
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    
    /// Source service that published the event
    pub source: String,
    
    /// Event payload (type depends on event_type)
    pub payload: serde_json::Value,
}

impl Event {
    /// Create a new event
    pub fn new(
        event_type: EventType,
        source: impl Into<String>,
        payload: impl Serialize,
    ) -> Result<Self> {
        let payload_value = serde_json::to_value(payload)?;
        
        Ok(Self {
            event_type,
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            source: source.into(),
            payload: payload_value,
        })
    }

    /// Deserialize the payload into a specific type
    pub fn payload_as<T: for<'de> Deserialize<'de>>(&self) -> Result<T> {
        serde_json::from_value(self.payload.clone())
            .map_err(|e| ArmoricoreError::InvalidPayload(e.to_string()))
    }

    /// Validate the event structure
    pub fn validate(&self) -> Result<()> {
        // Validate event type matches payload structure
        match self.event_type {
            EventType::MediaUploaded => {
                let _: MediaUploadedPayload = self.payload_as()?;
            }
            EventType::MediaReady => {
                let _: MediaReadyPayload = self.payload_as()?;
            }
            EventType::TranscriptionRequested => {
                let _: TranscriptionRequestedPayload = self.payload_as()?;
            }
            EventType::TranscriptionComplete => {
                let _: TranscriptionCompletePayload = self.payload_as()?;
            }
            EventType::TranscriptionFailed => {
                // No specific payload type for failed events
            }
            EventType::CaptioningRequested => {
                // No specific payload type yet
            }
            EventType::CaptioningComplete => {
                // No specific payload type yet
            }
            EventType::CaptioningFailed => {
                // No specific payload type for failed events
            }
            EventType::ModerationRequested => {
                // No specific payload type yet
            }
            EventType::ModerationComplete => {
                // No specific payload type yet
            }
            EventType::ModerationFailed => {
                // No specific payload type for failed events
            }
            EventType::TranslationRequested => {
                // No specific payload type yet
            }
            EventType::TranslationComplete => {
                // No specific payload type yet
            }
            EventType::TranslationFailed => {
                // No specific payload type for failed events
            }
            EventType::ChatMessage => {
                let _: ChatMessagePayload = self.payload_as()?;
            }
            EventType::PresenceUpdate => {
                let _: PresenceUpdatePayload = self.payload_as()?;
            }
            EventType::StreamStarted => {
                // No specific payload type for stream started events
            }
            EventType::StreamEnded => {
                // No specific payload type for stream ended events
            }
            EventType::StreamFailed => {
                // No specific payload type for stream failed events
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let payload = MediaUploadedPayload {
            media_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            file_path: "s3://bucket/key".to_string(),
            content_type: "video/mp4".to_string(),
            file_size: 1048576,
            metadata: Default::default(),
        };

        let event = Event::new(EventType::MediaUploaded, "test-service", payload).unwrap();
        assert_eq!(event.event_type, EventType::MediaUploaded);
        assert_eq!(event.source, "test-service");
    }

}

