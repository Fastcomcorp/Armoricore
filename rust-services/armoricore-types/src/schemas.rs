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

//! Event payload schemas
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


use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================================
// Media Event Payloads
// ============================================================================

/// Payload for `media.uploaded` event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaUploadedPayload {
    pub media_id: Uuid,
    pub user_id: Uuid,
    pub file_path: String,
    pub content_type: String,
    pub file_size: u64,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Payload for `media.ready` event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaReadyPayload {
    pub media_id: Uuid,
    pub playback_urls: PlaybackUrls,
    pub thumbnail_urls: Vec<String>,
    pub duration: u64, // Duration in seconds
    pub resolutions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybackUrls {
    pub hls: Option<String>,
    pub dash: Option<String>,
    /// MP4 file URLs by resolution (future implementation)
    /// Format: {"1080p": "https://...", "720p": "https://...", ...}
    #[serde(default)]
    pub mp4: std::collections::HashMap<String, String>,
}

// ============================================================================
// Transcription Event Payloads
// ============================================================================

/// Payload for `transcription.requested` event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionRequestedPayload {
    pub media_id: Uuid,
    pub user_id: Uuid,
    pub source_file_path: String,
    pub language: Option<String>,
}

/// Payload for `transcription.complete` event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptionCompletePayload {
    pub media_id: Uuid,
    pub transcription_id: Uuid,
    pub transcript_file_path: String,
    pub language: String,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Chat Event Payloads
// ============================================================================

/// Payload for `chat.message` event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessagePayload {
    pub message_id: Uuid,
    pub room_id: String,
    pub user_id: Uuid,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Presence Event Payloads
// ============================================================================

/// Payload for `presence.update` event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceUpdatePayload {
    pub user_id: Uuid,
    pub room_id: String,
    pub status: PresenceStatus,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    Online,
    Offline,
    Away,
}

