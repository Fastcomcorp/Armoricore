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

//! Error types for the realtime media engine
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


use thiserror::Error;

/// Result type for media engine operations
pub type MediaEngineResult<T> = Result<T, MediaEngineError>;

/// Errors that can occur in the media engine
#[derive(Error, Debug)]
pub enum MediaEngineError {
    /// RTP packet parsing error
    #[error("RTP packet parse error: {0}")]
    RtpParseError(String),

    /// SRTP encryption/decryption error
    #[error("SRTP error: {0}")]
    SrtpError(String),

    /// Invalid packet format
    #[error("Invalid packet format: {0}")]
    InvalidPacket(String),

    /// Key management error
    #[error("Key management error: {0}")]
    KeyError(String),

    /// Stream not found
    #[error("Stream not found: {stream_id}")]
    StreamNotFound { stream_id: String },

    /// Stream already exists
    #[error("Stream already exists: {stream_id}")]
    StreamExists { stream_id: String },

    /// Invalid stream state
    #[error("Invalid stream state: {state}")]
    InvalidStreamState { state: String },

    /// Buffer error
    #[error("Buffer error: {0}")]
    BufferError(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Codec error
    #[error("Codec error: {0}")]
    CodecError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl From<armoricore_keys::KeyError> for MediaEngineError {
    fn from(err: armoricore_keys::KeyError) -> Self {
        MediaEngineError::KeyError(err.to_string())
    }
}

impl From<std::io::Error> for MediaEngineError {
    fn from(err: std::io::Error) -> Self {
        MediaEngineError::NetworkError(err.to_string())
    }
}

