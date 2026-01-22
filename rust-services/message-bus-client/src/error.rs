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

//! Error types for message bus operations
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

/// Errors that can occur in message bus operations
#[derive(Error, Debug)]
pub enum MessageBusError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Publish error: {0}")]
    Publish(String),

    #[error("Subscribe error: {0}")]
    Subscribe(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("NATS error: {0}")]
    Nats(#[from] async_nats::Error),

    #[error("Timeout error")]
    Timeout,

    #[error("Invalid subject: {0}")]
    InvalidSubject(String),
}

pub type Result<T> = std::result::Result<T, MessageBusError>;

