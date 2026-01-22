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

//! Error types for media relay
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

/// Media relay error
#[derive(Debug, Error)]
pub enum RelayError {
    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Allocation not found
    #[error("Allocation not found: {0}")]
    AllocationNotFound(String),

    /// Allocation expired
    #[error("Allocation expired: {0}")]
    AllocationExpired(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// STUN/TURN protocol error
    #[error("STUN/TURN error: {0}")]
    StunTurnError(String),

    /// Server error
    #[error("Server error: {0}")]
    ServerError(String),
}

/// Result type for relay operations
pub type RelayResult<T> = Result<T, RelayError>;

