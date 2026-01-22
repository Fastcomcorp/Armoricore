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

//! Error types for AI connectors
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

#[derive(Error, Debug)]
pub enum AIConnectorError {
    #[error("API request failed: {0}")]
    ApiError(String),

    #[error("Authentication failed: {0}")]
    AuthenticationError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitError(String),

    #[error("Invalid configuration: {0}")]
    ConfigurationError(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type AIConnectorResult<T> = Result<T, AIConnectorError>;

