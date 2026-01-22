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
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, Serialize)]
struct ValidateRequest {
    stream_key: String,
}

#[derive(Debug, Deserialize)]
struct ValidateResponse {
    valid: bool,
    user_id: Option<String>,
    key_id: Option<String>,
    error: Option<String>,
}

pub struct StreamKeyValidator {
    client: Client,
    api_url: String,
    timeout: Duration,
}

impl StreamKeyValidator {
    pub fn new(api_url: String, timeout_secs: u64) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            api_url,
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Validate a stream key with the Elixir API
    pub async fn validate(&self, stream_key: &str) -> Result<ValidationResult> {
        let url = format!("{}/api/v1/stream-keys/validate", self.api_url);
        let request = ValidateRequest {
            stream_key: stream_key.to_string(),
        };

        info!(stream_key = stream_key, "Validating stream key");

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| LiveIngestError::Http(format!("Request failed: {}", e)))?;

        let status = response.status();

        if status.is_success() {
            let result: ValidateResponse = response
                .json()
                .await
                .map_err(|e| LiveIngestError::Http(e.to_string()))?;

            if result.valid {
                info!(
                    stream_key = stream_key,
                    user_id = result.user_id.as_deref(),
                    "Stream key validated successfully"
                );
                Ok(ValidationResult {
                    valid: true,
                    user_id: result.user_id,
                    key_id: result.key_id,
                })
            } else {
                warn!(
                    stream_key = stream_key,
                    error = result.error.as_deref(),
                    "Stream key validation failed"
                );
                Ok(ValidationResult {
                    valid: false,
                    user_id: None,
                    key_id: None,
                })
            }
        } else {
            error!(
                status = %status,
                stream_key = stream_key,
                "Stream key validation request failed"
            );
            Err(LiveIngestError::StreamKeyValidation(format!(
                "API returned status {}",
                status
            )))
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub user_id: Option<String>,
    pub key_id: Option<String>,
}

