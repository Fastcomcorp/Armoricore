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

//! AI Service Manager
//!
//! Manages multiple AI connectors and routes requests to available services.
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


use crate::error::{AIConnectorError, AIConnectorResult};
use crate::traits::{AIConnector, CaptionResult, ModerationResult, TextGenerationResult, TranscriptionResult};
use std::sync::Arc;
use tracing::{info, warn};

/// Manages multiple AI connectors
pub struct AIServiceManager {
    connectors: Vec<Arc<dyn AIConnector>>,
    default_connector: Option<Arc<dyn AIConnector>>,
}

impl AIServiceManager {
    /// Create a new AI service manager
    pub fn new() -> Self {
        Self {
            connectors: Vec::new(),
            default_connector: None,
        }
    }

    /// Add a connector
    pub fn add_connector(&mut self, connector: Arc<dyn AIConnector>) {
        info!(connector = connector.name(), "Adding AI connector");
        self.connectors.push(connector.clone());
        
        // Set first available connector as default
        if self.default_connector.is_none() && connector.is_available() {
            self.default_connector = Some(connector);
        }
    }

    /// Set the default connector
    pub fn set_default(&mut self, connector_name: &str) {
        if let Some(connector) = self.connectors.iter().find(|c| c.name() == connector_name) {
            if connector.is_available() {
                self.default_connector = Some(connector.clone());
                info!(connector = connector_name, "Set default AI connector");
            } else {
                warn!(connector = connector_name, "Cannot set unavailable connector as default");
            }
        } else {
            warn!(connector = connector_name, "Connector not found");
        }
    }

    /// Get the default connector
    pub fn get_default(&self) -> Option<Arc<dyn AIConnector>> {
        self.default_connector.clone()
    }

    /// Get a connector by name
    pub fn get_connector(&self, name: &str) -> Option<Arc<dyn AIConnector>> {
        self.connectors.iter().find(|c| c.name() == name).cloned()
    }

    /// Get all available connectors
    pub fn get_available_connectors(&self) -> Vec<Arc<dyn AIConnector>> {
        self.connectors
            .iter()
            .filter(|c| c.is_available())
            .cloned()
            .collect()
    }

    /// Transcribe using default connector
    pub async fn transcribe(
        &self,
        audio_data: &[u8],
        language: Option<&str>,
    ) -> AIConnectorResult<TranscriptionResult> {
        if let Some(connector) = &self.default_connector {
            connector.transcribe(audio_data, language).await
        } else {
            Err(AIConnectorError::ServiceUnavailable(
                "No AI connector available".to_string(),
            ))
        }
    }

    /// Generate captions using default connector
    pub async fn generate_captions(
        &self,
        transcription: &TranscriptionResult,
        language: &str,
    ) -> AIConnectorResult<CaptionResult> {
        if let Some(connector) = &self.default_connector {
            connector.generate_captions(transcription, language).await
        } else {
            Err(AIConnectorError::ServiceUnavailable(
                "No AI connector available".to_string(),
            ))
        }
    }

    /// Moderate content using default connector
    pub async fn moderate(
        &self,
        content: &str,
        content_type: &str,
    ) -> AIConnectorResult<ModerationResult> {
        if let Some(connector) = &self.default_connector {
            connector.moderate(content, content_type).await
        } else {
            Err(AIConnectorError::ServiceUnavailable(
                "No AI connector available".to_string(),
            ))
        }
    }

    /// Generate text using default connector
    pub async fn generate_text(
        &self,
        prompt: &str,
        max_tokens: Option<u32>,
        temperature: Option<f64>,
    ) -> AIConnectorResult<TextGenerationResult> {
        if let Some(connector) = &self.default_connector {
            connector.generate_text(prompt, max_tokens, temperature).await
        } else {
            Err(AIConnectorError::ServiceUnavailable(
                "No AI connector available".to_string(),
            ))
        }
    }

    /// Summarize text using default connector
    pub async fn summarize(
        &self,
        text: &str,
        max_length: Option<usize>,
    ) -> AIConnectorResult<String> {
        if let Some(connector) = &self.default_connector {
            connector.summarize(text, max_length).await
        } else {
            Err(AIConnectorError::ServiceUnavailable(
                "No AI connector available".to_string(),
            ))
        }
    }

    /// Translate text using default connector
    pub async fn translate(
        &self,
        text: &str,
        from_language: Option<&str>,
        to_language: &str,
    ) -> AIConnectorResult<String> {
        if let Some(connector) = &self.default_connector {
            connector.translate(text, from_language, to_language).await
        } else {
            Err(AIConnectorError::ServiceUnavailable(
                "No AI connector available".to_string(),
            ))
        }
    }
}

impl Default for AIServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

