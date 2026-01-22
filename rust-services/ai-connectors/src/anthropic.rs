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

//! Anthropic (Claude) connector
//!
//! Provides integration with Anthropic's Claude API:
//! - Text generation
//! - Summarization
//! - Content analysis
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
use crate::traits::{
    AIConnector, CaptionResult, ModerationResult, TextGenerationResult, TranscriptionResult,
};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::info;

/// Anthropic connector configuration
#[derive(Debug, Clone)]
pub struct AnthropicConfig {
    pub api_key: String,
    pub base_url: Option<String>,
    pub timeout_seconds: u64,
}

impl AnthropicConfig {
    pub fn from_env() -> Option<Self> {
        std::env::var("ANTHROPIC_API_KEY").ok().map(|api_key| {
            Self {
                api_key,
                base_url: std::env::var("ANTHROPIC_BASE_URL").ok(),
                timeout_seconds: std::env::var("ANTHROPIC_TIMEOUT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30),
            }
        })
    }
}

/// Anthropic connector
pub struct AnthropicConnector {
    config: AnthropicConfig,
    client: reqwest::Client,
}

impl AnthropicConnector {
    pub fn new(config: AnthropicConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    fn base_url(&self) -> &str {
        self.config
            .base_url
            .as_deref()
            .unwrap_or("https://api.anthropic.com/v1")
    }
}

#[async_trait]
impl AIConnector for AnthropicConnector {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn is_available(&self) -> bool {
        !self.config.api_key.is_empty()
    }

    async fn transcribe(
        &self,
        _audio_data: &[u8],
        _language: Option<&str>,
    ) -> AIConnectorResult<TranscriptionResult> {
        Err(AIConnectorError::UnsupportedFeature(
            "Anthropic does not support transcription".to_string(),
        ))
    }

    async fn generate_captions(
        &self,
        transcription: &TranscriptionResult,
        language: &str,
    ) -> AIConnectorResult<CaptionResult> {
        info!("Generating captions from transcription using Anthropic");

        // Convert transcription to captions
        let captions = if let Some(ref segments) = transcription.segments {
            segments
                .iter()
                .map(|seg| super::traits::Caption {
                    start: seg.start,
                    end: seg.end,
                    text: seg.text.clone(),
                })
                .collect()
        } else {
            vec![super::traits::Caption {
                start: 0.0,
                end: 0.0,
                text: transcription.text.clone(),
            }]
        };

        Ok(CaptionResult {
            captions,
            language: language.to_string(),
        })
    }

    async fn moderate(
        &self,
        _content: &str,
        _content_type: &str,
    ) -> AIConnectorResult<ModerationResult> {
        Err(AIConnectorError::UnsupportedFeature(
            "Anthropic moderation not implemented".to_string(),
        ))
    }

    async fn generate_text(
        &self,
        prompt: &str,
        max_tokens: Option<u32>,
        temperature: Option<f64>,
    ) -> AIConnectorResult<TextGenerationResult> {
        info!("Generating text with Anthropic Claude");

        let max_tokens = max_tokens.unwrap_or(1024);
        let temperature = temperature.unwrap_or(1.0);

        let body = serde_json::json!({
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        let url = format!("{}/messages", self.base_url());

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AIConnectorError::ApiError(format!(
                "Anthropic API error ({}): {}",
                status, error_text
            )));
        }

        #[derive(Deserialize)]
        struct AnthropicResponse {
            content: Vec<AnthropicContent>,
            model: String,
            usage: Option<AnthropicUsage>,
        }

        #[derive(Deserialize)]
        struct AnthropicContent {
            text: String,
        }

        #[derive(Deserialize)]
        struct AnthropicUsage {
            input_tokens: u32,
            output_tokens: u32,
        }

        let result: AnthropicResponse = response.json().await?;

        if let Some(content) = result.content.first() {
            let usage = result.usage.map(|u| crate::traits::TokenUsage {
                prompt_tokens: u.input_tokens,
                completion_tokens: u.output_tokens,
                total_tokens: u.input_tokens + u.output_tokens,
            });

            Ok(TextGenerationResult {
                text: content.text.clone(),
                model: result.model,
                usage,
            })
        } else {
            Err(AIConnectorError::InvalidResponse(
                "No content in response".to_string(),
            ))
        }
    }

    async fn summarize(
        &self,
        text: &str,
        max_length: Option<usize>,
    ) -> AIConnectorResult<String> {
        info!("Summarizing text with Anthropic");

        let max_length = max_length.unwrap_or(100);
        let prompt = format!(
            "Summarize the following text in approximately {} words:\n\n{}",
            max_length, text
        );

        let body = serde_json::json!({
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        let url = format!("{}/messages", self.base_url());

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AIConnectorError::ApiError(format!(
                "Anthropic API error ({}): {}",
                status, error_text
            )));
        }

        #[derive(Deserialize)]
        struct AnthropicResponse {
            content: Vec<AnthropicContent>,
        }

        #[derive(Deserialize)]
        struct AnthropicContent {
            text: String,
        }

        let result: AnthropicResponse = response.json().await?;

        if let Some(content) = result.content.first() {
            Ok(content.text.clone())
        } else {
            Err(AIConnectorError::InvalidResponse(
                "No content in response".to_string(),
            ))
        }
    }

    async fn translate(
        &self,
        text: &str,
        from_language: Option<&str>,
        to_language: &str,
    ) -> AIConnectorResult<String> {
        info!(
            from_language = ?from_language,
            to_language = to_language,
            "Translating text with Anthropic"
        );

        let from_lang_desc = from_language
            .map(|l| format!(" from {}", l))
            .unwrap_or_default();

        let prompt = format!(
            "Translate the following text{} to {}:\n\n{}",
            from_lang_desc, to_language, text
        );

        let body = serde_json::json!({
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        });

        let url = format!("{}/messages", self.base_url());

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.config.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AIConnectorError::ApiError(format!(
                "Anthropic API error ({}): {}",
                status, error_text
            )));
        }

        #[derive(Deserialize)]
        struct AnthropicResponse {
            content: Vec<AnthropicContent>,
        }

        #[derive(Deserialize)]
        struct AnthropicContent {
            text: String,
        }

        let result: AnthropicResponse = response.json().await?;

        if let Some(content) = result.content.first() {
            Ok(content.text.clone())
        } else {
            Err(AIConnectorError::InvalidResponse(
                "No content in response".to_string(),
            ))
        }
    }
}

