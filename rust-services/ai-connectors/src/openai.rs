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

//! OpenAI connector
//!
//! Provides integration with OpenAI services:
//! - Whisper (transcription)
//! - GPT models (text generation, summarization)
//! - Moderation API
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
    TranscriptionSegment,
};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{info, warn};

/// OpenAI connector configuration
#[derive(Debug, Clone)]
pub struct OpenAIConfig {
    pub api_key: String,
    pub base_url: Option<String>, // For custom endpoints or Azure OpenAI
    pub organization: Option<String>,
    pub timeout_seconds: u64,
}

impl OpenAIConfig {
    pub fn from_env() -> Option<Self> {
        std::env::var("OPENAI_API_KEY").ok().map(|api_key| {
            Self {
                api_key,
                base_url: std::env::var("OPENAI_BASE_URL").ok(),
                organization: std::env::var("OPENAI_ORGANIZATION").ok(),
                timeout_seconds: std::env::var("OPENAI_TIMEOUT")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(30),
            }
        })
    }
}

/// OpenAI connector
pub struct OpenAIConnector {
    config: OpenAIConfig,
    client: reqwest::Client,
}

impl OpenAIConnector {
    pub fn new(config: OpenAIConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    fn base_url(&self) -> &str {
        self.config.base_url.as_deref().unwrap_or("https://api.openai.com/v1")
    }

    async fn make_request<T: for<'de> Deserialize<'de>>(
        &self,
        endpoint: &str,
        body: serde_json::Value,
    ) -> AIConnectorResult<T> {
        let url = format!("{}/{}", self.base_url(), endpoint);

        let mut request = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json");

        if let Some(ref org) = self.config.organization {
            request = request.header("OpenAI-Organization", org);
        }

        let response = request.json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AIConnectorError::ApiError(format!(
                "OpenAI API error ({}): {}",
                status, error_text
            )));
        }

        let result: T = response.json().await?;
        Ok(result)
    }
}

#[async_trait]
impl AIConnector for OpenAIConnector {
    fn name(&self) -> &str {
        "openai"
    }

    fn is_available(&self) -> bool {
        !self.config.api_key.is_empty()
    }

    async fn transcribe(
        &self,
        audio_data: &[u8],
        language: Option<&str>,
    ) -> AIConnectorResult<TranscriptionResult> {
        info!("Transcribing audio with OpenAI Whisper");

        // Convert language to owned String early to avoid lifetime issues
        let language_owned = language.map(|s| s.to_string());

        // Create multipart form for file upload
        let mut form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(audio_data.to_vec())
                .file_name("audio.mp3")
                .mime_str("audio/mpeg")
                .map_err(|e| AIConnectorError::ConfigurationError(format!("Invalid mime type: {}", e)))?)
            .text("model", "whisper-1");

        // Add language if specified (clone to avoid borrow issues)
        if let Some(lang) = &language_owned {
            form = form.text("language", lang.clone());
        }

        // Add response_format for verbose output (includes timestamps)
        form = form.text("response_format", "verbose_json");

        let url = format!("{}/audio/transcriptions", self.base_url());

        let mut request = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .multipart(form);

        if let Some(ref org) = self.config.organization {
            request = request.header("OpenAI-Organization", org);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AIConnectorError::ApiError(format!(
                "OpenAI Whisper API error ({}): {}",
                status, error_text
            )));
        }

        #[derive(Deserialize)]
        struct WhisperResponse {
            text: String,
            language: Option<String>,
            #[allow(dead_code)]
            duration: Option<f64>,
            words: Option<Vec<WhisperWord>>,
        }

        #[derive(Deserialize)]
        struct WhisperWord {
            word: String,
            start: f64,
            end: f64,
        }

        let whisper_result: WhisperResponse = response.json().await?;

        // Convert words to segments if available
        let segments = whisper_result.words.as_ref().map(|words| {
            // Group words into segments (e.g., by sentence or time gaps)
            let mut segments = Vec::new();
            let mut current_segment = Vec::new();
            let mut segment_start = 0.0;
            let mut segment_end = 0.0;

            for word in words {
                if current_segment.is_empty() {
                    segment_start = word.start;
                }
                current_segment.push(word.word.clone());
                segment_end = word.end;

                // Create segment every ~10 words or 3 seconds
                if current_segment.len() >= 10 || (segment_end - segment_start) >= 3.0 {
                    segments.push(TranscriptionSegment {
                        start: segment_start,
                        end: segment_end,
                        text: current_segment.join(" "),
                    });
                    current_segment.clear();
                }
            }

            // Add remaining words as final segment
            if !current_segment.is_empty() {
                segments.push(TranscriptionSegment {
                    start: segment_start,
                    end: segment_end,
                    text: current_segment.join(" "),
                });
            }

            segments
        });

        info!(
            text_length = whisper_result.text.len(),
            language = ?whisper_result.language,
            segments_count = segments.as_ref().map(|s| s.len()).unwrap_or(0),
            "Transcription completed"
        );

        let detected_language = whisper_result.language
            .or(language_owned);

        Ok(TranscriptionResult {
            text: whisper_result.text,
            language: detected_language,
            segments,
            confidence: None, // Whisper API doesn't provide confidence scores
        })
    }

    async fn generate_captions(
        &self,
        transcription: &TranscriptionResult,
        language: &str,
    ) -> AIConnectorResult<CaptionResult> {
        info!("Generating captions from transcription");

        // Convert transcription segments to captions
        let captions = if let Some(ref segments) = transcription.segments {
            segments
                .iter()
                .map(|seg| crate::traits::Caption {
                    start: seg.start,
                    end: seg.end,
                    text: seg.text.clone(),
                })
                .collect()
        } else {
            // Create single caption from full text
            vec![crate::traits::Caption {
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
        content_type: &str,
    ) -> AIConnectorResult<ModerationResult> {
        info!(content_type = content_type, "Moderating content with OpenAI");

        if content_type != "text" {
            return Err(AIConnectorError::UnsupportedFeature(
                format!("Content type '{}' not supported", content_type),
            ));
        }

        // For now, return a placeholder
        // In production, this would call OpenAI Moderation API
        warn!("OpenAI moderation not fully implemented - returning placeholder");
        Ok(ModerationResult {
            flagged: false,
            categories: vec![],
            severity: None,
            details: None,
        })
    }

    async fn generate_text(
        &self,
        _prompt: &str,
        _max_tokens: Option<u32>,
        _temperature: Option<f64>,
    ) -> AIConnectorResult<TextGenerationResult> {
        info!("Generating text with OpenAI GPT");

        // For now, return a placeholder
        // In production, this would:
        // 1. Call GPT API with prompt
        // 2. Parse response
        // 3. Return generated text

        warn!("OpenAI text generation not fully implemented - returning placeholder");
        Ok(TextGenerationResult {
            text: "[Text generation placeholder - OpenAI integration pending]".to_string(),
            model: "gpt-4".to_string(),
            usage: None,
        })
    }

    async fn summarize(
        &self,
        text: &str,
        max_length: Option<usize>,
    ) -> AIConnectorResult<String> {
        info!("Summarizing text with OpenAI");

        let max_length = max_length.unwrap_or(100);
        let prompt = format!(
            "Summarize the following text in approximately {} words:\n\n{}",
            max_length, text
        );

        let body = serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": (max_length as f64 * 1.5) as u32,
            "temperature": 0.3
        });

        #[derive(Deserialize)]
        struct ChatResponse {
            choices: Vec<ChatChoice>,
        }

        #[derive(Deserialize)]
        struct ChatChoice {
            message: ChatMessage,
        }

        #[derive(Deserialize)]
        struct ChatMessage {
            content: String,
        }

        let response: ChatResponse = self.make_request("chat/completions", body).await?;

        if let Some(choice) = response.choices.first() {
            Ok(choice.message.content.clone())
        } else {
            Err(AIConnectorError::InvalidResponse(
                "No choices in response".to_string(),
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
            "Translating text with OpenAI"
        );

        let from_lang_desc = from_language
            .map(|l| format!(" from {}", l))
            .unwrap_or_default();

        let prompt = format!(
            "Translate the following text{} to {}:\n\n{}",
            from_lang_desc, to_language, text
        );

        let body = serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.3
        });

        #[derive(Deserialize)]
        struct ChatResponse {
            choices: Vec<ChatChoice>,
        }

        #[derive(Deserialize)]
        struct ChatChoice {
            message: ChatMessage,
        }

        #[derive(Deserialize)]
        struct ChatMessage {
            content: String,
        }

        let response: ChatResponse = self.make_request("chat/completions", body).await?;

        if let Some(choice) = response.choices.first() {
            Ok(choice.message.content.clone())
        } else {
            Err(AIConnectorError::InvalidResponse(
                "No choices in response".to_string(),
            ))
        }
    }
}

