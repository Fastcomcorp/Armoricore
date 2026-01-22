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

//! Trait definitions for AI connectors
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


use async_trait::async_trait;
use crate::error::AIConnectorResult;

/// Transcription result
#[derive(Debug, Clone)]
pub struct TranscriptionResult {
    pub text: String,
    pub language: Option<String>,
    pub segments: Option<Vec<TranscriptionSegment>>,
    pub confidence: Option<f64>,
}

/// Transcription segment
#[derive(Debug, Clone)]
pub struct TranscriptionSegment {
    pub start: f64,
    pub end: f64,
    pub text: String,
}

/// Caption result
#[derive(Debug, Clone)]
pub struct CaptionResult {
    pub captions: Vec<Caption>,
    pub language: String,
}

/// Caption entry
#[derive(Debug, Clone)]
pub struct Caption {
    pub start: f64,
    pub end: f64,
    pub text: String,
}

/// Moderation result
#[derive(Debug, Clone)]
pub struct ModerationResult {
    pub flagged: bool,
    pub categories: Vec<String>,
    pub severity: Option<f64>,
    pub details: Option<serde_json::Value>,
}

/// Text generation result
#[derive(Debug, Clone)]
pub struct TextGenerationResult {
    pub text: String,
    pub model: String,
    pub usage: Option<TokenUsage>,
}

/// Token usage information
#[derive(Debug, Clone)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Trait for AI service connectors
#[async_trait]
pub trait AIConnector: Send + Sync {
    /// Get the name of the connector
    fn name(&self) -> &str;

    /// Check if the connector is available/configured
    fn is_available(&self) -> bool;

    /// Transcribe audio/video to text
    async fn transcribe(
        &self,
        audio_data: &[u8],
        language: Option<&str>,
    ) -> AIConnectorResult<TranscriptionResult>;

    /// Generate captions/subtitles from transcription
    async fn generate_captions(
        &self,
        transcription: &TranscriptionResult,
        language: &str,
    ) -> AIConnectorResult<CaptionResult>;

    /// Moderate content (text, images, etc.)
    async fn moderate(
        &self,
        content: &str,
        content_type: &str, // "text", "image", "video"
    ) -> AIConnectorResult<ModerationResult>;

    /// Generate text using AI
    async fn generate_text(
        &self,
        prompt: &str,
        max_tokens: Option<u32>,
        temperature: Option<f64>,
    ) -> AIConnectorResult<TextGenerationResult>;

    /// Summarize text
    async fn summarize(
        &self,
        text: &str,
        max_length: Option<usize>,
    ) -> AIConnectorResult<String>;

    /// Translate text from one language to another
    async fn translate(
        &self,
        text: &str,
        from_language: Option<&str>, // Auto-detect if None
        to_language: &str,
    ) -> AIConnectorResult<String>;
}

