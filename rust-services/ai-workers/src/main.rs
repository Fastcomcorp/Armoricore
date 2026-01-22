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

//! AI Workers
//!
//! Consumes AI-related events from the message bus and processes them:
//! - Transcription requests
//! - Captioning requests
//! - Moderation requests
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


mod worker;

use ai_connectors::AIServiceManager;
use ai_connectors::openai::{OpenAIConnector, OpenAIConfig};
use ai_connectors::anthropic::{AnthropicConnector, AnthropicConfig};
use armoricore_config::AppConfig;
use armoricore_logging::init_console_logging;
use message_bus_client::nats::NatsClient;
use std::sync::Arc;
use tracing::{error, info, warn};
use worker::AIWorker;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    init_console_logging("ai-workers", "info");

    info!("Starting AI Workers");

    // Load configuration
    let config = AppConfig::from_env()
        .map_err(|e| anyhow::anyhow!("Failed to load configuration: {}", e))?;

    // Connect to message bus
    let nats_url = config.message_bus.url.clone();

    let client = Arc::new(
        NatsClient::new(&nats_url, None)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to NATS: {}", e))?,
    );

    info!("Connected to message bus");

    // Initialize AI Service Manager
    let mut ai_manager = AIServiceManager::new();

    // Add OpenAI connector if configured
    if let Some(openai_config) = OpenAIConfig::from_env() {
        info!("OpenAI connector configured");
        let openai_connector = Arc::new(OpenAIConnector::new(openai_config));
        ai_manager.add_connector(openai_connector.clone());
        ai_manager.set_default("openai");
    } else {
        info!("No OpenAI API key found - OpenAI connector disabled");
    }

    // Add Anthropic connector if configured
    if let Some(anthropic_config) = AnthropicConfig::from_env() {
        info!("Anthropic connector configured");
        let anthropic_connector = Arc::new(AnthropicConnector::new(anthropic_config));
        ai_manager.add_connector(anthropic_connector);
    } else {
        info!("No Anthropic API key found - Anthropic connector disabled");
    }

    // Check if any connectors are available
    let available = ai_manager.get_available_connectors();
    if available.is_empty() {
        warn!("No AI connectors available - AI features will be disabled");
    } else {
        info!(count = available.len(), "AI connectors available");
    }

    // Start AI worker
    let worker = AIWorker::new(client, ai_manager);
    
    // Run worker (this blocks)
    if let Err(e) = worker.start().await {
        error!(error = %e, "AI Worker failed");
        return Err(e);
    }

    Ok(())
}
