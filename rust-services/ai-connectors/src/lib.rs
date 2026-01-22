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

//! AI & ML Connectors
//!
//! This crate provides optional connectors to various AI/ML services:
//! - OpenAI (GPT, Whisper, etc.)
//! - Anthropic (Claude)
//! - Azure OpenAI
//! - Google AI
//! - Custom AI services
//!
//! All connectors are optional and can be enabled via feature flags.
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


pub mod error;
pub mod traits;
pub mod manager;

// Optional connectors (enabled via features)
// For now, include all connectors (can be made optional later)
pub mod openai;
pub mod anthropic;

#[cfg(feature = "azure-openai")]
pub mod azure_openai;

#[cfg(feature = "google-ai")]
pub mod google_ai;

pub use error::{AIConnectorError, AIConnectorResult};
pub use traits::AIConnector;
pub use manager::AIServiceManager;

