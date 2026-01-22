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

//! Structured logging setup for Armoricore services
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


use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Initialize structured logging for Armoricore services
///
/// This sets up:
/// - JSON formatted logs (for production)
/// - Environment-based log level filtering
/// - Service name tagging
pub fn init_logging(service_name: &str, default_level: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_file(true)
                .with_line_number(true)
                .with_current_span(false)
                .with_span_list(false),
        )
        .init();

    tracing::info!(
        service = service_name,
        "Logging initialized"
    );
}

/// Initialize simple console logging (for development)
///
/// This sets up:
/// - Human-readable formatted logs
/// - Environment-based log level filtering
pub fn init_console_logging(service_name: &str, default_level: &str) {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    tracing::info!(
        service = service_name,
        "Console logging initialized"
    );
}

