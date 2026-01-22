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

use anyhow::{Context, Result};
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    /// RTMP server port
    pub rtmp_port: u16,
    /// API server port (for stream key validation)
    pub api_port: u16,
    /// Elixir API URL for stream key validation
    pub api_url: String,
    /// Message bus URL
    pub message_bus_url: String,
    /// Stream key validation timeout (seconds)
    pub validation_timeout_secs: u64,
    /// Recordings base directory
    pub recordings_base_dir: std::path::PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            rtmp_port: env::var("RTMP_PORT")
                .unwrap_or_else(|_| "1935".to_string())
                .parse()
                .context("Invalid RTMP_PORT")?,
            api_port: env::var("API_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .context("Invalid API_PORT")?,
            api_url: env::var("API_URL")
                .unwrap_or_else(|_| "http://localhost:4000".to_string()),
            message_bus_url: env::var("MESSAGE_BUS_URL")
                .unwrap_or_else(|_| "nats://localhost:4222".to_string()),
            validation_timeout_secs: env::var("VALIDATION_TIMEOUT_SECS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .context("Invalid VALIDATION_TIMEOUT_SECS")?,
            recordings_base_dir: env::var("RECORDINGS_BASE_DIR")
                .unwrap_or_else(|_| "/tmp/recordings".to_string())
                .into(),
        })
    }
}

