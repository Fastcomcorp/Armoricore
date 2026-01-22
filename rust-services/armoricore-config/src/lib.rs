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

//! Configuration management for Armoricore services
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


use serde::Deserialize;
use std::env;

/// Message bus configuration
#[derive(Debug, Clone, Deserialize)]
pub struct MessageBusConfig {
    pub url: String,
    pub stream_name: Option<String>,
    pub subject_prefix: Option<String>,
}

/// Object storage configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ObjectStorageConfig {
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    pub bucket: String,
    pub region: Option<String>,
}

/// Application configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub message_bus: MessageBusConfig,
    pub object_storage: Option<ObjectStorageConfig>,
    pub log_level: Option<String>,
}

impl AppConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, config::ConfigError> {
        // Load .env file if it exists
        let _ = dotenvy::dotenv();

        let message_bus_url = env::var("MESSAGE_BUS_URL")
            .unwrap_or_else(|_| "nats://localhost:4222".to_string());
        
        let stream_name = env::var("MESSAGE_BUS_STREAM_NAME").ok();
        
        let log_level = env::var("LOG_LEVEL")
            .unwrap_or_else(|_| "info".to_string());

        // Build object storage config if all required vars are present
        let object_storage = if let (Ok(endpoint), Ok(access_key), Ok(secret_key), Ok(bucket)) = (
            env::var("OBJECT_STORAGE_ENDPOINT"),
            env::var("OBJECT_STORAGE_ACCESS_KEY"),
            env::var("OBJECT_STORAGE_SECRET_KEY"),
            env::var("OBJECT_STORAGE_BUCKET"),
        ) {
            Some(ObjectStorageConfig {
                endpoint,
                access_key,
                secret_key,
                bucket,
                region: env::var("OBJECT_STORAGE_REGION").ok(),
            })
        } else {
            None
        };

        Ok(Self {
            message_bus: MessageBusConfig {
                url: message_bus_url,
                stream_name,
                subject_prefix: Some("armoricore".to_string()),
            },
            object_storage,
            log_level: Some(log_level),
        })
    }

    /// Get message bus URL
    pub fn message_bus_url(&self) -> &str {
        &self.message_bus.url
    }

    /// Get log level, defaulting to "info"
    pub fn log_level(&self) -> &str {
        self.log_level.as_deref().unwrap_or("info")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    // Mutex to serialize tests that modify environment variables
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn setup_test_env() {
        env::set_var("MESSAGE_BUS_URL", "nats://localhost:4222");
        env::remove_var("MESSAGE_BUS_STREAM_NAME");
        env::remove_var("OBJECT_STORAGE_ENDPOINT");
        env::remove_var("OBJECT_STORAGE_ACCESS_KEY");
        env::remove_var("OBJECT_STORAGE_SECRET_KEY");
        env::remove_var("OBJECT_STORAGE_BUCKET");
        env::remove_var("LOG_LEVEL");
    }

    fn cleanup_test_env() {
        env::remove_var("MESSAGE_BUS_URL");
        env::remove_var("MESSAGE_BUS_STREAM_NAME");
        env::remove_var("OBJECT_STORAGE_ENDPOINT");
        env::remove_var("OBJECT_STORAGE_ACCESS_KEY");
        env::remove_var("OBJECT_STORAGE_SECRET_KEY");
        env::remove_var("OBJECT_STORAGE_BUCKET");
        env::remove_var("LOG_LEVEL");
        env::remove_var("OBJECT_STORAGE_REGION");
    }

    #[test]
    fn test_config_defaults() {
        let _guard = ENV_MUTEX.lock().unwrap();
        setup_test_env();
        
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.message_bus.url, "nats://localhost:4222");
        assert_eq!(config.message_bus_url(), "nats://localhost:4222");
        assert_eq!(config.log_level(), "info");
        
        cleanup_test_env();
    }

    #[test]
    fn test_config_with_custom_message_bus_url() {
        let _guard = ENV_MUTEX.lock().unwrap();
        setup_test_env();
        env::set_var("MESSAGE_BUS_URL", "nats://custom:4222");
        
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.message_bus.url, "nats://custom:4222");
        
        cleanup_test_env();
    }

    #[test]
    fn test_config_with_stream_name() {
        let _guard = ENV_MUTEX.lock().unwrap();
        setup_test_env();
        env::set_var("MESSAGE_BUS_STREAM_NAME", "test-stream");
        
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.message_bus.stream_name, Some("test-stream".to_string()));
        
        cleanup_test_env();
    }

    #[test]
    fn test_config_with_object_storage() {
        let _guard = ENV_MUTEX.lock().unwrap();
        // Clean up first
        cleanup_test_env();
        
        // Set all required variables
        env::set_var("MESSAGE_BUS_URL", "nats://localhost:4222");
        env::set_var("OBJECT_STORAGE_ENDPOINT", "https://storage.example.com");
        env::set_var("OBJECT_STORAGE_ACCESS_KEY", "test-key");
        env::set_var("OBJECT_STORAGE_SECRET_KEY", "test-secret");
        env::set_var("OBJECT_STORAGE_BUCKET", "test-bucket");
        env::set_var("OBJECT_STORAGE_REGION", "us-east-1");
        
        let config = AppConfig::from_env().unwrap();
        assert!(config.object_storage.is_some(), "Object storage should be configured");
        let storage = config.object_storage.unwrap();
        assert_eq!(storage.endpoint, "https://storage.example.com");
        assert_eq!(storage.access_key, "test-key");
        assert_eq!(storage.secret_key, "test-secret");
        assert_eq!(storage.bucket, "test-bucket");
        assert_eq!(storage.region, Some("us-east-1".to_string()));
        
        cleanup_test_env();
    }

    #[test]
    fn test_config_without_object_storage() {
        let _guard = ENV_MUTEX.lock().unwrap();
        setup_test_env();
        
        let config = AppConfig::from_env().unwrap();
        assert!(config.object_storage.is_none());
        
        cleanup_test_env();
    }

    #[test]
    fn test_config_log_level() {
        let _guard = ENV_MUTEX.lock().unwrap();
        cleanup_test_env();
        env::set_var("MESSAGE_BUS_URL", "nats://localhost:4222");
        env::set_var("LOG_LEVEL", "debug");
        
        let config = AppConfig::from_env().unwrap();
        assert_eq!(config.log_level(), "debug");
        
        cleanup_test_env();
    }

    #[test]
    fn test_message_bus_config() {
        let config = MessageBusConfig {
            url: "nats://localhost:4222".to_string(),
            stream_name: Some("test-stream".to_string()),
            subject_prefix: Some("test".to_string()),
        };
        
        assert_eq!(config.url, "nats://localhost:4222");
        assert_eq!(config.stream_name, Some("test-stream".to_string()));
        assert_eq!(config.subject_prefix, Some("test".to_string()));
    }

    #[test]
    fn test_object_storage_config() {
        let config = ObjectStorageConfig {
            endpoint: "https://storage.example.com".to_string(),
            access_key: "key".to_string(),
            secret_key: "secret".to_string(),
            bucket: "bucket".to_string(),
            region: Some("us-east-1".to_string()),
        };
        
        assert_eq!(config.endpoint, "https://storage.example.com");
        assert_eq!(config.region, Some("us-east-1".to_string()));
    }
}

