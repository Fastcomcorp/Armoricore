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

//! Retry logic with exponential backoff for upload operations
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


use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

/// Retry configuration for upload operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial delay in seconds
    pub initial_delay_secs: u64,
    /// Maximum delay in seconds (cap for exponential backoff)
    pub max_delay_secs: u64,
    /// Multiplier for exponential backoff (e.g., 2.0 for doubling)
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_secs: 1,
            max_delay_secs: 60,
            multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration
    pub fn new(max_retries: u32, initial_delay_secs: u64, max_delay_secs: u64, multiplier: f64) -> Self {
        Self {
            max_retries,
            initial_delay_secs,
            max_delay_secs,
            multiplier,
        }
    }

    /// Get delay for a specific retry attempt
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::from_secs(0);
        }

        // Calculate exponential backoff: initial_delay * (multiplier ^ (attempt - 1))
        let delay_secs = (self.initial_delay_secs as f64) * self.multiplier.powi((attempt - 1) as i32);
        let delay_secs = delay_secs.min(self.max_delay_secs as f64) as u64;

        Duration::from_secs(delay_secs)
    }

    /// Get retry config from environment variables
    pub fn from_env() -> Self {
        use std::env;
        
        let max_retries = env::var("UPLOAD_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);
        
        let initial_delay = env::var("UPLOAD_RETRY_INITIAL_DELAY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        
        let max_delay = env::var("UPLOAD_RETRY_MAX_DELAY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);
        
        let multiplier = env::var("UPLOAD_RETRY_MULTIPLIER")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2.0);

        Self::new(max_retries, initial_delay, max_delay, multiplier)
    }
}

/// Retry a function with exponential backoff
pub async fn retry_with_backoff<F, T, E>(
    config: &RetryConfig,
    mut f: F,
) -> Result<T, E>
where
    F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
    E: std::fmt::Display,
{
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        match f().await {
            Ok(result) => {
                if attempt > 0 {
                    debug!(
                        attempt = attempt,
                        total_attempts = attempt + 1,
                        "Upload succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                last_error = Some(e);

                if attempt < config.max_retries {
                    let delay = config.delay_for_attempt(attempt + 1);
                    warn!(
                        attempt = attempt + 1,
                        max_retries = config.max_retries,
                        delay_secs = delay.as_secs(),
                        error = %last_error.as_ref().unwrap(),
                        "Upload failed, retrying with exponential backoff"
                    );
                    sleep(delay).await;
                } else {
                    warn!(
                        attempt = attempt + 1,
                        max_retries = config.max_retries,
                        error = %last_error.as_ref().unwrap(),
                        "Upload failed after all retries"
                    );
                }
            }
        }
    }

    Err(last_error.expect("Should have at least one error"))
}

/// Check if an upload error is retryable (transient)
pub fn is_retryable_upload_error(error: &anyhow::Error) -> bool {
    let error_str = error.to_string().to_lowercase();
    
    // Network errors are usually retryable
    if error_str.contains("network") 
        || error_str.contains("timeout")
        || error_str.contains("connection")
        || error_str.contains("temporary")
        || error_str.contains("unavailable")
        || error_str.contains("rate limit")
        || error_str.contains("429") // HTTP 429 Too Many Requests
        || error_str.contains("503") // HTTP 503 Service Unavailable
        || error_str.contains("502") // HTTP 502 Bad Gateway
        || error_str.contains("500") // HTTP 500 Internal Server Error
        || error_str.contains("eof") // End of file (network issue)
        || error_str.contains("broken pipe")
    {
        return true;
    }

    // Authentication/authorization errors are usually not retryable
    if error_str.contains("unauthorized")
        || error_str.contains("forbidden")
        || error_str.contains("401")
        || error_str.contains("403")
        || error_str.contains("invalid")
        || error_str.contains("malformed")
        || error_str.contains("not found")
        || error_str.contains("404")
    {
        return false;
    }

    // Default: assume retryable for unknown errors (network issues are common)
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_delays() {
        let config = RetryConfig::default();
        
        assert_eq!(config.delay_for_attempt(0), Duration::from_secs(0));
        assert_eq!(config.delay_for_attempt(1), Duration::from_secs(1));
        assert_eq!(config.delay_for_attempt(2), Duration::from_secs(2));
        assert_eq!(config.delay_for_attempt(3), Duration::from_secs(4));
    }

    #[test]
    fn test_retry_config_max_delay() {
        let config = RetryConfig::new(5, 1, 10, 2.0);
        
        // Should cap at max_delay_secs
        assert!(config.delay_for_attempt(10).as_secs() <= 10);
    }

    #[tokio::test]
    async fn test_retry_succeeds_on_first_attempt() {
        let config = RetryConfig::new(3, 1, 10, 2.0);
        let mut attempts = 0;

        let result = retry_with_backoff(&config, || {
            attempts += 1;
            Box::pin(async move { Ok::<i32, String>(42) })
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_retries() {
        let config = RetryConfig::new(3, 0, 10, 2.0); // 0 delay for faster tests
        let mut attempts = 0;

        let result = retry_with_backoff(&config, || {
            attempts += 1;
            Box::pin(async move {
                if attempts < 3 {
                    Err::<i32, String>("network timeout".to_string())
                } else {
                    Ok(42)
                }
            })
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn test_retry_fails_after_max_retries() {
        let config = RetryConfig::new(2, 0, 10, 2.0); // 0 delay for faster tests
        let mut attempts = 0;

        let result = retry_with_backoff(&config, || {
            attempts += 1;
            Box::pin(async move { Err::<i32, String>("persistent error".to_string()) })
        })
        .await;

        assert!(result.is_err());
        assert_eq!(attempts, 3); // initial + 2 retries
    }

    #[test]
    fn test_is_retryable_upload_error() {
        assert!(is_retryable_upload_error(&anyhow::anyhow!("network error")));
        assert!(is_retryable_upload_error(&anyhow::anyhow!("timeout occurred")));
        assert!(is_retryable_upload_error(&anyhow::anyhow!("HTTP 429 Too Many Requests")));
        assert!(is_retryable_upload_error(&anyhow::anyhow!("HTTP 503 Service Unavailable")));
        assert!(is_retryable_upload_error(&anyhow::anyhow!("broken pipe")));
        
        assert!(!is_retryable_upload_error(&anyhow::anyhow!("unauthorized access")));
        assert!(!is_retryable_upload_error(&anyhow::anyhow!("HTTP 401 Unauthorized")));
        assert!(!is_retryable_upload_error(&anyhow::anyhow!("invalid token")));
        assert!(!is_retryable_upload_error(&anyhow::anyhow!("file not found")));
    }
}

