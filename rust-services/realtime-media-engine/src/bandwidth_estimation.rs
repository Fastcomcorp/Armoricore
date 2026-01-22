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

//! Advanced bandwidth estimation
//!
//! Implements multiple algorithms for accurately estimating available bandwidth:
//! - Loss-based estimation (packet loss indicates congestion)
//! - Delay-based estimation (RTT increase indicates congestion)
//! - Hybrid approach (combines both)
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


use crate::error::MediaEngineResult;
use crate::connection_health::NetworkMetrics;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Bandwidth estimate
#[derive(Debug, Clone)]
pub struct BandwidthEstimate {
    /// Available bandwidth in bits per second
    pub available_bps: f64,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Estimation method used
    pub method: EstimationMethod,
}

/// Estimation method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimationMethod {
    /// Loss-based estimation
    LossBased,
    /// Delay-based estimation
    DelayBased,
    /// Hybrid (combines both)
    Hybrid,
}

/// Bandwidth estimator configuration
#[derive(Debug, Clone)]
pub struct BandwidthEstimatorConfig {
    /// Initial bandwidth estimate (bps)
    pub initial_bandwidth_bps: f64,
    /// Minimum bandwidth (bps)
    pub min_bandwidth_bps: f64,
    /// Maximum bandwidth (bps)
    pub max_bandwidth_bps: f64,
    /// Safety margin (0.0 - 1.0, typically 0.1 = 10%)
    pub safety_margin: f32,
    /// History window size
    pub history_size: usize,
    /// Use hybrid estimation
    pub use_hybrid: bool,
}

impl Default for BandwidthEstimatorConfig {
    fn default() -> Self {
        BandwidthEstimatorConfig {
            initial_bandwidth_bps: 1_000_000.0,  // 1 Mbps
            min_bandwidth_bps: 64_000.0,        // 64 kbps
            max_bandwidth_bps: 10_000_000.0,    // 10 Mbps
            safety_margin: 0.1,                  // 10% safety margin
            history_size: 20,
            use_hybrid: true,
        }
    }
}

/// Bandwidth sample
#[derive(Debug, Clone)]
struct BandwidthSample {
    #[allow(dead_code)]
    send_rate: f64,
    #[allow(dead_code)]
    receive_rate: f64,
    packet_loss: f32,
    rtt: f64,
    #[allow(dead_code)]
    timestamp: Instant,
}

/// Advanced bandwidth estimator
pub struct BandwidthEstimator {
    config: BandwidthEstimatorConfig,
    history: VecDeque<BandwidthSample>,
    current_send_rate: f64,
    current_receive_rate: f64,
    last_estimate: f64,
}

impl BandwidthEstimator {
    /// Create a new bandwidth estimator
    pub fn new(config: BandwidthEstimatorConfig) -> Self {
        let initial_bandwidth = config.initial_bandwidth_bps;
        BandwidthEstimator {
            config,
            history: VecDeque::new(),
            current_send_rate: 0.0,
            current_receive_rate: 0.0,
            last_estimate: initial_bandwidth,
        }
    }

    /// Update with network metrics
    pub fn update(&mut self, metrics: &NetworkMetrics) {
        let sample = BandwidthSample {
            send_rate: self.current_send_rate,
            receive_rate: self.current_receive_rate,
            packet_loss: metrics.packet_loss_rate,
            rtt: metrics.rtt_ms,
            timestamp: Instant::now(),
        };

        self.history.push_back(sample);
        if self.history.len() > self.config.history_size {
            self.history.pop_front();
        }
    }

    /// Update send rate
    pub fn update_send_rate(&mut self, bytes_sent: u64, duration: Duration) {
        if duration.as_secs_f64() > 0.0 {
            self.current_send_rate = (bytes_sent as f64 * 8.0) / duration.as_secs_f64();
        }
    }

    /// Update receive rate
    pub fn update_receive_rate(&mut self, bytes_received: u64, duration: Duration) {
        if duration.as_secs_f64() > 0.0 {
            self.current_receive_rate = (bytes_received as f64 * 8.0) / duration.as_secs_f64();
        }
    }

    /// Estimate available bandwidth
    pub fn estimate(&mut self) -> MediaEngineResult<BandwidthEstimate> {
        if self.history.is_empty() {
            return Ok(BandwidthEstimate {
                available_bps: self.config.initial_bandwidth_bps,
                confidence: 0.5,
                method: EstimationMethod::Hybrid,
            });
        }

        let loss_based = self.estimate_from_loss()?;
        let delay_based = self.estimate_from_delay()?;

        let (available, method) = if self.config.use_hybrid {
            // Use minimum (conservative estimate)
            let min_estimate = loss_based.min(delay_based);
            (min_estimate * (1.0 - self.config.safety_margin as f64), EstimationMethod::Hybrid)
        } else {
            // Use loss-based by default
            (loss_based * (1.0 - self.config.safety_margin as f64), EstimationMethod::LossBased)
        };

        // Clamp to bounds
        let available = available
            .max(self.config.min_bandwidth_bps)
            .min(self.config.max_bandwidth_bps);

        // Calculate confidence based on history size and consistency
        let confidence = self.calculate_confidence();

        self.last_estimate = available;

        Ok(BandwidthEstimate {
            available_bps: available,
            confidence,
            method,
        })
    }

    /// Estimate bandwidth from packet loss
    fn estimate_from_loss(&self) -> MediaEngineResult<f64> {
        if self.history.is_empty() {
            return Ok(self.config.initial_bandwidth_bps);
        }

        // Average packet loss over history
        let avg_loss: f32 = self.history.iter().map(|s| s.packet_loss).sum::<f32>() / self.history.len() as f32;

        // If loss is very low, bandwidth is likely high
        if avg_loss < 0.01 {
            // No congestion, use current send rate as estimate
            return Ok(self.current_send_rate.max(self.config.initial_bandwidth_bps));
        }

        // Loss indicates congestion
        // Reduce bandwidth estimate based on loss
        // Formula: bandwidth = current_rate * (1 - loss_rate)
        let estimated = self.current_send_rate * (1.0 - avg_loss as f64);

        Ok(estimated.max(self.config.min_bandwidth_bps))
    }

    /// Estimate bandwidth from delay (RTT)
    fn estimate_from_delay(&self) -> MediaEngineResult<f64> {
        if self.history.is_empty() {
            return Ok(self.config.initial_bandwidth_bps);
        }

        // Get baseline RTT (minimum RTT in history)
        let baseline_rtt = self.history.iter()
            .map(|s| s.rtt)
            .fold(f64::INFINITY, f64::min);

        if baseline_rtt == f64::INFINITY || baseline_rtt <= 0.0 {
            return Ok(self.config.initial_bandwidth_bps);
        }

        // Current RTT
        let current_rtt = self.history.back().map(|s| s.rtt).unwrap_or(baseline_rtt);

        // RTT increase indicates congestion
        let rtt_increase = current_rtt / baseline_rtt;

        // If RTT increased significantly, reduce bandwidth
        if rtt_increase > 1.2 {
            // RTT increased by >20%, reduce bandwidth
            let reduction_factor = 1.0 / rtt_increase;
            let estimated = self.current_send_rate * reduction_factor;
            return Ok(estimated.max(self.config.min_bandwidth_bps));
        }

        // RTT is stable, use current send rate
        Ok(self.current_send_rate.max(self.config.initial_bandwidth_bps))
    }

    /// Calculate confidence in the estimate
    fn calculate_confidence(&self) -> f32 {
        if self.history.len() < 5 {
            return 0.3; // Low confidence with few samples
        }

        // Check consistency of estimates
        let recent_samples: Vec<&BandwidthSample> = self.history.iter().rev().take(5).collect();
        
        // Calculate variance in packet loss
        let avg_loss: f32 = recent_samples.iter().map(|s| s.packet_loss).sum::<f32>() / recent_samples.len() as f32;
        let loss_variance: f32 = recent_samples.iter()
            .map(|s| (s.packet_loss - avg_loss).powi(2))
            .sum::<f32>() / recent_samples.len() as f32;

        // Lower variance = higher confidence
        let consistency = 1.0 - (loss_variance.min(1.0));

        // More samples = higher confidence
        let sample_confidence = (self.history.len() as f32 / self.config.history_size as f32).min(1.0);

        (consistency * 0.7 + sample_confidence * 0.3).min(1.0)
    }

    /// Get last estimate
    pub fn last_estimate(&self) -> f64 {
        self.last_estimate
    }

    /// Reset estimator
    pub fn reset(&mut self) {
        self.history.clear();
        self.current_send_rate = 0.0;
        self.current_receive_rate = 0.0;
        self.last_estimate = self.config.initial_bandwidth_bps;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_estimator_initial() {
        let config = BandwidthEstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        let estimate = estimator.estimate().unwrap();
        assert!(estimate.available_bps > 0.0);
        assert_eq!(estimate.method, EstimationMethod::Hybrid);
    }

    #[test]
    fn test_bandwidth_estimation_with_loss() {
        let config = BandwidthEstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        // Update with high packet loss
        let metrics = NetworkMetrics {
            rtt_ms: 100.0,
            packet_loss_rate: 0.1,  // 10% loss
            jitter_ms: 20.0,
            bandwidth_kbps: 0.0,
            timestamp: Instant::now(),
        };

        estimator.update_send_rate(100_000, Duration::from_secs(1)); // 800 kbps
        estimator.update(&metrics);

        let estimate = estimator.estimate().unwrap();
        // Should reduce bandwidth due to loss
        assert!(estimate.available_bps < 800_000.0);
    }

    #[test]
    fn test_bandwidth_estimation_with_delay() {
        let config = BandwidthEstimatorConfig::default();
        let mut estimator = BandwidthEstimator::new(config);

        // First sample with low RTT
        let metrics1 = NetworkMetrics {
            rtt_ms: 50.0,
            packet_loss_rate: 0.0,
            jitter_ms: 10.0,
            bandwidth_kbps: 0.0,
            timestamp: Instant::now(),
        };
        estimator.update_send_rate(1_000_000, Duration::from_secs(1)); // 8 Mbps
        estimator.update(&metrics1);

        // Second sample with high RTT
        let metrics2 = NetworkMetrics {
            rtt_ms: 150.0,  // 3x increase
            packet_loss_rate: 0.0,
            jitter_ms: 20.0,
            bandwidth_kbps: 0.0,
            timestamp: Instant::now(),
        };
        estimator.update(&metrics2);

        let estimate = estimator.estimate().unwrap();
        // Should reduce bandwidth due to RTT increase
        assert!(estimate.available_bps < 8_000_000.0);
    }
}

