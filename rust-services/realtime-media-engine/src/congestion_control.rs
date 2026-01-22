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

//! Congestion control
//!
//! Implements congestion control algorithms to prevent network congestion
//! and maintain call quality.
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

/// Congestion control configuration
#[derive(Debug, Clone)]
pub struct CongestionControlConfig {
    /// Initial send rate (bps)
    pub initial_rate_bps: f64,
    /// Minimum send rate (bps)
    pub min_rate_bps: f64,
    /// Maximum send rate (bps)
    pub max_rate_bps: f64,
    /// Packet loss threshold (0.0 - 1.0)
    pub packet_loss_threshold: f32,
    /// RTT threshold (milliseconds)
    pub rtt_threshold_ms: f64,
    /// Additive increase rate (bps per update)
    pub additive_increase_bps: f64,
    /// Multiplicative decrease factor (0.0 - 1.0)
    pub multiplicative_decrease: f32,
}

impl Default for CongestionControlConfig {
    fn default() -> Self {
        CongestionControlConfig {
            initial_rate_bps: 1_000_000.0,  // 1 Mbps
            min_rate_bps: 64_000.0,         // 64 kbps
            max_rate_bps: 10_000_000.0,     // 10 Mbps
            packet_loss_threshold: 0.05,    // 5% loss
            rtt_threshold_ms: 200.0,        // 200ms RTT
            additive_increase_bps: 10_000.0, // 10 kbps
            multiplicative_decrease: 0.8,   // Reduce by 20%
        }
    }
}

/// Congestion controller
pub struct CongestionController {
    config: CongestionControlConfig,
    current_rate: f64,
    target_rate: f64,
}

impl CongestionController {
    /// Create a new congestion controller
    pub fn new(config: CongestionControlConfig) -> Self {
        let initial_rate = config.initial_rate_bps;
        CongestionController {
            config,
            current_rate: initial_rate,
            target_rate: initial_rate,
        }
    }

    /// Adjust send rate based on network metrics
    pub fn adjust_rate(&mut self, metrics: &NetworkMetrics) -> MediaEngineResult<f64> {
        // Check for congestion indicators
        let is_congested = metrics.packet_loss_rate > self.config.packet_loss_threshold
            || metrics.rtt_ms > self.config.rtt_threshold_ms;

        if is_congested {
            // Congestion detected: multiplicative decrease
            self.target_rate *= self.config.multiplicative_decrease as f64;
        } else if metrics.packet_loss_rate < 0.01 && metrics.rtt_ms < self.config.rtt_threshold_ms * 0.8 {
            // Good conditions: additive increase
            self.target_rate += self.config.additive_increase_bps;
        }
        // Otherwise, maintain current rate

        // Clamp to bounds
        self.target_rate = self.target_rate
            .max(self.config.min_rate_bps)
            .min(self.config.max_rate_bps);

        // Smooth rate adjustment
        let rate_diff = self.target_rate - self.current_rate;
        self.current_rate += rate_diff * 0.1; // Smooth transition

        Ok(self.current_rate)
    }

    /// Get current send rate
    pub fn current_rate(&self) -> f64 {
        self.current_rate
    }

    /// Get target send rate
    pub fn target_rate(&self) -> f64 {
        self.target_rate
    }

    /// Set target rate (for external control)
    pub fn set_target_rate(&mut self, rate: f64) {
        self.target_rate = rate
            .max(self.config.min_rate_bps)
            .min(self.config.max_rate_bps);
    }

    /// Reset controller
    pub fn reset(&mut self) {
        self.current_rate = self.config.initial_rate_bps;
        self.target_rate = self.config.initial_rate_bps;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_congestion_control_decrease() {
        let config = CongestionControlConfig::default();
        let mut controller = CongestionController::new(config);

        // High packet loss indicates congestion
        let metrics = NetworkMetrics {
            rtt_ms: 100.0,
            packet_loss_rate: 0.1,  // 10% loss (above 5% threshold)
            jitter_ms: 20.0,
            bandwidth_kbps: 0.0,
            timestamp: std::time::Instant::now(),
        };

        let initial_rate = controller.current_rate();
        controller.adjust_rate(&metrics).unwrap();

        // Rate should decrease
        assert!(controller.current_rate() < initial_rate);
    }

    #[test]
    fn test_congestion_control_increase() {
        let config = CongestionControlConfig::default();
        let mut controller = CongestionController::new(config);

        // Good conditions
        let metrics = NetworkMetrics {
            rtt_ms: 50.0,  // Low RTT
            packet_loss_rate: 0.0,  // No loss
            jitter_ms: 10.0,
            bandwidth_kbps: 0.0,
            timestamp: std::time::Instant::now(),
        };

        let initial_rate = controller.current_rate();
        
        // Apply multiple times to see increase
        for _ in 0..10 {
            controller.adjust_rate(&metrics).unwrap();
        }

        // Rate should increase
        assert!(controller.current_rate() > initial_rate);
    }

    #[test]
    fn test_congestion_control_bounds() {
        let config = CongestionControlConfig {
            min_rate_bps: 100_000.0,
            max_rate_bps: 1_000_000.0,
            ..Default::default()
        };
        let min_rate = config.min_rate_bps;
        let max_rate = config.max_rate_bps;
        let mut controller = CongestionController::new(config);

        // Try to set rate below minimum
        controller.set_target_rate(50_000.0);
        assert!(controller.target_rate() >= min_rate);

        // Try to set rate above maximum
        controller.set_target_rate(2_000_000.0);
        assert!(controller.target_rate() <= max_rate);
    }
}

