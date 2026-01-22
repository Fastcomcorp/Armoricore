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

//! Connection health monitoring
//!
//! Tracks connection quality metrics and provides health status.
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


// MediaEngineError and MediaEngineResult not currently used
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Connection quality level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionQuality {
    /// Excellent: < 50ms RTT, < 1% loss
    Excellent,
    /// Good: < 100ms RTT, < 3% loss
    Good,
    /// Fair: < 200ms RTT, < 5% loss
    Fair,
    /// Poor: > 200ms RTT, > 5% loss
    Poor,
    /// Disconnected: No response
    Disconnected,
}

/// Network metrics
#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f32,
    /// Jitter in milliseconds
    pub jitter_ms: f64,
    /// Available bandwidth estimate in kbps
    pub bandwidth_kbps: f64,
    /// Timestamp
    pub timestamp: Instant,
}

/// Connection health monitor
pub struct ConnectionHealthMonitor {
    #[allow(dead_code)]
    stream_id: Uuid,
    #[allow(dead_code)]
    heartbeat_interval: Duration,
    heartbeat_timeout: Duration,
    last_heartbeat: Instant,
    consecutive_timeouts: u32,
    connection_quality: ConnectionQuality,
    metrics_history: VecDeque<NetworkMetrics>,
    max_history: usize,
    // Statistics
    packets_sent: u64,
    packets_received: u64,
    packets_lost: u64,
    rtt_samples: VecDeque<f64>,
    jitter_samples: VecDeque<f64>,
}

impl ConnectionHealthMonitor {
    /// Create a new connection health monitor
    pub fn new(stream_id: Uuid) -> Self {
        ConnectionHealthMonitor {
            stream_id,
            heartbeat_interval: Duration::from_millis(1000),  // 1 second
            heartbeat_timeout: Duration::from_millis(5000),   // 5 seconds
            last_heartbeat: Instant::now(),
            consecutive_timeouts: 0,
            connection_quality: ConnectionQuality::Good,
            metrics_history: VecDeque::with_capacity(100),
            max_history: 100,
            packets_sent: 0,
            packets_received: 0,
            packets_lost: 0,
            rtt_samples: VecDeque::with_capacity(50),
            jitter_samples: VecDeque::with_capacity(50),
        }
    }

    /// Record packet sent
    pub fn record_packet_sent(&mut self) {
        self.packets_sent += 1;
    }

    /// Record packet received
    pub fn record_packet_received(&mut self) {
        self.packets_received += 1;
        self.last_heartbeat = Instant::now();
        self.consecutive_timeouts = 0;
    }

    /// Record packet lost
    pub fn record_packet_lost(&mut self) {
        self.packets_lost += 1;
    }

    /// Record RTT measurement
    pub fn record_rtt(&mut self, rtt_ms: f64) {
        self.rtt_samples.push_back(rtt_ms);
        if self.rtt_samples.len() > 50 {
            self.rtt_samples.pop_front();
        }
        self.last_heartbeat = Instant::now();
        self.consecutive_timeouts = 0;
    }

    /// Record jitter measurement
    pub fn record_jitter(&mut self, jitter_ms: f64) {
        self.jitter_samples.push_back(jitter_ms);
        if self.jitter_samples.len() > 50 {
            self.jitter_samples.pop_front();
        }
    }

    /// Update connection health
    pub fn update_health(&mut self) -> ConnectionQuality {
        // Check for timeout
        let elapsed = self.last_heartbeat.elapsed();
        if elapsed > self.heartbeat_timeout {
            self.consecutive_timeouts += 1;
            if self.consecutive_timeouts > 3 {
                self.connection_quality = ConnectionQuality::Disconnected;
                return self.connection_quality;
            }
        } else {
            self.consecutive_timeouts = 0;
        }

        // Calculate current metrics
        let rtt = self.average_rtt();
        let packet_loss = self.packet_loss_rate();
        let jitter = self.average_jitter();

        // Determine quality level
        self.connection_quality = if rtt < 50.0 && packet_loss < 0.01 && jitter < 20.0 {
            ConnectionQuality::Excellent
        } else if rtt < 100.0 && packet_loss < 0.03 && jitter < 50.0 {
            ConnectionQuality::Good
        } else if rtt < 200.0 && packet_loss < 0.05 && jitter < 100.0 {
            ConnectionQuality::Fair
        } else {
            ConnectionQuality::Poor
        };

        // Store metrics
        let metrics = NetworkMetrics {
            rtt_ms: rtt,
            packet_loss_rate: packet_loss,
            jitter_ms: jitter,
            bandwidth_kbps: 0.0,  // Will be calculated separately
            timestamp: Instant::now(),
        };

        self.metrics_history.push_back(metrics);
        if self.metrics_history.len() > self.max_history {
            self.metrics_history.pop_front();
        }

        self.connection_quality
    }

    /// Get current connection quality
    pub fn quality(&self) -> ConnectionQuality {
        self.connection_quality
    }

    /// Get current metrics
    pub fn current_metrics(&self) -> Option<NetworkMetrics> {
        self.metrics_history.back().cloned()
    }

    /// Get average RTT
    pub fn average_rtt(&self) -> f64 {
        if self.rtt_samples.is_empty() {
            return 100.0; // Default estimate
        }
        self.rtt_samples.iter().sum::<f64>() / self.rtt_samples.len() as f64
    }

    /// Get average jitter
    pub fn average_jitter(&self) -> f64 {
        if self.jitter_samples.is_empty() {
            return 20.0; // Default estimate
        }
        self.jitter_samples.iter().sum::<f64>() / self.jitter_samples.len() as f64
    }

    /// Get packet loss rate
    pub fn packet_loss_rate(&self) -> f32 {
        let total = self.packets_sent;
        if total == 0 {
            return 0.0;
        }
        self.packets_lost as f32 / total as f32
    }

    /// Get statistics
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            packets_lost: self.packets_lost,
            packet_loss_rate: self.packet_loss_rate(),
            average_rtt_ms: self.average_rtt(),
            average_jitter_ms: self.average_jitter(),
            quality: self.connection_quality,
        }
    }

    /// Reset monitor
    pub fn reset(&mut self) {
        self.packets_sent = 0;
        self.packets_received = 0;
        self.packets_lost = 0;
        self.rtt_samples.clear();
        self.jitter_samples.clear();
        self.metrics_history.clear();
        self.consecutive_timeouts = 0;
        self.last_heartbeat = Instant::now();
        self.connection_quality = ConnectionQuality::Good;
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packets lost
    pub packets_lost: u64,
    /// Packet loss rate
    pub packet_loss_rate: f32,
    /// Average RTT in milliseconds
    pub average_rtt_ms: f64,
    /// Average jitter in milliseconds
    pub average_jitter_ms: f64,
    /// Connection quality
    pub quality: ConnectionQuality,
}

impl ConnectionQuality {
    /// Get quality as string
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionQuality::Excellent => "excellent",
            ConnectionQuality::Good => "good",
            ConnectionQuality::Fair => "fair",
            ConnectionQuality::Poor => "poor",
            ConnectionQuality::Disconnected => "disconnected",
        }
    }

    /// Get quality score (0-100)
    pub fn score(&self) -> u8 {
        match self {
            ConnectionQuality::Excellent => 100,
            ConnectionQuality::Good => 75,
            ConnectionQuality::Fair => 50,
            ConnectionQuality::Poor => 25,
            ConnectionQuality::Disconnected => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_health_monitor() {
        let stream_id = Uuid::new_v4();
        let mut monitor = ConnectionHealthMonitor::new(stream_id);

        // Record some packets with excellent metrics
        for _ in 0..10 {
            monitor.record_packet_sent();
            monitor.record_packet_received();
        }
        monitor.record_rtt(40.0);  // < 50ms
        monitor.record_jitter(10.0);  // < 20ms
        // No packet loss

        let quality = monitor.update_health();
        assert_eq!(quality, ConnectionQuality::Excellent);
    }

    #[test]
    fn test_connection_quality_scoring() {
        assert_eq!(ConnectionQuality::Excellent.score(), 100);
        assert_eq!(ConnectionQuality::Good.score(), 75);
        assert_eq!(ConnectionQuality::Fair.score(), 50);
        assert_eq!(ConnectionQuality::Poor.score(), 25);
        assert_eq!(ConnectionQuality::Disconnected.score(), 0);
    }

    #[test]
    fn test_packet_loss_calculation() {
        let stream_id = Uuid::new_v4();
        let mut monitor = ConnectionHealthMonitor::new(stream_id);

        // Send 100 packets, lose 5
        for _ in 0..100 {
            monitor.record_packet_sent();
        }
        for _ in 0..95 {
            monitor.record_packet_received();
        }
        for _ in 0..5 {
            monitor.record_packet_lost();
        }

        let loss_rate = monitor.packet_loss_rate();
        assert!((loss_rate - 0.05).abs() < 0.001); // ~5% loss
    }
}

