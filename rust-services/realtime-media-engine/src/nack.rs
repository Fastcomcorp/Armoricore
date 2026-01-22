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

//! Selective Retransmission (NACK)
//!
//! Implements NACK (Negative Acknowledgment) for requesting retransmission
//! of critical packets (audio keyframes, video I-frames).
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


// MediaEngineError and MediaEngineResult not used in this module
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// NACK configuration
#[derive(Debug, Clone)]
pub struct NackConfig {
    /// Maximum retransmissions per packet
    pub max_retries: u32,
    /// Timeout before giving up (milliseconds)
    pub timeout_ms: u64,
    /// Interval between NACK requests (milliseconds)
    pub nack_interval_ms: u64,
    /// Enable NACK
    pub enabled: bool,
}

impl Default for NackConfig {
    fn default() -> Self {
        NackConfig {
            max_retries: 3,
            timeout_ms: 100,  // 100ms timeout
            nack_interval_ms: 10,  // Request every 10ms
            enabled: true,
        }
    }
}

/// Missing packet information
#[derive(Debug, Clone)]
struct MissingPacket {
    #[allow(dead_code)]
    sequence: u16,
    first_requested: Instant,
    retry_count: u32,
    #[allow(dead_code)]
    is_critical: bool,  // Audio keyframe, video I-frame, etc.
}

/// NACK manager for tracking missing packets and generating NACK requests
pub struct NackManager {
    config: NackConfig,
    missing_packets: BTreeSet<u16>,
    missing_details: std::collections::HashMap<u16, MissingPacket>,
    last_nack: Instant,
    stream_id: Uuid,
}

impl NackManager {
    /// Create a new NACK manager
    pub fn new(config: NackConfig, stream_id: Uuid) -> Self {
        NackManager {
            config,
            missing_packets: BTreeSet::new(),
            missing_details: std::collections::HashMap::new(),
            last_nack: Instant::now(),
            stream_id,
        }
    }

    /// Detect packet loss (called when sequence gap is detected)
    pub fn detect_loss(&mut self, expected_sequence: u16, is_critical: bool) {
        if !self.config.enabled {
            return;
        }

        // Only request retransmission for critical packets or if within retry limit
        if is_critical || self.missing_packets.len() < 10 {
            self.missing_packets.insert(expected_sequence);
            self.missing_details.insert(
                expected_sequence,
                MissingPacket {
                    sequence: expected_sequence,
                    first_requested: Instant::now(),
                    retry_count: 0,
                    is_critical,
                },
            );
        }
    }

    /// Mark packet as received (remove from missing set)
    pub fn mark_received(&mut self, sequence: u16) {
        self.missing_packets.remove(&sequence);
        self.missing_details.remove(&sequence);
    }

    /// Generate NACK message if needed
    pub fn generate_nack(&mut self) -> Option<NackMessage> {
        if !self.config.enabled {
            return None;
        }

        // Check if enough time has passed since last NACK
        if self.last_nack.elapsed() < Duration::from_millis(self.config.nack_interval_ms) {
            return None;
        }

        // Clean up expired packets
        self.cleanup_expired();

        if self.missing_packets.is_empty() {
            return None;
        }

        // Build NACK message with missing sequences
        let missing_sequences: Vec<u16> = self.missing_packets.iter().cloned().collect();

        // Update retry counts
        for seq in &missing_sequences {
            if let Some(details) = self.missing_details.get_mut(seq) {
                details.retry_count += 1;
            }
        }

        self.last_nack = Instant::now();

        Some(NackMessage {
            stream_id: self.stream_id,
            missing_sequences,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        })
    }

    /// Clean up expired packets (give up after timeout)
    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let timeout = Duration::from_millis(self.config.timeout_ms);

        let expired: Vec<u16> = self
            .missing_details
            .iter()
            .filter(|(_, details)| {
                now.duration_since(details.first_requested) > timeout
                    || details.retry_count >= self.config.max_retries
            })
            .map(|(seq, _)| *seq)
            .collect();

        for seq in expired {
            self.missing_packets.remove(&seq);
            self.missing_details.remove(&seq);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> NackStats {
        NackStats {
            missing_count: self.missing_packets.len(),
            total_retries: self
                .missing_details
                .values()
                .map(|d| d.retry_count)
                .sum(),
        }
    }

    /// Reset NACK manager
    pub fn reset(&mut self) {
        self.missing_packets.clear();
        self.missing_details.clear();
        self.last_nack = Instant::now();
    }
}

/// NACK message to send
#[derive(Debug, Clone)]
pub struct NackMessage {
    /// Stream ID
    pub stream_id: Uuid,
    /// Missing sequence numbers
    pub missing_sequences: Vec<u16>,
    /// Timestamp
    pub timestamp: u64,
}

/// NACK statistics
#[derive(Debug, Clone)]
pub struct NackStats {
    /// Number of currently missing packets
    pub missing_count: usize,
    /// Total retry attempts
    pub total_retries: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nack_detect_loss() {
        let config = NackConfig::default();
        let stream_id = Uuid::new_v4();
        let mut manager = NackManager::new(config, stream_id);

        manager.detect_loss(100, true);
        assert_eq!(manager.missing_packets.len(), 1);
        assert!(manager.missing_packets.contains(&100));
    }

    #[test]
    fn test_nack_generate_message() {
        let config = NackConfig {
            nack_interval_ms: 0,  // No delay for testing
            ..Default::default()
        };
        let stream_id = Uuid::new_v4();
        let mut manager = NackManager::new(config, stream_id);

        manager.detect_loss(100, true);
        manager.detect_loss(101, true);

        let nack = manager.generate_nack();
        assert!(nack.is_some());
        let nack = nack.unwrap();
        assert_eq!(nack.missing_sequences.len(), 2);
        assert_eq!(nack.stream_id, stream_id);
    }

    #[test]
    fn test_nack_mark_received() {
        let config = NackConfig::default();
        let stream_id = Uuid::new_v4();
        let mut manager = NackManager::new(config, stream_id);

        manager.detect_loss(100, true);
        assert_eq!(manager.missing_packets.len(), 1);

        manager.mark_received(100);
        assert_eq!(manager.missing_packets.len(), 0);
    }

    #[test]
    fn test_nack_cleanup_expired() {
        let config = NackConfig {
            timeout_ms: 10,  // Very short timeout for testing
            ..Default::default()
        };
        let stream_id = Uuid::new_v4();
        let mut manager = NackManager::new(config, stream_id);

        manager.detect_loss(100, true);
        assert_eq!(manager.missing_packets.len(), 1);

        // Wait for timeout
        std::thread::sleep(Duration::from_millis(20));

        // Generate NACK to trigger cleanup
        manager.generate_nack();
        assert_eq!(manager.missing_packets.len(), 0);
    }
}

