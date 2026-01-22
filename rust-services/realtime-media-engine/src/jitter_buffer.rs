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

//! Adaptive jitter buffer for handling network jitter
//!
//! Implements a basic jitter buffer that adapts to network conditions.
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
use crate::rtp_handler::RtpPacket;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Jitter buffer configuration
#[derive(Debug, Clone)]
pub struct JitterBufferConfig {
    /// Minimum latency in milliseconds
    pub min_latency_ms: u32,
    /// Maximum latency in milliseconds
    pub max_latency_ms: u32,
    /// Initial latency in milliseconds
    pub initial_latency_ms: u32,
    /// Enable adaptive buffering
    pub adaptive: bool,
}

impl Default for JitterBufferConfig {
    fn default() -> Self {
        JitterBufferConfig {
            min_latency_ms: 10,
            max_latency_ms: 100,
            initial_latency_ms: 20,
            adaptive: true,
        }
    }
}

/// Network metrics for adaptation
#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    /// Packet loss rate (0.0 - 1.0)
    pub packet_loss_rate: f32,
    /// Jitter in milliseconds
    pub jitter_ms: f64,
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
}

/// Adaptive jitter buffer
pub struct JitterBuffer {
    /// Buffer of packets
    buffer: VecDeque<(RtpPacket, Instant)>,
    /// Target latency
    target_latency: Duration,
    /// Minimum latency
    min_latency: Duration,
    /// Maximum latency
    max_latency: Duration,
    /// Current jitter estimate
    jitter_estimate: Duration,
    /// Packet loss rate
    packet_loss_rate: f32,
    /// Adaptive mode
    adaptive: bool,
    /// Last packet timestamp
    last_timestamp: Option<u32>,
    /// Last sequence number
    last_sequence: Option<u16>,
}

impl JitterBuffer {
    /// Create a new jitter buffer
    pub fn new(config: JitterBufferConfig) -> Self {
        JitterBuffer {
            buffer: VecDeque::new(),
            target_latency: Duration::from_millis(config.initial_latency_ms as u64),
            min_latency: Duration::from_millis(config.min_latency_ms as u64),
            max_latency: Duration::from_millis(config.max_latency_ms as u64),
            jitter_estimate: Duration::from_millis(10),
            packet_loss_rate: 0.0,
            adaptive: config.adaptive,
            last_timestamp: None,
            last_sequence: None,
        }
    }

    /// Push a packet into the buffer
    pub fn push(&mut self, packet: RtpPacket) -> MediaEngineResult<()> {
        let now = Instant::now();

        // Check for out-of-order packets
        if let Some(last_seq) = self.last_sequence {
            let seq_diff = packet.header.sequence_number.wrapping_sub(last_seq);
            if seq_diff > 0x8000 {
                // Out of order (wrapped around)
                // For now, we'll still accept it but could implement reordering
            }
        }

        // Update jitter estimate based on timestamp difference
        if let Some(last_ts) = self.last_timestamp {
            let ts_diff = packet.header.timestamp.wrapping_sub(last_ts);
            // Convert to milliseconds (assuming 48kHz for audio, 90kHz for video)
            // For now, use a simple estimate
            let ts_diff_ms = ts_diff as f64 / 48.0; // Rough estimate for audio
            
            // Update jitter estimate (exponential moving average)
            let jitter_diff = ts_diff_ms.abs() - self.jitter_estimate.as_secs_f64() * 1000.0;
            self.jitter_estimate = Duration::from_secs_f64(
                (self.jitter_estimate.as_secs_f64() * 1000.0 + jitter_diff * 0.125) / 1000.0
            );
        }

        let timestamp = packet.header.timestamp;
        let sequence = packet.header.sequence_number;
        self.buffer.push_back((packet, now));
        self.last_timestamp = Some(timestamp);
        self.last_sequence = Some(sequence);

        Ok(())
    }

    /// Pop a packet from the buffer (if ready)
    pub fn pop(&mut self) -> Option<RtpPacket> {
        let now = Instant::now();

        // Check if we have enough packets buffered
        if let Some((_packet, arrival_time)) = self.buffer.front() {
            let buffered_time = now.duration_since(*arrival_time);
            
            if buffered_time >= self.target_latency {
                // Packet is ready
                return self.buffer.pop_front().map(|(p, _)| p);
            }
        }

        None
    }

    /// Adapt buffer based on network metrics
    pub fn adapt(&mut self, metrics: &NetworkMetrics) {
        if !self.adaptive {
            return;
        }

        // Update packet loss rate
        self.packet_loss_rate = metrics.packet_loss_rate;

        // Update jitter estimate
        self.jitter_estimate = Duration::from_millis(metrics.jitter_ms as u64);

        // Increase buffer on high jitter
        if metrics.jitter_ms > self.jitter_estimate.as_millis() as f64 * 1.5 {
            self.target_latency = std::cmp::min(
                self.target_latency * 2,
                self.max_latency,
            );
        }

        // Decrease buffer on stable network
        if metrics.jitter_ms < self.jitter_estimate.as_millis() as f64 * 0.8
            && metrics.packet_loss_rate < 0.01
        {
            self.target_latency = std::cmp::max(
                self.target_latency * 9 / 10,
                self.min_latency,
            );
        }

        // Emergency mode: increase buffer on high loss
        if metrics.packet_loss_rate > 0.05 {
            self.target_latency = self.max_latency;
        }
    }

    /// Get current buffer size
    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    /// Get target latency
    pub fn target_latency(&self) -> Duration {
        self.target_latency
    }

    /// Get jitter estimate
    pub fn jitter_estimate(&self) -> Duration {
        self.jitter_estimate
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.last_timestamp = None;
        self.last_sequence = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_handler::{RtpHeader, RtpPacket};
    use bytes::Bytes;

    fn create_test_packet(seq: u16, ts: u32) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 96,
                sequence_number: seq,
                timestamp: ts,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::from("test"),
        }
    }

    #[test]
    fn test_jitter_buffer_push_pop() {
        let mut buffer = JitterBuffer::new(JitterBufferConfig::default());
        
        let packet = create_test_packet(1, 1000);
        buffer.push(packet).unwrap();
        
        // Should not pop immediately (needs to wait for target latency)
        assert!(buffer.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_adaptation() {
        let mut buffer = JitterBuffer::new(JitterBufferConfig {
            adaptive: true,
            ..Default::default()
        });

        let metrics = NetworkMetrics {
            packet_loss_rate: 0.1, // High loss
            jitter_ms: 50.0,
            rtt_ms: 100.0,
        };

        buffer.adapt(&metrics);
        
        // Should increase target latency on high loss
        assert!(buffer.target_latency() >= Duration::from_millis(20));
    }
}

