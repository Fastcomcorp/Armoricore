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

//! RFC 4588 - RTP Retransmission Payload Format
//!
//! Implements RTP retransmission for reliable media recovery.
//! Boosts Quality of Experience (QoE) in lossy networks.
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


use crate::error::{MediaEngineError, MediaEngineResult};
use crate::rtp_handler::RtpPacket;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[cfg(test)]
use bytes::Bytes;

/// Retransmission Request (RFC 4588)
#[derive(Debug, Clone)]
pub struct RetransmissionRequest {
    /// SSRC of the source
    pub ssrc: u32,
    /// Sequence numbers to retransmit
    pub sequence_numbers: Vec<u16>,
    /// Timestamp of the request
    pub timestamp: Instant,
}

/// RTP Retransmission Handler (RFC 4588)
/// 
/// Enhanced with sequence number tracking for accurate retransmission.
pub struct RtpRetransmissionHandler {
    /// Buffer of sent packets (for retransmission)
    sent_packets: HashMap<u16, (RtpPacket, Instant)>,
    /// Sequence number history for tracking gaps
    sequence_history: VecDeque<u16>,
    /// Maximum sequence history size
    max_history_size: usize,
    /// Last sequence number seen
    last_sequence: Option<u16>,
    /// Maximum buffer size
    max_buffer_size: usize,
    /// Packet timeout (after which packets are removed from buffer)
    packet_timeout: Duration,
    /// Retransmission payload type (typically original payload type + 1)
    retransmission_payload_type: u8,
}

impl RtpRetransmissionHandler {
    /// Create a new RTP retransmission handler
    pub fn new(
        max_buffer_size: usize,
        packet_timeout: Duration,
        retransmission_payload_type: u8,
    ) -> Self {
        Self {
            sent_packets: HashMap::new(),
            sequence_history: VecDeque::with_capacity(1000),
            max_history_size: 1000,
            last_sequence: None,
            max_buffer_size,
            packet_timeout,
            retransmission_payload_type,
        }
    }

    /// Store a sent packet for potential retransmission
    /// 
    /// Enhanced with sequence number tracking for accurate gap detection.
    pub fn store_sent_packet(&mut self, packet: RtpPacket) {
        // Clean up old packets
        self.cleanup_old_packets();

        let seq_num = packet.header.sequence_number;

        // Update sequence history
        self.update_sequence_history(seq_num);

        // Check buffer size
        if self.sent_packets.len() >= self.max_buffer_size {
            // Remove oldest packet (simple FIFO - in production, use LRU)
            if let Some(oldest_seq) = self.sent_packets.keys().min().copied() {
                self.sent_packets.remove(&oldest_seq);
            }
        }

        self.sent_packets.insert(seq_num, (packet, Instant::now()));
    }

    /// Update sequence number history for gap detection
    fn update_sequence_history(&mut self, seq_num: u16) {
        // Add to history
        if self.sequence_history.len() >= self.max_history_size {
            self.sequence_history.pop_front();
        }
        self.sequence_history.push_back(seq_num);

        // Update last sequence
        self.last_sequence = Some(seq_num);
    }

    /// Detect missing sequence numbers based on history
    /// 
    /// Returns a list of missing sequence numbers that should be retransmitted.
    pub fn detect_missing_sequences(&self, expected_sequence: u16) -> Vec<u16> {
        let mut missing = Vec::new();

        if let Some(last_seq) = self.last_sequence {
            // Calculate gap
            let gap = expected_sequence.wrapping_sub(last_seq);
            
            if gap > 0 && gap < 1000 { // Reasonable gap size
                // Generate missing sequence numbers
                for i in 1..gap {
                    let missing_seq = last_seq.wrapping_add(i as u16);
                    // Only include if not in sent_packets (truly missing)
                    if !self.sent_packets.contains_key(&missing_seq) {
                        missing.push(missing_seq);
                    }
                }
            }
        }

        missing
    }

    /// Create retransmission packet (RFC 4588)
    ///
    /// RFC 4588 defines a retransmission payload format that includes:
    /// - Original RTP header (with modified payload type)
    /// - Original RTP payload
    pub fn create_retransmission_packet(
        &self,
        sequence_number: u16,
    ) -> MediaEngineResult<RtpPacket> {
        let (original_packet, _) = self
            .sent_packets
            .get(&sequence_number)
            .ok_or_else(|| {
                MediaEngineError::RtpParseError(format!(
                    "Packet {} not found in retransmission buffer",
                    sequence_number
                ))
            })?;

        // Create retransmission packet with original RTP header
        // but with retransmission payload type
        let mut retransmission_header = original_packet.header.clone();
        retransmission_header.payload_type = self.retransmission_payload_type;
        retransmission_header.marker = false; // Retransmission packets don't use marker bit

        Ok(RtpPacket {
            header: retransmission_header,
            payload: original_packet.payload.clone(),
        })
    }

    /// Process retransmission request and return packets to retransmit
    pub fn process_retransmission_request(
        &self,
        request: &RetransmissionRequest,
    ) -> MediaEngineResult<Vec<RtpPacket>> {
        let mut retransmission_packets = Vec::new();

        for &seq_num in &request.sequence_numbers {
            if let Ok(packet) = self.create_retransmission_packet(seq_num) {
                retransmission_packets.push(packet);
            }
        }

        Ok(retransmission_packets)
    }

    /// Extract original packet from retransmission packet (RFC 4588)
    ///
    /// When receiving a retransmission packet, extract the original RTP packet.
    pub fn extract_original_packet(
        &self,
        retransmission_packet: &RtpPacket,
        original_payload_type: u8,
    ) -> RtpPacket {
        // Retransmission packet has the same structure as original,
        // just with different payload type
        let mut original_header = retransmission_packet.header.clone();
        original_header.payload_type = original_payload_type;

        RtpPacket {
            header: original_header,
            payload: retransmission_packet.payload.clone(),
        }
    }

    /// Clean up old packets from buffer
    fn cleanup_old_packets(&mut self) {
        let now = Instant::now();
        self.sent_packets.retain(|_, (_, timestamp)| {
            now.duration_since(*timestamp) < self.packet_timeout
        });
    }

    /// Get statistics about the retransmission buffer
    pub fn get_stats(&self) -> RetransmissionStats {
        RetransmissionStats {
            buffered_packets: self.sent_packets.len(),
            max_buffer_size: self.max_buffer_size,
        }
    }
}

/// Retransmission statistics
#[derive(Debug, Clone)]
pub struct RetransmissionStats {
    /// Number of packets currently buffered
    pub buffered_packets: usize,
    /// Maximum buffer size
    pub max_buffer_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_handler::RtpHeader;

    fn create_test_packet(seq_num: u16) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 96,
                sequence_number: seq_num,
                timestamp: 1000,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::from("test payload"),
        }
    }

    #[test]
    fn test_store_and_retransmit() {
        let mut handler = RtpRetransmissionHandler::new(100, Duration::from_secs(10), 97);
        
        let packet = create_test_packet(1);
        handler.store_sent_packet(packet);

        let retransmission = handler.create_retransmission_packet(1).unwrap();
        assert_eq!(retransmission.header.payload_type, 97);
        assert_eq!(retransmission.header.sequence_number, 1);
    }

    #[test]
    fn test_retransmission_request() {
        let mut handler = RtpRetransmissionHandler::new(100, Duration::from_secs(10), 97);
        
        handler.store_sent_packet(create_test_packet(1));
        handler.store_sent_packet(create_test_packet(2));
        handler.store_sent_packet(create_test_packet(3));

        let request = RetransmissionRequest {
            ssrc: 12345,
            sequence_numbers: vec![1, 3],
            timestamp: Instant::now(),
        };

        let retransmitted = handler.process_retransmission_request(&request).unwrap();
        assert_eq!(retransmitted.len(), 2);
    }
}

