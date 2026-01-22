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

//! Forward Error Correction (FEC)
//!
//! Implements XOR-based FEC for recovering from packet loss without retransmission.
//! For Phase 2, we use simple XOR FEC. Reed-Solomon can be added later.
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
use bytes::Bytes;

/// FEC configuration
#[derive(Debug, Clone)]
pub struct FecConfig {
    /// Redundancy ratio (0.0 - 1.0, typically 0.10 - 0.20)
    pub redundancy: f32,
    /// Block size (number of packets per FEC block)
    pub block_size: usize,
    /// Enable FEC
    pub enabled: bool,
}

impl Default for FecConfig {
    fn default() -> Self {
        FecConfig {
            redundancy: 0.15,  // 15% redundancy (good for VoIP)
            block_size: 10,    // 10 packets per block
            enabled: true,
        }
    }
}

/// FEC encoder for generating redundant packets
pub struct FecEncoder {
    config: FecConfig,
    current_block: Vec<RtpPacket>,
    block_index: usize,
}

impl FecEncoder {
    /// Create a new FEC encoder
    pub fn new(config: FecConfig) -> Self {
        FecEncoder {
            config,
            current_block: Vec::new(),
            block_index: 0,
        }
    }

    /// Add a packet to the current block and generate FEC packets if needed
    pub fn add_packet(&mut self, packet: RtpPacket) -> MediaEngineResult<Vec<FecPacket>> {
        if !self.config.enabled {
            return Ok(vec![]);
        }

        self.current_block.push(packet);
        self.block_index += 1;

        // Generate FEC packets when block is complete
        if self.current_block.len() >= self.config.block_size {
            let fec_packets = self.generate_fec_packets()?;
            self.current_block.clear();
            self.block_index = 0;
            Ok(fec_packets)
        } else {
            Ok(vec![])
        }
    }

    /// Generate FEC packets using XOR
    fn generate_fec_packets(&self) -> MediaEngineResult<Vec<FecPacket>> {
        if self.current_block.is_empty() {
            return Ok(vec![]);
        }

        // Calculate number of FEC packets to generate
        let num_fec_packets = (self.current_block.len() as f32 * self.config.redundancy).ceil() as usize;
        
        if num_fec_packets == 0 {
            return Ok(vec![]);
        }

        let mut fec_packets = Vec::with_capacity(num_fec_packets);

        // Generate FEC packets by XORing source packets
        for fec_idx in 0..num_fec_packets {
            // XOR all packets in the block
            let mut fec_payload = if let Some(first) = self.current_block.first() {
                first.payload.to_vec()
            } else {
                continue;
            };

            // XOR with remaining packets
            for packet in self.current_block.iter().skip(1) {
                let min_len = fec_payload.len().min(packet.payload.len());
                for i in 0..min_len {
                    fec_payload[i] ^= packet.payload[i];
                }
                // Extend if needed
                if packet.payload.len() > fec_payload.len() {
                    fec_payload.extend_from_slice(&packet.payload[fec_payload.len()..]);
                }
            }

            // Create FEC packet using the first packet's header as template
            let base_packet = &self.current_block[0];
            let fec_packet = FecPacket {
                sequence_number: base_packet.header.sequence_number + fec_idx as u16 + 1,
                block_index: self.block_index as u16,
                fec_index: fec_idx as u16,
                payload: Bytes::from(fec_payload),
                source_sequences: self.current_block
                    .iter()
                    .map(|p| p.header.sequence_number)
                    .collect(),
            };

            fec_packets.push(fec_packet);
        }

        Ok(fec_packets)
    }

    /// Flush remaining packets in block (for end of stream)
    pub fn flush(&mut self) -> MediaEngineResult<Vec<FecPacket>> {
        if self.current_block.is_empty() {
            return Ok(vec![]);
        }

        let fec_packets = self.generate_fec_packets()?;
        self.current_block.clear();
        self.block_index = 0;
        Ok(fec_packets)
    }
}

/// FEC packet structure
#[derive(Debug, Clone)]
pub struct FecPacket {
    /// Sequence number for this FEC packet
    pub sequence_number: u16,
    /// Block index
    pub block_index: u16,
    /// FEC packet index within block
    pub fec_index: u16,
    /// FEC payload (XOR of source packets)
    pub payload: Bytes,
    /// Source packet sequence numbers
    pub source_sequences: Vec<u16>,
}

/// FEC decoder for recovering lost packets
pub struct FecDecoder {
    config: FecConfig,
    received_packets: Vec<Option<RtpPacket>>,
    fec_packets: Vec<FecPacket>,
    block_start_sequence: Option<u16>,
}

impl FecDecoder {
    /// Create a new FEC decoder
    pub fn new(config: FecConfig) -> Self {
        let block_size = config.block_size;
        FecDecoder {
            config,
            received_packets: Vec::with_capacity(block_size),
            fec_packets: Vec::new(),
            block_start_sequence: None,
        }
    }

    /// Add a received RTP packet
    pub fn add_packet(&mut self, packet: RtpPacket) -> MediaEngineResult<Vec<RtpPacket>> {
        if !self.config.enabled {
            return Ok(vec![packet]);
        }

        let seq = packet.header.sequence_number;

        // Initialize block if needed
        if self.block_start_sequence.is_none() {
            self.block_start_sequence = Some(seq);
            self.received_packets.clear();
            self.received_packets.resize(self.config.block_size, None);
        }

        let block_start = self.block_start_sequence.unwrap();
        let offset = seq.wrapping_sub(block_start) as usize;

        // Check if packet is within current block
        if offset < self.config.block_size {
            self.received_packets[offset] = Some(packet);
        }

        // Try to recover lost packets
        self.try_recover()
    }

    /// Add a received FEC packet
    pub fn add_fec_packet(&mut self, fec_packet: FecPacket) -> MediaEngineResult<Vec<RtpPacket>> {
        if !self.config.enabled {
            return Ok(vec![]);
        }

        self.fec_packets.push(fec_packet);

        // Try to recover lost packets
        self.try_recover()
    }

    /// Try to recover lost packets using FEC
    fn try_recover(&mut self) -> MediaEngineResult<Vec<RtpPacket>> {
        let mut recovered = Vec::new();

        // Count received packets
        let received_count = self.received_packets.iter().filter(|p| p.is_some()).count();
        let lost_count = self.config.block_size - received_count;

        // Need at least one FEC packet and some lost packets
        if self.fec_packets.is_empty() || lost_count == 0 {
            return Ok(recovered);
        }

        // If we have enough FEC packets, try to recover
        if self.fec_packets.len() >= lost_count {
            // Simple recovery: XOR FEC packet with all received packets
            for fec_packet in &self.fec_packets {
                // Find which packet this FEC can recover
                for (idx, received) in self.received_packets.iter().enumerate() {
                    if received.is_none() {
                        // Try to recover this packet
                        if let Some(recovered_packet) = self.recover_packet(idx, fec_packet)? {
                            self.received_packets[idx] = Some(recovered_packet.clone());
                            recovered.push(recovered_packet);
                            break;
                        }
                    }
                }
            }
        }

        // Check if block is complete
        if self.received_packets.iter().all(|p| p.is_some()) {
            // Block complete, reset for next block
            let mut completed_packets = Vec::new();
            for packet in self.received_packets.drain(..) {
                if let Some(p) = packet {
                    completed_packets.push(p);
                }
            }
            self.fec_packets.clear();
            self.block_start_sequence = None;
            return Ok(completed_packets);
        }

        Ok(recovered)
    }

    /// Recover a single packet using FEC
    fn recover_packet(&self, index: usize, fec_packet: &FecPacket) -> MediaEngineResult<Option<RtpPacket>> {
        // XOR FEC payload with all received packets except the one we're recovering
        let mut recovered_payload = fec_packet.payload.to_vec();

        for (idx, received) in self.received_packets.iter().enumerate() {
            if idx != index {
                if let Some(packet) = received {
                    let min_len = recovered_payload.len().min(packet.payload.len());
                    for i in 0..min_len {
                        recovered_payload[i] ^= packet.payload[i];
                    }
                }
            }
        }

        // Create recovered packet using first received packet as template
        if let Some(template) = self.received_packets.iter().find_map(|p| p.as_ref()) {
            
            let block_start = self.block_start_sequence.unwrap();
            let recovered_seq = block_start.wrapping_add(index as u16);
            
            let mut header = template.header.clone();
            header.sequence_number = recovered_seq;
            header.marker = false; // FEC-recovered packets are not markers

            Ok(Some(RtpPacket {
                header,
                payload: Bytes::from(recovered_payload),
            }))
        } else {
            Ok(None)
        }
    }

    /// Reset decoder for new block
    pub fn reset(&mut self) {
        self.received_packets.clear();
        self.fec_packets.clear();
        self.block_start_sequence = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_handler::{RtpHeader, RtpPacket};
    use bytes::Bytes;

    fn create_test_packet(seq: u16, payload_data: &[u8]) -> RtpPacket {
        RtpPacket {
            header: RtpHeader {
                version: 2,
                padding: false,
                extension: false,
                csrc_count: 0,
                marker: false,
                payload_type: 96,
                sequence_number: seq,
                timestamp: 1000,
                ssrc: 12345,
                csrc: vec![],
                extension_header: None,
            },
            payload: Bytes::copy_from_slice(payload_data),
        }
    }

    #[test]
    fn test_fec_encoder_generates_packets() {
        let config = FecConfig {
            redundancy: 0.2,  // 20%
            block_size: 5,
            enabled: true,
        };

        let mut encoder = FecEncoder::new(config);

        // Add 5 packets
        for i in 0..5 {
            let packet = create_test_packet(i, &[i as u8; 10]);
            let fec_packets = encoder.add_packet(packet).unwrap();
            
            if i == 4 {
                // Should generate FEC packets on 5th packet
                assert_eq!(fec_packets.len(), 1); // 20% of 5 = 1 packet
            } else {
                assert_eq!(fec_packets.len(), 0);
            }
        }
    }

    #[test]
    fn test_fec_decoder_recovers_lost_packet() {
        let config = FecConfig {
            redundancy: 0.2,
            block_size: 5,
            enabled: true,
        };

        let mut decoder = FecDecoder::new(config);

        // Simulate receiving packets 0, 1, 3, 4 (missing 2)
        let packets = vec![
            create_test_packet(0, &[0; 10]),
            create_test_packet(1, &[1; 10]),
            create_test_packet(3, &[3; 10]),
            create_test_packet(4, &[4; 10]),
        ];

        for packet in packets {
            decoder.add_packet(packet).unwrap();
        }

        // Add FEC packet
        let fec_packet = FecPacket {
            sequence_number: 100,
            block_index: 0,
            fec_index: 0,
            payload: Bytes::from(vec![0u8; 10]), // XOR of all packets
            source_sequences: vec![0, 1, 2, 3, 4],
        };

        let recovered = decoder.add_fec_packet(fec_packet).unwrap();
        // Should recover packet 2
        assert!(!recovered.is_empty());
    }
}

