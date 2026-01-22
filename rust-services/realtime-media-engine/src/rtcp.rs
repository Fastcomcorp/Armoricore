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

//! RTCP (RTP Control Protocol) implementation
//!
//! Implements RFC 3550 RTCP packet types for RTP session control and statistics.
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
use crate::rtp_retransmission::RetransmissionRequest;
use bytes::{BufMut, BytesMut};
use std::time::{SystemTime, UNIX_EPOCH, Instant};

/// RTCP packet types (RFC 3550 Section 6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpPacketType {
    /// Sender Report (SR) - 200
    SenderReport = 200,
    /// Receiver Report (RR) - 201
    ReceiverReport = 201,
    /// Source Description (SDES) - 202
    SourceDescription = 202,
    /// Goodbye (BYE) - 203
    Goodbye = 203,
    /// Application Defined (APP) - 204
    ApplicationDefined = 204,
}

/// RTCP packet header (RFC 3550 Section 6.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpHeader {
    /// Version (must be 2)
    pub version: u8,
    /// Padding flag
    pub padding: bool,
    /// Reception report count (for SR/RR) or source count (for SDES/BYE)
    pub count: u8,
    /// Packet type
    pub packet_type: RtcpPacketType,
    /// Length in 32-bit words minus 1
    pub length: u16,
}

/// RTCP Sender Report (RFC 3550 Section 6.4.1)
#[derive(Debug, Clone)]
pub struct SenderReport {
    /// Header
    pub header: RtcpHeader,
    /// SSRC of sender
    pub ssrc: u32,
    /// NTP timestamp (most significant word)
    pub ntp_timestamp_msw: u32,
    /// NTP timestamp (least significant word)
    pub ntp_timestamp_lsw: u32,
    /// RTP timestamp
    pub rtp_timestamp: u32,
    /// Sender's packet count
    pub sender_packet_count: u32,
    /// Sender's octet count
    pub sender_octet_count: u32,
    /// Reception report blocks (0-31)
    pub reception_reports: Vec<ReceptionReport>,
}

/// RTCP Receiver Report (RFC 3550 Section 6.4.2)
#[derive(Debug, Clone)]
pub struct ReceiverReport {
    /// Header
    pub header: RtcpHeader,
    /// SSRC of receiver
    pub ssrc: u32,
    /// Reception report blocks (0-31)
    pub reception_reports: Vec<ReceptionReport>,
}

/// Reception report block (RFC 3550 Section 6.4.1)
#[derive(Debug, Clone)]
pub struct ReceptionReport {
    /// SSRC of source
    pub ssrc: u32,
    /// Fraction lost (8 bits)
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (24 bits, signed)
    pub cumulative_packets_lost: i32,
    /// Extended highest sequence number received
    pub extended_sequence_number: u32,
    /// Interarrival jitter (RFC 3550 Section 6.4.1)
    pub jitter: u32,
    /// Last SR timestamp (LSR)
    pub last_sr_timestamp: u32,
    /// Delay since last SR (DLSR)
    pub delay_since_last_sr: u32,
}

/// RTCP Source Description (SDES) (RFC 3550 Section 6.5)
#[derive(Debug, Clone)]
pub struct SourceDescription {
    /// Header
    pub header: RtcpHeader,
    /// SDES chunks
    pub chunks: Vec<SdesChunk>,
}

/// SDES chunk (RFC 3550 Section 6.5)
#[derive(Debug, Clone)]
pub struct SdesChunk {
    /// SSRC or CSRC
    pub ssrc: u32,
    /// SDES items
    pub items: Vec<SdesItem>,
}

/// SDES item (RFC 3550 Section 6.5)
#[derive(Debug, Clone)]
pub struct SdesItem {
    /// Item type
    pub item_type: SdesItemType,
    /// Item value
    pub value: String,
}

/// SDES item types (RFC 3550 Section 6.5.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdesItemType {
    /// CNAME (Canonical End-Point Identifier) - required
    Cname = 1,
    /// NAME (User Name)
    Name = 2,
    /// EMAIL (Electronic Mail Address)
    Email = 3,
    /// PHONE (Phone Number)
    Phone = 4,
    /// LOC (Geographic User Location)
    Loc = 5,
    /// TOOL (Application or Tool Name)
    Tool = 6,
    /// NOTE (Notice/Status)
    Note = 7,
    /// PRIV (Private Extensions)
    Priv = 8,
}

/// RTCP Goodbye (BYE) (RFC 3550 Section 6.6)
#[derive(Debug, Clone)]
pub struct Goodbye {
    /// Header
    pub header: RtcpHeader,
    /// SSRCs/CSRCs leaving
    pub ssrcs: Vec<u32>,
    /// Optional reason for leaving
    pub reason: Option<String>,
}

impl RtcpHeader {
    /// Parse RTCP header from bytes
    pub fn parse(data: &[u8]) -> MediaEngineResult<(Self, &[u8])> {
        if data.len() < 4 {
            return Err(MediaEngineError::RtpParseError(
                "RTCP header too short".to_string()
            ));
        }

        let first_byte = data[0];
        let version = (first_byte >> 6) & 0x03;
        if version != 2 {
            return Err(MediaEngineError::RtpParseError(
                format!("Invalid RTCP version: {}", version)
            ));
        }
        let padding = (first_byte & 0x20) != 0;
        let count = first_byte & 0x1F;

        let packet_type = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);

        let packet_type_enum = match packet_type {
            200 => RtcpPacketType::SenderReport,
            201 => RtcpPacketType::ReceiverReport,
            202 => RtcpPacketType::SourceDescription,
            203 => RtcpPacketType::Goodbye,
            204 => RtcpPacketType::ApplicationDefined,
            _ => {
                return Err(MediaEngineError::RtpParseError(
                    format!("Unknown RTCP packet type: {}", packet_type)
                ));
            }
        };

        let header = RtcpHeader {
            version,
            padding,
            count,
            packet_type: packet_type_enum,
            length,
        };

        Ok((header, &data[4..]))
    }

    /// Serialize RTCP header to bytes
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(4);

        let mut first_byte = (self.version & 0x03) << 6;
        if self.padding {
            first_byte |= 0x20;
        }
        first_byte |= self.count & 0x1F;

        buf.put_u8(first_byte);
        buf.put_u8(self.packet_type as u8);
        buf.put_u16(self.length);

        buf
    }
}

impl SenderReport {
    /// Create a new Sender Report
    pub fn new(
        ssrc: u32,
        rtp_timestamp: u32,
        sender_packet_count: u32,
        sender_octet_count: u32,
        reception_reports: Vec<ReceptionReport>,
    ) -> Self {
        // Get NTP timestamp
        let ntp_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ntp_msw = (ntp_time + 2208988800) as u32; // NTP epoch offset
        let ntp_lsw = 0; // Fractional seconds (simplified)

        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: reception_reports.len().min(31) as u8,
            packet_type: RtcpPacketType::SenderReport,
            length: 0, // Will be calculated during serialization
        };

        SenderReport {
            header,
            ssrc,
            ntp_timestamp_msw: ntp_msw,
            ntp_timestamp_lsw: ntp_lsw,
            rtp_timestamp,
            sender_packet_count,
            sender_octet_count,
            reception_reports,
        }
    }

    /// Serialize Sender Report to bytes (RFC 3550 compliant)
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // Header (will update length later)
        let header_start = buf.len();
        buf.put_slice(&self.header.serialize());

        // SSRC
        buf.put_u32(self.ssrc);

        // NTP timestamp
        buf.put_u32(self.ntp_timestamp_msw);
        buf.put_u32(self.ntp_timestamp_lsw);

        // RTP timestamp
        buf.put_u32(self.rtp_timestamp);

        // Sender packet count
        buf.put_u32(self.sender_packet_count);

        // Sender octet count
        buf.put_u32(self.sender_octet_count);

        // Reception reports
        for report in &self.reception_reports {
            buf.put_u32(report.ssrc);
            buf.put_u8(report.fraction_lost);
            // Cumulative packets lost (24 bits signed)
            let lost_bytes = report.cumulative_packets_lost.to_be_bytes();
            buf.put_u8(lost_bytes[1]);
            buf.put_u8(lost_bytes[2]);
            buf.put_u8(lost_bytes[3]);
            buf.put_u32(report.extended_sequence_number);
            buf.put_u32(report.jitter);
            buf.put_u32(report.last_sr_timestamp);
            buf.put_u32(report.delay_since_last_sr);
        }

        // Update length in header (in 32-bit words minus 1)
        let total_length = buf.len();
        let length_words = (total_length / 4) - 1;
        buf[header_start + 2..header_start + 4]
            .copy_from_slice(&(length_words as u16).to_be_bytes());

        buf
    }
}

impl ReceiverReport {
    /// Create a new Receiver Report
    pub fn new(ssrc: u32, reception_reports: Vec<ReceptionReport>) -> Self {
        let header = RtcpHeader {
            version: 2,
            padding: false,
            count: reception_reports.len().min(31) as u8,
            packet_type: RtcpPacketType::ReceiverReport,
            length: 0, // Will be calculated during serialization
        };

        ReceiverReport {
            header,
            ssrc,
            reception_reports,
        }
    }

    /// Serialize Receiver Report to bytes (RFC 3550 compliant)
    pub fn serialize(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        // Header (will update length later)
        let header_start = buf.len();
        buf.put_slice(&self.header.serialize());

        // SSRC
        buf.put_u32(self.ssrc);

        // Reception reports
        for report in &self.reception_reports {
            buf.put_u32(report.ssrc);
            buf.put_u8(report.fraction_lost);
            // Cumulative packets lost (24 bits signed)
            let lost_bytes = report.cumulative_packets_lost.to_be_bytes();
            buf.put_u8(lost_bytes[1]);
            buf.put_u8(lost_bytes[2]);
            buf.put_u8(lost_bytes[3]);
            buf.put_u32(report.extended_sequence_number);
            buf.put_u32(report.jitter);
            buf.put_u32(report.last_sr_timestamp);
            buf.put_u32(report.delay_since_last_sr);
        }

        // Update length in header
        let total_length = buf.len();
        let length_words = (total_length / 4) - 1;
        buf[header_start + 2..header_start + 4]
            .copy_from_slice(&(length_words as u16).to_be_bytes());

        buf
    }

    /// Generate retransmission request from reception report (RFC 4588 integration)
    /// 
    /// Converts RTCP reception report packet loss information into
    /// retransmission requests for RFC 4588 handler.
    pub fn generate_retransmission_request(
        &self,
        source_ssrc: u32,
        last_sequence: u16,
    ) -> Option<RetransmissionRequest> {
        // Find reception report for the source SSRC
        let report = self.reception_reports.iter()
            .find(|r| r.ssrc == source_ssrc)?;

        // If no packets lost, no retransmission needed
        if report.cumulative_packets_lost <= 0 && report.fraction_lost == 0 {
            return None;
        }

        // Calculate missing sequence numbers
        // Note: This is a simplified approach. In production, you'd track
        // the exact sequence numbers that were lost.
        let mut missing_sequences = Vec::new();
        
        // Estimate missing sequences based on cumulative loss
        if report.cumulative_packets_lost > 0 {
            // For simplicity, request retransmission of recent packets
            // In production, maintain a sequence number history
            let lost_count = report.cumulative_packets_lost.min(50) as u16; // Limit to 50 packets
            for i in 1..=lost_count {
                let seq = last_sequence.wrapping_sub(lost_count).wrapping_add(i);
                missing_sequences.push(seq);
            }
        }

        if missing_sequences.is_empty() {
            return None;
        }

        Some(RetransmissionRequest {
            ssrc: source_ssrc,
            sequence_numbers: missing_sequences,
            timestamp: Instant::now(),
        })
    }
}

/// Calculate interarrival jitter per RFC 3550 Section 6.4.1
pub fn calculate_jitter(
    previous_jitter: u32,
    previous_timestamp: u32,
    current_timestamp: u32,
    arrival_time: u32,
) -> u32 {
    // D(i,j) = (R(j) - R(i)) - (S(j) - S(i))
    // J(i) = J(i-1) + (|D(i-1,i)| - J(i-1)) / 16
    let d = (arrival_time as i64) - (previous_timestamp as i64) - 
            ((current_timestamp as i64) - (previous_timestamp as i64));
    let d_abs = d.abs() as u32;
    
    previous_jitter + ((d_abs as i64 - previous_jitter as i64) / 16) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtcp_header_parse() {
        let data = [
            0x81, 0xC8, // V=2, P=0, RC=1, PT=200 (SR)
            0x00, 0x06, // Length = 7 words (28 bytes)
        ];

        let (header, _) = RtcpHeader::parse(&data).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.padding, false);
        assert_eq!(header.count, 1);
        assert_eq!(header.packet_type, RtcpPacketType::SenderReport);
        assert_eq!(header.length, 6);
    }

    #[test]
    fn test_sender_report_serialize() {
        let report = SenderReport::new(
            12345,
            1000,
            100,
            10000,
            vec![],
        );

        let serialized = report.serialize();
        assert!(serialized.len() >= 28); // Minimum SR size
    }
}

