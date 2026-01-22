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

//! ArcRTP (Enhanced RTP) packet handling
//!
//! Implements ArcRTP with quality/priority fields and enhanced header information.
//! Based on standard RTP (RFC 3550) with ArcRTC-specific enhancements.
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
use crate::rtp_handler::RtpHeader;
use bytes::{BufMut, Bytes, BytesMut};

/// ArcRTP quality indicator
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArcRtpQuality {
    /// Excellent quality
    Excellent = 0,
    /// Good quality
    Good = 1,
    /// Fair quality
    Fair = 2,
    /// Poor quality
    Poor = 3,
}

impl ArcRtpQuality {
    /// Parse quality from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ArcRtpQuality::Excellent),
            1 => Some(ArcRtpQuality::Good),
            2 => Some(ArcRtpQuality::Fair),
            3 => Some(ArcRtpQuality::Poor),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// ArcRTP priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArcRtpPriority {
    /// Critical priority (audio keyframes, silence breaks)
    Critical = 0,
    /// High priority (video keyframes)
    High = 1,
    /// Medium priority (video delta frames)
    Medium = 2,
    /// Low priority (redundant data, B-frames)
    Low = 3,
}

impl ArcRtpPriority {
    /// Parse priority from u8
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ArcRtpPriority::Critical),
            1 => Some(ArcRtpPriority::High),
            2 => Some(ArcRtpPriority::Medium),
            3 => Some(ArcRtpPriority::Low),
            _ => None,
        }
    }

    /// Convert to u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// ArcRTP enhanced header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcRtpHeader {
    /// Base RTP header
    pub base: RtpHeader,
    /// Quality indicator (2 bits)
    pub quality: ArcRtpQuality,
    /// Priority level (2 bits)
    pub priority: ArcRtpPriority,
    /// Bandwidth estimate (optional, 16 bits, in kbps)
    pub bandwidth_estimate: Option<u16>,
    /// Packet loss rate (optional, 8 bits, in 0.1% units)
    pub packet_loss_rate: Option<u8>,
}

/// ArcRTP packet
#[derive(Debug, Clone)]
pub struct ArcRtpPacket {
    /// Enhanced header
    pub header: ArcRtpHeader,
    /// Payload data
    pub payload: Bytes,
}

impl ArcRtpPacket {
    /// Create a new ArcRTP packet
    pub fn new(
        base_header: RtpHeader,
        quality: ArcRtpQuality,
        priority: ArcRtpPriority,
        payload: Bytes,
    ) -> Self {
        ArcRtpPacket {
            header: ArcRtpHeader {
                base: base_header,
                quality,
                priority,
                bandwidth_estimate: None,
                packet_loss_rate: None,
            },
            payload,
        }
    }

    /// Create ArcRTP packet with network metrics
    pub fn with_metrics(
        base_header: RtpHeader,
        quality: ArcRtpQuality,
        priority: ArcRtpPriority,
        payload: Bytes,
        bandwidth_estimate_kbps: Option<u16>,
        packet_loss_rate_percent: Option<f32>,
    ) -> Self {
        ArcRtpPacket {
            header: ArcRtpHeader {
                base: base_header,
                quality,
                priority,
                bandwidth_estimate: bandwidth_estimate_kbps,
                packet_loss_rate: packet_loss_rate_percent.map(|rate| {
                    // Convert percentage (0.0-100.0) to 0.1% units (0-1000)
                    (rate * 10.0) as u8
                }),
            },
            payload,
        }
    }

    /// Serialize ArcRTP packet to bytes
    pub fn serialize(&self) -> MediaEngineResult<Bytes> {
        let mut buf = BytesMut::new();

        // Serialize base RTP header directly
        let header_bytes = self.header.base.serialize();
        buf.put_slice(&header_bytes);

        // ArcRTP extension (4 bytes)
        // Byte 0: Quality (2 bits) + Priority (2 bits) + Reserved (4 bits)
        let quality_priority = (self.header.quality.to_u8() << 6) | (self.header.priority.to_u8() << 4);
        buf.put_u8(quality_priority);

        // Byte 1: Flags
        let mut flags = 0u8;
        if self.header.bandwidth_estimate.is_some() {
            flags |= 0x01; // Bit 0: Bandwidth estimate present
        }
        if self.header.packet_loss_rate.is_some() {
            flags |= 0x02; // Bit 1: Packet loss rate present
        }
        buf.put_u8(flags);

        // Byte 2-3: Bandwidth estimate (if present) or reserved
        if let Some(bw) = self.header.bandwidth_estimate {
            buf.put_u16(bw);
        } else {
            buf.put_u16(0);
        }

        // Byte 4: Packet loss rate (if present)
        if let Some(plr) = self.header.packet_loss_rate {
            buf.put_u8(plr);
        }

        // Add payload
        buf.put_slice(&self.payload);

        Ok(Bytes::from(buf))
    }

    /// Parse ArcRTP packet from bytes
    pub fn parse(data: &[u8]) -> MediaEngineResult<Self> {
        if data.len() < 16 {
            return Err(MediaEngineError::RtpParseError(
                "ArcRTP packet too short".to_string()
            ));
        }

        // Parse base RTP header to get header size
        let (base_header, _) = crate::rtp_handler::RtpHeader::parse(data)?;
        
        // Calculate RTP header size (including CSRC and extension)
        let mut offset = 12 + (base_header.csrc_count as usize * 4);
        
        if base_header.extension {
            if data.len() < offset + 4 {
                return Err(MediaEngineError::RtpParseError(
                    "ArcRTP packet too short for extension header".to_string()
                ));
            }
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4 + (ext_len * 4); // Extension header + data (padded to 32-bit boundary)
        }

        // ArcRTP extension starts right after RTP header
        // Parse ArcRTP extension (starts at offset)
        if data.len() < offset + 5 {
            return Err(MediaEngineError::RtpParseError(
                "ArcRTP packet too short for ArcRTP extension".to_string()
            ));
        }

        // Byte 0: Quality + Priority
        let quality_priority = data[offset];
        let quality = ArcRtpQuality::from_u8((quality_priority >> 6) & 0x03)
            .ok_or_else(|| MediaEngineError::RtpParseError("Invalid quality value".to_string()))?;
        let priority = ArcRtpPriority::from_u8((quality_priority >> 4) & 0x03)
            .ok_or_else(|| MediaEngineError::RtpParseError("Invalid priority value".to_string()))?;

        // Byte 1: Flags
        let flags = data[offset + 1];
        let has_bandwidth = (flags & 0x01) != 0;
        let has_packet_loss = (flags & 0x02) != 0;

        // Calculate payload start (after ArcRTP extension)
        let mut payload_start = offset + 2; // After quality/priority and flags
        
        // Byte 2-3: Bandwidth estimate (always present, but may be 0)
        let bandwidth_estimate = if has_bandwidth && data.len() >= payload_start + 2 {
            let bw = Some(u16::from_be_bytes([data[payload_start], data[payload_start + 1]]));
            payload_start += 2;
            bw
        } else {
            payload_start += 2; // Skip even if not present
            None
        };

        // Byte 4: Packet loss rate (if present)
        let packet_loss_rate = if has_packet_loss && data.len() > payload_start {
            let plr = Some(data[payload_start]);
            payload_start += 1;
            plr
        } else {
            None
        };

        // Payload starts after ArcRTP extension
        if data.len() < payload_start {
            return Err(MediaEngineError::RtpParseError(
                "ArcRTP packet too short for payload".to_string()
            ));
        }
        let payload = Bytes::copy_from_slice(&data[payload_start..]);

        Ok(ArcRtpPacket {
            header: ArcRtpHeader {
                base: base_header,
                quality,
                priority,
                bandwidth_estimate,
                packet_loss_rate,
            },
            payload,
        })
    }

    /// Convert ArcRTP packet to standard RTP packet
    pub fn to_rtp(&self) -> crate::rtp_handler::RtpPacket {
        crate::rtp_handler::RtpPacket {
            header: self.header.base.clone(),
            payload: self.payload.clone(),
        }
    }

    /// Create ArcRTP packet from standard RTP packet
    pub fn from_rtp(
        rtp: &crate::rtp_handler::RtpPacket,
        quality: ArcRtpQuality,
        priority: ArcRtpPriority,
    ) -> Self {
        ArcRtpPacket {
            header: ArcRtpHeader {
                base: rtp.header.clone(),
                quality,
                priority,
                bandwidth_estimate: None,
                packet_loss_rate: None,
            },
            payload: rtp.payload.clone(),
        }
    }

    /// Get quality indicator
    pub fn quality(&self) -> ArcRtpQuality {
        self.header.quality
    }

    /// Get priority level
    pub fn priority(&self) -> ArcRtpPriority {
        self.header.priority
    }

    /// Update quality indicator
    pub fn set_quality(&mut self, quality: ArcRtpQuality) {
        self.header.quality = quality;
    }

    /// Update priority level
    pub fn set_priority(&mut self, priority: ArcRtpPriority) {
        self.header.priority = priority;
    }

    /// Update network metrics
    pub fn set_metrics(&mut self, bandwidth_estimate_kbps: Option<u16>, packet_loss_rate_percent: Option<f32>) {
        self.header.bandwidth_estimate = bandwidth_estimate_kbps;
        self.header.packet_loss_rate = packet_loss_rate_percent.map(|rate| (rate * 10.0) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp_handler::RtpHeader;

    fn create_test_rtp_header() -> RtpHeader {
        RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 96,
            sequence_number: 1,
            timestamp: 1000,
            ssrc: 12345,
            csrc: vec![],
            extension_header: None,
        }
    }

    #[test]
    fn test_arcrtp_serialize_parse() {
        let base_header = create_test_rtp_header();
        let payload = Bytes::from("test payload");
        
        let arcrtp = ArcRtpPacket::new(
            base_header.clone(),
            ArcRtpQuality::Good,
            ArcRtpPriority::High,
            payload.clone(),
        );

        let serialized = arcrtp.serialize().unwrap();
        let parsed = ArcRtpPacket::parse(&serialized).unwrap();

        assert_eq!(parsed.header.base.sequence_number, base_header.sequence_number);
        assert_eq!(parsed.header.quality, ArcRtpQuality::Good);
        assert_eq!(parsed.header.priority, ArcRtpPriority::High);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_arcrtp_with_metrics() {
        let base_header = create_test_rtp_header();
        let payload = Bytes::from("test");
        
        let arcrtp = ArcRtpPacket::with_metrics(
            base_header,
            ArcRtpQuality::Excellent,
            ArcRtpPriority::Critical,
            payload,
            Some(5000), // 5 Mbps
            Some(0.5),  // 0.5% packet loss
        );

        assert_eq!(arcrtp.header.bandwidth_estimate, Some(5000));
        assert_eq!(arcrtp.header.packet_loss_rate, Some(5)); // 0.5% = 5 in 0.1% units
    }

    #[test]
    fn test_arcrtp_to_rtp_conversion() {
        let base_header = create_test_rtp_header();
        let payload = Bytes::from("test");
        
        let arcrtp = ArcRtpPacket::new(
            base_header.clone(),
            ArcRtpQuality::Fair,
            ArcRtpPriority::Medium,
            payload.clone(),
        );

        let rtp = arcrtp.to_rtp();
        assert_eq!(rtp.header.sequence_number, base_header.sequence_number);
        assert_eq!(rtp.payload, payload);
    }

    #[test]
    fn test_arcrtp_from_rtp() {
        let base_header = create_test_rtp_header();
        let payload = Bytes::from("test");
        
        let rtp = crate::rtp_handler::RtpPacket {
            header: base_header.clone(),
            payload: payload.clone(),
        };

        let arcrtp = ArcRtpPacket::from_rtp(&rtp, ArcRtpQuality::Good, ArcRtpPriority::High);
        
        assert_eq!(arcrtp.header.base.sequence_number, base_header.sequence_number);
        assert_eq!(arcrtp.header.quality, ArcRtpQuality::Good);
        assert_eq!(arcrtp.header.priority, ArcRtpPriority::High);
        assert_eq!(arcrtp.payload, payload);
    }

    #[test]
    fn test_quality_priority_conversion() {
        assert_eq!(ArcRtpQuality::Excellent.to_u8(), 0);
        assert_eq!(ArcRtpQuality::Good.to_u8(), 1);
        assert_eq!(ArcRtpQuality::Fair.to_u8(), 2);
        assert_eq!(ArcRtpQuality::Poor.to_u8(), 3);

        assert_eq!(ArcRtpPriority::Critical.to_u8(), 0);
        assert_eq!(ArcRtpPriority::High.to_u8(), 1);
        assert_eq!(ArcRtpPriority::Medium.to_u8(), 2);
        assert_eq!(ArcRtpPriority::Low.to_u8(), 3);
    }
}

